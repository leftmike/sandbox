package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	continueSyscall = math.MaxInt32 / 3
)

func recvFd(fd int) (int, error) {
	buf := make([]byte, unix.CmsgSpace(4))
	_, n, _, _, err := unix.Recvmsg(fd, nil, buf, 0)
	if err != nil {
		return -1, err
	}

	msgs, err := unix.ParseSocketControlMessage(buf[:n])
	if err != nil {
		return -1, err
	}

	if len(msgs) == 1 && msgs[0].Header.Level == unix.SOL_SOCKET &&
		msgs[0].Header.Type == unix.SCM_RIGHTS {

		fds, err := unix.ParseUnixRights(&msgs[0])
		if err != nil {
			return -1, err
		} else if len(fds) == 1 {
			return fds[0], nil
		}
	}

	return -1, errors.New("sandbox: no fd from child")
}

func sendConfig(fd int, cfg *childConfig) error {
	buf, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return unix.Sendmsg(fd, buf, nil, nil, 0)
}

func listenNotif(fd int, cancelFd int, h Handler) error {
	for {
		ntf, err := ioctlNotifRecv(fd, cancelFd)
		if err != nil || ntf == nil {
			return err
		}

		val, errno := handleNotif(fd, ntf, h)

		rsp := notifResp{id: ntf.id}
		if errno > 0 {
			if errno != continueSyscall {
				panic(fmt.Sprintf("errno > 0 && errno != continueSyscall: %d", errno))
			}
			rsp.flags = unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
		} else if errno < 0 {
			rsp.errno = errno
		} else {
			rsp.val = val
		}

		err = ioctlNotifSend(fd, rsp)
		if err != nil {
			return err
		}
	}
}

type openHow struct {
	flags   uint64
	mode    uint64
	resolve uint64
}

func handleNotif(fd int, ntf *notif, h Handler) (int64, int32) {
	switch ntf.data.nr {
	case unix.SYS_CLONE:
		if h.Clone(ntf.pid, int(ntf.data.nr), ntf.data.args[0]) {
			return 0, continueSyscall
		}
		return 0, -int32(unix.EACCES)

	case unix.SYS_CLONE3:
		n := ntf.data.args[1]
		if n > 512 {
			n = 512
		}
		buf, err := readMemory(fd, ntf, ntf.data.args[0], n)
		if err != nil || len(buf) < 8 {
			fmt.Printf("clone3: read flags: %s\n", err)
			return 0, -int32(unix.EACCES)
		}
		if h.Clone(ntf.pid, int(ntf.data.nr), binary.LittleEndian.Uint64(buf)) {
			return 0, continueSyscall
		}
		return 0, -int32(unix.EACCES)

	case unix.SYS_EXECVE:
		return handleExecvat(fd, ntf, h, unix.AT_FDCWD, ntf.data.args[0], ntf.data.args[1],
			ntf.data.args[2], 0)

	case unix.SYS_EXECVEAT:
		return handleExecvat(fd, ntf, h, int32(ntf.data.args[0]), ntf.data.args[1],
			ntf.data.args[2], ntf.data.args[3], ntf.data.args[4])

	case unix.SYS_OPENAT:
		return handleOpenat(fd, ntf, h, int32(ntf.data.args[0]), ntf.data.args[1],
			ntf.data.args[2], ntf.data.args[3], 0)

	case unix.SYS_OPENAT2:
		var oh openHow
		buf, err := readMemory(fd, ntf, ntf.data.args[2], uint64(unsafe.Sizeof(oh)))
		if err != nil || len(buf) < int(unsafe.Sizeof(oh)) {
			fmt.Printf("openat2: read open_how: %s\n", err)
			return 0, -int32(unix.EACCES)
		}
		oh = *(*openHow)(unsafe.Pointer(&buf[0]))

		return handleOpenat(fd, ntf, h, int32(ntf.data.args[0]), ntf.data.args[1], oh.flags,
			oh.mode, oh.resolve)

	default:
		return handleNotifArch(fd, ntf, h)
	}
}

func handlePath(fd int, ntf *notif, dirfd int32, path uint64) (string, string, bool) {
	pathname, err := readString(fd, ntf, path, 2048)
	if err != nil {
		fmt.Printf("%s: read string: %s\n", Sysnums[ntf.data.nr], err)
		return "", "", false
	}

	if filepath.IsAbs(pathname) {
		return "", pathname, true
	}

	var dir string
	if dirfd == unix.AT_FDCWD {
		dir, err = os.Readlink(fmt.Sprintf("/proc/%d/cwd", ntf.pid))
	} else {
		dir, err = os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", ntf.pid, dirfd))
	}
	if err != nil {
		fmt.Printf("%s: resolve dirfd: %s\n", Sysnums[ntf.data.nr], err)
		return "", "", false
	}

	return dir, pathname, true
}

func handleOpenat(fd int, ntf *notif, h Handler, dirfd int32, path, flags, mode,
	resolve uint64) (int64, int32) {

	dir, pathname, ok := handlePath(fd, ntf, dirfd, path)
	if !ok {
		return 0, -int32(unix.EACCES)
	}

	if !h.Open(ntf.pid, int(ntf.data.nr), filepath.Join(dir, pathname), int32(flags),
		uint32(mode)) {

		return 0, -int32(unix.EACCES)
	}

	dfd := int(-1)
	if !filepath.IsAbs(pathname) {
		var err error
		dfd, err = unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY, 0)
		if err != nil {
			if errno, ok := err.(unix.Errno); ok {
				return 0, -int32(errno)
			}
			return 0, -int32(unix.EACCES)
		}

		defer unix.Close(dfd)
	}

	var err error
	var sfd int
	if ntf.data.nr == unix.SYS_OPENAT2 {
		sfd, err = unix.Openat2(dfd, pathname, &unix.OpenHow{
			Flags:   flags,
			Mode:    mode,
			Resolve: resolve,
		})
	} else {
		sfd, err = unix.Openat(dfd, pathname, int(flags), uint32(mode))
	}
	if err != nil {
		if errno, ok := err.(unix.Errno); ok {
			return 0, -int32(errno)
		}
		return 0, -int32(unix.EACCES)
	}
	defer unix.Close(sfd)

	addfd := notifAddfd{
		id:    ntf.id,
		srcfd: uint32(sfd),
	}
	if flags&unix.O_CLOEXEC != 0 {
		addfd.newfdFlags = unix.O_CLOEXEC
	}
	cfd, errno := ioctlNotifAddfd(fd, addfd)
	if errno != 0 {
		return 0, -int32(errno)
	} else if cfd < 0 {
		return 0, 0
	}

	return int64(cfd), 0
}

func handleExecvat(fd int, ntf *notif, h Handler, dirfd int32, path, args, env,
	flags uint64) (int64, int32) {

	var dir, pathname string
	if flags&unix.AT_EMPTY_PATH != 0 {
		var err error
		pathname, err = os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", ntf.pid, dirfd))
		if err != nil {
			fmt.Printf("%s: resolve dirfd (AT_EMPTY_PATH): %s\n", Sysnums[ntf.data.nr], err)
			return 0, -int32(unix.EACCES)
		}
	} else {
		var ok bool
		dir, pathname, ok = handlePath(fd, ntf, dirfd, path)
		if !ok {
			return 0, -int32(unix.EACCES)
		}
	}

	argv, err := readStringSlice(fd, ntf, args, 4096)
	if err != nil {
		fmt.Printf("%s: read argv: %s\n", Sysnums[ntf.data.nr], err)
		return 0, -int32(unix.EACCES)
	}

	envp, err := readStringSlice(fd, ntf, env, 4096)
	if err != nil {
		fmt.Printf("%s: read envp: %s\n", Sysnums[ntf.data.nr], err)
		return 0, -int32(unix.EACCES)
	}

	if h.Exec(ntf.pid, int(ntf.data.nr), filepath.Join(dir, pathname), argv, envp) {
		return 0, continueSyscall
	}
	return 0, -int32(unix.EACCES)
}

func init() {
	for n, s := range Sysnums {
		if s != "" {
			sysnum, ok := syscalls[s]
			if !ok {
				panic(fmt.Sprintf("syscalls missing %s", s))
			} else if sysnum != n {
				panic(fmt.Sprintf("%s: syscalls: %d; sysnums: %d", s, sysnum, n))
			}
		}
	}

	for s, n := range syscalls {
		if Sysnums[n] != s {
			panic(fmt.Sprintf("%d: syscalls: %s; sysnums: %s", n, s, Sysnums[n]))
		}
	}
}
