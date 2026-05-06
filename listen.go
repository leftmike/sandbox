package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/unix"
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
			if errno != unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE {
				panic(fmt.Sprintf("errno > 0 && errno != SECCOMP_USER_NOTIF_FLAG_CONTINUE: %d",
					errno))
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
			return 0, unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
		}
		return 0, -int32(unix.EACCES)

	case unix.SYS_CLONE3:
		n := ntf.data.args[1]
		if n > 512 {
			n = 512
		}
		buf, err := readMemory(fd, ntf, uintptr(ntf.data.args[0]), uintptr(n))
		if err != nil || len(buf) < 8 {
			fmt.Printf("clone3: read flags: %s\n", err)
			return 0, -int32(unix.EACCES)
		}
		if h.Clone(ntf.pid, int(ntf.data.nr), binary.LittleEndian.Uint64(buf)) {
			return 0, unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
		}
		return 0, -int32(unix.EACCES)

	case unix.SYS_EXECVE:
		pathname, err := readString(fd, ntf, uintptr(ntf.data.args[0]), 2048)
		if err != nil {
			fmt.Printf("execve: read pathname: %s\n", err)
			return 0, -int32(unix.EACCES)
		}
		argv, err := readStringSlice(fd, ntf, uintptr(ntf.data.args[1]), 4096)
		if err != nil {
			fmt.Printf("execve: read argv: %s\n", err)
			return 0, -int32(unix.EACCES)
		}
		env, err := readStringSlice(fd, ntf, uintptr(ntf.data.args[2]), 4096)
		if err != nil {
			fmt.Printf("execve: read env: %s\n", err)
			return 0, -int32(unix.EACCES)
		}
		if h.Exec(ntf.pid, int(ntf.data.nr), pathname, argv, env) {
			return 0, unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
		}
		return 0, -int32(unix.EACCES)

	case unix.SYS_EXECVEAT:
		dirfd := int32(ntf.data.args[0])
		var pathname string
		var err error
		if ntf.data.args[4]&unix.AT_EMPTY_PATH != 0 {
			pathname, err = os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", ntf.pid, dirfd))
			if err != nil {
				fmt.Printf("execveat: resolve dirfd (AT_EMPTY_PATH): %s\n", err)
				return 0, -int32(unix.EACCES)
			}
		} else {
			pathname, err = readString(fd, ntf, uintptr(ntf.data.args[1]), 2048)
			if err != nil {
				fmt.Printf("execveat: read pathname: %s\n", err)
				return 0, -int32(unix.EACCES)
			}
			if !filepath.IsAbs(pathname) {
				var dir string
				if dirfd == unix.AT_FDCWD {
					dir, err = os.Readlink(fmt.Sprintf("/proc/%d/cwd", ntf.pid))
				} else {
					dir, err = os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", ntf.pid, dirfd))
				}
				if err != nil {
					fmt.Printf("execveat: resolve dirfd: %s\n", err)
					return 0, -int32(unix.EACCES)
				}
				pathname = filepath.Join(dir, pathname)
			}
		}
		argv, err := readStringSlice(fd, ntf, uintptr(ntf.data.args[2]), 4096)
		if err != nil {
			fmt.Printf("execveat: read argv: %s\n", err)
			return 0, -int32(unix.EACCES)
		}
		env, err := readStringSlice(fd, ntf, uintptr(ntf.data.args[3]), 4096)
		if err != nil {
			fmt.Printf("execveat: read env: %s\n", err)
			return 0, -int32(unix.EACCES)
		}
		if h.Exec(ntf.pid, int(ntf.data.nr), pathname, argv, env) {
			return 0, unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
		}
		return 0, -int32(unix.EACCES)

	case unix.SYS_OPENAT:
		pathname, err := readString(fd, ntf, uintptr(ntf.data.args[1]), 2048)
		if err != nil {
			fmt.Printf("openat: read string: %s\n", err)
			return 0, -int32(unix.EACCES)
		}
		if !filepath.IsAbs(pathname) {
			dirfd := int32(ntf.data.args[0])
			var dir string
			if dirfd == unix.AT_FDCWD {
				dir, err = os.Readlink(fmt.Sprintf("/proc/%d/cwd", ntf.pid))
			} else {
				dir, err = os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", ntf.pid, dirfd))
			}
			if err != nil {
				fmt.Printf("openat: resolve dirfd: %s\n", err)
				return 0, -int32(unix.EACCES)
			}
			pathname = filepath.Join(dir, pathname)
		}
		if h.Open(ntf.pid, int(ntf.data.nr), pathname, int32(ntf.data.args[2]),
			uint32(ntf.data.args[3])) {

			return 0, unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
		}
		return 0, -int32(unix.EACCES)

	case unix.SYS_OPENAT2:
		pathname, err := readString(fd, ntf, uintptr(ntf.data.args[1]), 2048)
		if err != nil {
			fmt.Printf("openat2: read pathname: %s\n", err)
			return 0, -int32(unix.EACCES)
		}
		if !filepath.IsAbs(pathname) {
			dirfd := int32(ntf.data.args[0])
			var dir string
			if dirfd == unix.AT_FDCWD {
				dir, err = os.Readlink(fmt.Sprintf("/proc/%d/cwd", ntf.pid))
			} else {
				dir, err = os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", ntf.pid, dirfd))
			}
			if err != nil {
				fmt.Printf("openat2: resolve dirfd: %s\n", err)
				return 0, -int32(unix.EACCES)
			}
			pathname = filepath.Join(dir, pathname)
		}

		var oh openHow
		buf, err := readMemory(fd, ntf, uintptr(ntf.data.args[2]), unsafe.Sizeof(oh))
		if err != nil || len(buf) < int(unsafe.Sizeof(oh)) {
			fmt.Printf("openat2: read open_how: %s\n", err)
			return 0, -int32(unix.EACCES)
		}
		oh = *(*openHow)(unsafe.Pointer(&buf[0]))
		if h.Open(ntf.pid, int(ntf.data.nr), pathname, int32(oh.flags), uint32(oh.mode)) {
			return 0, unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
		}
		return 0, -int32(unix.EACCES)

	default:
		return handleNotifArch(fd, ntf, h)
	}
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
