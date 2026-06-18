package sandbox

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

func (cmd *Cmd) listenNotif(fd int, cancelFd int) error {
	for {
		ntf, err := ioctlNotifRecv(fd, cancelFd)
		if err != nil || ntf == nil {
			return err
		}

		val, errno := cmd.handleNotif(fd, ntf)

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

func (cmd *Cmd) handleNotif(fd int, ntf *notif) (int64, int32) {
	switch ntf.data.nr {
	case unix.SYS_CLONE:
		if cmd.Sandbox.Clone == nil || cmd.Sandbox.Clone(ntf.pid, int(ntf.data.nr),
			ntf.data.args[0]) {

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
			if cmd.Sandbox.Failed != nil {
				cmd.Sandbox.Failed(ntf.pid, int(ntf.data.nr),
					fmt.Errorf("clone3: read flags: %s", err))
			}
			return 0, -int32(unix.EACCES)
		}
		if cmd.Sandbox.Clone == nil || cmd.Sandbox.Clone(ntf.pid, int(ntf.data.nr),
			binary.LittleEndian.Uint64(buf)) {

			return 0, continueSyscall
		}
		return 0, -int32(unix.EACCES)

	case unix.SYS_EXECVE:
		return cmd.handleExecvat(fd, ntf, unix.AT_FDCWD, ntf.data.args[0], ntf.data.args[1],
			ntf.data.args[2], 0)

	case unix.SYS_EXECVEAT:
		return cmd.handleExecvat(fd, ntf, int32(ntf.data.args[0]), ntf.data.args[1],
			ntf.data.args[2], ntf.data.args[3], ntf.data.args[4])

	case unix.SYS_OPENAT:
		return cmd.handleOpenat(fd, ntf, int32(ntf.data.args[0]), ntf.data.args[1],
			ntf.data.args[2], ntf.data.args[3], 0)

	case unix.SYS_OPENAT2:
		var oh unix.OpenHow
		buf, err := readMemory(fd, ntf, ntf.data.args[2], uint64(unsafe.Sizeof(oh)))
		if err != nil || len(buf) < int(unsafe.Sizeof(oh)) {
			if cmd.Sandbox.OpenFailed != nil {
				cmd.Sandbox.OpenFailed(ntf.pid, int(ntf.data.nr), "",
					fmt.Errorf("read open_how: %s", err))
			}
			return 0, -int32(unix.EACCES)
		}
		oh = *(*unix.OpenHow)(unsafe.Pointer(&buf[0]))

		return cmd.handleOpenat(fd, ntf, int32(ntf.data.args[0]), ntf.data.args[1], oh.Flags,
			oh.Mode, oh.Resolve)

	default:
		return cmd.handleNotifArch(fd, ntf)
	}
}

func handlePath(fd int, ntf *notif, dirfd int32, path uint64) (string, string, error) {
	pathname, err := readString(fd, ntf, path, 2048)
	if err != nil {
		return "", "", fmt.Errorf("read string: %s", err)

	}

	if filepath.IsAbs(pathname) {
		return "", pathname, nil
	}

	var dir string
	if dirfd == unix.AT_FDCWD {
		dir, err = os.Readlink(fmt.Sprintf("/proc/%d/cwd", ntf.pid))
	} else {
		dir, err = os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", ntf.pid, dirfd))
	}
	if err != nil {
		return "", pathname, fmt.Errorf("resolve dirfd: %s", err)
	}

	return dir, pathname, nil
}

func (cmd *Cmd) handleOpenat(fd int, ntf *notif, dirfd int32, path, flags, mode,
	resolve uint64) (int64, int32) {

	dir, pathname, err := handlePath(fd, ntf, dirfd, path)
	if err != nil {
		if cmd.Sandbox.OpenFailed != nil {
			cmd.Sandbox.OpenFailed(ntf.pid, int(ntf.data.nr), pathname, err)
		}
		return 0, -int32(unix.EACCES)
	}
	abspath := filepath.Join(dir, pathname)

	if cmd.Sandbox.Mode == LandlockMode {
		if cmd.Sandbox.Open != nil && !cmd.Sandbox.Open(ntf.pid, int(ntf.data.nr),
			abspath, int32(flags), uint32(mode), resolve) {

			return 0, -int32(unix.EACCES)
		}

		return 0, continueSyscall
	}

	// SeccompMode
	dfd := int(-1)
	if !filepath.IsAbs(pathname) {
		var err error
		dfd, err = unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY, 0)
		if err != nil {
			if cmd.Sandbox.OpenFailed != nil {
				cmd.Sandbox.OpenFailed(ntf.pid, int(ntf.data.nr), abspath, err)
			}
			if errno, ok := err.(unix.Errno); ok {
				return 0, -int32(errno)
			}
			return 0, -int32(unix.EACCES)
		}

		defer unix.Close(dfd)
	}

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
		if cmd.Sandbox.OpenFailed != nil {
			cmd.Sandbox.OpenFailed(ntf.pid, int(ntf.data.nr), abspath, err)
		}
		if errno, ok := err.(unix.Errno); ok {
			return 0, -int32(errno)
		}
		return 0, -int32(unix.EACCES)
	}
	defer unix.Close(sfd)

	realpath, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", sfd))
	if err != nil {
		if cmd.Sandbox.OpenFailed != nil {
			cmd.Sandbox.OpenFailed(ntf.pid, int(ntf.data.nr), abspath, err)
		}
		return 0, -int32(unix.EACCES)
	}

	if !cmd.Sandbox.fsAllows(realpath, flags) {
		if cmd.Sandbox.OpenFailed != nil {
			cmd.Sandbox.OpenFailed(ntf.pid, int(ntf.data.nr), realpath, unix.EACCES)
		}
		return 0, -int32(unix.EACCES)
	}

	if cmd.Sandbox.Open != nil && !cmd.Sandbox.Open(ntf.pid, int(ntf.data.nr),
		realpath, int32(flags), uint32(mode), resolve) {

		return 0, -int32(unix.EACCES)
	}

	addfd := notifAddfd{
		id:    ntf.id,
		srcfd: uint32(sfd),
	}
	if flags&unix.O_CLOEXEC != 0 {
		addfd.newfdFlags = unix.O_CLOEXEC
	}
	cfd, errno := ioctlNotifAddfd(fd, addfd)
	if errno != 0 {
		if cmd.Sandbox.OpenFailed != nil {
			cmd.Sandbox.OpenFailed(ntf.pid, int(ntf.data.nr), realpath, errno)
		}
		return 0, -int32(errno)
	}

	return int64(cfd), 0
}

func (cmd *Cmd) handleExecvat(fd int, ntf *notif, dirfd int32, path, args, env,
	flags uint64) (int64, int32) {

	var dir, pathname string
	if flags&unix.AT_EMPTY_PATH != 0 {
		var err error
		pathname, err = os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", ntf.pid, dirfd))
		if err != nil {
			if cmd.Sandbox.Failed != nil {
				cmd.Sandbox.Failed(ntf.pid, int(ntf.data.nr),
					fmt.Errorf("resolve dirfd (AT_EMPTY_PATH): %s", err))
			}
			return 0, -int32(unix.EACCES)
		}
	} else {
		var err error
		dir, pathname, err = handlePath(fd, ntf, dirfd, path)
		if err != nil {
			if cmd.Sandbox.Failed != nil {
				cmd.Sandbox.Failed(ntf.pid, int(ntf.data.nr), fmt.Errorf("%s: %s", err, pathname))
			}
			return 0, -int32(unix.EACCES)
		}
	}
	abspath := filepath.Join(dir, pathname)

	argv, err := readStringSlice(fd, ntf, args, 4096)
	if err != nil {
		if cmd.Sandbox.Failed != nil {
			cmd.Sandbox.Failed(ntf.pid, int(ntf.data.nr),
				fmt.Errorf("read argv: %s: %s", err, abspath))
		}
		return 0, -int32(unix.EACCES)
	}

	envp, err := readStringSlice(fd, ntf, env, 4096)
	if err != nil {
		if cmd.Sandbox.Failed != nil {
			cmd.Sandbox.Failed(ntf.pid, int(ntf.data.nr),
				fmt.Errorf("read envp: %s: %s", err, abspath))
		}
		return 0, -int32(unix.EACCES)
	}

	if cmd.Sandbox.Exec == nil ||
		cmd.Sandbox.Exec(ntf.pid, int(ntf.data.nr), abspath, argv, envp) {

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
			} else if sysnum != uint32(n) {
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
