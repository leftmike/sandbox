package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/leftmike/sandbox/seccomp"
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

	for _, msg := range msgs {
		if msg.Header.Level == unix.SOL_SOCKET && msg.Header.Type == unix.SCM_RIGHTS {
			fds, err := unix.ParseUnixRights(&msg)
			if err != nil {
				return -1, err
			} else if len(fds) > 0 {
				return fds[0], nil
			}
		}
	}
	return -1, errors.New("sandbox: no fd from child")
}

func listen(fd int, cancelFd int, h Handler) error {
	for {
		notif, err := seccomp.IoctlNotifRecv(fd, cancelFd)
		if err != nil || notif == nil {
			return err
		}

		allowed := handler(fd, notif, h)

		rsp := seccomp.NotifResp{ID: notif.ID}
		if allowed {
			rsp.Flags = unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
		} else {
			rsp.Error = -int32(unix.EACCES)
		}

		err = seccomp.IoctlNotifSend(fd, rsp)
		if err != nil {
			return err
		}
	}
}

func handler(fd int, notif *seccomp.Notif, h Handler) bool {
	switch notif.Data.NR {
	case unix.SYS_CLONE:
		return h.Clone(notif.PID, notif.Data.Args[0])

	case unix.SYS_CLONE3:
		n := notif.Data.Args[1]
		if n > 512 {
			n = 512
		}
		buf, err := seccomp.ReadMemory(fd, notif, uintptr(notif.Data.Args[0]), uintptr(n))
		if err != nil || len(buf) < 8 {
			fmt.Printf("clone3: read flags: %s\n", err)
			return false
		}
		return h.Clone(notif.PID, binary.LittleEndian.Uint64(buf))

	case unix.SYS_EXECVE:
		pathname, err := seccomp.ReadString(fd, notif, uintptr(notif.Data.Args[0]), 2048)
		if err != nil {
			fmt.Printf("execve: read string: %s\n", err)
			return false
		}
		return h.Exec(notif.PID, pathname)

	case unix.SYS_EXECVEAT:
		pathname, err := seccomp.ReadString(fd, notif, uintptr(notif.Data.Args[1]), 2048)
		if err != nil {
			fmt.Printf("execveat: read string: %s\n", err)
			return false
		}
		return h.Exec(notif.PID, pathname)

	case unix.SYS_FORK, unix.SYS_VFORK:
		return h.Clone(notif.PID, 0)

	case unix.SYS_OPEN:
		pathname, err := seccomp.ReadString(fd, notif, uintptr(notif.Data.Args[0]), 2048)
		if err != nil {
			fmt.Printf("open: read string: %s\n", err)
			return false
		}
		if !filepath.IsAbs(pathname) {
			cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", notif.PID))
			if err != nil {
				fmt.Printf("open: resolve cwd: %s\n", err)
				return false
			}
			pathname = filepath.Join(cwd, pathname)
		}
		return h.Open(notif.PID, pathname, int32(notif.Data.Args[1]), uint32(notif.Data.Args[2]))

	case unix.SYS_OPENAT:
		pathname, err := seccomp.ReadString(fd, notif, uintptr(notif.Data.Args[1]), 2048)
		if err != nil {
			fmt.Printf("openat: read string: %s\n", err)
			return false
		}
		if !filepath.IsAbs(pathname) {
			dirfd := int32(notif.Data.Args[0])
			var dir string
			if dirfd == unix.AT_FDCWD {
				dir, err = os.Readlink(fmt.Sprintf("/proc/%d/cwd", notif.PID))
			} else {
				dir, err = os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", notif.PID, dirfd))
			}
			if err != nil {
				fmt.Printf("openat: resolve dirfd: %s\n", err)
				return false
			}
			pathname = filepath.Join(dir, pathname)
		}
		return h.Open(notif.PID, pathname, int32(notif.Data.Args[2]), uint32(notif.Data.Args[3]))

	default:
		return h.Syscall(notif.PID, notif.Data.NR)
	}
}
