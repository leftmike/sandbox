package main

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"

	"github.com/leftmike/sandbox/seccomp"
)

func recvmsg(f *os.File, buf []byte) ([]byte, error) {
	sc, err := f.SyscallConn()
	if err != nil {
		return nil, err
	}

	var n int
	var rerr error
	err = sc.Read(func(fd uintptr) bool {
		_, n, _, _, rerr = unix.Recvmsg(int(fd), make([]byte, 1), buf, 0)
		return rerr != unix.EAGAIN && rerr != unix.EWOULDBLOCK
	})
	if err != nil {
		return nil, err
	} else if rerr != nil {
		return nil, rerr
	}

	return buf[:n], nil
}

func recvFd(f *os.File) (int, error) {
	buf, err := recvmsg(f, make([]byte, unix.CmsgSpace(4)))
	if err != nil {
		return -1, err
	}
	msgs, err := unix.ParseSocketControlMessage(buf)
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

// redirectExecPath opens the validated executable at pathname, injects the fd
// into the child process, then overwrites the pathname buffer in child memory
// with /proc/self/fd/{n}. When CONTINUE is sent the kernel will exec the
// supervisor-validated inode rather than re-reading the user-controlled string,
// closing the window where a sibling thread could swap the filename between the
// supervisor's check and the kernel's re-read.
//
// The overwrite requires the replacement path to fit in the original buffer; if
// it does not, the function returns without error and the exec proceeds with the
// original NOTIF_ID_VALID sandwich as the only protection.
func redirectExecPath(fd int, notif *seccomp.Notif, pathnameAddr uintptr, pathname string) {
	f, err := os.Open(pathname)
	if err != nil {
		return
	}
	defer f.Close()

	childFd, err := seccomp.IoctlNotifAddFd(fd, &seccomp.NotifAddFd{
		ID:         notif.ID,
		SrcFd:      uint32(f.Fd()),
		NewFdFlags: unix.O_CLOEXEC,
	})
	if err != nil {
		return
	}

	newPath := fmt.Sprintf("/proc/self/fd/%d", childFd)
	if len(newPath) > len(pathname) {
		return
	}
	newPathBytes := append([]byte(newPath), 0)
	seccomp.WriteMemory(notif, pathnameAddr, newPathBytes) //nolint:errcheck
}

func handler(fd int, notif *seccomp.Notif, h Handler) bool {
	switch notif.Data.NR {
	case unix.SYS_EXECVE:
		pathnameAddr := uintptr(notif.Data.Args[0])
		pathname, err := seccomp.ReadString(fd, notif, pathnameAddr, 2048)
		if err != nil {
			fmt.Printf("execve: read string: %s\n", err)
			return false
		}
		if !h.Exec(notif.PID, pathname) {
			return false
		}
		redirectExecPath(fd, notif, pathnameAddr, pathname)
		return true

	case unix.SYS_EXECVEAT:
		pathnameAddr := uintptr(notif.Data.Args[1])
		pathname, err := seccomp.ReadString(fd, notif, pathnameAddr, 2048)
		if err != nil {
			fmt.Printf("execveat: read string: %s\n", err)
			return false
		}
		if !h.Exec(notif.PID, pathname) {
			return false
		}
		redirectExecPath(fd, notif, pathnameAddr, pathname)
		return true

	case unix.SYS_OPEN:
		pathname, err := seccomp.ReadString(fd, notif, uintptr(notif.Data.Args[0]), 2048)
		if err != nil {
			fmt.Printf("open: read string: %s\n", err)
			return false
		}
		return h.Open(notif.PID, pathname, int32(notif.Data.Args[1]), uint32(notif.Data.Args[2]))

	case unix.SYS_OPENAT:
		pathname, err := seccomp.ReadString(fd, notif, uintptr(notif.Data.Args[1]), 2048)
		if err != nil {
			fmt.Printf("openat: read string: %s\n", err)
			return false
		}
		return h.Open(notif.PID, pathname, int32(notif.Data.Args[2]), uint32(notif.Data.Args[3]))

	default:
		return h.Syscall(notif.PID, notif.Data.NR)
	}
}
