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

		rsp := handler(fd, notif, h)
		if rsp == nil {
			// Handler already sent the response (e.g. via ADDFD+SEND).
			continue
		}

		err = seccomp.IoctlNotifSend(fd, *rsp)
		if err != nil {
			return err
		}
	}
}

// handler dispatches a seccomp notification to the appropriate Handler method
// and returns the response to send, or nil if the response was already sent.
func handler(fd int, notif *seccomp.Notif, h Handler) *seccomp.NotifResp {
	switch notif.Data.NR {
	case unix.SYS_EXECVE:
		pathname, err := seccomp.ReadString(fd, notif, uintptr(notif.Data.Args[0]), 2048)
		if err != nil {
			fmt.Printf("execve: read string: %s\n", err)
			return &seccomp.NotifResp{ID: notif.ID, Error: -int32(unix.EACCES)}
		}
		if !h.Exec(notif.PID, pathname) {
			return &seccomp.NotifResp{ID: notif.ID, Error: -int32(unix.EACCES)}
		}
		return &seccomp.NotifResp{ID: notif.ID, Flags: unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE}

	case unix.SYS_EXECVEAT:
		pathname, err := seccomp.ReadString(fd, notif, uintptr(notif.Data.Args[1]), 2048)
		if err != nil {
			fmt.Printf("execveat: read string: %s\n", err)
			return &seccomp.NotifResp{ID: notif.ID, Error: -int32(unix.EACCES)}
		}
		if !h.Exec(notif.PID, pathname) {
			return &seccomp.NotifResp{ID: notif.ID, Error: -int32(unix.EACCES)}
		}
		return &seccomp.NotifResp{ID: notif.ID, Flags: unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE}

	case unix.SYS_OPEN:
		pathname, err := seccomp.ReadString(fd, notif, uintptr(notif.Data.Args[0]), 2048)
		if err != nil {
			fmt.Printf("open: read string: %s\n", err)
			return &seccomp.NotifResp{ID: notif.ID, Error: -int32(unix.EACCES)}
		}
		flags := int32(notif.Data.Args[1])
		mode := uint32(notif.Data.Args[2])
		if !h.Open(notif.PID, pathname, flags, mode) {
			return &seccomp.NotifResp{ID: notif.ID, Error: -int32(unix.EACCES)}
		}
		return doOpen(fd, notif, unix.AT_FDCWD, pathname, int(flags), mode)

	case unix.SYS_OPENAT:
		dirfd := int(int32(notif.Data.Args[0]))
		pathname, err := seccomp.ReadString(fd, notif, uintptr(notif.Data.Args[1]), 2048)
		if err != nil {
			fmt.Printf("openat: read string: %s\n", err)
			return &seccomp.NotifResp{ID: notif.ID, Error: -int32(unix.EACCES)}
		}
		flags := int32(notif.Data.Args[2])
		mode := uint32(notif.Data.Args[3])
		if !h.Open(notif.PID, pathname, flags, mode) {
			return &seccomp.NotifResp{ID: notif.ID, Error: -int32(unix.EACCES)}
		}
		return doOpen(fd, notif, dirfd, pathname, int(flags), mode)

	default:
		if !h.Syscall(notif.PID, notif.Data.NR) {
			return &seccomp.NotifResp{ID: notif.ID, Error: -int32(unix.EACCES)}
		}
		return &seccomp.NotifResp{ID: notif.ID, Flags: unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE}
	}
}

// doOpen opens the file in the supervisor process and injects the resulting fd
// into the child, preventing TOCTOU: the kernel never re-reads the path from
// the child's memory.
func doOpen(fd int, notif *seccomp.Notif, dirfd int, path string, flags int, mode uint32) *seccomp.NotifResp {
	var newFdFlags uint32
	if flags&unix.O_CLOEXEC != 0 {
		newFdFlags = unix.O_CLOEXEC
	}
	supervisorFd, err := supervisorOpenat(notif.PID, dirfd, path, flags|unix.O_CLOEXEC, mode)
	if err != nil {
		if errno, ok := err.(unix.Errno); ok {
			return &seccomp.NotifResp{ID: notif.ID, Error: -int32(errno)}
		}
		return &seccomp.NotifResp{ID: notif.ID, Error: -int32(unix.EIO)}
	}
	defer unix.Close(supervisorFd)

	_, err = seccomp.IoctlNotifAddFd(fd, notif.ID, supervisorFd, seccomp.AddFdFlagSend, newFdFlags)
	if err != nil {
		if errno, ok := err.(unix.Errno); ok {
			return &seccomp.NotifResp{ID: notif.ID, Error: -int32(errno)}
		}
		return &seccomp.NotifResp{ID: notif.ID, Error: -int32(unix.EIO)}
	}
	return nil // response already sent atomically by ADDFD+SEND
}

// supervisorOpenat opens path in the supervisor, resolving dirfd via /proc
// so that relative paths and non-AT_FDCWD dirfds work correctly.
func supervisorOpenat(pid uint32, dirfd int, path string, flags int, mode uint32) (int, error) {
	if path != "" && path[0] == '/' {
		return unix.Open(path, flags, mode)
	}
	var baseDir string
	if dirfd == unix.AT_FDCWD {
		baseDir = fmt.Sprintf("/proc/%d/cwd", pid)
	} else {
		baseDir = fmt.Sprintf("/proc/%d/fd/%d", pid, dirfd)
	}
	baseFd, err := unix.Open(baseDir, unix.O_PATH|unix.O_DIRECTORY, 0)
	if err != nil {
		return -1, err
	}
	defer unix.Close(baseFd)
	return unix.Openat(baseFd, path, flags, mode)
}
