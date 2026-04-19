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

		rsp := handleNotif(fd, ntf, h)
		if rsp == nil {
			// Handler already sent the response (e.g. via ADDFD+SEND).
			continue
		}

		err = ioctlNotifSend(fd, *rsp)
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

// handleNotif dispatches a seccomp notification to the appropriate Handler
// method and returns the response to send, or nil if the response was already
// sent atomically (e.g. via ioctlNotifAddFd with addFdFlagSend).
func handleNotif(fd int, ntf *notif, h Handler) *notifResp {
	switch ntf.data.nr {
	case unix.SYS_CLONE:
		if !h.Clone(ntf.pid, int(ntf.data.nr), ntf.data.args[0]) {
			return &notifResp{id: ntf.id, errno: -int32(unix.EACCES)}
		}
		return &notifResp{id: ntf.id, flags: unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE}

	case unix.SYS_CLONE3:
		n := ntf.data.args[1]
		if n > 512 {
			n = 512
		}
		buf, err := readMemory(fd, ntf, uintptr(ntf.data.args[0]), uintptr(n))
		if err != nil || len(buf) < 8 {
			fmt.Printf("clone3: read flags: %s\n", err)
			return &notifResp{id: ntf.id, errno: -int32(unix.EACCES)}
		}
		if !h.Clone(ntf.pid, int(ntf.data.nr), binary.LittleEndian.Uint64(buf)) {
			return &notifResp{id: ntf.id, errno: -int32(unix.EACCES)}
		}
		return &notifResp{id: ntf.id, flags: unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE}

	case unix.SYS_EXECVE:
		pathname, err := readString(fd, ntf, uintptr(ntf.data.args[0]), 2048)
		if err != nil {
			fmt.Printf("execve: read pathname: %s\n", err)
			return &notifResp{id: ntf.id, errno: -int32(unix.EACCES)}
		}
		argv, err := readStringSlice(fd, ntf, uintptr(ntf.data.args[1]), 4096)
		if err != nil {
			fmt.Printf("execve: read argv: %s\n", err)
			return &notifResp{id: ntf.id, errno: -int32(unix.EACCES)}
		}
		env, err := readStringSlice(fd, ntf, uintptr(ntf.data.args[2]), 4096)
		if err != nil {
			fmt.Printf("execve: read env: %s\n", err)
			return &notifResp{id: ntf.id, errno: -int32(unix.EACCES)}
		}
		if !h.Exec(ntf.pid, int(ntf.data.nr), pathname, argv, env) {
			return &notifResp{id: ntf.id, errno: -int32(unix.EACCES)}
		}
		return &notifResp{id: ntf.id, flags: unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE}

	case unix.SYS_EXECVEAT:
		dirfd := int32(ntf.data.args[0])
		var pathname string
		var err error
		if ntf.data.args[4]&unix.AT_EMPTY_PATH != 0 {
			pathname, err = os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", ntf.pid, dirfd))
			if err != nil {
				fmt.Printf("execveat: resolve dirfd (AT_EMPTY_PATH): %s\n", err)
				return &notifResp{id: ntf.id, errno: -int32(unix.EACCES)}
			}
		} else {
			pathname, err = readString(fd, ntf, uintptr(ntf.data.args[1]), 2048)
			if err != nil {
				fmt.Printf("execveat: read pathname: %s\n", err)
				return &notifResp{id: ntf.id, errno: -int32(unix.EACCES)}
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
					return &notifResp{id: ntf.id, errno: -int32(unix.EACCES)}
				}
				pathname = filepath.Join(dir, pathname)
			}
		}
		argv, err := readStringSlice(fd, ntf, uintptr(ntf.data.args[2]), 4096)
		if err != nil {
			fmt.Printf("execveat: read argv: %s\n", err)
			return &notifResp{id: ntf.id, errno: -int32(unix.EACCES)}
		}
		env, err := readStringSlice(fd, ntf, uintptr(ntf.data.args[3]), 4096)
		if err != nil {
			fmt.Printf("execveat: read env: %s\n", err)
			return &notifResp{id: ntf.id, errno: -int32(unix.EACCES)}
		}
		if !h.Exec(ntf.pid, int(ntf.data.nr), pathname, argv, env) {
			return &notifResp{id: ntf.id, errno: -int32(unix.EACCES)}
		}
		return &notifResp{id: ntf.id, flags: unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE}

	case unix.SYS_OPENAT:
		dirfd := int(int32(ntf.data.args[0]))
		pathname, err := readString(fd, ntf, uintptr(ntf.data.args[1]), 2048)
		if err != nil {
			fmt.Printf("openat: read string: %s\n", err)
			return &notifResp{id: ntf.id, errno: -int32(unix.EACCES)}
		}
		absPathname := pathname
		if !filepath.IsAbs(pathname) {
			var dir string
			if int32(dirfd) == unix.AT_FDCWD {
				dir, err = os.Readlink(fmt.Sprintf("/proc/%d/cwd", ntf.pid))
			} else {
				dir, err = os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", ntf.pid, dirfd))
			}
			if err != nil {
				fmt.Printf("openat: resolve dirfd: %s\n", err)
				return &notifResp{id: ntf.id, errno: -int32(unix.EACCES)}
			}
			absPathname = filepath.Join(dir, pathname)
		}
		flags := int32(ntf.data.args[2])
		mode := uint32(ntf.data.args[3])
		if !h.Open(ntf.pid, int(ntf.data.nr), absPathname, flags, mode) {
			return &notifResp{id: ntf.id, errno: -int32(unix.EACCES)}
		}
		return doOpen(fd, ntf, dirfd, pathname, int(flags), mode)

	case unix.SYS_OPENAT2:
		dirfd := int(int32(ntf.data.args[0]))
		pathname, err := readString(fd, ntf, uintptr(ntf.data.args[1]), 2048)
		if err != nil {
			fmt.Printf("openat2: read pathname: %s\n", err)
			return &notifResp{id: ntf.id, errno: -int32(unix.EACCES)}
		}
		absPathname := pathname
		if !filepath.IsAbs(pathname) {
			var dir string
			if int32(dirfd) == unix.AT_FDCWD {
				dir, err = os.Readlink(fmt.Sprintf("/proc/%d/cwd", ntf.pid))
			} else {
				dir, err = os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", ntf.pid, dirfd))
			}
			if err != nil {
				fmt.Printf("openat2: resolve dirfd: %s\n", err)
				return &notifResp{id: ntf.id, errno: -int32(unix.EACCES)}
			}
			absPathname = filepath.Join(dir, pathname)
		}
		var oh openHow
		buf, err := readMemory(fd, ntf, uintptr(ntf.data.args[2]), unsafe.Sizeof(oh))
		if err != nil || len(buf) < int(unsafe.Sizeof(oh)) {
			fmt.Printf("openat2: read open_how: %s\n", err)
			return &notifResp{id: ntf.id, errno: -int32(unix.EACCES)}
		}
		oh = *(*openHow)(unsafe.Pointer(&buf[0]))
		if !h.Open(ntf.pid, int(ntf.data.nr), absPathname, int32(oh.flags), uint32(oh.mode)) {
			return &notifResp{id: ntf.id, errno: -int32(unix.EACCES)}
		}
		return doOpen2(fd, ntf, dirfd, pathname, oh)

	default:
		return handleNotifArch(fd, ntf, h)
	}
}

// doOpen opens the file in the supervisor process and injects the resulting fd
// into the child, preventing TOCTOU: the kernel never re-reads the path from
// the child's memory.
func doOpen(fd int, ntf *notif, dirfd int, path string, flags int, mode uint32) *notifResp {
	var newFdFlags uint32
	if flags&unix.O_CLOEXEC != 0 {
		newFdFlags = unix.O_CLOEXEC
	}
	supervisorFd, err := supervisorOpenat(ntf.pid, dirfd, path, flags|unix.O_CLOEXEC, mode)
	if err != nil {
		if errno, ok := err.(unix.Errno); ok {
			return &notifResp{id: ntf.id, errno: -int32(errno)}
		}
		return &notifResp{id: ntf.id, errno: -int32(unix.EIO)}
	}
	defer unix.Close(supervisorFd)

	_, err = ioctlNotifAddFd(fd, ntf.id, supervisorFd, addFdFlagSend, newFdFlags)
	if err != nil {
		if errno, ok := err.(unix.Errno); ok {
			return &notifResp{id: ntf.id, errno: -int32(errno)}
		}
		return &notifResp{id: ntf.id, errno: -int32(unix.EIO)}
	}
	return nil // response already sent atomically by ADDFD+SEND
}

// doOpen2 is like doOpen but for openat2, preserving the openHow flags
// (including resolve flags) in the supervisor's open call.
func doOpen2(fd int, ntf *notif, dirfd int, path string, oh openHow) *notifResp {
	var newFdFlags uint32
	if oh.flags&unix.O_CLOEXEC != 0 {
		newFdFlags = unix.O_CLOEXEC
	}
	supervisorFd, err := supervisorOpenat2(ntf.pid, dirfd, path, oh)
	if err != nil {
		if errno, ok := err.(unix.Errno); ok {
			return &notifResp{id: ntf.id, errno: -int32(errno)}
		}
		return &notifResp{id: ntf.id, errno: -int32(unix.EIO)}
	}
	defer unix.Close(supervisorFd)

	_, err = ioctlNotifAddFd(fd, ntf.id, supervisorFd, addFdFlagSend, newFdFlags)
	if err != nil {
		if errno, ok := err.(unix.Errno); ok {
			return &notifResp{id: ntf.id, errno: -int32(errno)}
		}
		return &notifResp{id: ntf.id, errno: -int32(unix.EIO)}
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

// supervisorOpenat2 is like supervisorOpenat but preserves the openHow flags.
func supervisorOpenat2(pid uint32, dirfd int, path string, oh openHow) (int, error) {
	how := &unix.OpenHow{Flags: oh.flags | unix.O_CLOEXEC, Mode: oh.mode, Resolve: oh.resolve}
	if path != "" && path[0] == '/' {
		return unix.Openat2(unix.AT_FDCWD, path, how)
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
	return unix.Openat2(baseFd, path, how)
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
