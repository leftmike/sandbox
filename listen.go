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

func listen(fd int, cancelFd int, h Handler) error {
	for {
		ntf, err := ioctlNotifRecv(fd, cancelFd)
		if err != nil || ntf == nil {
			return err
		}

		allowed := handler(fd, ntf, h)

		rsp := notifResp{id: ntf.id}
		if allowed {
			rsp.flags = unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
		} else {
			rsp.errno = -int32(unix.EACCES)
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

func handler(fd int, ntf *notif, h Handler) bool {
	switch ntf.data.nr {
	case unix.SYS_CLONE:
		return h.Clone(ntf.pid, ntf.data.args[0])

	case unix.SYS_CLONE3:
		n := ntf.data.args[1]
		if n > 512 {
			n = 512
		}
		buf, err := readMemory(fd, ntf, uintptr(ntf.data.args[0]), uintptr(n))
		if err != nil || len(buf) < 8 {
			fmt.Printf("clone3: read flags: %s\n", err)
			return false
		}
		return h.Clone(ntf.pid, binary.LittleEndian.Uint64(buf))

	case unix.SYS_EXECVE:
		pathname, err := readString(fd, ntf, uintptr(ntf.data.args[0]), 2048)
		if err != nil {
			fmt.Printf("execve: read pathname: %s\n", err)
			return false
		}
		argv, err := readStringSlice(fd, ntf, uintptr(ntf.data.args[1]), 4096)
		if err != nil {
			fmt.Printf("execve: read argv: %s\n", err)
			return false
		}
		env, err := readStringSlice(fd, ntf, uintptr(ntf.data.args[2]), 4096)
		if err != nil {
			fmt.Printf("execve: read env: %s\n", err)
			return false
		}
		return h.Exec(ntf.pid, pathname, argv, env)

	case unix.SYS_EXECVEAT:
		dirfd := int32(ntf.data.args[0])
		var pathname string
		var err error
		if ntf.data.args[4]&unix.AT_EMPTY_PATH != 0 {
			pathname, err = os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", ntf.pid, dirfd))
			if err != nil {
				fmt.Printf("execveat: resolve dirfd (AT_EMPTY_PATH): %s\n", err)
				return false
			}
		} else {
			pathname, err = readString(fd, ntf, uintptr(ntf.data.args[1]), 2048)
			if err != nil {
				fmt.Printf("execveat: read pathname: %s\n", err)
				return false
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
					return false
				}
				pathname = filepath.Join(dir, pathname)
			}
		}
		argv, err := readStringSlice(fd, ntf, uintptr(ntf.data.args[2]), 4096)
		if err != nil {
			fmt.Printf("execveat: read argv: %s\n", err)
			return false
		}
		env, err := readStringSlice(fd, ntf, uintptr(ntf.data.args[3]), 4096)
		if err != nil {
			fmt.Printf("execveat: read env: %s\n", err)
			return false
		}
		return h.Exec(ntf.pid, pathname, argv, env)

	case unix.SYS_FORK, unix.SYS_VFORK:
		return h.Clone(ntf.pid, 0)

	case unix.SYS_OPEN:
		pathname, err := readString(fd, ntf, uintptr(ntf.data.args[0]), 2048)
		if err != nil {
			fmt.Printf("open: read string: %s\n", err)
			return false
		}
		if !filepath.IsAbs(pathname) {
			cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", ntf.pid))
			if err != nil {
				fmt.Printf("open: resolve cwd: %s\n", err)
				return false
			}
			pathname = filepath.Join(cwd, pathname)
		}
		return h.Open(ntf.pid, pathname, int32(ntf.data.args[1]), uint32(ntf.data.args[2]))

	case unix.SYS_OPENAT:
		pathname, err := readString(fd, ntf, uintptr(ntf.data.args[1]), 2048)
		if err != nil {
			fmt.Printf("openat: read string: %s\n", err)
			return false
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
				return false
			}
			pathname = filepath.Join(dir, pathname)
		}
		return h.Open(ntf.pid, pathname, int32(ntf.data.args[2]), uint32(ntf.data.args[3]))

	case unix.SYS_OPENAT2:
		pathname, err := readString(fd, ntf, uintptr(ntf.data.args[1]), 2048)
		if err != nil {
			fmt.Printf("openat2: read pathname: %s\n", err)
			return false
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
				return false
			}
			pathname = filepath.Join(dir, pathname)
		}

		var oh openHow
		buf, err := readMemory(fd, ntf, uintptr(ntf.data.args[2]), unsafe.Sizeof(oh))
		if err != nil || len(buf) < int(unsafe.Sizeof(oh)) {
			fmt.Printf("openat2: read open_how: %s\n", err)
			return false
		}
		oh = *(*openHow)(unsafe.Pointer(&buf[0]))
		return h.Open(ntf.pid, pathname, int32(oh.flags), uint32(oh.mode))

	default:
		return h.Syscall(ntf.pid, ntf.data.nr)
	}
}
