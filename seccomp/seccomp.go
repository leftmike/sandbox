package seccomp

import (
	"errors"
	"fmt"
	"io"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

type notifSizes struct {
	notif     uint16
	notifResp uint16
	data      uint16
}

var (
	notifSize     int
	notifRespSize int
	dataSize      int
)

func init() {
	var ns notifSizes
	_, _, errno := unix.Syscall(unix.SYS_SECCOMP, uintptr(unix.SECCOMP_GET_NOTIF_SIZES), 0,
		uintptr(unsafe.Pointer(&ns)))
	if errno != 0 {
		panic(fmt.Sprintf("seccomp(GET_NOTIF_SIZES): %d", errno))
	}

	if uintptr(ns.notif) < unsafe.Sizeof(Notif{}) {
		panic(fmt.Sprintf("ns.notif < unsafe.Sizeof(Notif{}): %d %d", ns.notif,
			unsafe.Sizeof(Notif{})))
	}
	if uintptr(ns.data) < unsafe.Sizeof(Data{}) {
		panic(fmt.Sprintf("ns.data < unsafe.Sizeof(Data{}): %d %d", ns.data,
			unsafe.Sizeof(Data{})))
	}
	if uintptr(ns.notifResp) < unsafe.Sizeof(NotifResp{}) {
		panic(fmt.Sprintf("ns.notifResp < unsafe.Sizeof(NotifResp{}): %d %d", ns.notifResp,
			unsafe.Sizeof(NotifResp{})))
	}

	notifSize = int(ns.notif)
	dataSize = int(ns.data)
	notifRespSize = int(ns.notifResp)
}

type Notif struct {
	ID    uint64
	PID   uint32
	Flags uint32
	Data  Data
}

type Data struct {
	NR                 int32
	Arch               uint32
	InstructionPointer uint64
	Args               [6]uint64
}

type NotifResp struct {
	ID    uint64
	Val   int64
	Error int32
	Flags uint32
}

func IoctlNotifRecv(fd int, cancelFd int) (*Notif, error) {
	buf := make([]byte, notifSize)
	pfds := []unix.PollFd{
		{Fd: int32(fd), Events: unix.POLLIN},
		{Fd: int32(cancelFd), Events: unix.POLLIN},
	}
	for {
		_, err := unix.Poll(pfds, -1)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return nil, err
		} else if pfds[0].Revents&(unix.POLLHUP|unix.POLLERR) != 0 {
			return nil, nil
		} else if pfds[1].Revents&unix.POLLIN != 0 {
			return nil, nil
		}

		_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SECCOMP_IOCTL_NOTIF_RECV,
			uintptr(unsafe.Pointer(&buf[0])))
		if errno == 0 {
			break
		} else if errors.Is(errno, unix.ENOENT) || errors.Is(errno, unix.EBADF) {
			return nil, nil
		} else if !errors.Is(errno, unix.EINTR) {
			return nil, errno
		}
	}

	return (*Notif)(unsafe.Pointer(&buf[0])), nil
}

func ReadMemory(fd int, notif *Notif, addr, size uintptr) ([]byte, error) {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SECCOMP_IOCTL_NOTIF_ID_VALID,
		uintptr(unsafe.Pointer(&notif.ID)))
	if errno != 0 {
		return nil, errno
	}

	f, err := os.OpenFile(fmt.Sprintf("/proc/%d/mem", notif.PID), os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	_, _, errno = unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SECCOMP_IOCTL_NOTIF_ID_VALID,
		uintptr(unsafe.Pointer(&notif.ID)))
	if errno != 0 {
		return nil, errno
	}

	buf := make([]byte, size)
	n, err := f.ReadAt(buf, int64(addr))
	if err != nil && !errors.Is(err, io.EOF) && n == 0 {
		return nil, err
	}
	buf = buf[:n]

	_, _, errno = unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SECCOMP_IOCTL_NOTIF_ID_VALID,
		uintptr(unsafe.Pointer(&notif.ID)))
	if errno != 0 {
		return nil, errno
	}

	return buf, nil
}

func ReadString(fd int, notif *Notif, addr, size uintptr) (string, error) {
	buf, err := ReadMemory(fd, notif, addr, size)
	if err != nil {
		return "", err
	}

	for i := range buf {
		if buf[i] == 0 {
			return string(buf[:i]), nil
		}
	}

	return "", errors.New("string not NUL terminated")
}

// NotifAddFd is the argument to SECCOMP_IOCTL_NOTIF_ADDFD.
type NotifAddFd struct {
	ID         uint64
	Flags      uint32
	SrcFd      uint32
	NewFd      uint32
	NewFdFlags uint32
}

const (
	// SECCOMP_IOCTL_NOTIF_ADDFD = _IOW('!', 3, struct seccomp_notif_addfd)
	ioctlNotifAddFd = 0x40182103
	// AddFdFlagSend is SECCOMP_ADDFD_FLAG_SEND: atomically add the fd and
	// send the notification response so the child receives the new fd number
	// as the return value of its blocked syscall.
	AddFdFlagSend = uint32(2)
)

// IoctlNotifAddFd injects srcFd into the notified process's fd table.
// When flags includes AddFdFlagSend the notification response is sent
// atomically, making this the sole response for that notification.
// Returns the fd number installed in the target process.
func IoctlNotifAddFd(fd int, id uint64, srcFd int, flags, newFdFlags uint32) (int, error) {
	addfd := NotifAddFd{
		ID:         id,
		Flags:      flags,
		SrcFd:      uint32(srcFd),
		NewFdFlags: newFdFlags,
	}
	r, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), ioctlNotifAddFd,
		uintptr(unsafe.Pointer(&addfd)))
	if errno != 0 {
		return -1, errno
	}
	return int(r), nil
}

func IoctlNotifSend(fd int, rsp NotifResp) error {
	buf := make([]byte, notifRespSize)
	*(*NotifResp)(unsafe.Pointer(&buf[0])) = rsp

	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SECCOMP_IOCTL_NOTIF_SEND,
		uintptr(unsafe.Pointer(&buf[0])))
	if errno != 0 {
		// ENOENT: child died between recv and send
		if errors.Is(errno, unix.ENOENT) {
			return nil
		}
		return errno
	}
	return nil
}
