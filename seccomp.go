package main

import (
	"encoding/binary"
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

	if uintptr(ns.notif) < unsafe.Sizeof(notif{}) {
		panic(fmt.Sprintf("ns.notif < unsafe.Sizeof(notif{}): %d %d", ns.notif,
			unsafe.Sizeof(notif{})))
	}
	if uintptr(ns.data) < unsafe.Sizeof(notifData{}) {
		panic(fmt.Sprintf("ns.data < unsafe.Sizeof(notifData{}): %d %d", ns.data,
			unsafe.Sizeof(notifData{})))
	}
	if uintptr(ns.notifResp) < unsafe.Sizeof(notifResp{}) {
		panic(fmt.Sprintf("ns.notifResp < unsafe.Sizeof(notifResp{}): %d %d", ns.notifResp,
			unsafe.Sizeof(notifResp{})))
	}

	notifSize = int(ns.notif)
	dataSize = int(ns.data)
	notifRespSize = int(ns.notifResp)
}

type notif struct {
	id    uint64
	pid   uint32
	flags uint32
	data  notifData
}

type notifData struct {
	nr                 int32
	arch               uint32
	instructionPointer uint64
	args               [6]uint64
}

type notifResp struct {
	id    uint64
	val   int64
	errno int32
	flags uint32
}

func ioctlNotifRecv(fd int, cancelFd int) (*notif, error) {
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

	return (*notif)(unsafe.Pointer(&buf[0])), nil
}

func readMemory(fd int, ntf *notif, addr, size uintptr) ([]byte, error) {
	f, err := os.OpenFile(fmt.Sprintf("/proc/%d/mem", ntf.pid), os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SECCOMP_IOCTL_NOTIF_ID_VALID,
		uintptr(unsafe.Pointer(&ntf.id)))
	if errno != 0 {
		return nil, errno
	}

	buf := make([]byte, size)
	n, err := f.ReadAt(buf, int64(addr))
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, unix.EIO) {
		return nil, err
	}
	buf = buf[:n]

	_, _, errno = unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SECCOMP_IOCTL_NOTIF_ID_VALID,
		uintptr(unsafe.Pointer(&ntf.id)))
	if errno != 0 {
		return nil, errno
	}

	return buf, nil
}

func readString(fd int, ntf *notif, addr, size uintptr) (string, error) {
	buf, err := readMemory(fd, ntf, addr, size)
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

func readStringSlice(fd int, ntf *notif, addr, size uintptr) ([]string, error) {
	if addr == 0 {
		return nil, nil
	}

	buf, err := readMemory(fd, ntf, addr, size)
	if err != nil {
		return nil, err
	}

	ps := unsafe.Sizeof(addr)
	var ret []string
	for len(buf) >= int(ps) {
		p := binary.LittleEndian.Uint64(buf)
		if p == 0 {
			break
		}
		buf = buf[ps:]

		s, err := readString(fd, ntf, uintptr(p), size)
		if err != nil {
			return nil, err
		}
		ret = append(ret, s)
	}

	return ret, nil
}

func ioctlNotifSend(fd int, rsp notifResp) error {
	buf := make([]byte, notifRespSize)
	*(*notifResp)(unsafe.Pointer(&buf[0])) = rsp

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
