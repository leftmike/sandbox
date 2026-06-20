package sandbox

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

type notifAddfd struct {
	id         uint64
	flags      uint32
	srcfd      uint32
	newfd      uint32
	newfdFlags uint32
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
		} else if pfds[1].Revents&(unix.POLLIN|unix.POLLHUP|unix.POLLERR) != 0 {
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

type procMem struct {
	fd int
	id uint64
	mf *os.File
}

func openProcMem(fd int, ntf *notif) (procMem, error) {
	mf, err := os.OpenFile(fmt.Sprintf("/proc/%d/mem", ntf.pid), os.O_RDONLY, 0)
	if err != nil {
		return procMem{}, err
	}

	return procMem{fd: fd, id: ntf.id, mf: mf}, nil

}

func (pm *procMem) readMemory(addr, size uint64) ([]byte, error) {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(pm.fd), unix.SECCOMP_IOCTL_NOTIF_ID_VALID,
		uintptr(unsafe.Pointer(&pm.id)))
	if errno != 0 {
		return nil, errno
	}

	buf := make([]byte, size)
	n, err := pm.mf.ReadAt(buf, int64(addr))
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, unix.EIO) {
		return nil, err
	}
	buf = buf[:n]

	_, _, errno = unix.Syscall(unix.SYS_IOCTL, uintptr(pm.fd), unix.SECCOMP_IOCTL_NOTIF_ID_VALID,
		uintptr(unsafe.Pointer(&pm.id)))
	if errno != 0 {
		return nil, errno
	}

	return buf, nil
}

func (pm *procMem) readString(addr, size uint64) (string, error) {
	buf, err := pm.readMemory(addr, size)
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

func (pm *procMem) readStringSlice(addr, cnt, size uint64) ([]string, error) {
	if addr == 0 {
		return nil, nil
	}

	sz := unsafe.Sizeof(addr)

	buf, err := pm.readMemory(addr, (cnt+1)*uint64(sz))
	if err != nil {
		return nil, err
	}

	var ret []string
	for len(buf) >= int(sz) {
		p := binary.LittleEndian.Uint64(buf)
		if p == 0 {
			return ret, nil
		}
		buf = buf[sz:]

		s, err := pm.readString(p, size)
		if err != nil {
			return nil, err
		}
		ret = append(ret, s)
	}

	return nil, fmt.Errorf("read proc memory: more than %d strings in slice", cnt)
}

func readMemory(fd int, ntf *notif, addr, size uint64) ([]byte, error) {
	pm, err := openProcMem(fd, ntf)
	if err != nil {
		return nil, err
	}
	defer pm.mf.Close()

	return pm.readMemory(addr, size)
}

func ioctlNotifSend(fd int, rsp notifResp) error {
	buf := make([]byte, notifRespSize)
	*(*notifResp)(unsafe.Pointer(&buf[0])) = rsp

	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SECCOMP_IOCTL_NOTIF_SEND,
		uintptr(unsafe.Pointer(&buf[0])))
	if errno != 0 {
		if errors.Is(errno, unix.ENOENT) {
			return nil // Child died.
		}
		return errno
	}
	return nil
}

func ioctlNotifAddfd(fd int, addfd notifAddfd) (int, unix.Errno) {
	cfd, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SECCOMP_IOCTL_NOTIF_ADDFD,
		uintptr(unsafe.Pointer(&addfd)))
	if errno != 0 {
		return -1, errno
	}
	return int(cfd), 0
}
