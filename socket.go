package sandbox

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/unix"
)

// mmsghdr mirrors the kernel struct mmsghdr passed to sendmmsg(2): a struct
// msghdr followed by an unsigned msg_len. Only its size is used, to stride over
// the array; each entry's msghdr (and thus its msg_name pointer) begins at the
// start of the entry.
type mmsghdr struct {
	hdr unix.Msghdr
	len uint32
}

const sizeofMmsghdr = unsafe.Sizeof(mmsghdr{})

// sockaddrAddrPort parses an AF_INET or AF_INET6 sockaddr from buf, returning
// the address and port. ok is false for any other address family (such as
// AF_UNIX) or a buffer that is too short to hold the parsed family. The
// sa_family field is in native byte order; both supported architectures
// (amd64 and arm64) are little-endian.
func sockaddrAddrPort(buf []byte) (addr netip.AddrPort, ok bool) {
	if len(buf) < 2 {
		return netip.AddrPort{}, false
	}

	switch binary.LittleEndian.Uint16(buf) {
	case unix.AF_INET:
		if len(buf) < unix.SizeofSockaddrInet4 {
			return netip.AddrPort{}, false
		}
		port := binary.BigEndian.Uint16(buf[2:4])
		return netip.AddrPortFrom(netip.AddrFrom4([4]byte(buf[4:8])), port), true

	case unix.AF_INET6:
		if len(buf) < unix.SizeofSockaddrInet6 {
			return netip.AddrPort{}, false
		}
		port := binary.BigEndian.Uint16(buf[2:4])
		return netip.AddrPortFrom(netip.AddrFrom16([16]byte(buf[8:24])), port), true
	}

	return netip.AddrPort{}, false
}

// readSockaddr reads a sockaddr of length bytes from ptr in the process and
// parses it. ok is false (with a nil error) when ptr is NULL or the address is
// not AF_INET/AF_INET6, in which case the syscall should be allowed without
// reporting.
func (cmd *Cmd) readSockaddr(fd int, ntf *notif, ptr, length uint64) (netip.AddrPort, bool,
	error) {

	if ptr == 0 {
		return netip.AddrPort{}, false, nil
	}
	if length == 0 || length > unix.SizeofSockaddrAny {
		length = unix.SizeofSockaddrAny
	}

	buf, err := readMemory(fd, ntf, ptr, length)
	if err != nil {
		return netip.AddrPort{}, false, err
	}

	addr, ok := sockaddrAddrPort(buf)
	return addr, ok, nil
}

func (cmd *Cmd) handleSocket(ntf *notif) (int64, int32) {
	domain := int(int32(ntf.data.args[0]))
	if domain != unix.AF_INET && domain != unix.AF_INET6 {
		return 0, continueSyscall
	}

	typ := int(int32(ntf.data.args[1])) &^ (unix.SOCK_CLOEXEC | unix.SOCK_NONBLOCK)
	protocol := int(int32(ntf.data.args[2]))

	if cmd.Sandbox.Socket == nil ||
		cmd.Sandbox.Socket(ntf.pid, int(ntf.data.nr), domain, typ, protocol) {

		return 0, continueSyscall
	}
	return 0, -int32(unix.EACCES)
}

// reportSockaddr reads the sockaddr at ptr and, when it is an AF_INET or
// AF_INET6 address, reports it to cb. Other address families (such as AF_UNIX)
// and NULL addresses are allowed without calling cb.
func (cmd *Cmd) reportSockaddr(fd int, ntf *notif, sockfd int, ptr, length uint64,
	cb func(pid uint32, sysnum int, sockfd int, addr netip.AddrPort) bool) (int64, int32) {

	addr, ok, err := cmd.readSockaddr(fd, ntf, ptr, length)
	if err != nil {
		if cmd.Sandbox.Failed != nil {
			cmd.Sandbox.Failed(ntf.pid, int(ntf.data.nr),
				fmt.Errorf("read sockaddr: %s", err))
		}
		return 0, -int32(unix.EACCES)
	}
	if !ok {
		return 0, continueSyscall
	}

	if cb == nil || cb(ntf.pid, int(ntf.data.nr), sockfd, addr) {
		return 0, continueSyscall
	}
	return 0, -int32(unix.EACCES)
}

func (cmd *Cmd) handleConnect(fd int, ntf *notif) (int64, int32) {
	return cmd.reportSockaddr(fd, ntf, int(int32(ntf.data.args[0])), ntf.data.args[1],
		ntf.data.args[2], cmd.Sandbox.Connect)
}

func (cmd *Cmd) handleBind(fd int, ntf *notif) (int64, int32) {
	return cmd.reportSockaddr(fd, ntf, int(int32(ntf.data.args[0])), ntf.data.args[1],
		ntf.data.args[2], cmd.Sandbox.Bind)
}

func (cmd *Cmd) handleSendto(fd int, ntf *notif) (int64, int32) {
	// sendto(sockfd, buf, len, flags, dest_addr, addrlen)
	return cmd.reportSockaddr(fd, ntf, int(int32(ntf.data.args[0])), ntf.data.args[4],
		ntf.data.args[5], cmd.Sandbox.Sendto)
}

// readMsghdrName reads the msg_name pointer and msg_namelen from a struct
// msghdr at ptr. ok is false (with a nil error) when there is no destination
// address (msg_name is NULL or the header is too short), in which case the
// send should be allowed without reporting.
func (cmd *Cmd) readMsghdrName(fd int, ntf *notif, ptr uint64) (name, namelen uint64, ok bool,
	err error) {

	// msg_name is the first field (a pointer) and msg_namelen the second (a
	// uint32) of struct msghdr.
	buf, err := readMemory(fd, ntf, ptr, 12)
	if err != nil {
		return 0, 0, false, err
	}
	if len(buf) < 12 {
		return 0, 0, false, nil
	}

	name = binary.LittleEndian.Uint64(buf[0:8])
	if name == 0 {
		return 0, 0, false, nil
	}
	namelen = uint64(binary.LittleEndian.Uint32(buf[8:12]))
	return name, namelen, true, nil
}

func (cmd *Cmd) handleSendmsg(fd int, ntf *notif) (int64, int32) {
	// sendmsg(sockfd, msg, flags)
	name, namelen, ok, err := cmd.readMsghdrName(fd, ntf, ntf.data.args[1])
	if err != nil {
		if cmd.Sandbox.Failed != nil {
			cmd.Sandbox.Failed(ntf.pid, int(ntf.data.nr), fmt.Errorf("read msghdr: %s", err))
		}
		return 0, -int32(unix.EACCES)
	}
	if !ok {
		return 0, continueSyscall
	}

	return cmd.reportSockaddr(fd, ntf, int(int32(ntf.data.args[0])), name, namelen,
		cmd.Sandbox.Sendto)
}

func (cmd *Cmd) handleSendmmsg(fd int, ntf *notif) (int64, int32) {
	// sendmmsg(sockfd, msgvec, vlen, flags)
	sockfd := int(int32(ntf.data.args[0]))
	ptr := ntf.data.args[1]
	vlen := ntf.data.args[2]
	if vlen > 1024 {
		vlen = 1024
	}

	for i := uint64(0); i < vlen; i++ {
		name, namelen, ok, err := cmd.readMsghdrName(fd, ntf, ptr+i*uint64(sizeofMmsghdr))
		if err != nil {
			if cmd.Sandbox.Failed != nil {
				cmd.Sandbox.Failed(ntf.pid, int(ntf.data.nr),
					fmt.Errorf("read msghdr: %s", err))
			}
			return 0, -int32(unix.EACCES)
		}
		if !ok {
			continue
		}

		addr, ok, err := cmd.readSockaddr(fd, ntf, name, namelen)
		if err != nil {
			if cmd.Sandbox.Failed != nil {
				cmd.Sandbox.Failed(ntf.pid, int(ntf.data.nr),
					fmt.Errorf("read sockaddr: %s", err))
			}
			return 0, -int32(unix.EACCES)
		}
		if !ok {
			continue
		}

		if cmd.Sandbox.Sendto != nil &&
			!cmd.Sandbox.Sendto(ntf.pid, int(ntf.data.nr), sockfd, addr) {

			return 0, -int32(unix.EACCES)
		}
	}

	return 0, continueSyscall
}
