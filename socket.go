package sandbox

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"golang.org/x/sys/unix"
)

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

// handleSockaddr reads the sockaddr argument shared by connect(2) and bind(2)
// and, when it is an AF_INET or AF_INET6 address, reports it to cb. Other
// address families (such as AF_UNIX) are allowed without calling cb.
func (cmd *Cmd) handleSockaddr(fd int, ntf *notif,
	cb func(pid uint32, sysnum int, sockfd int, addr netip.AddrPort) bool) (int64, int32) {

	addrlen := ntf.data.args[2]
	if addrlen > unix.SizeofSockaddrAny {
		addrlen = unix.SizeofSockaddrAny
	}
	buf, err := readMemory(fd, ntf, ntf.data.args[1], addrlen)
	if err != nil {
		if cmd.Sandbox.Failed != nil {
			cmd.Sandbox.Failed(ntf.pid, int(ntf.data.nr),
				fmt.Errorf("read sockaddr: %s", err))
		}
		return 0, -int32(unix.EACCES)
	}

	addr, ok := sockaddrAddrPort(buf)
	if !ok {
		return 0, continueSyscall
	}

	if cb == nil || cb(ntf.pid, int(ntf.data.nr), int(int32(ntf.data.args[0])), addr) {
		return 0, continueSyscall
	}
	return 0, -int32(unix.EACCES)
}

func (cmd *Cmd) handleConnect(fd int, ntf *notif) (int64, int32) {
	return cmd.handleSockaddr(fd, ntf, cmd.Sandbox.Connect)
}

func (cmd *Cmd) handleBind(fd int, ntf *notif) (int64, int32) {
	return cmd.handleSockaddr(fd, ntf, cmd.Sandbox.Bind)
}
