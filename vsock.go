package sandbox

import (
	"os"

	"golang.org/x/sys/unix"
)

// vsockListener is the host end of the host<->guest control/stdio channel. The
// guest agent dials back to the host (VMADDR_CID_HOST) on the listener's port.
type vsockListener struct {
	fd   int
	port uint32
}

// listenVsock binds and listens on an AF_VSOCK stream socket. Pass
// unix.VMADDR_PORT_ANY to let the kernel choose a free port (read back via Port).
func listenVsock(port uint32) (*vsockListener, error) {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}

	err = unix.Bind(fd, &unix.SockaddrVM{CID: unix.VMADDR_CID_ANY, Port: port})
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	err = unix.Listen(fd, 1)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}

	sa, err := unix.Getsockname(fd)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	if vm, ok := sa.(*unix.SockaddrVM); ok {
		port = vm.Port
	}

	return &vsockListener{fd: fd, port: port}, nil
}

// Port returns the port the agent should dial back on.
func (l *vsockListener) Port() uint32 { return l.port }

// accept blocks for the guest agent's connection and returns it as an
// *os.File (a ReadWriteCloser over the vsock stream).
func (l *vsockListener) accept() (*os.File, error) {
	nfd, _, err := unix.Accept(l.fd)
	if err != nil {
		return nil, err
	}
	unix.CloseOnExec(nfd)
	return os.NewFile(uintptr(nfd), "vsock-conn"), nil
}

func (l *vsockListener) Close() error { return unix.Close(l.fd) }
