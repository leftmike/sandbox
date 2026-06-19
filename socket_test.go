package sandbox_test

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"slices"
	"testing"

	"github.com/leftmike/sandbox"
	"golang.org/x/sys/unix"
)

// socketScript creates a socket of the given type, then connects and binds it
// using the supplied addresses. Failures are ignored so the syscalls are still
// observed by the sandbox even when the operation itself does not succeed.
// The socket(2) syscall is intercepted before the kernel runs it, so the
// Socket handler observes the call even when socket creation later fails (for
// example, AF_INET6 on a host without IPv6). All errors are swallowed so the
// process exits 0 and the test can assert on what the handler observed.
const socketScript = `import socket, sys
fam, typ = int(sys.argv[1]), int(sys.argv[2])
connect_addr, bind_addr, port = sys.argv[3], sys.argv[4], int(sys.argv[5])
try:
    s = socket.socket(fam, typ)
except Exception:
    sys.exit(0)
try:
    s.bind((bind_addr, port))
except Exception:
    pass
try:
    s.connect((connect_addr, port))
except Exception:
    pass
s.close()
`

func pythonOrSkip(t *testing.T) string {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	return python
}

func TestSocketCreate(t *testing.T) {
	python := pythonOrSkip(t)

	cases := []struct {
		fam  int
		typ  int
		want int
	}{
		{unix.AF_INET, unix.SOCK_STREAM, unix.SOCK_STREAM},
		{unix.AF_INET, unix.SOCK_DGRAM, unix.SOCK_DGRAM},
		{unix.AF_INET6, unix.SOCK_STREAM, unix.SOCK_STREAM},
		{unix.AF_INET6, unix.SOCK_DGRAM, unix.SOCK_DGRAM},
	}

	for _, c := range cases {
		var gotDomain, gotType int
		var found bool
		cmd := sandbox.Command(python, "-c", socketScript,
			fmt.Sprint(c.fam), fmt.Sprint(c.typ), "127.0.0.1", "127.0.0.1", "9")
		cmd.Sandbox = &sandbox.Sandbox{
			NoLandlock: true,
			Socket: func(pid uint32, sysnum, domain, typ, protocol int) bool {
				gotDomain, gotType, found = domain, typ, true
				return true
			},
		}
		if err := cmd.Run(); err != nil {
			t.Errorf("Run() failed: %s", err)
		} else if !found {
			t.Errorf("socket(%d, %d): handler not called", c.fam, c.typ)
		} else if gotDomain != c.fam || gotType != c.want {
			t.Errorf("socket(%d, %d): got domain=%d type=%d, want domain=%d type=%d",
				c.fam, c.typ, gotDomain, gotType, c.fam, c.want)
		}
	}
}

// TestSocketUnixIgnored verifies that AF_UNIX sockets do not trigger the Socket
// handler, since only TCP and UDP (IP) sockets are reported.
func TestSocketUnixIgnored(t *testing.T) {
	python := pythonOrSkip(t)

	script := `import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.close()
`
	var called bool
	cmd := sandbox.Command(python, "-c", script)
	cmd.Sandbox = &sandbox.Sandbox{
		NoLandlock: true,
		Socket: func(pid uint32, sysnum, domain, typ, protocol int) bool {
			called = true
			return true
		},
	}
	if err := cmd.Run(); err != nil {
		t.Errorf("Run() failed: %s", err)
	} else if called {
		t.Error("socket(AF_UNIX): handler called, want not called")
	}
}

func TestSocketConnect(t *testing.T) {
	python := pythonOrSkip(t)

	want := netip.MustParseAddrPort("127.0.0.1:9")

	var got netip.AddrPort
	var found bool
	cmd := sandbox.Command(python, "-c", socketScript,
		fmt.Sprint(unix.AF_INET), fmt.Sprint(unix.SOCK_DGRAM),
		want.Addr().String(), "0.0.0.0", fmt.Sprint(want.Port()))
	cmd.Sandbox = &sandbox.Sandbox{
		NoLandlock: true,
		Connect: func(pid uint32, sysnum, sockfd int, addr netip.AddrPort) bool {
			got, found = addr, true
			return true
		},
	}
	if err := cmd.Run(); err != nil {
		t.Errorf("Run() failed: %s", err)
	} else if !found {
		t.Error("connect: handler not called")
	} else if got != want {
		t.Errorf("connect: got %s, want %s", got, want)
	}
}

func TestSocketBind(t *testing.T) {
	python := pythonOrSkip(t)

	want := netip.MustParseAddrPort("127.0.0.1:0")

	var got netip.AddrPort
	var found bool
	cmd := sandbox.Command(python, "-c", socketScript,
		fmt.Sprint(unix.AF_INET), fmt.Sprint(unix.SOCK_DGRAM),
		"127.0.0.1", want.Addr().String(), fmt.Sprint(want.Port()))
	cmd.Sandbox = &sandbox.Sandbox{
		NoLandlock: true,
		Bind: func(pid uint32, sysnum, sockfd int, addr netip.AddrPort) bool {
			got, found = addr, true
			return true
		},
	}
	if err := cmd.Run(); err != nil {
		t.Errorf("Run() failed: %s", err)
	} else if !found {
		t.Error("bind: handler not called")
	} else if got.Addr() != want.Addr() {
		t.Errorf("bind: got %s, want addr %s", got, want.Addr())
	}
}

// TestSocketSendto verifies that sendto(2) on an unconnected UDP socket
// reports the explicit destination address.
func TestSocketSendto(t *testing.T) {
	python := pythonOrSkip(t)

	want := netip.MustParseAddrPort("127.0.0.1:9")

	script := `import socket, sys
addr, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b"hello", (addr, port))
s.close()
`
	var got netip.AddrPort
	var found bool
	cmd := sandbox.Command(python, "-c", script,
		want.Addr().String(), fmt.Sprint(want.Port()))
	cmd.Sandbox = &sandbox.Sandbox{
		NoLandlock: true,
		Sendto: func(pid uint32, sysnum, sockfd int, addr netip.AddrPort) bool {
			got, found = addr, true
			return true
		},
	}
	if err := cmd.Run(); err != nil {
		t.Errorf("Run() failed: %s", err)
	} else if !found {
		t.Error("sendto: handler not called")
	} else if got != want {
		t.Errorf("sendto: got %s, want %s", got, want)
	}
}

// TestSocketSendmsg verifies that sendmsg(2) with an explicit destination
// address reports it.
func TestSocketSendmsg(t *testing.T) {
	python := pythonOrSkip(t)

	want := netip.MustParseAddrPort("127.0.0.1:9")

	script := `import socket, sys
addr, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendmsg([b"hello"], [], 0, (addr, port))
s.close()
`
	var got netip.AddrPort
	var found bool
	cmd := sandbox.Command(python, "-c", script,
		want.Addr().String(), fmt.Sprint(want.Port()))
	cmd.Sandbox = &sandbox.Sandbox{
		NoLandlock: true,
		Sendto: func(pid uint32, sysnum, sockfd int, addr netip.AddrPort) bool {
			got, found = addr, true
			return true
		},
	}
	if err := cmd.Run(); err != nil {
		t.Errorf("Run() failed: %s", err)
	} else if !found {
		t.Error("sendmsg: handler not called")
	} else if got != want {
		t.Errorf("sendmsg: got %s, want %s", got, want)
	}
}

// sendmmsgScript sends two datagrams in a single sendmmsg(2) to 127.0.0.1 on
// the two ports given in argv, exercising the per-message striding of the
// msgvec array. Python has no sendmmsg binding, so it is called via ctypes.
const sendmmsgScript = `import ctypes, socket, sys
libc = ctypes.CDLL(None, use_errno=True)

class sockaddr_in(ctypes.Structure):
    _fields_ = [("sin_family", ctypes.c_ushort), ("sin_port", ctypes.c_ushort),
                ("sin_addr", ctypes.c_ubyte * 4), ("sin_zero", ctypes.c_ubyte * 8)]

class iovec(ctypes.Structure):
    _fields_ = [("iov_base", ctypes.c_void_p), ("iov_len", ctypes.c_size_t)]

class msghdr(ctypes.Structure):
    _fields_ = [("msg_name", ctypes.c_void_p), ("msg_namelen", ctypes.c_uint32),
                ("msg_iov", ctypes.c_void_p), ("msg_iovlen", ctypes.c_size_t),
                ("msg_control", ctypes.c_void_p), ("msg_controllen", ctypes.c_size_t),
                ("msg_flags", ctypes.c_int)]

class mmsghdr(ctypes.Structure):
    _fields_ = [("msg_hdr", msghdr), ("msg_len", ctypes.c_uint)]

ports = [int(p) for p in sys.argv[1:]]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
buf = ctypes.create_string_buffer(b"hi")
arr = (mmsghdr * len(ports))()
keep = []
for i, port in enumerate(ports):
    a = sockaddr_in()
    a.sin_family = socket.AF_INET
    a.sin_port = socket.htons(port)
    a.sin_addr[:] = [127, 0, 0, 1]
    iv = iovec(ctypes.cast(buf, ctypes.c_void_p), 2)
    keep += [a, iv]
    arr[i].msg_hdr.msg_name = ctypes.cast(ctypes.pointer(a), ctypes.c_void_p)
    arr[i].msg_hdr.msg_namelen = ctypes.sizeof(a)
    arr[i].msg_hdr.msg_iov = ctypes.cast(ctypes.pointer(iv), ctypes.c_void_p)
    arr[i].msg_hdr.msg_iovlen = 1
libc.sendmmsg(s.fileno(), arr, len(ports), 0)
s.close()
`

func TestSocketSendmmsg(t *testing.T) {
	python := pythonOrSkip(t)

	want := []netip.AddrPort{
		netip.MustParseAddrPort("127.0.0.1:9"),
		netip.MustParseAddrPort("127.0.0.1:10"),
	}

	var got []netip.AddrPort
	cmd := sandbox.Command(python, "-c", sendmmsgScript,
		fmt.Sprint(want[0].Port()), fmt.Sprint(want[1].Port()))
	cmd.Sandbox = &sandbox.Sandbox{
		NoLandlock: true,
		Sendto: func(pid uint32, sysnum, sockfd int, addr netip.AddrPort) bool {
			got = append(got, addr)
			return true
		},
	}
	if err := cmd.Run(); err != nil {
		t.Errorf("Run() failed: %s", err)
	} else if !slices.Equal(got, want) {
		t.Errorf("sendmmsg: got %v, want %v", got, want)
	}
}

// TestSocketSendConnectedIgnored verifies that send(2) on a connected socket,
// which carries no destination address, does not call Sendto.
func TestSocketSendConnectedIgnored(t *testing.T) {
	python := pythonOrSkip(t)

	script := `import socket, sys
addr, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect((addr, port))
s.send(b"hello")
s.close()
`
	var called bool
	cmd := sandbox.Command(python, "-c", script, "127.0.0.1", "9")
	cmd.Sandbox = &sandbox.Sandbox{
		NoLandlock: true,
		Sendto: func(pid uint32, sysnum, sockfd int, addr netip.AddrPort) bool {
			called = true
			return true
		},
	}
	if err := cmd.Run(); err != nil {
		t.Errorf("Run() failed: %s", err)
	} else if called {
		t.Error("send on connected socket: Sendto called, want not called")
	}
}

// TestSocketSendtoDenied verifies that returning false from Sendto denies the
// send.
func TestSocketSendtoDenied(t *testing.T) {
	python := pythonOrSkip(t)

	deny := netip.MustParseAddrPort("127.0.0.1:9")

	script := `import socket, sys
addr, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    s.sendto(b"hello", (addr, port))
    print("sent")
except OSError as e:
    print("denied", e.errno)
s.close()
`
	var denied bool
	cmd := sandbox.Command(python, "-c", script,
		deny.Addr().String(), fmt.Sprint(deny.Port()))
	cmd.Sandbox = &sandbox.Sandbox{
		NoLandlock: true,
		Sendto: func(pid uint32, sysnum, sockfd int, addr netip.AddrPort) bool {
			if addr == deny {
				denied = true
				return false
			}
			return true
		},
	}
	out, err := cmd.Output()
	if err != nil {
		t.Errorf("Run() failed: %s", err)
	} else if !denied {
		t.Error("sendto: handler not called for destination address")
	} else if got := string(out); got == "sent\n" {
		t.Errorf("sendto denied but process sent: %q", got)
	}
}

// TestSocketConnectDenied verifies that returning false from Connect denies the
// connection so the sandboxed process cannot reach the address.
func TestSocketConnectDenied(t *testing.T) {
	python := pythonOrSkip(t)

	// A listener the sandboxed process would otherwise be able to connect to.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	addr := netip.MustParseAddrPort(ln.Addr().String())

	script := `import socket, sys
addr, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    s.connect((addr, port))
    print("connected")
except OSError as e:
    print("denied", e.errno)
s.close()
`
	var denied bool
	cmd := sandbox.Command(python, "-c", script,
		addr.Addr().String(), fmt.Sprint(addr.Port()))
	cmd.Sandbox = &sandbox.Sandbox{
		NoLandlock: true,
		Connect: func(pid uint32, sysnum, sockfd int, a netip.AddrPort) bool {
			if a == addr {
				denied = true
				return false
			}
			return true
		},
	}
	out, err := cmd.Output()
	if err != nil {
		t.Errorf("Run() failed: %s", err)
	} else if !denied {
		t.Error("connect: handler not called for listener address")
	} else if got := string(out); got == "connected\n" {
		t.Errorf("connect denied but process connected: %q", got)
	}
}
