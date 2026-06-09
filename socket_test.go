package sandbox_test

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"
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
