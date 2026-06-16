// Command guest is the in-VM sandbox agent. It runs as PID 1 (/init) inside the
// KVM guest: it mounts the host filesystem shares exported over 9p, reads its
// GuestConfig from the kernel cmdline, dials back to the host over vsock, runs the
// target command (chrooted into the shared host root), relays stdio as framed
// streams, reports the exit code, and powers the VM off.
//
// It must build static and CGO-free (CGO_ENABLED=0) so it can serve as init with
// no libc present.
package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/leftmike/sandbox/internal/vmproto"
	"golang.org/x/sys/unix"
)

const rootDir = "/newroot"

func main() {
	code := run()
	// Best effort: flush and power off so QEMU (-no-reboot) exits.
	unix.Sync()
	unix.Reboot(unix.LINUX_REBOOT_CMD_POWER_OFF)
	os.Exit(code)
}

func run() int {
	cfg, err := readConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "guest: config: %v\n", err)
		return 127
	}

	conn, err := dialHost(cfg.Port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "guest: dial host: %v\n", err)
		return 127
	}
	defer conn.Close()

	if err := mountShares(cfg.Shares); err != nil {
		reportErr(conn, fmt.Sprintf("guest: mount: %v", err))
		return 127
	}

	return execCommand(conn, cfg)
}

// readConfig parses the base64 GuestConfig from /proc/cmdline. /proc must be
// mounted first.
func readConfig() (*vmproto.GuestConfig, error) {
	_ = os.MkdirAll("/proc", 0o555)
	if err := unix.Mount("proc", "/proc", "proc", 0, ""); err != nil {
		return nil, fmt.Errorf("mount /proc: %w", err)
	}
	raw, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return nil, err
	}
	for _, tok := range strings.Fields(string(raw)) {
		if v, ok := strings.CutPrefix(tok, vmproto.CmdlineConfigKey+"="); ok {
			return vmproto.UnmarshalConfig(v)
		}
	}
	return nil, fmt.Errorf("%s not on cmdline", vmproto.CmdlineConfigKey)
}

func dialHost(port uint32) (*os.File, error) {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	err = unix.Connect(fd, &unix.SockaddrVM{CID: unix.VMADDR_CID_HOST, Port: port})
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), "vsock-host"), nil
}

// mountShares mounts each 9p export under rootDir, in order, so the root share
// (MountPoint "/") lands at rootDir and the rest overlay beneath it.
func mountShares(shares []vmproto.GuestShare) error {
	for _, s := range shares {
		target := filepath.Join(rootDir, s.MountPoint)
		if err := os.MkdirAll(target, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", target, err)
		}
		var flags uintptr
		if !s.Writable {
			flags |= unix.MS_RDONLY
		}
		err := unix.Mount(s.Tag, target, "9p", flags, "trans=virtio,version=9p2000.L")
		if err != nil {
			return fmt.Errorf("mount %s at %s: %w", s.Tag, target, err)
		}
	}
	return nil
}

// execCommand runs the target chrooted into the shared host root, relaying stdio
// over vsock frames, and returns its exit code.
func execCommand(conn *os.File, cfg *vmproto.GuestConfig) int {
	cmd := exec.Command(cfg.Path, cfg.Args[1:]...)
	cmd.Args = cfg.Args
	cmd.Env = cfg.Env
	cmd.Dir = cfg.Dir
	cmd.SysProcAttr = &syscall.SysProcAttr{Chroot: rootDir}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		reportErr(conn, fmt.Sprintf("guest: stdin pipe: %v", err))
		return 127
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		reportErr(conn, fmt.Sprintf("guest: stdout pipe: %v", err))
		return 127
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		reportErr(conn, fmt.Sprintf("guest: stderr pipe: %v", err))
		return 127
	}

	if err := cmd.Start(); err != nil {
		reportErr(conn, fmt.Sprintf("guest: exec %s: %v", cfg.Path, err))
		return 127
	}

	done := make(chan struct{}, 2)
	go func() { pump(conn, vmproto.StreamStdout, stdout); done <- struct{}{} }()
	go func() { pump(conn, vmproto.StreamStderr, stderr); done <- struct{}{} }()
	go demuxStdin(conn, stdin)

	err = cmd.Wait()
	<-done
	<-done

	code := exitCode(err)
	vmproto.WriteFrame(conn, vmproto.StreamExit, vmproto.ExitPayload(code))
	return code
}

// pump copies r into framed writes on conn under the given stream tag.
func pump(conn io.Writer, tag vmproto.Stream, r io.Reader) {
	buf := make([]byte, 32*1024)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if werr := vmproto.WriteFrame(conn, tag, buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// demuxStdin reads frames from the host and writes StreamStdin payloads to w.
func demuxStdin(conn io.Reader, w io.WriteCloser) {
	for {
		tag, payload, err := vmproto.ReadFrame(conn)
		if err != nil {
			w.Close()
			return
		}
		switch tag {
		case vmproto.StreamStdin:
			w.Write(payload)
		case vmproto.StreamClose:
			w.Close()
			return
		}
	}
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode()
	}
	return 127
}

func reportErr(conn io.Writer, msg string) {
	vmproto.WriteFrame(conn, vmproto.StreamStderr, []byte(msg+"\n"))
	vmproto.WriteFrame(conn, vmproto.StreamExit, vmproto.ExitPayload(127))
}
