package sandbox

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"time"

	"github.com/leftmike/sandbox/internal/vmproto"
)

// Mode selects the isolation tier used by a Cmd.
type Mode int

const (
	// ModeSeccomp is the default: in-kernel isolation via seccomp + Landlock,
	// supervised by the parent over a seccomp user notification.
	ModeSeccomp Mode = iota
	// ModeVM runs the target command inside a KVM micro-VM for hardware-level
	// isolation. Requires /dev/kvm and a qemu-system-* binary on PATH. See
	// VMConfig.
	ModeVM
)

// VMConfig tunes ModeVM. The zero value is usable: empty fields are auto-detected
// or defaulted (see vmDefaults).
type VMConfig struct {
	Hypervisor    string        // qemu-system-* binary; "" => auto-detect for GOARCH
	KernelPath    string        // bzImage/vmlinuz; "" => /boot/vmlinuz-$(uname -r)
	InitramfsPath string        // guest-agent initramfs; "" => built on demand
	MemoryMiB     int           // guest RAM; 0 => 256
	VCPUs         int           // guest vCPUs; 0 => 1
	ShareRootRO   bool          // export host / read-only as the guest root tree
	ExtraShares   []Share       // additional host directories to expose
	Timeout       time.Duration // hard wall-clock limit; 0 => none
}

// Share is one host directory exported into the guest over 9p/virtiofs.
type Share struct {
	HostPath string // absolute host path to export
	Tag      string // 9p/virtiofs mount tag; assigned automatically if empty
	Writable bool   // false => read-only inside the guest
}

func (vc *VMConfig) withDefaults() VMConfig {
	out := *vc
	if out.MemoryMiB == 0 {
		out.MemoryMiB = 256
	}
	if out.VCPUs == 0 {
		out.VCPUs = 1
	}
	return out
}

// shares derives the VM mount scope from an FSPolicy. Inside a VM there is no
// per-openat supervisor, so the Read/Write/Execute allow-lists degrade to mount
// scope: Write roots become writable shares, Read/Execute roots become read-only
// shares, and anything not listed is simply absent from the guest.
func (fs *FSPolicy) shares() []Share {
	var shares []Share
	add := func(paths []string, writable bool) {
		for _, p := range paths {
			shares = append(shares, Share{HostPath: p, Writable: writable})
		}
	}
	add(fs.Write, true)
	add(fs.Read, false)
	add(fs.Execute, false)
	return shares
}

// rootMountPoint is the guest-side path of the root share; the agent mounts the
// root share there and overlays every other share beneath it before switching root.
const rootMountPoint = "/"

// resolveShares produces the host-side share list (with unique 9p tags) and the
// matching guest-side mount instructions. When cfg.ShareRootRO is set, host "/" is
// exported read-only as the guest root so an arbitrary host Path resolves with its
// libraries; FSPolicy- and ExtraShares-derived directories overlay beneath it.
func resolveShares(cfg *VMConfig, fs *FSPolicy) ([]Share, []vmproto.GuestShare) {
	var hostShares []Share
	if cfg.ShareRootRO {
		hostShares = append(hostShares, Share{HostPath: "/", Writable: false})
	}
	if fs != nil {
		hostShares = append(hostShares, fs.shares()...)
	}
	hostShares = append(hostShares, cfg.ExtraShares...)

	var resolved []Share
	var guest []vmproto.GuestShare
	for i := range hostShares {
		s := hostShares[i]
		if s.Tag == "" {
			if s.HostPath == "/" {
				s.Tag = "root"
			} else {
				s.Tag = "s" + strconv.Itoa(i)
			}
		}
		mount := s.HostPath
		if s.HostPath == "/" {
			mount = rootMountPoint
		}
		resolved = append(resolved, s)
		guest = append(guest, vmproto.GuestShare{
			Tag:        s.Tag,
			MountPoint: mount,
			Writable:   s.Writable,
		})
	}
	return resolved, guest
}

// vmSpec is the resolved, driver-agnostic description of one VM boot.
type vmSpec struct {
	hypervisor string
	kernel     string
	initramfs  string
	memoryMiB  int
	vcpus      int
	cid        uint32
	cmdline    string
	shares     []Share // each with a resolved, unique Tag
}

// vmHandle is a running VM owned by a driver.
type vmHandle struct {
	proc    *os.Process
	waitErr chan error // QEMU process exit delivered here
}

// vmDriver boots a vmSpec and returns a handle to the running VM. qemuDriver is
// the only implementation today; a virshDriver could be added behind this
// interface for users who already run libvirtd.
type vmDriver interface {
	boot(spec vmSpec) (*vmHandle, error)
}

// vmRun holds the host-side runtime state for a ModeVM command.
type vmRun struct {
	handle   *vmHandle
	listener *vsockListener
	conn     *os.File
	exitCh   chan int
	relayErr chan error
	timer    *time.Timer
}

func (cmd *Cmd) startVM() error {
	vc := cmd.Sandbox.VM
	if vc == nil {
		vc = &VMConfig{ShareRootRO: true}
	}
	cfg := vc.withDefaults()

	drv, err := newQemuDriver(cfg.Hypervisor)
	if err != nil {
		return err
	}

	kernel := cfg.KernelPath
	if kernel == "" {
		kernel, err = defaultKernel()
		if err != nil {
			return err
		}
	}

	initramfs := cfg.InitramfsPath
	if initramfs == "" {
		initramfs, err = defaultInitramfs()
		if err != nil {
			return err
		}
	}

	// Control + stdio channel: host listens, guest agent dials back.
	lis, err := listenVsock(uint32(vmproto.PortAny))
	if err != nil {
		return fmt.Errorf("sandbox: vsock listen: %w", err)
	}

	shares, gshares := resolveShares(&cfg, cmd.Sandbox.FS)

	if cmd.Env == nil {
		cmd.Env = os.Environ()
	}
	dir := cmd.Dir
	if dir == "" {
		dir = "/"
	}
	gcfg := &vmproto.GuestConfig{
		Path:   cmd.Path,
		Args:   cmd.Args,
		Env:    cmd.Env,
		Dir:    dir,
		Port:   lis.Port(),
		Shares: gshares,
	}
	encoded, err := vmproto.MarshalConfig(gcfg)
	if err != nil {
		lis.Close()
		return err
	}

	spec := vmSpec{
		hypervisor: drv.path,
		kernel:     kernel,
		initramfs:  initramfs,
		memoryMiB:  cfg.MemoryMiB,
		vcpus:      cfg.VCPUs,
		cid:        allocCID(),
		cmdline:    fmt.Sprintf("console=ttyS0 init=/init %s=%s", vmproto.CmdlineConfigKey, encoded),
		shares:     shares,
	}

	handle, err := drv.boot(spec)
	if err != nil {
		lis.Close()
		return err
	}

	run := &vmRun{
		handle:   handle,
		listener: lis,
		exitCh:   make(chan int, 1),
		relayErr: make(chan error, 1),
	}
	if cfg.Timeout > 0 {
		run.timer = time.AfterFunc(cfg.Timeout, func() {
			handle.proc.Kill()
		})
	}

	// Accept the agent connection and start relaying stdio. accept blocks, so do
	// it in a goroutine and let Wait collect the result.
	go run.serve(cmd.Stdin, cmd.Stdout, cmd.Stderr)

	cmd.vm = run
	return nil
}

// serve accepts the guest agent connection and relays stdio frames until the
// agent reports an exit code or the connection closes.
func (run *vmRun) serve(stdin io.Reader, stdout, stderr io.Writer) {
	conn, err := run.listener.accept()
	if err != nil {
		run.relayErr <- fmt.Errorf("sandbox: vsock accept: %w", err)
		return
	}
	run.conn = conn

	// Host -> guest stdin.
	if stdin != nil {
		go func() {
			buf := make([]byte, 32*1024)
			for {
				n, rerr := stdin.Read(buf)
				if n > 0 {
					if werr := vmproto.WriteFrame(conn, vmproto.StreamStdin, buf[:n]); werr != nil {
						return
					}
				}
				if rerr != nil {
					vmproto.WriteFrame(conn, vmproto.StreamClose, []byte{byte(vmproto.StreamStdin)})
					return
				}
			}
		}()
	}

	// Guest -> host stdout/stderr/exit.
	discard := io.Discard
	if stdout == nil {
		stdout = discard
	}
	if stderr == nil {
		stderr = discard
	}
	for {
		tag, payload, ferr := vmproto.ReadFrame(conn)
		if ferr != nil {
			if ferr == io.EOF {
				run.relayErr <- nil
			} else {
				run.relayErr <- ferr
			}
			return
		}
		switch tag {
		case vmproto.StreamStdout:
			stdout.Write(payload)
		case vmproto.StreamStderr:
			stderr.Write(payload)
		case vmproto.StreamExit:
			code, perr := vmproto.ParseExit(payload)
			if perr != nil {
				run.relayErr <- perr
				return
			}
			run.exitCh <- code
			run.relayErr <- nil
			return
		}
	}
}

func (cmd *Cmd) waitVM() error {
	run := cmd.vm
	defer func() {
		if run.timer != nil {
			run.timer.Stop()
		}
		if run.conn != nil {
			run.conn.Close()
		}
		run.listener.Close()
		// Ensure QEMU is gone, then reap it.
		run.handle.proc.Kill()
		<-run.handle.waitErr
	}()

	relayErr := <-run.relayErr
	if relayErr != nil {
		return relayErr
	}

	select {
	case code := <-run.exitCh:
		return synthExitError(code)
	default:
		return errors.New("sandbox: vm exited before reporting status")
	}
}

// sandboxExitArg0 is a re-exec sentinel (sibling of sandboxChildArg0) used only to
// manufacture a genuine *exec.ExitError carrying a chosen exit code.
const sandboxExitArg0 = "__sandbox_exitcode"

func init() {
	if len(os.Args) == 2 && os.Args[0] == sandboxExitArg0 {
		code, err := strconv.Atoi(os.Args[1])
		if err != nil {
			code = 1
		}
		os.Exit(code)
	}
}

// synthExitError returns nil for code 0, otherwise a real *exec.ExitError whose
// ExitCode() == code, so ModeVM callers see the same error type as ModeSeccomp.
// It does this by briefly re-exec'ing this binary via the sandboxExitArg0
// sentinel; the fork cost is negligible next to booting a VM.
func synthExitError(code int) error {
	if code == 0 {
		return nil
	}
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("sandbox: vm command exited with status %d", code)
	}
	c := exec.Command(self)
	c.Args = []string{sandboxExitArg0, strconv.Itoa(code)}
	return c.Run()
}
