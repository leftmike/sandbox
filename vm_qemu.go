package sandbox

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/leftmike/sandbox/internal/initramfs"
	"golang.org/x/sys/unix"
)

// qemuDriver boots VMs by invoking a qemu-system-* binary directly (no libvirt).
// The dependency surface is just "a QEMU binary on PATH", discovered at runtime
// the same way Landlock support is probed.
type qemuDriver struct {
	path    string // resolved qemu-system-* binary
	machine string // -machine value for this arch
}

// qemuBinaryForArch returns the conventional qemu-system binary name for GOARCH.
func qemuBinaryForArch() (string, string, error) {
	switch runtime.GOARCH {
	case "amd64":
		return "qemu-system-x86_64", "q35", nil
	case "arm64":
		return "qemu-system-aarch64", "virt", nil
	default:
		return "", "", fmt.Errorf("sandbox: vm mode unsupported on %s", runtime.GOARCH)
	}
}

func newQemuDriver(hint, machine string) (*qemuDriver, error) {
	if !kvmAvailable() {
		return nil, errors.New("sandbox: /dev/kvm not available")
	}

	name, defMachine, err := qemuBinaryForArch()
	if err != nil {
		return nil, err
	}
	if hint != "" {
		name = hint
	}
	path, err := exec.LookPath(name)
	if err != nil {
		return nil, fmt.Errorf("sandbox: qemu not found: %w", err)
	}

	switch {
	case machine != "":
		// Caller forced a machine type (e.g. "q35" to opt out of microvm).
	case runtime.GOARCH == "amd64" && qemuSupportsMachine(path, "microvm"):
		// Prefer the minimal, fast-booting microvm machine. Keep the legacy PIC
		// and timers enabled so a stock host kernel still boots.
		machine = "microvm,pic=on,pit=on,rtc=on"
	default:
		machine = defMachine
	}

	return &qemuDriver{path: path, machine: machine}, nil
}

// qemuSupportsMachine reports whether the qemu binary advertises a machine type,
// by parsing `qemu -machine help`.
func qemuSupportsMachine(path, name string) bool {
	out, err := exec.Command(path, "-machine", "help").Output()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		if fields := strings.Fields(line); len(fields) > 0 && fields[0] == name {
			return true
		}
	}
	return false
}

// isMicrovm reports whether a -machine value selects the microvm machine, which
// uses virtio-mmio rather than PCI for its devices.
func isMicrovm(machine string) bool {
	return machine == "microvm" || strings.HasPrefix(machine, "microvm,")
}

// kvmAvailable reports whether hardware virtualization is usable: /dev/kvm exists
// and is openable. VM tests gate on this and skip, mirroring the LandlockSupported
// skip pattern in landlock_test.go.
func kvmAvailable() bool {
	fd, err := unix.Open("/dev/kvm", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	unix.Close(fd)
	return true
}

// defaultKernel locates the running host kernel image, which stock distro kernels
// ship readable under /boot and which already enable virtio-9p/-fs and vsock.
func defaultKernel() (string, error) {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return "", err
	}
	release := string(uts.Release[:])
	if i := indexZero(uts.Release[:]); i >= 0 {
		release = string(uts.Release[:i])
	}
	path := "/boot/vmlinuz-" + release
	if _, err := os.Stat(path); err != nil {
		return "", fmt.Errorf("sandbox: kernel image %s not found; set VMConfig.KernelPath", path)
	}
	return path, nil
}

func indexZero(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return -1
}

// defaultInitramfs returns a cached initramfs containing the static guest agent,
// building it on first use. Set VMConfig.InitramfsPath to use a prebuilt image.
func defaultInitramfs() (string, error) {
	return initramfs.Default()
}

// allocCID picks a guest context id. CIDs 0-2 are reserved; collisions across
// concurrent VMs are possible but unlikely given the jittered range.
func allocCID() uint32 {
	n := uint32(os.Getpid()) ^ uint32(time.Now().UnixNano())
	return 3 + n%60000
}

// qemuArgs builds the qemu-system argv for a spec. Pure and dependency-free so it
// can be unit-tested without KVM.
func (d *qemuDriver) qemuArgs(spec vmSpec) []string {
	// microvm uses virtio-mmio; PCI machines (q35/virt) use the *-pci variants.
	vsockDev, p9Dev := "vhost-vsock-pci", "virtio-9p-pci"
	if isMicrovm(d.machine) {
		vsockDev, p9Dev = "vhost-vsock-device", "virtio-9p-device"
	}

	args := []string{
		"-machine", d.machine,
		"-enable-kvm",
		"-cpu", "host",
		"-m", strconv.Itoa(spec.memoryMiB),
		"-smp", strconv.Itoa(spec.vcpus),
		"-nodefaults",
		"-no-reboot",
		"-display", "none",
		"-serial", "null",
		"-kernel", spec.kernel,
		"-initrd", spec.initramfs,
		"-append", spec.cmdline,
		"-device", vsockDev + ",guest-cid=" + strconv.FormatUint(uint64(spec.cid), 10),
	}
	for i, s := range spec.shares {
		id := "fsdev" + strconv.Itoa(i)
		fsdev := fmt.Sprintf("local,id=%s,path=%s,security_model=none", id, s.HostPath)
		if !s.Writable {
			fsdev += ",readonly=on"
		}
		args = append(args,
			"-fsdev", fsdev,
			"-device", p9Dev+",fsdev="+id+",mount_tag="+s.Tag,
		)
	}
	return args
}

func (d *qemuDriver) boot(spec vmSpec) (*vmHandle, error) {
	c := exec.Command(d.path, d.qemuArgs(spec)...)
	c.Stdin = nil
	c.Stdout = io.Discard
	c.Stderr = io.Discard
	if os.Getenv("SANDBOX_VM_DEBUG") != "" {
		c.Stdout = os.Stderr
		c.Stderr = os.Stderr
	}

	if err := c.Start(); err != nil {
		return nil, fmt.Errorf("sandbox: start qemu: %w", err)
	}

	h := &vmHandle{proc: c.Process, waitErr: make(chan error, 1)}
	go func() { h.waitErr <- c.Wait() }()
	return h, nil
}
