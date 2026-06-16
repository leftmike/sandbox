package sandbox

import (
	"os/exec"
	"slices"
	"strings"
	"testing"
)

func TestFSPolicyShares(t *testing.T) {
	fs := &FSPolicy{
		Write:   []string{"/tmp"},
		Read:    []string{"/etc"},
		Execute: []string{"/usr"},
	}
	got := fs.shares()
	want := []Share{
		{HostPath: "/tmp", Writable: true},
		{HostPath: "/etc", Writable: false},
		{HostPath: "/usr", Writable: false},
	}
	if !slices.Equal(got, want) {
		t.Errorf("shares() = %v, want %v", got, want)
	}
}

func TestResolveShares(t *testing.T) {
	cfg := &VMConfig{
		ShareRootRO: true,
		ExtraShares: []Share{{HostPath: "/work", Writable: true}},
	}
	fs := &FSPolicy{Write: []string{"/tmp"}}

	host, guest := resolveShares(cfg, fs)
	if len(host) != len(guest) || len(host) != 3 {
		t.Fatalf("resolveShares lengths host=%d guest=%d, want 3", len(host), len(guest))
	}

	// Root share must come first and map to "/" read-only with the "root" tag.
	if host[0].HostPath != "/" || host[0].Writable {
		t.Errorf("host[0] = %+v, want root read-only", host[0])
	}
	if guest[0].Tag != "root" || guest[0].MountPoint != "/" || guest[0].Writable {
		t.Errorf("guest[0] = %+v, want {root / ro}", guest[0])
	}

	// Every share must have a unique, non-empty tag, and the guest mount point
	// must match the host path for non-root shares.
	seen := map[string]bool{}
	for i, s := range host {
		if s.Tag == "" || seen[s.Tag] {
			t.Errorf("share %d has empty/duplicate tag %q", i, s.Tag)
		}
		seen[s.Tag] = true
		if s.HostPath != "/" && guest[i].MountPoint != s.HostPath {
			t.Errorf("guest[%d].MountPoint = %s, want %s", i, guest[i].MountPoint, s.HostPath)
		}
	}
}

func TestResolveSharesWritable(t *testing.T) {
	cfg := &VMConfig{}
	fs := &FSPolicy{Write: []string{"/tmp"}, Read: []string{"/etc"}}
	_, guest := resolveShares(cfg, fs)

	for _, g := range guest {
		switch g.MountPoint {
		case "/tmp":
			if !g.Writable {
				t.Errorf("/tmp share not writable")
			}
		case "/etc":
			if g.Writable {
				t.Errorf("/etc share writable, want read-only")
			}
		}
	}
}

func TestQemuArgs(t *testing.T) {
	d := &qemuDriver{path: "qemu-system-x86_64", machine: "q35"}
	spec := vmSpec{
		kernel:    "/boot/vmlinuz",
		initramfs: "/tmp/guest.cpio",
		memoryMiB: 512,
		vcpus:     2,
		cid:       42,
		cmdline:   "console=ttyS0 init=/init sandbox.config=abc",
		shares: []Share{
			{HostPath: "/", Tag: "root", Writable: false},
			{HostPath: "/tmp", Tag: "s1", Writable: true},
		},
	}

	args := d.qemuArgs(spec)
	joined := strings.Join(args, " ")

	for _, want := range []string{
		"-enable-kvm",
		"-machine q35",
		"-m 512",
		"-smp 2",
		"-kernel /boot/vmlinuz",
		"-initrd /tmp/guest.cpio",
		"vhost-vsock-pci,guest-cid=42",
		"mount_tag=root",
		"mount_tag=s1",
		"readonly=on", // root share
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("qemuArgs missing %q in:\n%s", want, joined)
		}
	}

	// The writable /tmp share must NOT carry readonly=on.
	for i, a := range args {
		if strings.Contains(a, "path=/tmp") && strings.Contains(a, "readonly=on") {
			t.Errorf("arg %d makes /tmp read-only: %s", i, a)
		}
	}
}

func TestSynthExitError(t *testing.T) {
	if err := synthExitError(0); err != nil {
		t.Errorf("synthExitError(0) = %v, want nil", err)
	}

	err := synthExitError(7)
	ee, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("synthExitError(7) = %T, want *exec.ExitError", err)
	}
	if ee.ExitCode() != 7 {
		t.Errorf("ExitCode() = %d, want 7", ee.ExitCode())
	}
}
