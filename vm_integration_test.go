package sandbox_test

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/leftmike/sandbox"
)

// vmMode returns a Sandbox configured for ModeVM, or skips the test when KVM is
// not usable on this machine — mirroring the LandlockSupported skip in
// landlock_test.go so KVM-less CI stays green.
func vmMode(t *testing.T) *sandbox.Sandbox {
	t.Helper()
	if fd, err := os.Open("/dev/kvm"); err != nil {
		t.Skip("kvm not available: /dev/kvm not openable")
	} else {
		fd.Close()
	}
	if _, err := exec.LookPath("qemu-system-x86_64"); err != nil {
		t.Skip("kvm not available: qemu-system-x86_64 not on PATH")
	}
	return &sandbox.Sandbox{Mode: sandbox.ModeVM, VM: &sandbox.VMConfig{ShareRootRO: true}}
}

func TestVMRunExitCodes(t *testing.T) {
	cases := []struct {
		cmd string
		ret int
	}{
		{"/bin/true", 0},
		{"/bin/false", 1},
	}
	for _, c := range cases {
		cmd := sandbox.Command(c.cmd)
		cmd.Sandbox = vmMode(t) // may skip
		ret, err := vmExitCode(cmd.Run())
		if err != nil {
			t.Errorf("Run(%s) failed: %v", c.cmd, err)
		} else if ret != c.ret {
			t.Errorf("Run(%s) = %d, want %d", c.cmd, ret, c.ret)
		}
	}
}

func TestVMOutput(t *testing.T) {
	cmd := sandbox.Command("/bin/echo", "hello")
	cmd.Sandbox = vmMode(t) // may skip
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("Output() error: %v", err)
	}
	if !strings.Contains(string(out), "hello") {
		t.Errorf("Output() = %q, want to contain hello", out)
	}
}

func vmExitCode(err error) (int, error) {
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode(), nil
		}
		return 0, err
	}
	return 0, nil
}
