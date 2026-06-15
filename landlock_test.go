package sandbox_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/leftmike/sandbox"
)

// TestLandlockEnforced verifies that an FSPolicy's allow-list is enforced for
// a sandboxed child: reads from a path under the allow-list succeed, while
// reads from a path outside it are denied. Proxied opens are gated directly
// by the seccomp supervisor's FSPolicy check; landlock applies the same
// policy in the child as a kernel-level backstop for filesystem operations
// that aren't proxied through seccomp notify.
func TestLandlockEnforced(t *testing.T) {
	if !sandbox.LandlockSupported {
		t.Skip("landlock not available on this kernel")
	}

	dir := t.TempDir()
	allowed := filepath.Join(dir, "allowed")
	denied := filepath.Join(dir, "denied")
	if err := os.Mkdir(allowed, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(denied, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(allowed, "f"), []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(denied, "f"), []byte("no"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Landlock needs the binary itself (and its shared libraries) to be
	// executable/readable; grant common system locations plus the allowed dir.
	fs := &sandbox.FSPolicy{
		Read:    []string{"/usr", "/lib", "/lib64", "/etc", allowed},
		Execute: []string{"/usr"},
	}

	run := func(target string) error {
		cmd := sandbox.Command("/bin/cat", filepath.Join(target, "f"))
		cmd.Sandbox = &sandbox.Sandbox{FS: fs}
		return cmd.Run()
	}

	if err := run(allowed); err != nil {
		t.Errorf("reading allowed path failed: %s", err)
	}
	if err := run(denied); err == nil {
		t.Errorf("reading denied path unexpectedly succeeded")
	}
}
