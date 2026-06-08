package sandbox_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/leftmike/sandbox"
)

// TestLandlockEnforced verifies that an FSPolicy establishes a hard kernel
// boundary: a path outside the allow-list is denied even though the seccomp
// handler would permit it.
func TestLandlockEnforced(t *testing.T) {
	if !sandbox.LandlockAvailable() {
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
		Execute: []string{"/bin", "/usr/bin"},
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
