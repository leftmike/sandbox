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
	fsp := &sandbox.FSPolicy{
		Read:    []string{"/usr", "/lib", "/lib64", "/etc", allowed},
		Execute: []string{"/usr"},
	}

	run := func(target string) error {
		cmd := sandbox.Command("/bin/cat", filepath.Join(target, "f"))
		cmd.Sandbox = &sandbox.Sandbox{FSP: fsp}
		return cmd.Run()
	}

	if err := run(allowed); err != nil {
		t.Errorf("reading allowed path failed: %s", err)
	}
	if err := run(denied); err == nil {
		t.Errorf("reading denied path unexpectedly succeeded")
	}
}

// TestLandlockMode verifies that in LandlockMode the kernel enforces
// the FSPolicy on opens directly: a read under the allow-list succeeds while a
// read outside it is denied. Opens are still notified to the supervisor (like
// execs), so the Open callback is invoked even though the open is not proxied.
func TestLandlockMode(t *testing.T) {
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

	fsp := &sandbox.FSPolicy{
		Read:    []string{"/usr", "/lib", "/lib64", "/etc", allowed},
		Execute: []string{"/usr"},
	}

	target := filepath.Join(allowed, "f")
	var openSeen bool
	run := func(path string) error {
		cmd := sandbox.Command("/bin/cat", path)
		cmd.Sandbox = &sandbox.Sandbox{
			Mode: sandbox.LandlockMode,
			FSP:  fsp,
			Open: func(pid uint32, sysnum int, pathname string, flags int32, mode uint32,
				resolve uint64) bool {

				if pathname == path {
					openSeen = true
				}
				return true
			},
		}
		return cmd.Run()
	}

	if err := run(target); err != nil {
		t.Errorf("reading allowed path failed: %s", err)
	}
	if !openSeen {
		t.Errorf("Open callback not invoked in LandlockMode")
	}
	if err := run(filepath.Join(denied, "f")); err == nil {
		t.Errorf("reading denied path unexpectedly succeeded")
	}
}

// TestLandlockModeDeny verifies that an Open callback returning false denies an
// open even when landlock would otherwise allow it.
func TestLandlockModeDeny(t *testing.T) {
	if !sandbox.LandlockSupported {
		t.Skip("landlock not available on this kernel")
	}

	f, err := os.CreateTemp("", "sandbox-landlock-open")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("hello\n")
	f.Close()
	defer os.Remove(f.Name())

	fsp := sandbox.DefaultFSPolicy()
	fsp.Read = append(fsp.Read, f.Name())

	cmd := sandbox.Command("/bin/cat", f.Name())
	cmd.Sandbox = &sandbox.Sandbox{
		Mode: sandbox.LandlockMode,
		FSP:  fsp,
		Open: func(pid uint32, sysnum int, pathname string, flags int32, mode uint32,
			resolve uint64) bool {

			return pathname != f.Name()
		},
	}
	if err := cmd.Run(); err == nil {
		t.Error("Run() with denying Open callback = nil, want error")
	}
}
