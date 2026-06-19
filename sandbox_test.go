package sandbox

import (
	"testing"

	"golang.org/x/sys/unix"
)

const (
	readFlags   = uint64(unix.O_RDONLY)
	writeFlags  = uint64(unix.O_WRONLY)
	createFlags = uint64(unix.O_RDONLY | unix.O_CREAT)
	truncFlags  = uint64(unix.O_RDONLY | unix.O_TRUNC)
)

func TestFSAllowsRead(t *testing.T) {
	fsp := &FSPolicy{
		Read:    []string{"/etc"},
		Write:   []string{"/tmp"},
		Execute: []string{"/usr"},
	}

	cases := []struct {
		path string
		want bool
	}{
		{"/etc/passwd", true},  // under Read
		{"/usr/bin/cat", true}, // under Execute: execute implies read
		{"/tmp/foo", true},     // under Write: write implies read
		{"/var/log/foo", false},
		{"/usr", true},           // exact match on the Execute base itself
		{"/usrlocal/foo", false}, // must not match as a prefix of "/usr"
	}

	for _, c := range cases {
		if got := fsp.fsAllows(c.path, readFlags); got != c.want {
			t.Errorf("fsAllows(%q, read) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestFSAllowsWrite(t *testing.T) {
	fsp := &FSPolicy{
		Read:    []string{"/etc"},
		Write:   []string{"/tmp"},
		Execute: []string{"/usr"},
	}

	cases := []struct {
		path  string
		flags uint64
		want  bool
	}{
		{"/tmp/foo", writeFlags, true},      // under Write
		{"/etc/passwd", writeFlags, false},  // Read does not grant write
		{"/usr/bin/cat", writeFlags, false}, // Execute does not grant write
		{"/tmp/new", createFlags, true},     // O_CREAT routes through the write check
		{"/etc/new", createFlags, false},
		{"/tmp/foo", truncFlags, true}, // O_TRUNC routes through the write check
		{"/etc/passwd", truncFlags, false},
	}

	for _, c := range cases {
		if got := fsp.fsAllows(c.path, c.flags); got != c.want {
			t.Errorf("fsAllows(%q, %#x) = %v, want %v", c.path, c.flags, got, c.want)
		}
	}
}

func TestFSAllowsEmptyPolicy(t *testing.T) {
	fsp := &FSPolicy{}

	if fsp.fsAllows("/anything", readFlags) {
		t.Error("fsAllows with empty policy = true, want false")
	}
	if fsp.fsAllows("/anything", writeFlags) {
		t.Error("fsAllows with empty policy = true, want false")
	}
}

// TestFSAllowsCacheStable verifies that fsAllows continues to return consistent
// answers across repeated calls, since the first call lazily caches the combined
// read and write path lists on the FSPolicy.
func TestFSAllowsCacheStable(t *testing.T) {
	fsp := &FSPolicy{
		Read:  []string{"/etc"},
		Write: []string{"/tmp"},
	}

	for i := 0; i < 3; i++ {
		if !fsp.fsAllows("/etc/passwd", readFlags) {
			t.Errorf("call %d: fsAllows(/etc/passwd, read) = false, want true", i)
		}
		if !fsp.fsAllows("/tmp/foo", writeFlags) {
			t.Errorf("call %d: fsAllows(/tmp/foo, write) = false, want true", i)
		}
		if fsp.fsAllows("/var/foo", readFlags) {
			t.Errorf("call %d: fsAllows(/var/foo, read) = true, want false", i)
		}
	}
}
