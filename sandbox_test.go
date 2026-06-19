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
		{"/etc", true},           // exact match on the Read base itself
		{"/etcetera/foo", false}, // must not match as a prefix of "/etc"
		{"/tmp", true},           // exact match on the Write base itself
		{"/tmpfile", false},      // must not match as a prefix of "/tmp"
	}

	for _, c := range cases {
		if got := fsp.fsAllows(c.path, readFlags); got != c.want {
			t.Errorf("fsAllows(%q, read) = %v, want %v", c.path, got, c.want)
		}
	}
}

// TestFSAllowsReadOnlyFromWrite verifies that a policy with only a Write entry
// (no Read or Execute) still grants read access under that path.
func TestFSAllowsReadOnlyFromWrite(t *testing.T) {
	fsp := &FSPolicy{Write: []string{"/tmp"}}

	if !fsp.fsAllows("/tmp/foo", readFlags) {
		t.Error("fsAllows(/tmp/foo, read) = false, want true")
	}
	if fsp.fsAllows("/etc/passwd", readFlags) {
		t.Error("fsAllows(/etc/passwd, read) = true, want false")
	}
}

// TestFSAllowsOverlappingEntries verifies that redundant, overlapping allow-list
// entries (e.g. both a directory and a subdirectory of it) don't break matching.
func TestFSAllowsOverlappingEntries(t *testing.T) {
	fsp := &FSPolicy{Read: []string{"/usr", "/usr/local"}}

	if !fsp.fsAllows("/usr/local/bin/foo", readFlags) {
		t.Error("fsAllows(/usr/local/bin/foo, read) = false, want true")
	}
	if !fsp.fsAllows("/usr/share/foo", readFlags) {
		t.Error("fsAllows(/usr/share/foo, read) = false, want true")
	}
}

// TestFSAllowsPolicyWithTrailingSlash verifies that an allow-list entry that
// already has a trailing slash still matches correctly (no double slash).
func TestFSAllowsPolicyWithTrailingSlash(t *testing.T) {
	fsp := &FSPolicy{Read: []string{"/etc/"}}

	if !fsp.fsAllows("/etc/passwd", readFlags) {
		t.Error("fsAllows(/etc/passwd, read) = false, want true")
	}
	if !fsp.fsAllows("/etc", readFlags) {
		t.Error("fsAllows(/etc, read) = false, want true")
	}
	if fsp.fsAllows("/etcetera/foo", readFlags) {
		t.Error("fsAllows(/etcetera/foo, read) = true, want false")
	}
}

// TestFSAllowsRootPolicy verifies that a root entry ("/") grants access to
// everything.
func TestFSAllowsRootPolicy(t *testing.T) {
	fsp := &FSPolicy{Read: []string{"/"}}

	for _, path := range []string{"/", "/etc/passwd", "/usr/bin/cat", "/tmp/foo"} {
		if !fsp.fsAllows(path, readFlags) {
			t.Errorf("fsAllows(%q, read) = false, want true", path)
		}
	}
}

// TestFSAllowsWriteScopedNarrowerThanRead verifies that write access is scoped
// independently of (and can be narrower than) a sibling read allow-list under
// the same parent directory.
func TestFSAllowsWriteScopedNarrowerThanRead(t *testing.T) {
	fsp := &FSPolicy{Read: []string{"/data"}, Write: []string{"/data/tmp"}}

	if !fsp.fsAllows("/data/tmp/foo", writeFlags) {
		t.Error("fsAllows(/data/tmp/foo, write) = false, want true")
	}
	if fsp.fsAllows("/data/other", writeFlags) {
		t.Error("fsAllows(/data/other, write) = true, want false")
	}
	if !fsp.fsAllows("/data/other", readFlags) {
		t.Error("fsAllows(/data/other, read) = false, want true")
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
		{"/tmp/foo", uint64(unix.O_RDWR), true}, // O_RDWR routes through the write check
		{"/etc/passwd", uint64(unix.O_RDWR), false},
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

func TestAppendSlash(t *testing.T) {
	cases := []struct {
		slashed []string
		paths   []string
		want    []string
	}{
		{nil, nil, nil},
		{[]string{}, []string{"/etc"}, []string{"/etc/"}},
		{[]string{}, []string{"/etc/"}, []string{"/etc/"}}, // already suffixed: not doubled
		{[]string{}, []string{"/etc", "/usr/"}, []string{"/etc/", "/usr/"}},
		// accumulates onto an existing slice rather than replacing it
		{[]string{"/usr/"}, []string{"/etc"}, []string{"/usr/", "/etc/"}},
	}

	for _, c := range cases {
		got := appendSlash(c.slashed, c.paths)
		if len(got) != len(c.want) {
			t.Errorf("appendSlash(%v, %v) = %v, want %v", c.slashed, c.paths, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("appendSlash(%v, %v) = %v, want %v", c.slashed, c.paths, got, c.want)
				break
			}
		}
	}
}

func TestPathsAllows(t *testing.T) {
	cases := []struct {
		path  string
		paths []string
		want  bool
	}{
		{"/anything", nil, false},
		{"/anything", []string{}, false},
		{"/anything", []string{"/"}, true}, // root matches everything
		{"/usr", []string{"/usr/"}, true},  // exact match on the base itself
		{"/usr/lib", []string{"/usr/"}, true},
		{"/usrlocal", []string{"/usr/"}, false}, // not a real subpath
		{"/usr/lib", []string{"/etc/", "/usr/"}, true},
	}

	for _, c := range cases {
		if got := pathsAllows(c.path, c.paths); got != c.want {
			t.Errorf("pathsAllows(%q, %v) = %v, want %v", c.path, c.paths, got, c.want)
		}
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
