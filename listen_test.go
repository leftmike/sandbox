package main

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestOpenatAbsolute(t *testing.T) {
	f, err := os.CreateTemp("", "openat-abs")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	defer os.Remove(f.Name())
	want := f.Name()

	var found bool
	cmd := Command("/bin/cat", want)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.Handler = testHandler{
		open: func(pid uint32, pathname string, flags int32, mode uint32) bool {
			if pathname == want {
				found = true
			}
			return true
		},
	}
	err = cmd.Run()
	if err != nil {
		t.Errorf("Run() failed with %s", err)
	} else if !found {
		t.Errorf("openat(%s): handler(%s) not called", want, want)
	}
}

func TestOpenatATFDCWD(t *testing.T) {
	dir := t.TempDir()
	f, err := os.CreateTemp(dir, "openat-cwd")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	name := filepath.Base(f.Name())
	want := filepath.Join(dir, name)

	var found bool
	cmd := Command("/bin/cat", name)
	cmd.Dir = dir
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.Handler = testHandler{
		open: func(pid uint32, pathname string, flags int32, mode uint32) bool {
			if pathname == want {
				found = true
			}
			return true
		},
	}
	err = cmd.Run()
	if err != nil {
		t.Errorf("Run() failed with %s", err)
	} else if !found {
		t.Errorf("openat(AT_FDCWD, %s): handler(%s) not called", name, want)
	}
}

func TestOpenatDirfd(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}

	dir := t.TempDir()
	f, err := os.CreateTemp(dir, "openat-dirfd")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	name := filepath.Base(f.Name())
	want := filepath.Join(dir, name)

	// os.open with dir_fd calls openat(dirfd, name, ...) at the syscall level.
	script := `import os, sys
dir_path = sys.argv[1]
file_name = sys.argv[2]
dirfd = os.open(dir_path, os.O_RDONLY)
try:
    fd = os.open(file_name, os.O_RDONLY, dir_fd=dirfd)
    os.close(fd)
except Exception:
    pass
os.close(dirfd)
`
	var found bool
	cmd := Command(python, "-c", script, dir, name)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.Handler = testHandler{
		open: func(pid uint32, pathname string, flags int32, mode uint32) bool {
			if pathname == want {
				found = true
			}
			return true
		},
	}
	err = cmd.Run()
	if err != nil {
		t.Errorf("Run() failed with %s", err)
	} else if !found {
		t.Errorf("openat(%s, %s): handler(%s) not called", dir, name, want)
	}
}
