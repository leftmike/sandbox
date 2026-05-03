package main

import (
	"fmt"
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
	cmd.Handler = testHandler{
		open: func(pid uint32, sysnum int, pathname string, flags int32, mode uint32) bool {
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
	cmd.Handler = testHandler{
		open: func(pid uint32, sysnum int, pathname string, flags int32, mode uint32) bool {
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
	cmd.Handler = testHandler{
		open: func(pid uint32, sysnum int, pathname string, flags int32, mode uint32) bool {
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

const (
	// Python script that calls execveat(dirfd, name, argv, envp, flags)
	execveatScript = `import ctypes, os, sys
SYS_execveat = 322
libc = ctypes.CDLL(None)
fd = %s
argv = (ctypes.c_char_p * 2)(b'true', None)
envp = (ctypes.c_char_p * 1)(None)
libc.syscall(ctypes.c_long(SYS_execveat), ctypes.c_long(fd), ctypes.c_char_p(%s), argv, envp, ctypes.c_long(%s))
sys.exit(1)
`
)

func TestExecveatRelative(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	truePath, err := exec.LookPath("true")
	if err != nil {
		t.Skip("true not available")
	}
	trueDir := filepath.Dir(truePath)
	trueBase := filepath.Base(truePath)

	// execveat(dirfd_to_trueDir, trueBase, ..., 0): relative path resolved via dirfd.
	script := fmt.Sprintf(execveatScript,
		fmt.Sprintf(`os.open(%q, os.O_RDONLY)`, trueDir),
		fmt.Sprintf(`b%q`, trueBase),
		`0`)

	var found bool
	cmd := Command(python, "-c", script)
	cmd.Handler = testHandler{
		exec: func(pid uint32, sysnum int, pathname string, argv []string, env []string) bool {
			if pathname == truePath {
				found = true
			}
			return true
		},
	}
	if err := cmd.Run(); err != nil {
		t.Errorf("Run() failed: %s", err)
	} else if !found {
		t.Errorf("execveat(dirfd, %q): handler not called with %s", trueBase, truePath)
	}

	cmd = Command(python, "-c", script)
	cmd.Handler = testHandler{
		exec: func(pid uint32, sysnum int, pathname string, argv []string, env []string) bool {
			return pathname != truePath
		},
	}
	ret, err := exitCode(cmd.Run())
	if err != nil {
		t.Errorf("Run() failed: %s", err)
	} else if ret == 0 {
		t.Errorf("execveat(dirfd, %q) denied but process exited 0", trueBase)
	}
}

func TestExecveatATEmptyPath(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	truePath, err := exec.LookPath("true")
	if err != nil {
		t.Skip("true not available")
	}

	// execveat(fd_to_truePath, "", ..., AT_EMPTY_PATH): file identified by fd alone.
	script := fmt.Sprintf(execveatScript,
		fmt.Sprintf(`os.open(%q, os.O_RDONLY)`, truePath),
		`b''`,
		`0x1000`)

	var found bool
	cmd := Command(python, "-c", script)
	cmd.Handler = testHandler{
		exec: func(pid uint32, sysnum int, pathname string, argv []string, env []string) bool {
			if pathname == truePath {
				found = true
			}
			return true
		},
	}
	if err := cmd.Run(); err != nil {
		t.Errorf("Run() failed: %s", err)
	} else if !found {
		t.Errorf("execveat(fd, '', AT_EMPTY_PATH): handler not called with %s", truePath)
	}

	cmd = Command(python, "-c", script)
	cmd.Handler = testHandler{
		exec: func(pid uint32, sysnum int, pathname string, argv []string, env []string) bool {
			return pathname != truePath
		},
	}
	ret, err := exitCode(cmd.Run())
	if err != nil {
		t.Errorf("Run() failed: %s", err)
	} else if ret == 0 {
		t.Errorf("execveat(fd, '', AT_EMPTY_PATH) denied but process exited 0")
	}
}
