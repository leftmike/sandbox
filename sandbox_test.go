package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/leftmike/sandbox/seccomp"
	"golang.org/x/sys/unix"
)

func TestMain(m *testing.M) {
	cmd := exec.Command("go", "build", "-o", "child/child", "./child/")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to build child binary: %s\n", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func TestRun(t *testing.T) {
	cases := []struct {
		cmd string
		ret int
	}{
		{"/bin/true", 0},
		{"/bin/false", 1},
	}

	for _, c := range cases {
		ret, err := Run([]string{c.cmd}, nil, io.Discard, io.Discard,
			func(_ int, _ *seccomp.Notif) bool {
				return true
			})
		if err != nil {
			t.Errorf("Run(%s) failed with %s", c.cmd, err)
		} else if ret != c.ret {
			t.Errorf("Run(%s) got %d want %d", c.cmd, ret, c.ret)
		}
	}
}

// TestRunInterceptOpenat verifies openat syscalls are intercepted and the path is readable.
func TestRunInterceptOpenat(t *testing.T) {
	f, err := os.CreateTemp("", "sandbox-e2e-*")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("hello sandbox\n")
	f.Close()
	defer os.Remove(f.Name())

	var intercepted []string
	var out bytes.Buffer

	ret, err := Run([]string{"/bin/cat", f.Name()}, nil, &out, &out,
		func(fd int, notif *seccomp.Notif) bool {
			if notif.Data.NR == unix.SYS_OPENAT {
				path, rerr := seccomp.ReadString(fd, notif, uintptr(notif.Data.Args[1]), 2048)
				if rerr == nil {
					intercepted = append(intercepted, path)
				}
			}
			return true
		})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ret != 0 {
		t.Fatalf("expected exit code 0, got %d (output: %s)", ret, out.String())
	}
	if !strings.Contains(out.String(), "hello sandbox") {
		t.Fatalf("unexpected output: %q", out.String())
	}

	found := false
	for _, p := range intercepted {
		if p == f.Name() {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("temp file not intercepted; got paths: %v", intercepted)
	}
}

// TestRunDenyOpenat verifies that denying an openat syscall causes the process to fail.
func TestRunDenyOpenat(t *testing.T) {
	f, err := os.CreateTemp("", "sandbox-e2e-*")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	defer os.Remove(f.Name())

	targetPath := f.Name()
	var out bytes.Buffer

	ret, err := Run([]string{"/bin/cat", targetPath}, nil, io.Discard, &out,
		func(fd int, notif *seccomp.Notif) bool {
			if notif.Data.NR == unix.SYS_OPENAT {
				path, rerr := seccomp.ReadString(fd, notif, uintptr(notif.Data.Args[1]), 2048)
				if rerr == nil && path == targetPath {
					return false // deny
				}
			}
			return true
		})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ret == 0 {
		t.Fatal("expected non-zero exit code when file open is denied")
	}
}
