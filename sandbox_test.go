package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
)

type testHandler struct {
	open    func(pid uint32, pathname string, flags int32, mode uint32) bool
	syscall func(pid uint32, nr int32) bool
}

func (th testHandler) Open(pid uint32, pathname string, flags int32, mode uint32) bool {
	if th.open != nil {
		return th.open(pid, pathname, flags, mode)
	}

	return true
}

func (th testHandler) Syscall(pid uint32, nr int32) bool {
	if th.syscall != nil {
		return th.syscall(pid, nr)
	}

	return true
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
		ret, err := Run([]string{c.cmd}, nil, io.Discard, io.Discard, testHandler{})
		if err != nil {
			t.Errorf("Run(%s) failed with %s", c.cmd, err)
		} else if ret != c.ret {
			t.Errorf("Run(%s) got %d want %d", c.cmd, ret, c.ret)
		}
	}
}

func TestRunOpen(t *testing.T) {
	f, err := os.CreateTemp("", "sandbox-open")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("hello sandbox\n")
	f.Close()
	defer os.Remove(f.Name())

	var found bool
	var buf bytes.Buffer
	ret, err := Run([]string{"/bin/cat", f.Name()}, nil, &buf, io.Discard,
		testHandler{
			open: func(pid uint32, pathname string, flags int32, mode uint32) bool {
				if pathname == f.Name() {
					found = true
				}

				return true
			},
		})
	if err != nil {
		t.Errorf("Run() failed with %s", err)
	} else if ret != 0 {
		t.Errorf("Run() got %d want 0", ret)
	} else if !strings.Contains(buf.String(), "hello sandbox") {
		t.Errorf("Run() missing output: %s", buf.String())
	} else if !found {
		t.Errorf("Run() %s not handled", f.Name())
	}

	ret, err = Run([]string{"/bin/cat", f.Name()}, nil, io.Discard, io.Discard,
		testHandler{
			open: func(pid uint32, pathname string, flags int32, mode uint32) bool {
				if pathname == f.Name() {
					return false
				}

				return true
			},
		})
	if err != nil {
		t.Errorf("Run() failed with %s", err)
	} else if ret == 0 {
		t.Errorf("Run() got %d want not 0", ret)
	}
}

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
