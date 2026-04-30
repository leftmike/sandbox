package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

type testHandler struct {
	clone   func(pid uint32, flags uint64) bool
	exec    func(pid uint32, pathname string, argv []string, env []string) bool
	open    func(pid uint32, pathname string, flags int32, mode uint32) bool
	syscall func(pid uint32, nr int32) bool
}

func (th testHandler) Clone(pid uint32, flags uint64) bool {
	if th.clone != nil {
		return th.clone(pid, flags)
	}

	return true
}

func (th testHandler) Exec(pid uint32, pathname string, argv []string, env []string) bool {
	if th.exec != nil {
		return th.exec(pid, pathname, argv, env)
	}

	return true
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

func TestCommand(t *testing.T) {
	cmd := Command("/bin/echo", "hello")
	if cmd.Path != "/bin/echo" {
		t.Errorf("got path %s want /bin/echo", cmd.Path)
	}
}

func TestCommandContext(t *testing.T) {
	ctx := context.Background()
	cmd := CommandContext(ctx, "/bin/echo", "hello")
	if cmd.Path != "/bin/echo" {
		t.Errorf("got path %s want /bin/echo", cmd.Path)
	}
}

func TestCmdRun(t *testing.T) {
	cmd := Command("/bin/true")
	cmd.Handler = testHandler{}
	if err := cmd.Run(); err != nil {
		t.Errorf("Run(/bin/true) = %v, want nil", err)
	}

	cmd = Command("/bin/false")
	cmd.Handler = testHandler{}
	if err := cmd.Run(); err == nil {
		t.Error("Run(/bin/false) = nil, want error")
	}
}

func TestCmdOutput(t *testing.T) {
	cmd := Command("/bin/echo", "hello")
	cmd.Handler = testHandler{}
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("Output() error: %v", err)
	}
	if !strings.Contains(string(out), "hello") {
		t.Errorf("Output() = %s, want to contain 'hello'", out)
	}
}

func TestCmdOutputStdoutAlreadySet(t *testing.T) {
	cmd := Command("/bin/echo", "hello")
	cmd.Stdout = &strings.Builder{}
	_, err := cmd.Output()
	if err == nil || !strings.Contains(err.Error(), "stdout already set") {
		t.Errorf("Output() error = %v, want 'stdout already set'", err)
	}
}

func TestCmdCombinedOutput(t *testing.T) {
	cmd := Command("/bin/echo", "hello")
	cmd.Handler = testHandler{}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("CombinedOutput() error: %v", err)
	}
	if !strings.Contains(string(out), "hello") {
		t.Errorf("CombinedOutput() = %s, want to contain 'hello'", out)
	}
}

func TestCmdCombinedOutputStdoutAlreadySet(t *testing.T) {
	cmd := Command("/bin/echo")
	cmd.Stdout = &strings.Builder{}
	_, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(err.Error(), "stdout already set") {
		t.Errorf("CombinedOutput() error = %v, want 'stdout already set'", err)
	}
}

func TestCmdCombinedOutputStderrAlreadySet(t *testing.T) {
	cmd := Command("/bin/echo")
	cmd.Stderr = &strings.Builder{}
	_, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(err.Error(), "stderr already set") {
		t.Errorf("CombinedOutput() error = %v, want 'stderr already set'", err)
	}
}

func TestCmdEnviron(t *testing.T) {
	cmd := Command("/bin/true")
	cmd.Env = []string{"FOO=bar", "BAZ=qux"}
	env := cmd.Environ()
	if len(env) != 2 {
		t.Fatalf("Environ() returned %d entries, want 2", len(env))
	}
	want := map[string]bool{"FOO=bar": true, "BAZ=qux": true}
	for _, e := range env {
		if !want[e] {
			t.Errorf("Environ() returned unexpected entry %s", e)
		}
	}
}

func TestCmdEnvironPassthrough(t *testing.T) {
	cmd := Command("/bin/sh", "-c", "/usr/bin/echo $FOO")
	cmd.Handler = testHandler{}
	cmd.Env = []string{"FOO=hello"}
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("Output() error: %v", err)
	}
	if got := strings.TrimSpace(string(out)); got != "hello" {
		t.Errorf("env passthrough: got %s, want hello", got)
	}
}

func TestCmdString(t *testing.T) {
	cmd := Command("/usr/bin/echo", "hello", "world")
	if got, want := cmd.String(), "/usr/bin/echo hello world"; got != want {
		t.Errorf("String() = %s, want %s", got, want)
	}
}

func TestCmdStdoutPipe(t *testing.T) {
	cmd := Command("/usr/bin/echo", "hello")
	cmd.Handler = testHandler{}
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe() error: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	out, err := io.ReadAll(pipe)
	if err != nil {
		t.Fatalf("ReadAll() error: %v", err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("Wait() error: %v", err)
	}
	if got := strings.TrimSpace(string(out)); got != "hello" {
		t.Errorf("StdoutPipe: got %s, want hello", got)
	}
}

func TestCmdStderrPipe(t *testing.T) {
	cmd := Command("/bin/sh", "-c", "/usr/bin/echo error >&2")
	cmd.Handler = testHandler{}
	pipe, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("StderrPipe() error: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	out, err := io.ReadAll(pipe)
	if err != nil {
		t.Fatalf("ReadAll() error: %v", err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("Wait() error: %v", err)
	}
	if got := strings.TrimSpace(string(out)); got != "error" {
		t.Errorf("StderrPipe: got %s, want error", got)
	}
}

func TestCmdStdinPipe(t *testing.T) {
	cmd := Command("/bin/cat")
	cmd.Handler = testHandler{}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe() error: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe() error: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	if _, err := io.WriteString(stdin, "hello"); err != nil {
		t.Fatalf("Write() error: %v", err)
	}
	stdin.Close()
	out, err := io.ReadAll(stdout)
	if err != nil {
		t.Fatalf("ReadAll() error: %v", err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("Wait() error: %v", err)
	}
	if string(out) != "hello" {
		t.Errorf("StdinPipe: got %s, want hello", string(out))
	}
}

func exitCode(err error) (int, error) {
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode(), nil
		}
		return 0, err
	}
	return 0, nil
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
		cmd := Command(c.cmd)
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		cmd.Handler = testHandler{}

		ret, err := exitCode(cmd.Run())
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
	cmd := Command("/bin/cat", f.Name())
	cmd.Stdout = &buf
	cmd.Stderr = io.Discard
	cmd.Handler = testHandler{
		open: func(pid uint32, pathname string, flags int32, mode uint32) bool {
			if pathname == f.Name() {
				found = true
			}

			return true
		},
	}

	ret, err := exitCode(cmd.Run())
	if err != nil {
		t.Errorf("Run() failed with %s", err)
	} else if ret != 0 {
		t.Errorf("Run() got %d want 0", ret)
	} else if !strings.Contains(buf.String(), "hello sandbox") {
		t.Errorf("Run() missing output: %s", buf.String())
	} else if !found {
		t.Errorf("Run() %s not handled", f.Name())
	}

	cmd = Command("/bin/cat", f.Name())
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.Handler = testHandler{
		open: func(pid uint32, pathname string, flags int32, mode uint32) bool {
			if pathname == f.Name() {
				return false
			}

			return true
		},
	}

	ret, err = exitCode(cmd.Run())
	if err != nil {
		t.Errorf("Run() failed with %s", err)
	} else if ret == 0 {
		t.Errorf("Run() got %d want not 0", ret)
	}
}

func TestRunExec(t *testing.T) {
	var found bool
	var buf bytes.Buffer
	cmd := Command("/bin/echo", "hello")
	cmd.Stdout = &buf
	cmd.Stderr = io.Discard
	cmd.Handler = testHandler{
		exec: func(pid uint32, pathname string, argv []string, env []string) bool {
			if pathname == "/bin/echo" {
				found = true
			}

			return true
		},
	}

	ret, err := exitCode(cmd.Run())
	if err != nil {
		t.Errorf("Run() failed with %s", err)
	} else if ret != 0 {
		t.Errorf("Run() got %d want 0", ret)
	} else if !found {
		t.Errorf("Run() /bin/echo not handled")
	} else if got := buf.String(); got != "hello\n" {
		t.Errorf("Run() stdio got %s want hello", got)
	}

	buf.Reset()
	cmd = Command("/bin/echo", "hello")
	cmd.Stdout = &buf
	cmd.Stderr = io.Discard
	cmd.Handler = testHandler{
		exec: func(pid uint32, pathname string, argv []string, env []string) bool {
			if pathname == "/bin/echo" {
				return false
			}

			return true
		},
	}

	ret, err = exitCode(cmd.Run())
	if err != nil {
		t.Errorf("Run() failed with %s", err)
	} else if ret == 0 {
		t.Errorf("Run() got 0 want !0")
	} else if got := buf.String(); got != "" {
		t.Errorf("Run() stdout got %s want \"\"", got)
	}
}

func TestRunExecArgv(t *testing.T) {
	want := []string{"/bin/echo", "hello", "world"}
	cmd := Command(want[0], want[1:]...)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard

	var gotArgv []string
	cmd.Handler = testHandler{
		exec: func(pid uint32, pathname string, argv []string, env []string) bool {
			if pathname == "/bin/echo" {
				gotArgv = argv
			}
			return true
		},
	}

	ret, err := exitCode(cmd.Run())
	if err != nil {
		t.Errorf("Run() failed with %s", err)
	} else if ret != 0 {
		t.Errorf("Run() got %d want 0", ret)
	} else if !slices.Equal(gotArgv, want) {
		t.Errorf("argv = %v, want %v", gotArgv, want)
	}
}

func TestRunExecEnv(t *testing.T) {
	wantEnv := []string{"FOO=bar", "BAZ=qux"}
	cmd := Command("/bin/true")
	cmd.Env = wantEnv
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard

	var gotEnv []string
	cmd.Handler = testHandler{
		exec: func(pid uint32, pathname string, argv []string, env []string) bool {
			if pathname == "/bin/true" {
				gotEnv = env
			}
			return true
		},
	}

	ret, err := exitCode(cmd.Run())
	if err != nil {
		t.Errorf("Run() failed with %s", err)
	} else if ret != 0 {
		t.Errorf("Run() got %d want 0", ret)
	} else if !slices.Equal(gotEnv, wantEnv) {
		t.Errorf("env = %v, want %v", gotEnv, wantEnv)
	}
}

func TestRunCloneThread(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}

	const script = `
import threading
t = threading.Thread(target=lambda: None)
t.start()
t.join()
`
	var threadCloned bool
	cmd := Command(python, "-c", script)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.Handler = testHandler{
		clone: func(pid uint32, flags uint64) bool {
			if flags&unix.CLONE_THREAD != 0 {
				threadCloned = true
			}
			return true
		},
	}

	ret, err := exitCode(cmd.Run())
	if err != nil {
		t.Errorf("Run() failed with %s", err)
	} else if ret != 0 {
		t.Errorf("Run() got %d want 0", ret)
	} else if !threadCloned {
		t.Error("Run() thread clone not handled")
	}
}

func TestRunClone(t *testing.T) {
	var cloned bool
	cmd := Command("/bin/sh", "-c", "/bin/true")
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.Handler = testHandler{
		clone: func(pid uint32, flags uint64) bool {
			cloned = true
			return true
		},
	}

	ret, err := exitCode(cmd.Run())
	if err != nil {
		t.Errorf("Run() failed with %s", err)
	} else if ret != 0 {
		t.Errorf("Run() got %d want 0", ret)
	} else if !cloned {
		t.Error("Run() clone not handled")
	}

	cmd = Command("/bin/sh", "-c", "/bin/true")
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.Handler = testHandler{
		clone: func(pid uint32, flags uint64) bool {
			return false
		},
	}

	ret, err = exitCode(cmd.Run())
	if err != nil {
		t.Errorf("Run() failed with %s", err)
	} else if ret == 0 {
		t.Errorf("Run() got 0 want !0")
	}
}
