package main

import (
	"context"
	"io"
	"strings"
	"testing"
)

func TestCommand(t *testing.T) {
	cmd := Command("/bin/echo", "hello")
	if cmd.Path != "/bin/echo" {
		t.Errorf("got path %q want /bin/echo", cmd.Path)
	}
}

func TestCommandContext(t *testing.T) {
	ctx := context.Background()
	cmd := CommandContext(ctx, "/bin/echo", "hello")
	if cmd.Path != "/bin/echo" {
		t.Errorf("got path %q want /bin/echo", cmd.Path)
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
		t.Errorf("Output() = %q, want to contain 'hello'", out)
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
		t.Errorf("CombinedOutput() = %q, want to contain 'hello'", out)
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
			t.Errorf("Environ() returned unexpected entry %q", e)
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
		t.Errorf("env passthrough: got %q, want %q", got, "hello")
	}
}

func TestCmdString(t *testing.T) {
	cmd := Command("/usr/bin/echo", "hello", "world")
	if got, want := cmd.String(), "/usr/bin/echo hello world"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
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
		t.Errorf("StdoutPipe: got %q, want %q", got, "hello")
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
		t.Errorf("StderrPipe: got %q, want %q", got, "error")
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
		t.Errorf("StdinPipe: got %q, want %q", string(out), "hello")
	}
}
