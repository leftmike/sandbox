package main

import (
	"context"
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
	if err := Command("/bin/true").Run(); err != nil {
		t.Errorf("Run(/bin/true) = %v, want nil", err)
	}
	if err := Command("/bin/false").Run(); err == nil {
		t.Error("Run(/bin/false) = nil, want error")
	}
}

func TestCmdOutput(t *testing.T) {
	out, err := Command("/bin/echo", "hello").Output()
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
	out, err := Command("/bin/echo", "hello").CombinedOutput()
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
