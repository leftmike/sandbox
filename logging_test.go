package sandbox_test

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/leftmike/sandbox"
	"golang.org/x/sys/unix"
)

// newLogger returns a slog.Logger writing text records to buf, at Info level so
// both allowed (Info) and denied (Warn) decisions are captured.
func newLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

func TestWithLoggingCloneDelegates(t *testing.T) {
	var buf bytes.Buffer
	var called bool
	inner := &sandbox.Sandbox{
		Clone: func(pid uint32, sysnum int, flags uint64) bool {
			called = true
			return true
		},
	}
	sb := sandbox.WithLogging(inner, sandbox.LogOptions{Logger: newLogger(&buf)})

	if allow := sb.Clone(42, unix.SYS_CLONE, 0x10); !allow {
		t.Errorf("Clone allow = false, want true")
	}
	if !called {
		t.Error("inner Clone was not called")
	}
	got := buf.String()
	if !strings.Contains(got, "pid=42") || !strings.Contains(got, "decision=allow") {
		t.Errorf("Clone log = %q, want pid=42 and decision=allow", got)
	}
}

func TestWithLoggingNilInnerAllows(t *testing.T) {
	var buf bytes.Buffer
	sb := sandbox.WithLogging(nil, sandbox.LogOptions{Logger: newLogger(&buf)})

	if allow := sb.Clone(1, unix.SYS_CLONE, 0); !allow {
		t.Error("nil inner Clone should allow")
	}
	if buf.Len() == 0 {
		t.Error("expected a log record for nil-inner Clone")
	}
}

func TestWithLoggingOpenDenyPreserved(t *testing.T) {
	var buf bytes.Buffer
	inner := &sandbox.Sandbox{
		Open: func(pid uint32, sysnum int, pathname string, flags int32, mode uint32,
			resolve uint64) bool {
			return false // deny
		},
	}
	sb := sandbox.WithLogging(inner, sandbox.LogOptions{Logger: newLogger(&buf)})

	if allow := sb.Open(7, unix.SYS_OPENAT, "/etc/passwd", 0, 0, 0); allow {
		t.Error("Open allow = true, want false (deny preserved)")
	}
	got := buf.String()
	if !strings.Contains(got, "/etc/passwd") || !strings.Contains(got, "decision=deny") {
		t.Errorf("Open log = %q, want pathname and decision=deny", got)
	}
}

func TestWithLoggingIgnoreSuppressesButAllows(t *testing.T) {
	var buf bytes.Buffer
	sb := sandbox.WithLogging(nil, sandbox.LogOptions{
		Logger: newLogger(&buf),
		Ignore: []string{"/usr/lib/locale"},
	})

	// Ignored path: still allowed, but not logged.
	if allow := sb.Open(1, unix.SYS_OPENAT, "/usr/lib/locale/C.UTF-8", 0, 0, 0); !allow {
		t.Error("ignored Open should still allow")
	}
	if buf.Len() != 0 {
		t.Errorf("ignored path was logged: %q", buf.String())
	}

	// Non-ignored path: logged.
	sb.Open(1, unix.SYS_OPENAT, "/etc/hosts", 0, 0, 0)
	if !strings.Contains(buf.String(), "/etc/hosts") {
		t.Errorf("non-ignored Open not logged: %q", buf.String())
	}
}

func TestWithLoggingOpenFailedDelegates(t *testing.T) {
	var buf bytes.Buffer
	var gotErr error
	inner := &sandbox.Sandbox{
		OpenFailed: func(pid uint32, sysnum int, pathname string, err error) {
			gotErr = err
		},
	}
	sb := sandbox.WithLogging(inner, sandbox.LogOptions{Logger: newLogger(&buf)})

	want := errors.New("boom")
	sb.OpenFailed(3, unix.SYS_OPENAT, "/nope", want)
	if gotErr != want {
		t.Errorf("inner OpenFailed err = %v, want %v", gotErr, want)
	}
	got := buf.String()
	if !strings.Contains(got, "/nope") || !strings.Contains(got, "boom") {
		t.Errorf("OpenFailed log = %q, want pathname and error", got)
	}
}

func TestWithLoggingFailedDelegates(t *testing.T) {
	var buf bytes.Buffer
	var gotErr error
	inner := &sandbox.Sandbox{
		Failed: func(pid uint32, sysnum int, err error) {
			gotErr = err
		},
	}
	sb := sandbox.WithLogging(inner, sandbox.LogOptions{Logger: newLogger(&buf)})

	want := errors.New("kaboom")
	sb.Failed(5, unix.SYS_CLONE, want)
	if gotErr != want {
		t.Errorf("inner Failed err = %v, want %v", gotErr, want)
	}
	if !strings.Contains(buf.String(), "kaboom") {
		t.Errorf("Failed log = %q, want error", buf.String())
	}
}

func TestWithLoggingExecTruncatesEnv(t *testing.T) {
	var buf bytes.Buffer
	sb := sandbox.WithLogging(nil, sandbox.LogOptions{Logger: newLogger(&buf)})

	env := []string{"A=1", "B=2", "C=3", "D=4", "E=5", "F=6", "G=7"}
	sb.Exec(9, unix.SYS_EXECVE, "/bin/sh", []string{"sh"}, env)

	got := buf.String()
	if !strings.Contains(got, "...") {
		t.Errorf("Exec env not truncated: %q", got)
	}
	if strings.Contains(got, "D=4") { // a middle entry should be dropped
		t.Errorf("Exec env not truncated correctly (kept middle entry): %q", got)
	}
}
