package sandbox

import (
	"log/slog"
	"strings"
)

// LogOptions configures the logging middleware. The zero value is valid:
// logging goes to slog.Default() and no paths are suppressed.
type LogOptions struct {
	// Logger receives the log records. When nil, slog.Default() is used.
	Logger *slog.Logger

	// Ignore lists path prefixes whose Exec/Open/OpenFailed events are not
	// logged. The syscall is still delegated to the inner handler (allow by
	// default); only the log record is suppressed.
	Ignore []string
}

func (o LogOptions) logger() *slog.Logger {
	if o.Logger == nil {
		return slog.Default()
	}
	return o.Logger
}

func (o LogOptions) ignored(pathname string) bool {
	for _, p := range o.Ignore {
		if strings.HasPrefix(pathname, p) {
			return true
		}
	}
	return false
}

// decision renders the value of the "decision" log attribute for a bool handler.
func decision(allow bool) string {
	if allow {
		return "allow"
	}
	return "deny"
}

// logDecision logs an allowed syscall at Info and a denied one at Warn, so that
// denials stand out regardless of the configured level threshold.
func logDecision(logger *slog.Logger, allow bool, msg string, args ...any) {
	args = append(args, "decision", decision(allow))
	if allow {
		logger.Info(msg, args...)
	} else {
		logger.Warn(msg, args...)
	}
}

// WithLogging returns a new *Sandbox whose handler fields wrap those of sb,
// logging each intercepted syscall via opts.Logger before delegating to the
// original handler. A nil original bool-handler is treated as "allow", matching
// the dispatch semantics in notif.go; the informational handlers (OpenFailed,
// Failed) are called only when non-nil. The decision returned by the inner
// handler is preserved and recorded.
//
// The Filter and FS policy fields are copied unchanged, so the result is a
// drop-in replacement assignable to Cmd.Sandbox. sb is not mutated and may be
// nil, in which case WithLogging yields a pure logging sandbox that allows every
// intercepted syscall.
func WithLogging(sb *Sandbox, opts LogOptions) *Sandbox {
	if sb == nil {
		sb = &Sandbox{}
	}
	logger := opts.logger()

	inClone := sb.Clone
	inExec := sb.Exec
	inOpen := sb.Open
	inOpenFailed := sb.OpenFailed
	inSyscall := sb.Syscall
	inFailed := sb.Failed

	return &Sandbox{
		Clone: func(pid uint32, sysnum int, flags uint64) bool {
			allow := inClone == nil || inClone(pid, sysnum, flags)
			logDecision(logger, allow, "clone",
				"pid", pid, "syscall", Sysnums[sysnum], "sysnum", sysnum, "flags", flags)
			return allow
		},

		Exec: func(pid uint32, sysnum int, pathname string, argv, env []string) bool {
			allow := inExec == nil || inExec(pid, sysnum, pathname, argv, env)
			if !opts.ignored(pathname) {
				if len(env) > 5 {
					env = []string{env[0], env[1], "...", env[len(env)-2], env[len(env)-1]}
				}
				logDecision(logger, allow, "exec",
					"pid", pid, "syscall", Sysnums[sysnum], "pathname", pathname,
					"argv", argv, "env", env)
			}
			return allow
		},

		Open: func(pid uint32, sysnum int, pathname string, flags int32, mode uint32,
			resolve uint64) bool {

			allow := inOpen == nil || inOpen(pid, sysnum, pathname, flags, mode, resolve)
			if !opts.ignored(pathname) {
				logDecision(logger, allow, "open",
					"pid", pid, "syscall", Sysnums[sysnum], "pathname", pathname,
					"flags", flags, "mode", mode, "resolve", resolve)
			}
			return allow
		},

		OpenFailed: func(pid uint32, sysnum int, pathname string, err error) {
			if !opts.ignored(pathname) {
				logger.Error("open failed",
					"pid", pid, "syscall", Sysnums[sysnum], "pathname", pathname, "err", err)
			}
			if inOpenFailed != nil {
				inOpenFailed(pid, sysnum, pathname, err)
			}
		},

		Syscall: func(pid uint32, sysnum int) bool {
			allow := inSyscall == nil || inSyscall(pid, sysnum)
			logDecision(logger, allow, "syscall",
				"pid", pid, "syscall", Sysnums[sysnum], "sysnum", sysnum)
			return allow
		},

		Failed: func(pid uint32, sysnum int, err error) {
			logger.Error("failed",
				"pid", pid, "syscall", Sysnums[sysnum], "err", err)
			if inFailed != nil {
				inFailed(pid, sysnum, err)
			}
		},

		Filter: sb.Filter,
		FS:     sb.FS,
	}
}
