/*
https://github.com/systemd/systemd/blob/main/src/shared/seccomp-util.c
https://github.com/flatpak/flatpak/blob/main/common/flatpak-run.c
https://github.com/moby/profiles/blob/main/seccomp/default.json
*/
package main

import (
	"fmt"
	"maps"
	"syscall"

	"golang.org/x/sys/unix"
)

type FilterConfig struct {
	Action uint32
	Errno  syscall.Errno
}

// XXX: fc FilterConfig
func sockFilterAction(fltr []unix.SockFilter, what string, action uint32,
	errno syscall.Errno) []unix.SockFilter {

	switch action {
	case unix.SECCOMP_RET_ALLOW, unix.SECCOMP_RET_KILL_PROCESS,
		unix.SECCOMP_RET_USER_NOTIF:
		return append(fltr,
			unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: action})

	case unix.SECCOMP_RET_ERRNO:
		return append(fltr, unix.SockFilter{
			Code: unix.BPF_RET | unix.BPF_K,
			K:    action | uint32(errno&unix.SECCOMP_RET_DATA),
		})

	default:
		panic(fmt.Sprintf("%s: unexpected seccomp ret: %d", what, action))
	}
}

func makeSockFilter(cfg map[string]FilterConfig) []unix.SockFilter {
	fltr := []unix.SockFilter{
		// Reject anything that isn't native architecture
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 4}, // load seccomp_data.arch
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: auditArch, Jt: 1, Jf: 0},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS},

		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0}, // load seccomp_data.nr
	}

	for name, fc := range cfg {
		sc, ok := syscalls[name]
		if !ok {
			continue
		}

		fltr = append(fltr, unix.SockFilter{
			Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: sc, Jt: 0, Jf: 1})
		fltr = sockFilterAction(fltr, name, fc.Action, fc.Errno)
	}

	return append(fltr,
		unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW})
}

func DefaultFilterConfig() map[string]FilterConfig {
	return maps.Clone(defaultFilterConfig)
}

var (
	defaultFilterConfig = map[string]FilterConfig{
		"clone":    {Action: unix.SECCOMP_RET_USER_NOTIF},
		"clone3":   {Action: unix.SECCOMP_RET_USER_NOTIF},
		"execve":   {Action: unix.SECCOMP_RET_USER_NOTIF},
		"execveat": {Action: unix.SECCOMP_RET_USER_NOTIF},
		"fork":     {Action: unix.SECCOMP_RET_USER_NOTIF},
		"open":     {Action: unix.SECCOMP_RET_USER_NOTIF},
		"openat":   {Action: unix.SECCOMP_RET_USER_NOTIF},
		"openat2":  {Action: unix.SECCOMP_RET_USER_NOTIF},
		// No pathname is available from the file handle; deny unconditionally.
		"open_by_handle_at": {Action: unix.SECCOMP_RET_KILL_PROCESS},
		"vfork":             {Action: unix.SECCOMP_RET_USER_NOTIF},
	}

	defaultSockFilter = makeSockFilter(defaultFilterConfig)
)
