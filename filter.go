/*
https://github.com/systemd/systemd/blob/main/src/shared/seccomp-util.c
https://github.com/flatpak/flatpak/blob/main/common/flatpak-run.c
https://github.com/moby/profiles/blob/main/seccomp/default.json
*/
package main

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

type SyscallConfig struct {
	Syscall uint32
	Action  uint32
	Errno   syscall.Errno
}

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
			K:    action | uint32(errno|unix.SECCOMP_RET_DATA),
		})

	default:
		panic(fmt.Sprintf("%s: unexpected seccomp ret: %d", what, action))
	}
}

func makeSockFilter(args ...[]SyscallConfig) []unix.SockFilter {
	fltr := []unix.SockFilter{
		// Reject anything that isn't native architecture
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 4}, // load seccomp_data.arch
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: auditArch, Jt: 1, Jf: 0},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS},

		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0}, // load seccomp_data.nr
	}

	for _, arg := range args {
		for _, scfg := range arg {
			fltr = append(fltr, unix.SockFilter{
				Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K,
				K:    scfg.Syscall,
				Jt:   0,
				Jf:   1})
			fltr = sockFilterAction(fltr, Sysnums[scfg.Syscall], scfg.Action, scfg.Errno)
		}
	}

	return append(fltr,
		unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW})
}

var (
	defaultSockFilter = makeSockFilter([]SyscallConfig{
		{Syscall: unix.SYS_CLONE, Action: unix.SECCOMP_RET_USER_NOTIF},
		{Syscall: unix.SYS_CLONE3, Action: unix.SECCOMP_RET_USER_NOTIF},
		{Syscall: unix.SYS_EXECVE, Action: unix.SECCOMP_RET_USER_NOTIF},
		{Syscall: unix.SYS_EXECVEAT, Action: unix.SECCOMP_RET_USER_NOTIF},
		{Syscall: unix.SYS_OPENAT, Action: unix.SECCOMP_RET_USER_NOTIF},
		{Syscall: unix.SYS_OPENAT2, Action: unix.SECCOMP_RET_USER_NOTIF},

		// open_by_handle_at
		// No pathname is available from the file handle; deny unconditionally.
		{Syscall: unix.SYS_OPEN_BY_HANDLE_AT, Action: unix.SECCOMP_RET_KILL_PROCESS},
	}, archSyscallConfig)
)
