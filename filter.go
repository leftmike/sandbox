/*
https://github.com/systemd/systemd/blob/main/src/shared/seccomp-util.c
https://github.com/flatpak/flatpak/blob/main/common/flatpak-run.c
https://github.com/moby/profiles/blob/main/seccomp/default.json
*/
package main

import (
	"slices"

	"golang.org/x/sys/unix"
)

const denyErrno = uint32(unix.EPERM)

var (
	// notifiedSyscalls trigger SECCOMP_RET_USER_NOTIF; the userspace handler
	// inspects arguments and decides whether to allow them.
	notifiedSyscalls = []int{
		unix.SYS_CLONE,
		unix.SYS_CLONE3,
		unix.SYS_EXECVE,
		unix.SYS_EXECVEAT,
		unix.SYS_OPENAT,
		unix.SYS_OPENAT2,
	}

	// killedSyscalls trigger SECCOMP_RET_KILL_PROCESS unconditionally.
	killedSyscalls = []int{
		// No pathname can be recovered from the file handle, so the syscall
		// cannot be filtered meaningfully — refuse it outright.
		unix.SYS_OPEN_BY_HANDLE_AT,
	}

	// blockedSyscalls return -EPERM. The defaults are inspired by systemd's
	// @system-service deny list and Docker/Moby's default seccomp profile.
	blockedSyscalls = []int{
		// Kernel module manipulation.
		unix.SYS_INIT_MODULE,
		unix.SYS_FINIT_MODULE,
		unix.SYS_DELETE_MODULE,

		// Kexec / reboot.
		unix.SYS_KEXEC_LOAD,
		unix.SYS_KEXEC_FILE_LOAD,
		unix.SYS_REBOOT,

		// Mounts, filesystem context, namespace switching.
		unix.SYS_MOUNT,
		unix.SYS_UMOUNT2,
		unix.SYS_PIVOT_ROOT,
		unix.SYS_CHROOT,
		unix.SYS_FSOPEN,
		unix.SYS_FSCONFIG,
		unix.SYS_FSMOUNT,
		unix.SYS_FSPICK,
		unix.SYS_MOVE_MOUNT,
		unix.SYS_OPEN_TREE,
		unix.SYS_MOUNT_SETATTR,
		unix.SYS_UNSHARE,
		unix.SYS_SETNS,

		// Clock / time.
		unix.SYS_SETTIMEOFDAY,
		unix.SYS_CLOCK_SETTIME,
		unix.SYS_CLOCK_ADJTIME,
		unix.SYS_ADJTIMEX,

		// Hostname / domain.
		unix.SYS_SETHOSTNAME,
		unix.SYS_SETDOMAINNAME,

		// Quotas / swap.
		unix.SYS_QUOTACTL,
		unix.SYS_QUOTACTL_FD,
		unix.SYS_SWAPON,
		unix.SYS_SWAPOFF,

		// Kernel programmability / performance counters.
		unix.SYS_BPF,
		unix.SYS_PERF_EVENT_OPEN,

		// Cross-process inspection and tracing.
		unix.SYS_PTRACE,
		unix.SYS_PROCESS_VM_READV,
		unix.SYS_PROCESS_VM_WRITEV,
		unix.SYS_PROCESS_MADVISE,
		unix.SYS_KCMP,

		// Process accounting / obsolete or rarely-needed.
		unix.SYS_ACCT,
		unix.SYS_NFSSERVCTL,
		unix.SYS_VHANGUP,
		unix.SYS_LOOKUP_DCOOKIE,

		// userfaultfd and io_uring — repeated source of LPE bugs.
		unix.SYS_USERFAULTFD,
		unix.SYS_IO_URING_SETUP,
		unix.SYS_IO_URING_ENTER,
		unix.SYS_IO_URING_REGISTER,

		// Kernel keyring.
		unix.SYS_ADD_KEY,
		unix.SYS_REQUEST_KEY,
		unix.SYS_KEYCTL,

		// NUMA memory policy.
		unix.SYS_MBIND,
		unix.SYS_MIGRATE_PAGES,
		unix.SYS_MOVE_PAGES,
		unix.SYS_SET_MEMPOLICY,
		unix.SYS_GET_MEMPOLICY,
		unix.SYS_SET_MEMPOLICY_HOME_NODE,
	}

	defaultSockFilter = buildSockFilter()
)

func jeqAction(sysnum int, action uint32) []unix.SockFilter {
	return []unix.SockFilter{
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: uint32(sysnum), Jt: 0, Jf: 1},
		{Code: unix.BPF_RET | unix.BPF_K, K: action},
	}
}

func buildSockFilter() []unix.SockFilter {
	filter := []unix.SockFilter{
		// Reject anything that isn't the native architecture.
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 4}, // load seccomp_data.arch
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: auditArch, Jt: 1, Jf: 0},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS},

		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0}, // load seccomp_data.nr
	}

	for _, nr := range slices.Concat(killedSyscalls, archKilledSyscalls) {
		filter = append(filter, jeqAction(nr, unix.SECCOMP_RET_KILL_PROCESS)...)
	}
	for _, nr := range slices.Concat(notifiedSyscalls, archNotifiedSyscalls) {
		filter = append(filter, jeqAction(nr, unix.SECCOMP_RET_USER_NOTIF)...)
	}
	deny := uint32(unix.SECCOMP_RET_ERRNO) | (denyErrno & unix.SECCOMP_RET_DATA)
	for _, nr := range slices.Concat(blockedSyscalls, archBlockedSyscalls) {
		filter = append(filter, jeqAction(nr, deny)...)
	}

	filter = append(filter,
		unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW})
	return filter
}
