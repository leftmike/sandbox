package sandbox

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

func sockFilterAction(fltr []unix.SockFilter, what string, fc FilterConfig) []unix.SockFilter {

	switch fc.Action {
	case unix.SECCOMP_RET_ALLOW, unix.SECCOMP_RET_KILL_PROCESS,
		unix.SECCOMP_RET_USER_NOTIF:
		return append(fltr,
			unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: fc.Action})

	case unix.SECCOMP_RET_ERRNO:
		return append(fltr, unix.SockFilter{
			Code: unix.BPF_RET | unix.BPF_K,
			K:    fc.Action | uint32(fc.Errno&unix.SECCOMP_RET_DATA),
		})

	default:
		panic(fmt.Sprintf("%s: unexpected seccomp ret: %d", what, fc.Action))
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
		fltr = sockFilterAction(fltr, name, fc)
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
		"vfork":    {Action: unix.SECCOMP_RET_USER_NOTIF},

		// No pathname is available from the file handle; deny unconditionally.
		"open_by_handle_at": {Action: unix.SECCOMP_RET_KILL_PROCESS},

		// Default deny list: returns EPERM. Based on:
		// https://github.com/systemd/systemd/blob/main/src/shared/seccomp-util.c
		// https://github.com/moby/profiles/blob/main/seccomp/default.json

		// Kernel module manipulation
		"init_module":     FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
		"finit_module":    FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
		"delete_module":   FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
		"create_module":   FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
		"get_kernel_syms": FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
		"query_module":    FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},

		// Kexec and reboot
		"kexec_load":      FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
		"kexec_file_load": FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
		"reboot":          FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},

		// Mounts, filesystem context, and namespace switching
		"mount":         FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
		"umount2":       FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
		"pivot_root":    FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
		"chroot":        FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
		"fsopen":        FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
		"fsconfig":      FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
		"fsmount":       FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
		"fspick":        FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
		"move_mount":    FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
		"open_tree":     FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
		"mount_setattr": FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
		"unshare":       FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
		"setns":         FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},

		// Clock and time
		"settimeofday":  FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
		"clock_settime": FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
		"clock_adjtime": FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
		"adjtimex":      FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},

		// Hostname and domain
		"sethostname":   FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
		"setdomainname": FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},

		// Quotas and swap
		"quotactl":    FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
		"quotactl_fd": FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
		"swapon":      FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
		"swapoff":     FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},

		// Kernel programmability and performance counters
		"bpf":             FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
		"perf_event_open": FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},

		// Cross-process inspection and tracing
		"ptrace":            FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
		"process_vm_readv":  FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
		"process_vm_writev": FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
		"process_madvise":   FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
		"kcmp":              FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},

		// Process accounting: obsolete or rarely-needed
		"acct":           FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
		"nfsservctl":     FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
		"vhangup":        FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
		"lookup_dcookie": FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},

		// userfaultfd and io_uring
		"userfaultfd":       FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
		"io_uring_setup":    FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
		"io_uring_enter":    FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
		"io_uring_register": FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},

		// Kernel keyring
		"add_key":     FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
		"request_key": FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
		"keyctl":      FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},

		// NUMA memory policy
		"mbind":                   FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
		"migrate_pages":           FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
		"move_pages":              FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
		"set_mempolicy":           FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
		"get_mempolicy":           FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
		"set_mempolicy_home_node": FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},

		// amd64-only legacy and obsolete syscalls (ignored on other arches)
		"iopl":        FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
		"ioperm":      FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
		"_sysctl":     FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
		"afs_syscall": FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
		"tuxcall":     FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
		"vserver":     FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
		"getpmsg":     FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
		"putpmsg":     FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
		"security":    FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
		"uselib":      FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
		"ustat":       FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
		"sysfs":       FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
		"modify_ldt":  FilterConfig{Action: unix.SECCOMP_RET_ERRNO, Errno: unix.EPERM},
	}

	defaultSockFilter = makeSockFilter(defaultFilterConfig)
)
