package sandbox

// Sandbox is the central policy object for a sandboxed command. It owns the
// syscall event handlers, the seccomp filter configuration, and the filesystem
// lockdown policy. Assign it to Cmd.Sandbox before starting a command; when a
// Cmd is started without one, an empty Sandbox (which allows every intercepted
// syscall) is used.
//
// Each handler func is optional. A nil handler means "allow" for the syscalls it
// governs; the informational handlers (OpenFailed, Failed) are simply not called
// when nil.
//
// Filesystem access is locked down with two complementary mechanisms:
//
//   - FS (landlock) establishes a coarse allow-list enforced by the kernel as a
//     hard boundary applied in the child before exec.
//   - the seccomp openat/openat2 user-notification handlers (Open/OpenFailed)
//     refine per-open decisions within that boundary.
//
// Network access control is not yet implemented; a future Net policy will follow
// the same split: landlock Access_net for the coarse boundary plus seccomp
// interception of socket/connect/bind for refinement.
type Sandbox struct {
	Clone func(pid uint32, sysnum int, flags uint64) bool
	Exec  func(pid uint32, sysnum int, pathname string, argv []string, env []string) bool
	Open  func(pid uint32, sysnum int, pathname string, flags int32, mode uint32,
		resolve uint64) bool
	OpenFailed func(pid uint32, sysnum int, pathname string, err error)
	Syscall    func(pid uint32, sysnum int) bool
	Failed     func(pid uint32, sysnum int, err error)

	// Filter is the seccomp filter configuration. When nil, DefaultFilterConfig
	// is used.
	Filter map[string]FilterConfig

	// FS is the landlock filesystem allow-list. When nil, no landlock policy is
	// applied (filesystem access is mediated by the seccomp handlers only).
	FS *FSPolicy
}

// FSPolicy is a declarative filesystem allow-list compiled into landlock rules.
// Each slice lists paths (files or directories) granted the corresponding access
// beneath them. Paths not covered by any entry are denied for every access right
// the policy restricts.
type FSPolicy struct {
	Read    []string // read-only access
	Write   []string // read-write access (create, remove, truncate, ...)
	Execute []string // execute (and read) access
}

// DefaultFSPolicy returns a permissive but reasonable landlock allow-list for
// running typical dynamically-linked programs: the system binary and library
// trees are executable and readable, common configuration and runtime locations
// are read-only, and only scratch locations are writable. Listed paths that do
// not exist on the host are silently ignored, so the policy is portable across
// distributions.
//
// It is intentionally not applied automatically (a nil Sandbox.FS means no
// landlock); assign it explicitly, e.g. sb.FS = sandbox.DefaultFSPolicy().
func DefaultFSPolicy() *FSPolicy {
	return &FSPolicy{
		// Executables and shared libraries. Library directories need execute
		// access too: landlock requires LANDLOCK_ACCESS_FS_EXECUTE to mmap a
		// shared object with PROT_EXEC, which the dynamic loader does.
		Execute: []string{
			"/bin", "/sbin", "/usr",
			"/lib", "/lib32", "/lib64", "/libx32",
		},
		// Configuration and read-only runtime state (e.g. /etc/passwd,
		// /etc/ssl, /etc/resolv.conf, /proc/self/..., NSS data under /run).
		Read: []string{
			"/etc", "/opt", "/proc", "/sys", "/run", "/var",
		},
		// Scratch space. /dev is included so common device nodes such as
		// /dev/null, /dev/zero, and /dev/urandom can be written as well as read.
		Write: []string{
			"/tmp", "/var/tmp", "/dev",
		},
	}
}

// LandlockAvailable reports whether the running kernel supports landlock, and
// therefore whether an FSPolicy can be enforced.
func LandlockAvailable() bool {
	return landlockABI() >= 1
}

// filter returns the seccomp filter configuration, falling back to the default.
func (sb *Sandbox) filter() map[string]FilterConfig {
	if sb.Filter == nil {
		return defaultFilterConfig
	}
	return sb.Filter
}

// landlock compiles the filesystem policy into a landlockConfig for the child,
// or returns nil when no policy is configured.
func (sb *Sandbox) landlock() *landlockConfig {
	if sb.FS == nil {
		return nil
	}

	cfg := &landlockConfig{}
	add := func(paths []string, access uint64) {
		for _, p := range paths {
			cfg.Rules = append(cfg.Rules, landlockRule{Path: p, Access: access})
			cfg.HandledAccessFS |= access
		}
	}

	add(sb.FS.Read, landlockReadAccess)
	add(sb.FS.Write, landlockWriteAccess)
	add(sb.FS.Execute, landlockExecuteAccess)

	return cfg
}
