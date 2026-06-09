package sandbox

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// landlockConfig is the serializable filesystem landlock policy passed to the
// sandbox child. The child opens each rule's Path (relative to its own process)
// and adds a LANDLOCK_RULE_PATH_BENEATH rule granting Access beneath it.
type landlockConfig struct {
	// HandledAccessFS is the union of access rights restricted by the ruleset.
	// Any handled right not explicitly granted on a path is denied.
	HandledAccessFS uint64
	Rules           []landlockRule
}

type landlockRule struct {
	Path   string
	Access uint64
}

// Access-right combinations granted to paths in an FSPolicy. The actual bits
// applied are clamped to what the running kernel's landlock ABI supports (see
// supportedAccessFS).
const (
	landlockReadAccess uint64 = unix.LANDLOCK_ACCESS_FS_READ_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_DIR

	landlockExecuteAccess uint64 = unix.LANDLOCK_ACCESS_FS_EXECUTE |
		unix.LANDLOCK_ACCESS_FS_READ_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_DIR

	landlockWriteAccess uint64 = unix.LANDLOCK_ACCESS_FS_READ_FILE |
		unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_DIR |
		unix.LANDLOCK_ACCESS_FS_REMOVE_DIR |
		unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
		unix.LANDLOCK_ACCESS_FS_MAKE_CHAR |
		unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
		unix.LANDLOCK_ACCESS_FS_MAKE_REG |
		unix.LANDLOCK_ACCESS_FS_MAKE_SOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_FIFO |
		unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_SYM |
		unix.LANDLOCK_ACCESS_FS_TRUNCATE |
		unix.LANDLOCK_ACCESS_FS_REFER
)

func landlockCreateRuleset(attr *unix.LandlockRulesetAttr, size uintptr, flags int) (int, error) {
	var p unsafe.Pointer
	if attr != nil {
		p = unsafe.Pointer(attr)
	}
	fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(p), size,
		uintptr(flags))
	if errno != 0 {
		return -1, errno
	}
	return int(fd), nil
}

func landlockAddPathBeneath(rulesetFd int, attr *unix.LandlockPathBeneathAttr) error {
	_, _, errno := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, uintptr(rulesetFd),
		uintptr(unix.LANDLOCK_RULE_PATH_BENEATH), uintptr(unsafe.Pointer(attr)), 0, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func landlockRestrictSelf(rulesetFd int, flags int) error {
	_, _, errno := unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(rulesetFd),
		uintptr(flags), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// landlockABI returns the landlock ABI version supported by the running kernel,
// or 0 if landlock is unavailable.
func landlockABI() int {
	v, err := landlockCreateRuleset(nil, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if err != nil || v < 1 {
		return 0
	}
	return v
}

// supportedAccessFS returns the filesystem access-right bits known to the given
// landlock ABI version, so that policies stay forward/backward compatible across
// kernels.
func supportedAccessFS(abi int) uint64 {
	if abi < 1 {
		return 0
	}

	access := uint64(unix.LANDLOCK_ACCESS_FS_EXECUTE |
		unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_DIR |
		unix.LANDLOCK_ACCESS_FS_REMOVE_DIR |
		unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
		unix.LANDLOCK_ACCESS_FS_MAKE_CHAR |
		unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
		unix.LANDLOCK_ACCESS_FS_MAKE_REG |
		unix.LANDLOCK_ACCESS_FS_MAKE_SOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_FIFO |
		unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_SYM)

	if abi >= 2 {
		access |= unix.LANDLOCK_ACCESS_FS_REFER
	}
	if abi >= 3 {
		access |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
	}
	if abi >= 5 {
		access |= unix.LANDLOCK_ACCESS_FS_IOCTL_DEV
	}

	return access
}

// applyLandlock enforces the filesystem policy on the calling process. It must be
// called with PR_SET_NO_NEW_PRIVS already set and before exec. It is a no-op when
// cfg is nil.
func applyLandlock(cfg *landlockConfig) error {
	if cfg == nil {
		return nil
	}

	abi := landlockABI()
	if abi < 1 {
		return fmt.Errorf("landlock not supported by the running kernel")
	}

	supported := supportedAccessFS(abi)
	handled := cfg.HandledAccessFS & supported
	if handled == 0 {
		return nil
	}

	attr := unix.LandlockRulesetAttr{Access_fs: handled}
	rulesetFd, err := landlockCreateRuleset(&attr, unsafe.Sizeof(attr), 0)
	if err != nil {
		return fmt.Errorf("landlock_create_ruleset: %w", err)
	}
	defer unix.Close(rulesetFd)

	for _, rule := range cfg.Rules {
		access := rule.Access & supported & handled
		if access == 0 {
			continue
		}

		fd, err := unix.Open(rule.Path, unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil {
			// A path that does not exist grants nothing; skip it so that
			// policies (notably DefaultFSPolicy) stay portable across hosts.
			if err == unix.ENOENT {
				continue
			}
			return fmt.Errorf("landlock: open %s: %w", rule.Path, err)
		}

		err = landlockAddPathBeneath(rulesetFd, &unix.LandlockPathBeneathAttr{
			Allowed_access: access,
			Parent_fd:      int32(fd),
		})
		unix.Close(fd)
		if err != nil {
			return fmt.Errorf("landlock_add_rule %s: %w", rule.Path, err)
		}
	}

	err = landlockRestrictSelf(rulesetFd, 0)
	if err != nil {
		return fmt.Errorf("landlock_restrict_self: %w", err)
	}

	return nil
}
