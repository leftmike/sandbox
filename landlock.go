package sandbox

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	landlockReadAccess uint64 = unix.LANDLOCK_ACCESS_FS_READ_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_DIR

	landlockExecuteAccess uint64 = unix.LANDLOCK_ACCESS_FS_EXECUTE |
		unix.LANDLOCK_ACCESS_FS_READ_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_DIR
)

var (
	landlockWriteAccess uint64
	LandlockSupported   bool
)

func init() {
	n, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0,
		unix.LANDLOCK_CREATE_RULESET_VERSION)
	ver := int(n)
	if errno != 0 || ver < 1 {
		LandlockSupported = false
	} else {
		LandlockSupported = true

		landlockWriteAccess = unix.LANDLOCK_ACCESS_FS_READ_FILE |
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
			unix.LANDLOCK_ACCESS_FS_MAKE_SYM

		if ver >= 2 {
			landlockWriteAccess |= unix.LANDLOCK_ACCESS_FS_REFER
		}
		if ver >= 3 {
			landlockWriteAccess |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
		}
		// ver >= 5:  unix.LANDLOCK_ACCESS_FS_IOCTL_DEV
	}
}

func landlockCreateRuleset(attr unix.LandlockRulesetAttr) (int, error) {
	fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr), 0)
	if errno != 0 {
		return -1, errno
	}
	return int(fd), nil
}

func landlockAddPathBeneath(fd int, attr *unix.LandlockPathBeneathAttr) error {
	_, _, errno := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, uintptr(fd),
		uintptr(unix.LANDLOCK_RULE_PATH_BENEATH), uintptr(unsafe.Pointer(attr)), 0, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func landlockRestrictSelf(fd int, flags int) error {
	_, _, errno := unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(fd), uintptr(flags), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func landlockApplyAccess(fd int, paths []string, access uint64, strict bool) error {
	for _, path := range paths {
		pfd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
		if err == unix.ENOENT && !strict {
			continue
		} else if err != nil {
			return fmt.Errorf("landlock open: %s: %s", path, err)
		}

		err = landlockAddPathBeneath(fd, &unix.LandlockPathBeneathAttr{
			Allowed_access: access,
			Parent_fd:      int32(pfd),
		})
		unix.Close(pfd)
		if err != nil {
			return fmt.Errorf("landlock add rule: %s: %s", path, err)
		}
	}

	return nil
}

func landlockApplyFSPolicy(fs *FSPolicy, writeAccess uint64, executeOnly bool) error {
	var handledAccess uint64
	if executeOnly {
		handledAccess = unix.LANDLOCK_ACCESS_FS_EXECUTE
	} else {
		if len(fs.Read) > 0 {
			handledAccess |= landlockReadAccess
		}
		if len(fs.Write) > 0 {
			handledAccess |= writeAccess
		}
		if len(fs.Execute) > 0 {
			handledAccess |= landlockExecuteAccess
		}
	}

	fd, err := landlockCreateRuleset(unix.LandlockRulesetAttr{Access_fs: handledAccess})
	if err != nil {
		return fmt.Errorf("landlock create ruleset: %s", err)
	}
	defer unix.Close(fd)

	if executeOnly {
		err = landlockApplyAccess(fd, fs.Execute, unix.LANDLOCK_ACCESS_FS_EXECUTE, false)
		if err != nil {
			return err
		}
	} else {
		err = landlockApplyAccess(fd, fs.Read, landlockReadAccess, false)
		if err != nil {
			return err
		}
		err = landlockApplyAccess(fd, fs.Write, writeAccess, false)
		if err != nil {
			return err
		}
		err = landlockApplyAccess(fd, fs.Execute, landlockExecuteAccess, false)
		if err != nil {
			return err
		}
	}

	err = landlockRestrictSelf(fd, 0)
	if err != nil {
		return fmt.Errorf("landlock restrict self: %s", err)
	}

	return nil
}
