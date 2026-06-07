package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"golang.org/x/sys/unix"
)

const (
	sandboxNamespaceArg0 = "__sandbox_namespace"
)

var defaultBindMounts = []string{
	"/lib",
	"/lib64",
	"/usr/lib",
	"/usr/lib64",
	"/etc/ld.so.cache",
	"/etc/ld.so.conf",
	"/etc/ld.so.conf.d",
	"/etc/nsswitch.conf",
	"/etc/passwd",
	"/etc/group",
	"/etc/resolv.conf",
	"/etc/hosts",
	"/etc/localtime",
	"/etc/ssl/certs",
	"/usr/share/locale",
	"/usr/lib/locale",
	"/usr/share/terminfo",
	"/dev/null",
	"/dev/zero",
	"/dev/urandom",
	"/dev/random",
	"/dev/tty",
	"/dev/full",

	"/usr/bin", // XXX
}

func init() {
	if os.Args[0] != sandboxNamespaceArg0 {
		return
	}

	runtime.LockOSThread()

	//	runNamespaceHelper()
	os.Exit(0) // XXX
}

func namespaceSandbox(cfg *childConfig) {
	//sandboxDir := fmt.Sprintf("/run/user/%d/sandbox-%d/%d", cfg.UID, unix.Getppid(), unix.Getpid())
	//sandboxDir := fmt.Sprintf("/run/user/%d/sandbox", cfg.UID)
	sandboxDir := "./run"
	os.RemoveAll(sandboxDir)
	err := os.MkdirAll(sandboxDir, 0755)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sandbox child: mkdir all: %s: %s\n", sandboxDir, err)
		os.Exit(childMountFailed)
	}

	err = unix.Mount("", "/", "", unix.MS_PRIVATE|unix.MS_REC, "")
	if err != nil && err != unix.EPERM {
		fmt.Fprintf(os.Stderr, "sandbox child: mount / private: %s\n", err)
		os.Exit(childMountFailed)
	}
	rootDir := filepath.Join(sandboxDir, "root")
	err = os.Mkdir(rootDir, 0755)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sandbox child: mkdir: %s: %s\n", rootDir, err)
		os.Exit(childMountFailed)
	}

	err = unix.Mount("tmpfs", rootDir, "tmpfs", 0, "mode=755")
	if err != nil {
		fmt.Fprintf(os.Stderr, "sandbox child: mount tmpfs: %s: %s\n", rootDir, err)
		os.Exit(childMountFailed)
	}

	for _, src := range defaultBindMounts {
		err := bindMountRO(src, rootDir+src)
		if err != nil {
			fmt.Fprintf(os.Stderr, "bind mount read-only: %s: %s\n", src, err)
		}
	}

	// Bind-mount /proc from the host.  Mounting a fresh procfs would require
	// CAP_SYS_ADMIN in the user namespace that owns the current PID namespace
	// (the initial user namespace), which we don't have.  A bind mount of the
	// existing /proc works fine with the capabilities we have in our own namespace.
	if err := bindMount("/proc", filepath.Join(rootDir, "proc")); err != nil {
		fmt.Fprintf(os.Stderr, "sandbox child: bind mount proc: %s\n", err)
		os.Exit(childMountFailed)
	}

	// XXX: bind-mount part of / to allow resolving host paths from within the sandbox

	// pivot_root using the "same directory" trick: chdir into the new root,
	// call pivot_root(".", ".") to replace old root with cwd, then detach old root.
	if err := unix.Chdir(rootDir); err != nil {
		fmt.Fprintf(os.Stderr, "sandbox child: chdir %s: %s\n", rootDir, err)
		os.Exit(childPivotRootFailed)
	}
	if err := unix.PivotRoot(".", "."); err != nil {
		fmt.Fprintf(os.Stderr, "sandbox child: pivot_root: %s\n", err)
		os.Exit(childPivotRootFailed)
	}
	// Detach the old root that is now stacked on top of ".".
	if err := unix.Unmount(".", unix.MNT_DETACH); err != nil {
		fmt.Fprintf(os.Stderr, "sandbox child: unmount old root: %s\n", err)
		os.Exit(childPivotRootFailed)
	}
	if err := unix.Chdir("/"); err != nil {
		fmt.Fprintf(os.Stderr, "sandbox child: chdir /: %s\n", err)
		os.Exit(childPivotRootFailed)
	}

	// XXX

	// XXX: return sandboxDir
	// XXX: os.RemoveAll(sandboxDir) before exit
}

// ensureTarget creates an empty file or directory at dst to serve as a bind-mount target.
func ensureTarget(src, dst string) error {
	st, err := os.Stat(src)
	if err != nil {
		return err
	}
	if st.IsDir() {
		return os.MkdirAll(dst, 0755)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL, 0)
	if err != nil {
		if os.IsExist(err) {
			return nil
		}
		return err
	}
	return f.Close()
}

// bindMountRO bind-mounts src onto dst as read-only and nosuid.
func bindMountRO(src, dst string) error {
	if err := ensureTarget(src, dst); err != nil {
		return err
	}
	if err := unix.Mount(src, dst, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return err
	}
	//listDir(dst)
	return nil
	// return unix.Mount("", dst, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NOSUID, "")
}

func listDir(dst string) {
	entries, err := os.ReadDir(dst)
	if err != nil {
		fmt.Printf("readdir %s: %v\n", dst, err)
		return
	}

	fmt.Printf("%s: ", dst)
	for _, e := range entries {
		fmt.Printf("%s ", e.Name())
	}
	fmt.Println()
}

// bindMount bind-mounts src onto dst read-write (used for pseudo-filesystems like /proc).
func bindMount(src, dst string) error {
	if err := ensureTarget(src, dst); err != nil {
		return err
	}
	return unix.Mount(src, dst, "", unix.MS_BIND|unix.MS_REC, "")
}
