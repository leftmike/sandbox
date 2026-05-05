//go:build linux

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// defaultBindMounts contains paths bind-mounted read-only into the new root to satisfy
// the dynamic linker and libc requirements for typical glibc-linked binaries.
// Paths that do not exist on the host are silently skipped.
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
}

// setupMountNS builds a minimal tmpfs root containing only the allowlisted executables
// and their runtime dependencies, then pivot_roots into it.
// The child must already be in a new user+mount namespace (via Cloneflags
// CLONE_NEWUSER|CLONE_NEWNS) with uid/gid maps written by the parent via
// SysProcAttr.UidMappings/GidMappings so capabilities are set correctly at exec time.
// Must be called before installListener.
func setupMountNS(cfg *childConfig) {
	// Stop mount propagation so our mounts are invisible outside the namespace.
	if err := unix.Mount("", "/", "", unix.MS_PRIVATE|unix.MS_REC, ""); err != nil {
		fmt.Fprintf(os.Stderr, "sandbox child: mount / private: %s\n", err)
		os.Exit(childMountFailed)
	}

	stagingDir, err := os.MkdirTemp("", "sandbox-root-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "sandbox child: mkdirtemp: %s\n", err)
		os.Exit(childMountFailed)
	}
	if err := unix.Mount("tmpfs", stagingDir, "tmpfs", 0, "mode=755"); err != nil {
		fmt.Fprintf(os.Stderr, "sandbox child: mount tmpfs at %s: %s\n", stagingDir, err)
		os.Exit(childMountFailed)
	}

	// Bind-mount default dependencies; skip paths absent on this host.
	for _, src := range append(defaultBindMounts, cfg.BindMounts...) {
		_ = bindMountRO(src, stagingDir+src)
	}

	// Bind-mount allowlisted executables; failure here is fatal.
	for _, src := range cfg.AllowedExecs {
		if err := bindMountRO(src, stagingDir+src); err != nil {
			fmt.Fprintf(os.Stderr, "sandbox child: bind mount exec %s: %s\n", src, err)
			os.Exit(childMountFailed)
		}
	}

	// Bind-mount /proc from the host.  Mounting a fresh procfs would require
	// CAP_SYS_ADMIN in the user namespace that owns the current PID namespace
	// (the initial user namespace), which we don't have.  A bind mount of the
	// existing /proc works fine with the capabilities we have in our own namespace.
	if err := bindMount("/proc", filepath.Join(stagingDir, "proc")); err != nil {
		fmt.Fprintf(os.Stderr, "sandbox child: bind mount proc: %s\n", err)
		os.Exit(childMountFailed)
	}

	// pivot_root using the "same directory" trick: chdir into the new root,
	// call pivot_root(".", ".") to replace old root with cwd, then detach old root.
	if err := unix.Chdir(stagingDir); err != nil {
		fmt.Fprintf(os.Stderr, "sandbox child: chdir %s: %s\n", stagingDir, err)
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
}

// ensureTarget creates an empty file or directory at dst to serve as a bind-mount target.
func ensureTarget(src, dst string) error {
	st, err := os.Stat(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	if st.IsDir() {
		return os.MkdirAll(dst, 0755)
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
	if err := unix.Mount(src, dst, "", unix.MS_BIND, ""); err != nil {
		return err
	}
	return unix.Mount("", dst, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NOSUID, "")
}

// bindMount bind-mounts src onto dst read-write (used for pseudo-filesystems like /proc).
func bindMount(src, dst string) error {
	if err := ensureTarget(src, dst); err != nil {
		return err
	}
	return unix.Mount(src, dst, "", unix.MS_BIND|unix.MS_REC, "")
}
