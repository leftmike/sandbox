//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// hostRootMountpoint is the path inside the sandbox where the host's root
// filesystem is bind-mounted (read-only) when DynamicAllowedExecs is on.
// The mount helper uses this path to resolve host paths from within the
// sandbox's mount namespace.
const hostRootMountpoint = "/run/.host"

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

	// In dynamic mode the helper needs to resolve host paths from inside the
	// sandbox namespace.  We can't bind-mount / directly (the kernel rejects bind
	// mounts of the root mount with EINVAL in unprivileged user namespaces), so
	// we mirror each top-level entry of / individually under hostRootMountpoint.
	// MS_BIND (without MS_REC) deliberately omits submounts of / (e.g. /proc,
	// /tmp, /dev, /sys); the helper only needs read access to the regular file
	// hierarchy.  This still exposes host filenames to the sandboxed process;
	// the seccomp listener remains the authoritative gate on what may execute.
	if cfg.DynamicAllowedExecs {
		hostRoot := filepath.Join(stagingDir, hostRootMountpoint)
		if err := os.MkdirAll(hostRoot, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "sandbox child: mkdir host root mirror: %s\n", err)
			os.Exit(childMountFailed)
		}
		entries, err := os.ReadDir("/")
		if err != nil {
			fmt.Fprintf(os.Stderr, "sandbox child: readdir /: %s\n", err)
			os.Exit(childMountFailed)
		}
		for _, ent := range entries {
			name := ent.Name()
			// Skip pseudo-filesystems we don't need or that aren't bind-mountable.
			switch name {
			case "proc", "sys", "dev", "tmp", "run":
				continue
			}
			src := "/" + name
			dst := filepath.Join(hostRoot, name)
			_ = bindMountRO(src, dst)
		}
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

	// Dynamic mode: make the root and all submounts MS_SHARED so the helper's
	// runtime bind mounts propagate to the tracee.  The tracee will then
	// unshare its own mount namespace, mark it MS_SLAVE, and unmount
	// /run/.host -- slave-side unmounts don't propagate to the master, so the
	// helper retains its view of the host filesystem.
	if cfg.DynamicAllowedExecs {
		if err := unix.Mount("", "/", "", unix.MS_SHARED|unix.MS_REC, ""); err != nil {
			fmt.Fprintf(os.Stderr, "sandbox child: mount / shared: %s\n", err)
			os.Exit(childMountFailed)
		}
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

// mountWorker is the parent-side handle to the in-namespace mount helper process.
// Each BindMount call sends a textual request over a SOCK_SEQPACKET socket and
// reads back the helper's response.  Setns from the parent doesn't work in Go
// (the runtime is multi-threaded and setns(CLONE_NEWUSER) returns EINVAL), so the
// actual mount is done by a helper process that the sandbox child forks while it
// still has CAP_SYS_ADMIN in the new user namespace.
type mountWorker struct {
	mu      sync.Mutex
	fd      int
	mounted map[string]bool
}

func newMountWorker(fd int) *mountWorker {
	return &mountWorker{fd: fd, mounted: map[string]bool{}}
}

// BindMount asks the helper to bind-mount srcPath (a host-namespace absolute path)
// onto target (a path inside the sandbox's tmpfs root).  Repeated calls for the
// same target are no-ops.
func (w *mountWorker) BindMount(srcPath, target string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.mounted[target] {
		return nil
	}
	if strings.ContainsAny(srcPath, " \n") || strings.ContainsAny(target, " \n") {
		return fmt.Errorf("mount paths must not contain space or newline: %q %q", srcPath, target)
	}

	req := []byte(fmt.Sprintf("MOUNT %s %s", srcPath, target))
	if _, err := unix.Write(w.fd, req); err != nil {
		return fmt.Errorf("mount worker write: %w", err)
	}

	buf := make([]byte, 4096)
	n, err := unix.Read(w.fd, buf)
	if err != nil {
		return fmt.Errorf("mount worker read: %w", err)
	}
	resp := string(buf[:n])
	switch {
	case resp == "OK":
		w.mounted[target] = true
		return nil
	case strings.HasPrefix(resp, "ERR "):
		return errors.New(strings.TrimPrefix(resp, "ERR "))
	default:
		return fmt.Errorf("mount worker: unexpected response %q", resp)
	}
}

// Stop closes the socket; the helper process sees EOF and exits.
func (w *mountWorker) Stop() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.fd >= 0 {
		unix.Close(w.fd)
		w.fd = -1
	}
}

// runMountHelper is the entry point for the "__sandbox_mount_helper" subprocess.
// It is forked from the sandbox child after setupMountNS but before installListener,
// so it inherits the new user+mount namespaces and has CAP_SYS_ADMIN there.
// It reads MOUNT requests from fd 3 and replies in place.  Source paths are
// resolved through hostRootMountpoint inside the sandbox namespace.
func runMountHelper() {
	const fd = 3
	buf := make([]byte, 8192)
	for {
		n, err := unix.Read(fd, buf)
		if err != nil || n == 0 {
			return
		}
		msg := string(buf[:n])
		parts := strings.SplitN(msg, " ", 3)
		if len(parts) != 3 || parts[0] != "MOUNT" {
			_, _ = unix.Write(fd, []byte("ERR bad request"))
			continue
		}
		hostSrc := filepath.Join(hostRootMountpoint, parts[1])
		target := parts[2]
		if err := bindMountRO(hostSrc, target); err != nil {
			_, _ = unix.Write(fd, []byte("ERR "+err.Error()))
			continue
		}
		_, _ = unix.Write(fd, []byte("OK"))
	}
}

// startMountHelper is called from the sandbox child to fork the helper subprocess.
// The helper inherits the sandbox child's namespaces; it receives the helper end
// of the parent<->helper socket as fd 3 via ExtraFiles.
func startMountHelper(socketFd int) error {
	helperFile := os.NewFile(uintptr(socketFd), "mount-helper-sock")
	defer helperFile.Close()

	cmd := exec.Cmd{
		Path:       "/proc/self/exe",
		Args:       []string{"__sandbox_mount_helper"},
		Stdin:      nil,
		Stdout:     nil,
		Stderr:     os.Stderr,
		ExtraFiles: []*os.File{helperFile},
	}
	return cmd.Start()
}
