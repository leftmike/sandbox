package main

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	childSocketFd = 3

	// Failure error codes from the sandbox child.
	childBadArguments      = 189
	childNoNewPrivsFailed  = 190
	childNewListenerFailed = 191
	childSendmsgFailed     = 192
	childRecvConfigFailed  = 193
	childExecCommandFailed = 194
	childMountFailed       = 197
	childPivotRootFailed   = 198
)

type childConfig struct {
	Path         string
	Args         []string
	Env          []string
	Filter       []unix.SockFilter
	AllowedExecs []string // if non-nil, restrict execution to these absolute paths
	BindMounts   []string // additional paths to bind-mount read-only into the new root
}

func recvConfig(fd int) (*childConfig, error) {
	buf := make([]byte, 1024*64)
	n, _, _, _, err := unix.Recvmsg(fd, buf, nil, 0)
	if err != nil {
		return nil, err
	}

	var cfg childConfig
	err = json.Unmarshal(buf[:n], &cfg)
	if err != nil {
		return nil, err
	}

	return &cfg, nil
}

func installListener(sf []unix.SockFilter) int {
	sfp := unix.SockFprog{
		Len:    uint16(len(sf)),
		Filter: &sf[0],
	}

	fd, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER,
		unix.SECCOMP_FILTER_FLAG_NEW_LISTENER, uintptr(unsafe.Pointer(&sfp)))
	if errno != 0 {
		fmt.Fprintf(os.Stderr, "seccomp(SET_MODE_FILTER, NEW_LISTENER): %d", errno)
		os.Exit(childNewListenerFailed)
	}

	return int(fd)
}

func isSocketFd(fd int) bool {
	var st unix.Stat_t
	err := unix.Fstat(fd, &st)
	if err != nil || (st.Mode&unix.S_IFMT) != unix.S_IFSOCK {
		return false
	}

	sa, err := unix.Getsockname(fd)
	if err != nil {
		return false
	}
	_, ok := sa.(*unix.SockaddrUnix)
	return ok
}

func init() {
	if os.Args[0] != "__sandbox_child" {
		return
	}

	runtime.LockOSThread()

	if !isSocketFd(childSocketFd) {
		fmt.Fprintf(os.Stderr, "sandbox child: not a socket: fd %d\n", childSocketFd)
		os.Exit(childBadArguments)
	}
	unix.CloseOnExec(childSocketFd)

	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "sandbox child: expected no arguments")
		os.Exit(childBadArguments)
	}

	cfg, err := recvConfig(childSocketFd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sandbox child: recv config: %s\n", err)
		os.Exit(childRecvConfigFailed)
	}

	// Mount namespace setup must happen before PR_SET_NO_NEW_PRIVS: Linux blocks
	// unprivileged user namespace creation once no_new_privs is set.
	if cfg.AllowedExecs != nil {
		setupMountNS(cfg)
	}

	err = unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sandbox child: prctl(PR_SET_NO_NEW_PRIVS): %s\n", err)
		os.Exit(childNoNewPrivsFailed)
	}

	fd := installListener(cfg.Filter)
	unix.CloseOnExec(fd)

	err = unix.Sendmsg(childSocketFd, nil, unix.UnixRights(fd), nil, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sandbox child: sendmsg: %s\n", err)
		os.Exit(childSendmsgFailed)
	}

	err = unix.Exec(cfg.Path, cfg.Args, cfg.Env)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sandbox child: exec(%v): %s\n", cfg.Path, err)
		os.Exit(childExecCommandFailed)
	}
}
