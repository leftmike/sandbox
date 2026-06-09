package sandbox

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
	childLandlockFailed    = 195

	sandboxChildArg0 = "__sandbox_child"
)

type childConfig struct {
	Path        string
	Args        []string
	Env         []string
	Filter      []unix.SockFilter
	FSP         *FSPolicy
	WriteAccess uint64
	ExecuteOnly bool
	NoLandlock  bool
}

func recvConfig(fd int) (*childConfig, error) {
	buf := make([]byte, 1024*128)
	n, _, rf, _, err := unix.Recvmsg(fd, buf, nil, 0)
	if err != nil {
		return nil, err
	} else if rf&unix.MSG_TRUNC != 0 {
		return nil, fmt.Errorf("recv config: %d bytes exceeds receive buffer", n)
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
		fmt.Fprintf(os.Stderr, "seccomp(SET_MODE_FILTER, NEW_LISTENER): %d\n", errno)
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
	if os.Args[0] != sandboxChildArg0 {
		return
	}

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

	// The seccomp filter traps sendmsg, sendto, and sendmmsg so that socket
	// sends can be reported. The listener-fd handoff below also uses sendmsg,
	// and it would deadlock if it were trapped: the sandbox monitor cannot
	// service the notification until it has received the very fd being sent.
	//
	// The filter is installed without SECCOMP_FILTER_FLAG_TSYNC, so it applies
	// only to the thread that installs it. We therefore install the filter and
	// exec the command on a dedicated locked thread, and send the listener fd
	// to the monitor from this (unfiltered) thread. Because the locked
	// goroutine owns its thread exclusively, this goroutine runs on a different
	// thread and its sendmsg is not trapped. The exec inherits the filter from
	// the locked thread, and threads later created by the command inherit it in
	// turn.
	fdCh := make(chan int)
	sentCh := make(chan struct{})
	go func() {
		runtime.LockOSThread()

		err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "sandbox child: prctl(PR_SET_NO_NEW_PRIVS): %s\n", err)
			os.Exit(childNoNewPrivsFailed)
		}

		if cfg.FSP != nil && !cfg.NoLandlock {
			err = landlockApplyFSPolicy(cfg.FSP, cfg.WriteAccess, cfg.ExecuteOnly)
			if err != nil {
				fmt.Fprintf(os.Stderr, "sandbox child: landlock: %s\n", err)
				os.Exit(childLandlockFailed)
			}
		}

		fd := installListener(cfg.Filter)
		unix.CloseOnExec(fd)
		fdCh <- fd

		<-sentCh
		err = unix.Exec(cfg.Path, cfg.Args, cfg.Env)
		fmt.Fprintf(os.Stderr, "sandbox child: exec(%v): %s\n", cfg.Path, err)
		os.Exit(childExecCommandFailed)
	}()

	fd := <-fdCh
	err = unix.Sendmsg(childSocketFd, nil, unix.UnixRights(fd), nil, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sandbox child: sendmsg: %s\n", err)
		os.Exit(childSendmsgFailed)
	}
	close(sentCh)

	// Block forever: the locked goroutine execs over this process. Returning
	// from init would let the (unsandboxed) Go program continue running.
	select {}
}
