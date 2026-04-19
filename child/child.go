//go:build linux && amd64

package main

import (
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/leftmike/sandbox/shared"
)

func installListener() int {
	prog := []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},

		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: unix.SYS_OPENAT, Jt: 0, Jf: 1},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_USER_NOTIF},

		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: unix.SYS_OPEN, Jt: 0, Jf: 1},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_USER_NOTIF},

		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW},
	}

	fprog := unix.SockFprog{
		Len:    uint16(len(prog)),
		Filter: &prog[0],
	}

	fd, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER,
		unix.SECCOMP_FILTER_FLAG_NEW_LISTENER, uintptr(unsafe.Pointer(&fprog)))
	if errno != 0 {
		fmt.Fprintf(os.Stderr, "seccomp(SET_MODE_FILTER, NEW_LISTENER): %d", errno)
		os.Exit(shared.NewListenerFailed)
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

func main() {
	runtime.LockOSThread()

	if !isSocketFd(shared.SocketFd) {
		fmt.Fprintf(os.Stderr, "sandbox child: not a socket: fd %d\n", shared.SocketFd)
		os.Exit(shared.BadArguments)
	}
	defer unix.Close(shared.SocketFd)

	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "sandbox child: missing command to sandbox")
		os.Exit(shared.BadArguments)
	}

	err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sandbox child: prctl(PR_SET_NO_NEW_PRIVS): %s\n", err)
		os.Exit(shared.NoNewPrivsFailed)
	}

	fd := installListener()
	defer unix.Close(fd)

	err = unix.Sendmsg(shared.SocketFd, []byte{0}, unix.UnixRights(fd), nil, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sandbox child: sendmsg: %s\n", err)
		os.Exit(shared.SendmsgFailed)
	}

	err = unix.Exec(os.Args[1], os.Args[2:], os.Environ())
	if err != nil {
		fmt.Fprintf(os.Stderr, "sandbox child: exec(%v): %s\n", os.Args[1:], err)
		os.Exit(shared.ExecCommandFailed)
	}
}
