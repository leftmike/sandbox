package main

import (
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"

	"github.com/leftmike/sandbox"
)

var (
	ignoreExec = []string{}

	ignoreOpen = []string{
		"/usr/lib/locale",
	}

	ignoreOpenFailed = []string{
		"/usr/lib/locale",
	}
)

func handleClone(pid uint32, sysnum int, flags uint64) bool {
	fmt.Printf("%d: %s(%x)\n", pid, sandbox.Sysnums[sysnum], flags)
	return true
}

func handleExec(pid uint32, sysnum int, pathname string, argv []string, env []string) bool {
	if slices.ContainsFunc(ignoreExec,
		func(s string) bool { return strings.HasPrefix(pathname, s) }) {

		return true
	}

	if len(env) > 5 {
		env = []string{env[0], env[1], "...", env[len(env)-2], env[len(env)-1]}
	}
	fmt.Printf("%d: %s(%s, %v, %v)\n", pid, sandbox.Sysnums[sysnum], pathname, argv, env)
	return true
}

func handleOpen(pid uint32, sysnum int, pathname string, flags int32, mode uint32,
	resolve uint64) bool {

	if slices.ContainsFunc(ignoreOpen,
		func(s string) bool { return strings.HasPrefix(pathname, s) }) {

		return true
	}

	fmt.Printf("%d: %s(%s, %x, %x, %x)\n", pid, sandbox.Sysnums[sysnum], pathname, flags,
		mode, resolve)
	return true
}

func handleOpenFailed(pid uint32, sysnum int, pathname string, err error) {
	if slices.ContainsFunc(ignoreOpenFailed,
		func(s string) bool { return strings.HasPrefix(pathname, s) }) {

		return
	}

	fmt.Printf("%d: failed: %s(%s): %s\n", pid, sandbox.Sysnums[sysnum], pathname, err)
}

func handleSocket(pid uint32, sysnum int, domain, typ, protocol int) bool {
	fmt.Printf("%d: %s(%d, %d, %d)\n", pid, sandbox.Sysnums[sysnum], domain, typ, protocol)
	return true
}

func handleConnect(pid uint32, sysnum int, sockfd int, addr netip.AddrPort) bool {
	fmt.Printf("%d: %s(%d, %s)\n", pid, sandbox.Sysnums[sysnum], sockfd, addr)
	return true
}

func handleBind(pid uint32, sysnum int, sockfd int, addr netip.AddrPort) bool {
	fmt.Printf("%d: %s(%d, %s)\n", pid, sandbox.Sysnums[sysnum], sockfd, addr)
	return true
}

func handleSendto(pid uint32, sysnum int, sockfd int, addr netip.AddrPort) bool {
	fmt.Printf("%d: %s(%d, %s)\n", pid, sandbox.Sysnums[sysnum], sockfd, addr)
	return true
}

func handleSyscall(pid uint32, sysnum int) bool {
	fmt.Printf("%d: syscall: %s:%d\n", pid, sandbox.Sysnums[sysnum], sysnum)
	return true
}

func handleFailed(pid uint32, sysnum int, err error) {
	fmt.Printf("%d: failed: %s: %s\n", pid, sandbox.Sysnums[sysnum], err)
}

func parseMode(s string) (sandbox.Mode, error) {
	switch s {
	case "seccomp":
		return sandbox.SeccompMode, nil
	case "landlock":
		return sandbox.LandlockMode, nil
	default:
		return 0, fmt.Errorf("unknown mode %q (want seccomp or landlock)", s)
	}
}

func main() {
	modeArg := flag.String("mode", "seccomp",
		"sandbox mode: seccomp (proxy opens, landlock for execs) or "+
			"landlock (landlock for everything, kernel handles opens)")
	flag.Parse()

	mode, err := parseMode(*modeArg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %s\n", os.Args[0], err)
		os.Exit(1)
	}

	args := flag.Args()
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "%s: missing command to sandbox", os.Args[0])
		os.Exit(1)
	}

	fmt.Println(args)
	cmd := sandbox.Command(args[0], args[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	cmd.Sandbox = &sandbox.Sandbox{
		Mode:       mode,
		Clone:      handleClone,
		Exec:       handleExec,
		Open:       handleOpen,
		OpenFailed: handleOpenFailed,
		Socket:     handleSocket,
		Connect:    handleConnect,
		Bind:       handleBind,
		Sendto:     handleSendto,
		Syscall:    handleSyscall,
		Failed:     handleFailed,
	}

	err = cmd.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %s\n", os.Args[1], err)
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		os.Exit(1)
	}
}
