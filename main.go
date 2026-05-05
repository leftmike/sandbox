package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

type syscallHandler struct{}

func (_ syscallHandler) Clone(pid uint32, sysnum int, flags uint64) bool {
	fmt.Printf("%d: %s(%x)\n", pid, Sysnums[sysnum], flags)
	return true
}

func (_ syscallHandler) Exec(pid uint32, sysnum int, pathname string, argv []string,
	env []string) bool {

	if len(env) > 5 {
		env = []string{env[0], env[1], "...", env[len(env)-2], env[len(env)-1]}
	}
	fmt.Printf("%d: %s(%s, %v, %v)\n", pid, Sysnums[sysnum], pathname, argv, env)
	return true
}

func (_ syscallHandler) Open(pid uint32, sysnum int, pathname string, flags int32,
	mode uint32) bool {

	fmt.Printf("%d: %s(%s, %x, %x)\n", pid, Sysnums[sysnum], pathname, flags, mode)
	return true
}

func (_ syscallHandler) Syscall(pid uint32, sysnum int) bool {
	fmt.Printf("%d: syscall: %s:%d\n", pid, Sysnums[sysnum], sysnum)
	return true
}

func main() {
	var allowExecFlag multiFlag
	flag.Var(&allowExecFlag, "allow-exec",
		"allow execution of this absolute path (may be repeated; activates exec allowlist)")
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		log.Fatalln("missing command to sandbox")
	}

	fmt.Println(args)
	cmd := Command(args[0], args[1:]...)
	cmd.Handler = syscallHandler{}
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if len(allowExecFlag) > 0 {
		cmd.AllowedExecs = []string(allowExecFlag)
	}

	err := cmd.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %s\n", args[0], err)
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		os.Exit(1)
	}
}

// multiFlag is a repeatable string flag.
type multiFlag []string

func (f *multiFlag) String() string { return strings.Join(*f, ",") }
func (f *multiFlag) Set(v string) error {
	*f = append(*f, v)
	return nil
}
