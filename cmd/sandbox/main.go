package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"

	"github.com/leftmike/sandbox"
)

type syscallHandler struct{}

func (_ syscallHandler) Clone(pid uint32, sysnum int, flags uint64) bool {
	fmt.Printf("%d: %s(%x)\n", pid, sandbox.Sysnums[sysnum], flags)
	return true
}

func (_ syscallHandler) Exec(pid uint32, sysnum int, pathname string, argv []string,
	env []string) bool {

	if len(env) > 5 {
		env = []string{env[0], env[1], "...", env[len(env)-2], env[len(env)-1]}
	}
	fmt.Printf("%d: %s(%s, %v, %v)\n", pid, sandbox.Sysnums[sysnum], pathname, argv, env)
	return true
}

func (_ syscallHandler) ExecFailed(pid uint32, sysnum int, err error) {
	fmt.Printf("%d: %s failed: %s\n", pid, sandbox.Sysnums[sysnum], err)
}

func (_ syscallHandler) Open(pid uint32, sysnum int, pathname string, flags int32,
	mode uint32, resolve uint64) bool {

	fmt.Printf("%d: %s(%s, %x, %x, %x)\n", pid, sandbox.Sysnums[sysnum], pathname, flags, mode,
		resolve)
	return true
}

func (_ syscallHandler) OpenFailed(pid uint32, sysnum int, err error) {
	fmt.Printf("%d: %s failed: %s\n", pid, sandbox.Sysnums[sysnum], err)
}

func (_ syscallHandler) Syscall(pid uint32, sysnum int) bool {
	fmt.Printf("%d: syscall: %s:%d\n", pid, sandbox.Sysnums[sysnum], sysnum)
	return true
}

func main() {
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		log.Fatalln("missing command to sandbox")
	}

	fmt.Println(args)
	cmd := sandbox.Command(args[0], args[1:]...)
	cmd.Handler = syscallHandler{}
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %s\n", os.Args[1], err)
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		os.Exit(1)
	}
}
