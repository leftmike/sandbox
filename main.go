package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
)

type syscallHandler struct{}

func (_ syscallHandler) Clone(pid uint32, sysnum int, flags uint64) bool {
	fmt.Printf("%d: %s(%x)\n", pid, SysNums[sysnum], flags)
	return true
}

func (_ syscallHandler) Exec(pid uint32, sysnum int, pathname string, argv []string,
	env []string) bool {

	if len(env) > 5 {
		env = []string{env[0], env[1], "...", env[len(env)-2], env[len(env)-1]}
	}
	fmt.Printf("%d: %s(%s, %v, %v)\n", pid, SysNums[sysnum], pathname, argv, env)
	return true
}

func (_ syscallHandler) Open(pid uint32, sysnum int, pathname string, flags int32,
	mode uint32) bool {

	fmt.Printf("%d: %s(%s, %x, %x)\n", pid, SysNums[sysnum], pathname, flags, mode)
	return true
}

func (_ syscallHandler) Syscall(pid uint32, sysnum int) bool {
	fmt.Printf("%d: syscall: %s:%d\n", pid, SysNums[sysnum], sysnum)
	return true
}

func main() {
	if len(os.Args) < 2 {
		log.Fatalln("missing command to sandbox")
	}

	fmt.Println(os.Args[1:])
	cmd := Command(os.Args[1], os.Args[2:]...)
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
