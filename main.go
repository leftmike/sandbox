package main

import (
	"fmt"
	"log"
	"os"
)

type syscallHandler struct{}

func (_ syscallHandler) Open(pid uint32, pathname string, flags int32, mode uint32) bool {
	fmt.Printf("%d: openat(%s, %x, %x)\n", pid, pathname, flags, mode)
	return true
}

func (_ syscallHandler) Syscall(pid uint32, nr int32) bool {
	fmt.Printf("%d: syscall: %d\n", pid, nr)
	return true
}

func main() {
	if len(os.Args) < 2 {
		log.Fatalln("missing command to sandbox")
	}

	fmt.Println(os.Args[1:])
	ret, err := Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, syscallHandler{})
	fmt.Printf("%s: %d, %s\n", os.Args[1], ret, err)
}
