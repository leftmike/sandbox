/*
- cmd.Process.Kill(): kill all children too
- cmd.Wait(): when it returns, make sure all children have been killed too
- handle errors from listen by killing all children
*/
package main

import (
	"fmt"
	"log"
	"os"

	"golang.org/x/sys/unix"

	"github.com/leftmike/sandbox/seccomp"
)

func handler(fd int, notif *seccomp.Notif) bool {
	switch notif.Data.NR {
	case unix.SYS_OPENAT:
		path, err := seccomp.ReadString(fd, notif, uintptr(notif.Data.Args[1]), 2048)
		if err != nil {
			fmt.Printf("openat: read string: %s\n", err)
			return false
		}
		fmt.Printf("%d: openat(%s, %x, %x)\n", notif.PID, path, int32(notif.Data.Args[2]),
			uint32(notif.Data.Args[3]))

	case unix.SYS_OPEN:
		path, err := seccomp.ReadString(fd, notif, uintptr(notif.Data.Args[0]), 2048)
		if err != nil {
			fmt.Printf("open: read string: %s\n", err)
			return false
		}
		fmt.Printf("%d: open(%s, %x, %x)\n", notif.PID, path, int32(notif.Data.Args[1]),
			uint32(notif.Data.Args[2]))

	default:
		fmt.Printf("syscall: %d\n", notif.Data.NR)
	}

	return true
}

func main() {
	if len(os.Args) < 2 {
		log.Fatalln("missing command to sandbox")
	}

	fmt.Println(os.Args[1:])
	ret, err := Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, handler)
	fmt.Printf("%s: %d, %s\n", os.Args[1], ret, err)
}
