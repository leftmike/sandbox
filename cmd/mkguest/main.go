// Command mkguest builds the sandbox guest-agent initramfs and writes it to a
// file, so it can be shipped and passed via VMConfig.InitramfsPath instead of
// being built on demand.
//
// Usage: mkguest [-o guest-initramfs.cpio]
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/leftmike/sandbox/internal/initramfs"
)

func main() {
	out := flag.String("o", "guest-initramfs.cpio", "output initramfs path")
	flag.Parse()

	if err := initramfs.Build(*out); err != nil {
		fmt.Fprintf(os.Stderr, "mkguest: %s\n", err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s\n", *out)
}
