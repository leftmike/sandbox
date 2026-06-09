package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"

	"github.com/leftmike/sandbox"
)

func main() {
	landlock := flag.Bool("landlock", false,
		"restrict filesystem access with the default landlock policy")
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		log.Fatalln("missing command to sandbox")
	}

	fmt.Println(args)
	cmd := sandbox.Command(args[0], args[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	sb := sandbox.WithLogging(nil, sandbox.LogOptions{
		Ignore: []string{"/usr/lib/locale"},
	})
	if *landlock {
		if !sandbox.LandlockAvailable() {
			log.Fatalln("landlock not supported by the running kernel")
		}
		sb.FS = sandbox.DefaultFSPolicy()
	}
	cmd.Sandbox = sb

	err := cmd.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %s\n", os.Args[1], err)
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		os.Exit(1)
	}
}
