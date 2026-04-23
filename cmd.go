package main

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
)

type Cmd struct {
	exec.Cmd
	Handler Handler
}

func Command(name string, arg ...string) *Cmd {
	return &Cmd{
		Cmd: *exec.Command(name, arg...),
	}
}

func CommandContext(ctx context.Context, name string, arg ...string) *Cmd {
	return &Cmd{
		Cmd: *exec.CommandContext(ctx, name, arg...),
	}
}

func (cmd *Cmd) CombinedOutput() ([]byte, error) {
	// Copied from https://cs.opensource.google/go/go/+/master:src/os/exec/exec.go
	if cmd.Stdout != nil {
		return nil, errors.New("sandbox: stdout already set")
	}
	if cmd.Stderr != nil {
		return nil, errors.New("sandbox: stderr already set")
	}

	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.Bytes(), err
}

func (cmd *Cmd) Output() ([]byte, error) {
	// Copied from https://cs.opensource.google/go/go/+/master:src/os/exec/exec.go
	if cmd.Stdout != nil {
		return nil, errors.New("sandbox: stdout already set")
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	if cmd.Stderr == nil {
		cmd.Stderr = &stderrBuf
	}

	err := cmd.Run()
	if err != nil && cmd.Stderr == &stderrBuf {
		if exitError, ok := err.(*exec.ExitError); ok {
			buf := stderrBuf.Bytes()
			if len(buf) > 2048 {
				buf = buf[:2048]
			}
			exitError.Stderr = buf
		}
	}
	return stdoutBuf.Bytes(), err
}

func (cmd *Cmd) Run() error {
	err := cmd.Start()
	if err != nil {
		return err
	}
	return cmd.Wait()
}

func (cmd *Cmd) Start() error {
	err := cmd.Cmd.Start() // XXX
	if err != nil {
		return err
	}

	return nil
}

// XXX: func (cmd *Cmd) StderrPipe() (io.ReadCloser, error)
// XXX: func (cmd *Cmd) StdinPipe() (io.WriteCloser, error)
// XXX: func (cmd *Cmd) StdoutPipe() (io.ReadCloser, error)
// XXX: func (cmd *Cmd) String() string

func (cmd *Cmd) Wait() error {
	err := cmd.Cmd.Wait() // XXX
	return err
}
