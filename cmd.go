package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type Handler interface {
	Clone(pid uint32, flags uint64) bool
	Exec(pid uint32, pathname string, argv []string, env []string) bool
	Open(pid uint32, filename string, flags int32, mode uint32) bool
	Syscall(pid uint32, nr int32) bool
}

type Cmd struct {
	exec.Cmd

	Handler Handler

	closeFd int
	waitCh  chan error
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

func (cmd *Cmd) Start() (err error) {
	if cmd.Handler == nil {
		panic("sandbox: no handler")
	}

	var pipe [2]int
	err = unix.Pipe2(pipe[:], unix.O_CLOEXEC)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			unix.Close(pipe[0])
			unix.Close(pipe[1])
		}
	}()

	sp, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(sp[0])

	cf := os.NewFile(uintptr(sp[1]), "child")
	defer cf.Close()

	cmd.Args[0] = cmd.Path
	cfg := childConfig{
		Path: cmd.Path,
		Args: cmd.Args,
		Env:  cmd.Env,
	}

	cmd.Path = "/proc/self/exe" // XXX: os.Executable()?
	cmd.Args = []string{"__sandbox_child"}
	cmd.ExtraFiles = []*os.File{cf}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	err = cmd.Cmd.Start()
	if err != nil {
		// XXX: check the error code and return code from the child
		// XXX: informative error message if Seccomp filter already set (on WSL2)
		return err
	}

	fd, err := recvFd(sp[0])
	if err == nil {
		err = sendConfig(sp[0], &cfg)
	}
	if err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return err
	}

	cmd.waitCh = make(chan error, 2)
	go func() {
		err := listen(fd, pipe[0], cmd.Handler)
		if err != nil {
			cmd.waitCh <- err
		}

		unix.Close(fd)
		unix.Close(pipe[0])
	}()

	go func() {
		cmd.waitCh <- cmd.Cmd.Wait()
	}()

	cmd.closeFd = pipe[1]
	return nil
}

func (cmd *Cmd) Wait() error {
	err := <-cmd.waitCh

	unix.Close(cmd.closeFd)

	syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	go func() {
		time.Sleep(time.Second)
		syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}()

	return err
}
