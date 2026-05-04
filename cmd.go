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
	Clone(pid uint32, sysnum int, flags uint64) bool
	Exec(pid uint32, sysnum int, pathname string, argv []string, env []string) bool
	Open(pid uint32, sysnum int, filename string, flags int32, mode uint32) bool
	Syscall(pid uint32, sysnum int) bool
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

	if cmd.Env == nil {
		cmd.Env = os.Environ()
	}

	cmd.Args[0] = cmd.Path
	cfg := childConfig{
		Path:   cmd.Path,
		Args:   cmd.Args,
		Env:    cmd.Env,
		Filter: defaultSockFilter,
	}

	cmd.Path = "/proc/self/exe" // XXX: os.Executable()?
	cmd.Args = []string{"__sandbox_child"}
	cmd.ExtraFiles = []*os.File{cf}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	err = cmd.Cmd.Start()
	cf.Close()
	if err != nil {
		return err
	}

	err = sendConfig(sp[0], &cfg)
	if err != nil {
		return cmd.childFailed(err)
	}

	fd, err := recvFd(sp[0])
	if err != nil {
		return cmd.childFailed(err)
	}

	cmd.waitCh = make(chan error, 2)
	go func() {
		err := listenNotif(fd, pipe[0], cmd.Handler)
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

func (cmd *Cmd) childFailed(err error) error {
	cmd.Process.Kill()
	cmd.Cmd.Wait()

	if cmd.ProcessState != nil {
		switch cmd.ProcessState.ExitCode() {
		case childBadArguments:
			return errors.New("child: bad arguments")
		case childNoNewPrivsFailed:
			return errors.New("child: setting no new privileges failed")
		case childNewListenerFailed:
			return errors.New("child: new seccomp filter failed; likely because there is an " +
				"existing filter")
		case childSendmsgFailed:
			return errors.New("child: sending listener fd to sandbox failed")
		case childRecvConfigFailed:
			return errors.New("child: receiving config from sandbox failed")
		case childExecCommandFailed:
			return errors.New("child: executing command failed")
		}
	}

	return err
}

func (cmd *Cmd) Wait() error {
	err := <-cmd.waitCh

	unix.Close(cmd.closeFd)

	pid := cmd.Process.Pid
	syscall.Kill(-pid, syscall.SIGTERM)
	go func() {
		time.Sleep(time.Second)
		syscall.Kill(-pid, syscall.SIGKILL)
	}()

	return err
}
