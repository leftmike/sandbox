package sandbox

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

type Cmd struct {
	exec.Cmd

	Sandbox *Sandbox

	closeFd int
	waitCh  chan error
	vm      *vmRun
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

// applyDefaults fills in the Sandbox and its policies, shared by every mode.
func (cmd *Cmd) applyDefaults() {
	if cmd.Sandbox == nil {
		cmd.Sandbox = &Sandbox{}
	}
	if cmd.Sandbox.Filter == nil {
		cmd.Sandbox.Filter = DefaultFilterConfig()
	}
	if cmd.Sandbox.FS == nil {
		cmd.Sandbox.FS = DefaultFSPolicy()
	}
}

func (cmd *Cmd) Start() error {
	cmd.applyDefaults()
	if cmd.Sandbox.Mode == ModeVM {
		return cmd.startVM()
	}
	return cmd.startSeccomp()
}

// startSeccomp is the default isolation tier: re-exec self as a child that applies
// seccomp + Landlock, supervised by the parent over a seccomp user notification.
func (cmd *Cmd) startSeccomp() (err error) {
	path, err := os.Executable()
	if err != nil {
		return err
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
		Path:        cmd.Path,
		Args:        cmd.Args,
		Env:         cmd.Env,
		Filter:      makeSockFilter(cmd.Sandbox.Filter),
		WriteAccess: landlockWriteAccess,
	}

	if !cmd.Sandbox.NoLandlock {
		if !LandlockSupported {
			return errors.New("landlock not supported by kernel")
		}

		cfg.FS = cmd.Sandbox.FS
	}

	cmd.Path = path
	cmd.Args = []string{sandboxChildArg0}
	cmd.ExtraFiles = []*os.File{cf}

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
		/*
			Cloneflags:  unix.CLONE_NEWUSER | unix.CLONE_NEWNS,
			UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: unix.Getuid(), Size: 1}},
			GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: unix.Getgid(), Size: 1}},
		*/
	}

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
		err := cmd.listenNotif(fd, pipe[0])
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
		case childLandlockFailed:
			return errors.New("child: landlock failed")
		}
	}

	return err
}

func (cmd *Cmd) Wait() error {
	if cmd.vm != nil {
		return cmd.waitVM()
	}

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
