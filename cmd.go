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
	Open(pid uint32, sysnum int, pathname string, flags int32, mode uint32, resolve uint64) bool
	Syscall(pid uint32, sysnum int) bool
}

type Cmd struct {
	exec.Cmd

	Handler      Handler
	AllowedExecs []string // if non-nil, only these absolute paths may be executed
	BindMounts   []string // additional paths to bind-mount into the sandbox root

	// DynamicAllowedExecs lets the Handler decide allow/deny on each execve at
	// runtime; the listener bind-mounts the executable into the sandbox root on
	// allow, before the kernel resumes the syscall.  AllowedExecs is then ignored
	// as a static allowlist (Handler.Exec is the source of truth).
	DynamicAllowedExecs bool

	closeFd     int
	waitCh      chan error
	mountWorker *mountWorker
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

	// In dynamic mode the child forks a mount helper that lives in the new
	// namespaces and serves bind-mount requests over a SOCK_SEQPACKET socket.
	// The parent keeps mountSp[0]; mountSp[1] is passed to the sandbox child
	// (which forwards it on to the helper via fork+exec).
	var mountSp [2]int = [2]int{-1, -1}
	var mountCF *os.File
	if cmd.DynamicAllowedExecs {
		mountSp, err = unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return err
		}
		defer func() {
			if err != nil && mountSp[0] >= 0 {
				unix.Close(mountSp[0])
			}
		}()
		mountCF = os.NewFile(uintptr(mountSp[1]), "mount-helper-pass")
	}

	if cmd.Env == nil {
		cmd.Env = os.Environ()
	}

	cmd.Args[0] = cmd.Path
	cfg := childConfig{
		Path:                cmd.Path,
		Args:                cmd.Args,
		Env:                 cmd.Env,
		Filter:              defaultSockFilter,
		AllowedExecs:        cmd.AllowedExecs,
		BindMounts:          cmd.BindMounts,
		DynamicAllowedExecs: cmd.DynamicAllowedExecs,
	}

	cmd.Path = path
	cmd.Args = []string{"__sandbox_child"}
	cmd.ExtraFiles = []*os.File{cf}
	if mountCF != nil {
		cmd.ExtraFiles = append(cmd.ExtraFiles, mountCF)
	}

	// When AllowedExecs is set or dynamic mode is on, fork the child directly into
	// new user+mount namespaces.  The Go runtime is multi-threaded so
	// unshare(CLONE_NEWUSER) from within the child would fail with EINVAL; using
	// Cloneflags on the fork avoids that limitation.  UidMappings/GidMappings are
	// written by Go's runtime immediately after the fork, before exec(), so the
	// child has the correct capability set when it starts.
	needNS := len(cmd.AllowedExecs) > 0 || cmd.DynamicAllowedExecs
	attr := &syscall.SysProcAttr{Setpgid: true}
	if needNS {
		uid := os.Getuid()
		gid := os.Getgid()
		attr.Cloneflags = unix.CLONE_NEWUSER | unix.CLONE_NEWNS
		attr.UidMappings = []syscall.SysProcIDMap{{ContainerID: uid, HostID: uid, Size: 1}}
		attr.GidMappings = []syscall.SysProcIDMap{{ContainerID: gid, HostID: gid, Size: 1}}
	}
	cmd.SysProcAttr = attr

	err = cmd.Cmd.Start()
	cf.Close()
	if mountCF != nil {
		mountCF.Close()
	}
	if err != nil {
		return err
	}

	if cmd.DynamicAllowedExecs {
		cmd.mountWorker = newMountWorker(mountSp[0])
		mountSp[0] = -1 // ownership transferred
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
		err := listenNotif(fd, pipe[0], cmd.Handler, cmd.AllowedExecs, cmd.mountWorker)
		if err != nil {
			cmd.waitCh <- err
		}

		unix.Close(fd)
		unix.Close(pipe[0])
		if cmd.mountWorker != nil {
			cmd.mountWorker.Stop()
		}
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
		case childMountFailed:
			return errors.New("child: setting up mount namespace failed")
		case childPivotRootFailed:
			return errors.New("child: pivot_root failed")
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
