package main

import (
	"errors"
	"io"
	"os"
	"os/exec"

	"golang.org/x/sys/unix"

	"github.com/leftmike/sandbox/seccomp"
)

type SysCallHandler func(fd int, notif *seccomp.Notif) bool

func Run(cmdArgs []string, stdin io.Reader, stdout, stderr io.Writer, sch SysCallHandler) (int,
	error) {

	sp, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}

	pf := os.NewFile(uintptr(sp[0]), "sandbox")
	defer pf.Close()

	cf := os.NewFile(uintptr(sp[1]), "child")

	cmd := exec.Command("child/child")
	cmd.Args = append([]string{"child/child"}, cmdArgs...)
	cmd.ExtraFiles = []*os.File{cf}
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	err = cmd.Start()
	cf.Close()
	if err != nil {
		// XXX: check the error code and return code from the child
		// XXX: informative error message if Seccomp filter already set (on WSL2)
		return 0, err
	}

	fd, err := recvFd(pf)
	if err != nil {
		// XXX
		cmd.Process.Kill()
		cmd.Wait()
		return 0, err
	}

	go func() {
		// XXX: handle the error from cmd.Wait()
		cmd.Wait()
		unix.Close(fd)
	}()

	listen(fd, sch)
	return 0, nil
	/*
		// Run supervisor in background; it exits when the child dies and the kernel
		// closes the listener fd (RECV returns ENOENT).
		supErrCh := make(chan error, 1)
		go func() {
			supErrCh <- supervise(listenerFd, sch)
		}()

		waitErr := cmd.Wait()
		unix.Close(listenerFd) // wake supervisor if still blocked on RECV
		supErr := <-supErrCh

		code := 0
		if waitErr != nil {
			if exitErr, ok := waitErr.(*exec.ExitError); ok {
				code = exitErr.ExitCode()
			} else {
				return 0, fmt.Errorf("sandbox: wait: %w", waitErr)
			}
		}
		if supErr != nil {
			return code, supErr
		}
		return code, nil
	*/
}

func recvmsg(f *os.File, buf []byte) ([]byte, error) {
	sc, err := f.SyscallConn()
	if err != nil {
		return nil, err
	}

	var n int
	var rerr error
	err = sc.Read(func(fd uintptr) bool {
		_, n, _, _, rerr = unix.Recvmsg(int(fd), make([]byte, 1), buf, 0)
		return rerr != unix.EAGAIN && rerr != unix.EWOULDBLOCK
	})
	if err != nil {
		return nil, err
	} else if rerr != nil {
		return nil, rerr
	}

	return buf[:n], nil
}

func recvFd(f *os.File) (int, error) {
	buf, err := recvmsg(f, make([]byte, unix.CmsgSpace(4)))
	if err != nil {
		return -1, err
	}
	msgs, err := unix.ParseSocketControlMessage(buf)
	if err != nil {
		return -1, err
	}
	for _, msg := range msgs {
		if msg.Header.Level == unix.SOL_SOCKET && msg.Header.Type == unix.SCM_RIGHTS {
			fds, err := unix.ParseUnixRights(&msg)
			if err != nil {
				return -1, err
			} else if len(fds) > 0 {
				return fds[0], nil
			}
		}
	}
	return -1, errors.New("sandbox: no fd from child")
}

func listen(fd int, sch SysCallHandler) error {
	for {
		notif, err := seccomp.IoctlNotifRecv(fd)
		if err != nil || notif == nil {
			return err
		}

		allowed := sch(fd, notif)

		rsp := seccomp.NotifResp{ID: notif.ID}
		if allowed {
			rsp.Flags = unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
		} else {
			rsp.Error = -int32(unix.EACCES)
		}

		err = seccomp.IoctlNotifSend(fd, rsp)
		if err != nil {
			return err
		}
	}
}
