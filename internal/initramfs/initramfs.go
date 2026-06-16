// Package initramfs builds a minimal initramfs (newc cpio) containing the static
// guest agent as /init. It is used by the sandbox VM driver to boot a guest that
// can run an arbitrary host binary exported over 9p/virtiofs.
//
// On-demand building requires the Go toolchain and this module's source; for
// deployment, build the image once (see cmd/mkguest) and pass it via
// VMConfig.InitramfsPath.
package initramfs

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
)

const guestPkg = "github.com/leftmike/sandbox/internal/guest"

var (
	defaultOnce sync.Once
	defaultPath string
	defaultErr  error
)

// Default returns a path to a cached initramfs, building it once per process.
func Default() (string, error) {
	defaultOnce.Do(func() {
		out := filepath.Join(os.TempDir(),
			fmt.Sprintf("sandbox-guest-initramfs-%s.cpio", runtime.GOARCH))
		if err := Build(out); err != nil {
			defaultErr = err
			return
		}
		defaultPath = out
	})
	return defaultPath, defaultErr
}

// Build compiles the guest agent (static, CGO-free) and writes an initramfs cpio
// containing it as /init to outPath.
func Build(outPath string) error {
	tmp, err := os.MkdirTemp("", "sandbox-mkguest")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)

	agent := filepath.Join(tmp, "agent")
	build := exec.Command("go", "build", "-trimpath", "-ldflags=-s -w", "-o", agent, guestPkg)
	build.Env = append(os.Environ(),
		"CGO_ENABLED=0",
		"GOOS=linux",
		"GOARCH="+runtime.GOARCH,
	)
	if out, err := build.CombinedOutput(); err != nil {
		return fmt.Errorf("build guest agent: %v: %s", err, out)
	}

	data, err := os.ReadFile(agent)
	if err != nil {
		return err
	}

	f, err := os.Create(outPath)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	if err := WriteCPIO(w, data); err != nil {
		f.Close()
		return err
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// WriteCPIO writes a newc-format cpio archive with a single executable entry,
// /init, holding agent, followed by the standard trailer.
func WriteCPIO(w io.Writer, agent []byte) error {
	if err := writeEntry(w, "init", 0o100755, 1, agent); err != nil {
		return err
	}
	return writeEntry(w, "TRAILER!!!", 0, 2, nil)
}

func writeEntry(w io.Writer, name string, mode, ino uint32, data []byte) error {
	namesize := len(name) + 1 // include trailing NUL
	hdr := fmt.Sprintf("070701%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
		ino,       // c_ino
		mode,      // c_mode
		0,         // c_uid
		0,         // c_gid
		1,         // c_nlink
		0,         // c_mtime
		len(data), // c_filesize
		0,         // c_devmajor
		0,         // c_devminor
		0,         // c_rdevmajor
		0,         // c_rdevminor
		namesize,  // c_namesize
		0,         // c_check
	)
	if _, err := io.WriteString(w, hdr); err != nil {
		return err
	}
	if _, err := io.WriteString(w, name); err != nil {
		return err
	}
	if _, err := w.Write([]byte{0}); err != nil {
		return err
	}
	// Pad (header + name) to a 4-byte boundary.
	if err := pad(w, len(hdr)+namesize); err != nil {
		return err
	}
	if len(data) > 0 {
		if _, err := w.Write(data); err != nil {
			return err
		}
		if err := pad(w, len(data)); err != nil {
			return err
		}
	}
	return nil
}

func pad(w io.Writer, n int) error {
	if r := n % 4; r != 0 {
		_, err := w.Write(make([]byte, 4-r))
		return err
	}
	return nil
}
