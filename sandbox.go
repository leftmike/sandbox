package sandbox

import (
	"strings"

	"golang.org/x/sys/unix"
)

type Mode int

const (
	SeccompMode Mode = iota
	LandlockMode
)

type Sandbox struct {
	Clone func(pid uint32, sysnum int, flags uint64) bool
	Exec  func(pid uint32, sysnum int, pathname string, argv []string, env []string) bool
	Open  func(pid uint32, sysnum int, pathname string, flags int32, mode uint32,
		resolve uint64) bool
	OpenFailed func(pid uint32, sysnum int, pathname string, err error)
	Syscall    func(pid uint32, sysnum int) bool
	Failed     func(pid uint32, sysnum int, err error)

	Mode   Mode
	Filter map[string]FilterConfig
	FSP    *FSPolicy
}

// FSPolicy declares allow lists for read, write, and execute filesystem access. Each
// slice lists paths (files or directories) granted the corresponding access. All paths
// not covered are denied access.
type FSPolicy struct {
	Read    []string // read-only access
	Write   []string // read-write access (create, remove, truncate, ...)
	Execute []string // execute (and read) access

	read  []string
	write []string
}

func appendSlash(slashed, paths []string) []string {
	for _, path := range paths {
		if strings.HasSuffix(path, "/") {
			slashed = append(slashed, path)
		} else {
			slashed = append(slashed, path+"/")
		}
	}

	return slashed
}

func pathsAllows(path string, paths []string) bool {
	path += "/"
	for _, base := range paths {
		if strings.HasPrefix(path, base) {
			return true
		}
	}

	return false
}

func (fsp *FSPolicy) fsAllows(path string, flags uint64) bool {
	if (len(fsp.Read) > 0 || len(fsp.Write) > 0 || len(fsp.Execute) > 0) && len(fsp.write) == 0 {
		fsp.read = appendSlash(appendSlash(appendSlash([]string{}, fsp.Read), fsp.Execute),
			fsp.Write)
	}
	if len(fsp.Write) > 0 && len(fsp.write) == 0 {
		fsp.write = appendSlash([]string{}, fsp.Write)
	}

	if flags&unix.O_ACCMODE != unix.O_RDONLY || flags&(unix.O_CREAT|unix.O_TRUNC) != 0 {
		return pathsAllows(path, fsp.write)
	}

	return pathsAllows(path, fsp.read)
}

func DefaultFSPolicy() *FSPolicy {
	return &FSPolicy{
		// Executables and shared libraries. Library directories need execute
		// access too: landlock requires LANDLOCK_ACCESS_FS_EXECUTE to mmap a
		// shared object with PROT_EXEC, which the dynamic loader does.
		Execute: []string{
			"/bin", "/sbin", "/usr",
			"/lib", "/lib32", "/lib64", "/libx32",
		},
		// Configuration and read-only runtime state (e.g. /etc/passwd,
		// /etc/ssl, /etc/resolv.conf, /proc/self/..., NSS data under /run).
		Read: []string{
			"/etc", "/opt", "/proc", "/sys", "/run", "/var",
		},
		// Scratch space. /dev is included so common device nodes such as
		// /dev/null, /dev/zero, and /dev/urandom can be written as well as read.
		Write: []string{
			"/tmp", "/var/tmp", "/dev",
		},
	}
}
