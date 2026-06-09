package sandbox

type Sandbox struct {
	Clone      func(pid uint32, sysnum int, flags uint64) bool
	Exec       func(pid uint32, sysnum int, pathname string, argv []string, env []string) bool
	Open       func(pid uint32, sysnum int, pathname string, flags int32, mode uint32,
		resolve uint64) bool
	OpenFailed func(pid uint32, sysnum int, pathname string, err error)
	Syscall    func(pid uint32, sysnum int) bool
	Failed     func(pid uint32, sysnum int, err error)
}
