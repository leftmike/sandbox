# (Agent) Sandbox

## Sandbox object

A `Sandbox` owns the policy for a sandboxed command: the syscall event handler
funcs (`Clone`, `Exec`, `Open`, ...), the seccomp `Filter`, and an optional
landlock filesystem policy (`FS`). Each handler is optional (a nil handler means
allow). Assign it to `Cmd.Sandbox` before starting:

```go
cmd := sandbox.Command("/bin/cat", "/etc/hostname")
cmd.Sandbox = &sandbox.Sandbox{
    Open: func(pid uint32, sysnum int, pathname string, flags int32,
        mode uint32, resolve uint64) bool {
        return true
    },
    FS: &sandbox.FSPolicy{
        Read:    []string{"/usr", "/lib", "/etc"},
        Execute: []string{"/bin", "/usr/bin"},
    },
}
err := cmd.Run()
```

Filesystem access is locked down with two complementary layers:

- **landlock** (`FS *FSPolicy`) — a coarse allow-list of paths enforced by the
  kernel as a hard boundary, applied in the child before `exec`.
- **seccomp** — the existing `openat`/`openat2` user-notification handler refines
  per-open decisions within that boundary.

`sandbox.DefaultFSPolicy()` returns a reasonable allow-list for running typical
dynamically-linked programs: the system binary and library trees are
executable/readable, common config and runtime locations are read-only, and only
scratch space (`/tmp`, `/var/tmp`, `/dev`) is writable. Listed paths that do not
exist on the host are ignored, so it is portable across distributions. It is not
applied automatically — assign it when you want filesystem lockdown:

```go
cmd.Sandbox = &sandbox.Sandbox{FS: sandbox.DefaultFSPolicy()}
```

Network access control is not implemented yet; it will follow the same split
(landlock `Access_net` plus seccomp interception of `socket`/`connect`/`bind`).

### Landlock availability

`FSPolicy` requires a kernel with landlock enabled (Linux >= 5.13; the access
rights actually applied are clamped to the kernel's landlock ABI). Use
`sandbox.LandlockAvailable()` to check. Setting an `FSPolicy` on a kernel without
landlock makes the command fail to start.

### setuid executables

The child sets `PR_SET_NO_NEW_PRIVS`, so the kernel ignores the setuid/setgid
bits when executing — a setuid binary runs with the caller's privileges and
cannot elevate. Actively denying exec of setuid binaries can be layered on top via
the Sandbox's `Exec` handler, which can stat the target and reject
`S_ISUID`/`S_ISGID` files.

## WSL2
In .wslconfig; [wsl2] section, networkingMode != mirrored; if it is mirrored, then
creating the seccomp listener will fail because wsl2 has already set one for the mirrored
networking mode. See: https://github.com/microsoft/WSL/issues/9548
