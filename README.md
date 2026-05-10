# (Agent) Sandbox

## WSL2
In .wslconfig; [wsl2] section, networkingMode != mirrored; if it is mirrored, then
creating the seccomp listener will fail because wsl2 has already set one for the mirrored
networking mode. See: https://github.com/microsoft/WSL/issues/9548

## Execution control (AllowedExecs)

Setting `Cmd.AllowedExecs` to a non-nil slice restricts which programs may be executed
inside the sandbox.  Two enforcement layers work together:

**Mount namespace + bind mounts** — the child enters a new user+mount namespace before
installing the seccomp filter.  A fresh tmpfs root is constructed containing only the
allowlisted executables (each bind-mounted read-only at its original absolute path) plus
a fixed set of shared-library directories and config files needed by typical dynamically
linked binaries (`mountns.go:defaultBindMounts`).  The child then `pivot_root`s into
this restricted root, making unlisted files simply invisible.

**Seccomp user notify pre-check** — the listener inspects every `execve`/`execveat`
notification before forwarding it to the `Handler`.  If the resolved pathname is not in
`AllowedExecs` the notification is denied with EACCES immediately.  This catches
`execveat(fd, "", AT_EMPTY_PATH)` on memfds and other fd-based exec paths that the mount
namespace cannot block by itself.

### Requirements

- **Unprivileged user namespaces** must be available.  On most distributions this is the
  default.  Debian-stable and some hardened kernels set
  `kernel.unprivileged_userns_clone=0`; on those hosts `Cmd.Start()` will return an
  error explaining the root cause.  AppArmor-based systems may also restrict user
  namespace creation for specific binaries.
- The `PR_SET_NO_NEW_PRIVS` flag (already set unconditionally) and the `MS_NOSUID`
  remount flag together neutralise setuid/setgid bits on bind-mounted executables.

### Shell scripts

When a script starts with a `#!` line the kernel re-execs the interpreter, which
produces a fresh `execve` notification.  The interpreter (e.g. `/bin/sh`, `/usr/bin/env`)
must therefore appear in `AllowedExecs` and will be bind-mounted into the new root
automatically.

### CLI usage

```
sandbox --allow-exec=/bin/echo /bin/echo hello
sandbox --allow-exec=/bin/sh --allow-exec=/usr/bin/env /bin/sh myscript.sh
```

Each `--allow-exec` flag adds one absolute path to `AllowedExecs`.

## Dynamic exec control (DynamicAllowedExecs)

Setting `Cmd.DynamicAllowedExecs = true` makes the allowlist runtime-decided: on
every `execve`/`execveat` notification the listener calls `Handler.Exec`, and if
the handler returns `true` a mount helper bind-mounts the executable into the
sandbox's tmpfs root before the kernel resumes the syscall.  `AllowedExecs` is
ignored as a static gate in this mode (the handler is the sole source of truth).

### How it works

The sandbox child forks an `__sandbox_mount_helper` subprocess after
`setupMountNS` but before the seccomp filter is installed.  The helper inherits
the new user+mount namespaces and therefore has `CAP_SYS_ADMIN` to perform
mounts.  The host filesystem is exposed inside the sandbox at `/run/.host` (each
top-level entry of `/` is bind-mounted there read-only — `/` itself can't be
bind-mounted in an unprivileged user namespace).  The helper resolves a request
for `/bin/echo` as `/run/.host/bin/echo`.  Communication is a textual
SOCK_SEQPACKET protocol: `MOUNT <src> <target>` ↔ `OK` / `ERR <msg>`.

### Trade-offs

- `/run/.host` is visible to the sandboxed process — it can read host file
  contents but cannot bypass exec control, since `execve("/run/.host/bin/foo")`
  hits the seccomp listener with that pathname; the handler should normalise
  paths or reject the prefix if it cares.
- `SECCOMP_USER_NOTIF_FLAG_CONTINUE` has a known TOCTOU window where the kernel
  re-reads syscall arguments after the listener responds.  A multi-threaded
  tracee with a cooperating peer thread could swap the pathname between
  resolution and resume.
- Library dependencies of the freshly-mounted executable still come from the
  static `defaultBindMounts`; if the binary needs something outside that set
  (a custom rpath, a private libdir) you must add it to `Cmd.BindMounts`.
