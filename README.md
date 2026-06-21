# (Agent) Sandbox

## Isolation modes

By default a `Cmd` isolates the target with in-kernel seccomp + Landlock
(`Sandbox.Mode == ModeSeccomp`).

`ModeVM` is an opt-in tier that runs the command inside a KVM micro-VM for
hardware-level isolation, driven by a `qemu-system-*` binary (no libvirt, no cgo):

```go
cmd := sandbox.Command("/bin/echo", "hello")
cmd.Sandbox = &sandbox.Sandbox{
    Mode: sandbox.ModeVM,
    VM:   &sandbox.VMConfig{ShareRootRO: true},
}
out, err := cmd.Output()
```

or from the CLI: `sandbox -vm /bin/echo hello`.

How it works: the host kernel (`/boot/vmlinuz-$(uname -r)`) boots a tiny static
guest agent as `/init` (see `internal/guest`, packed into an initramfs by
`cmd/mkguest`). The host root filesystem is exported read-only over 9p/virtiofs so
an arbitrary host binary and its libraries resolve inside the guest; the agent
runs the command chrooted into that share and relays stdin/stdout/stderr and the
exit code back to the host over `vsock`. `FSPolicy` degrades to mount scope in a
VM: `Write` roots become writable shares, `Read`/`Execute` become read-only, and
unexported paths are simply absent.

On amd64 the guest boots QEMU's minimal `microvm` machine when the host QEMU
supports it (faster boot, virtio-mmio devices), falling back to `q35`; set
`VMConfig.Machine` to force a machine type (e.g. `"q35"`).

Requirements: `/dev/kvm` (typically the `kvm` group, not root), a
`qemu-system-$arch` binary, and a host kernel with virtio-9p/-fs and vsock (stock
distro kernels qualify). Tests that need a VM skip cleanly when `/dev/kvm` is
absent.

## WSL2
In .wslconfig; [wsl2] section, networkingMode != mirrored; if it is mirrored, then
creating the seccomp listener will fail because wsl2 has already set one for the mirrored
networking mode. See: https://github.com/microsoft/WSL/issues/9548
