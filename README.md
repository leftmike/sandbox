# (Agent) Sandbox

## WSL2
In .wslconfig; [wsl2] section, networkingMode != mirrored; if it is mirrored, then
creating the seccomp listener will fail because wsl2 has already set one for the mirrored
networking mode. See: https://github.com/microsoft/WSL/issues/9548
