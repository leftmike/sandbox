// Package vmproto defines the wire protocol shared between the sandbox host
// (package sandbox, the parent/QEMU supervisor) and the in-guest agent
// (cmd internal/guest). It is deliberately tiny and dependency-free so the guest
// agent can be built as a static, CGO-free init binary.
package vmproto

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
)

// PortAny mirrors VMADDR_PORT_ANY: ask the kernel to assign a free vsock port.
const PortAny = uint32(0xFFFFFFFF)

// CmdlineConfigKey is the kernel-cmdline key whose value is the base64 JSON of a
// GuestConfig (e.g. "sandbox.config=eyJ..."). Passing the config on the cmdline
// avoids a separate config share and matches the small JSON-over-channel
// convention used elsewhere in the project.
const CmdlineConfigKey = "sandbox.config"

// GuestConfig is handed from the host to the guest agent: a small description of
// what to run, the vsock port to dial back on, and which filesystem shares to
// mount. It is the VM analogue of the host-side childConfig.
type GuestConfig struct {
	Path string   // executable to run inside the guest (a path under the root share)
	Args []string // argv, including argv[0]
	Env  []string // environment for the executable
	Dir  string   // working directory inside the guest ("" => "/")

	Port   uint32       // vsock port the agent dials back on (host CID)
	Shares []GuestShare // filesystem shares to mount, applied in order
}

// GuestShare describes one 9p/virtiofs export the agent mounts. Tag is the QEMU
// mount_tag; MountPoint is the path inside the guest; Writable selects ro vs rw.
type GuestShare struct {
	Tag        string
	MountPoint string
	Writable   bool
}

// MarshalConfig encodes cfg as base64(JSON), suitable for a kernel cmdline value.
func MarshalConfig(cfg *GuestConfig) (string, error) {
	buf, err := json.Marshal(cfg)
	if err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(buf), nil
}

// UnmarshalConfig reverses MarshalConfig.
func UnmarshalConfig(s string) (*GuestConfig, error) {
	buf, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	var cfg GuestConfig
	if err := json.Unmarshal(buf, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Stream tags identify the logical stream a frame belongs to, multiplexed over a
// single vsock connection between host and guest.
type Stream uint8

const (
	StreamStdin  Stream = 0 // host -> guest
	StreamStdout Stream = 1 // guest -> host
	StreamStderr Stream = 2 // guest -> host
	StreamExit   Stream = 3 // guest -> host; payload is a 4-byte big-endian exit code
	StreamClose  Stream = 4 // either direction; signals EOF on the named stream
)

// maxFrame bounds a single frame payload to keep readers from allocating
// unbounded buffers on a malformed length.
const maxFrame = 1 << 20

// WriteFrame writes a single length-prefixed frame: [tag:1][len:4 BE][payload].
func WriteFrame(w io.Writer, tag Stream, payload []byte) error {
	if len(payload) > maxFrame {
		return errors.New("vmproto: frame too large")
	}
	var hdr [5]byte
	hdr[0] = byte(tag)
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	_, err := w.Write(payload)
	return err
}

// ReadFrame reads a single frame written by WriteFrame.
func ReadFrame(r io.Reader) (Stream, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[1:])
	if n > maxFrame {
		return 0, nil, errors.New("vmproto: frame too large")
	}
	if n == 0 {
		return Stream(hdr[0]), nil, nil
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, nil, err
	}
	return Stream(hdr[0]), buf, nil
}

// ExitPayload encodes an exit code as a StreamExit frame payload.
func ExitPayload(code int) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(int32(code)))
	return b[:]
}

// ParseExit decodes a StreamExit frame payload.
func ParseExit(payload []byte) (int, error) {
	if len(payload) != 4 {
		return 0, errors.New("vmproto: bad exit payload")
	}
	return int(int32(binary.BigEndian.Uint32(payload))), nil
}
