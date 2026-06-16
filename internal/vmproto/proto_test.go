package vmproto

import (
	"bytes"
	"slices"
	"testing"
)

func TestConfigRoundTrip(t *testing.T) {
	cfg := &GuestConfig{
		Path:   "/bin/echo",
		Args:   []string{"/bin/echo", "hello", "world"},
		Env:    []string{"FOO=bar"},
		Dir:    "/tmp",
		Port:   1234,
		Shares: []GuestShare{{Tag: "root", MountPoint: "/", Writable: false}},
	}

	enc, err := MarshalConfig(cfg)
	if err != nil {
		t.Fatalf("MarshalConfig: %v", err)
	}
	got, err := UnmarshalConfig(enc)
	if err != nil {
		t.Fatalf("UnmarshalConfig: %v", err)
	}
	if got.Path != cfg.Path || got.Port != cfg.Port || got.Dir != cfg.Dir {
		t.Errorf("round trip scalars mismatch: %+v", got)
	}
	if !slices.Equal(got.Args, cfg.Args) || !slices.Equal(got.Env, cfg.Env) {
		t.Errorf("round trip slices mismatch: %+v", got)
	}
	if len(got.Shares) != 1 || got.Shares[0].Tag != "root" {
		t.Errorf("round trip shares mismatch: %+v", got.Shares)
	}
}

func TestFrameRoundTrip(t *testing.T) {
	cases := []struct {
		tag     Stream
		payload []byte
	}{
		{StreamStdout, []byte("hello")},
		{StreamStderr, []byte("")},
		{StreamStdin, bytes.Repeat([]byte("x"), 4096)},
		{StreamExit, ExitPayload(3)},
		{StreamClose, []byte{byte(StreamStdin)}},
	}

	var buf bytes.Buffer
	for _, c := range cases {
		if err := WriteFrame(&buf, c.tag, c.payload); err != nil {
			t.Fatalf("WriteFrame(%d): %v", c.tag, err)
		}
	}
	for i, c := range cases {
		tag, payload, err := ReadFrame(&buf)
		if err != nil {
			t.Fatalf("ReadFrame %d: %v", i, err)
		}
		if tag != c.tag || !bytes.Equal(payload, c.payload) {
			t.Errorf("frame %d = (%d,%q), want (%d,%q)", i, tag, payload, c.tag, c.payload)
		}
	}
}

func TestExitPayload(t *testing.T) {
	for _, code := range []int{0, 1, 7, 255} {
		got, err := ParseExit(ExitPayload(code))
		if err != nil {
			t.Fatalf("ParseExit(%d): %v", code, err)
		}
		if got != code {
			t.Errorf("ParseExit round trip = %d, want %d", got, code)
		}
	}
	if _, err := ParseExit([]byte{1, 2}); err == nil {
		t.Error("ParseExit(short) = nil error, want error")
	}
}
