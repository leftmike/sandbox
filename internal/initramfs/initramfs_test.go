package initramfs

import (
	"bytes"
	"strings"
	"testing"
)

func TestWriteCPIO(t *testing.T) {
	agent := []byte("\x7fELF fake agent payload")

	var buf bytes.Buffer
	if err := WriteCPIO(&buf, agent); err != nil {
		t.Fatalf("WriteCPIO: %v", err)
	}
	out := buf.Bytes()

	// Every newc entry begins with the magic "070701".
	if !bytes.HasPrefix(out, []byte("070701")) {
		t.Fatalf("archive does not start with newc magic")
	}
	// The init entry name and the agent payload must be present.
	if !bytes.Contains(out, []byte("init")) {
		t.Errorf("archive missing init entry name")
	}
	if !bytes.Contains(out, agent) {
		t.Errorf("archive missing agent payload")
	}
	// The archive must end with the standard trailer entry.
	if !strings.Contains(string(out), "TRAILER!!!") {
		t.Errorf("archive missing TRAILER!!!")
	}
	// Total length must be 4-byte aligned (every entry is padded).
	if len(out)%4 != 0 {
		t.Errorf("archive length %d not 4-byte aligned", len(out))
	}
}
