//go:build amd64 && linux

package sandbox

import (
	"testing"
)

func TestDefaultFilterConfigNamesKnown(t *testing.T) {
	for name := range DefaultFilterConfig() {
		if _, ok := syscalls[name]; !ok {
			t.Errorf("default filter config: unknown syscall name %s", name)
		}
	}
}
