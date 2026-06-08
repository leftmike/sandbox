package sandbox

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestSandboxLandlockNil(t *testing.T) {
	sb := &Sandbox{}
	if sb.landlock() != nil {
		t.Errorf("landlock() with no FS policy = non-nil, want nil")
	}
}

func TestSandboxLandlockCompile(t *testing.T) {
	sb := &Sandbox{
		FS: &FSPolicy{
			Read:    []string{"/usr", "/lib"},
			Write:   []string{"/tmp"},
			Execute: []string{"/bin"},
		},
	}

	cfg := sb.landlock()
	if cfg == nil {
		t.Fatal("landlock() = nil, want config")
	}

	if len(cfg.Rules) != 4 {
		t.Errorf("got %d rules, want 4", len(cfg.Rules))
	}

	want := landlockReadAccess | landlockWriteAccess | landlockExecuteAccess
	if cfg.HandledAccessFS != want {
		t.Errorf("HandledAccessFS = %#x, want %#x", cfg.HandledAccessFS, want)
	}

	access := map[string]uint64{}
	for _, r := range cfg.Rules {
		access[r.Path] = r.Access
	}
	if access["/tmp"]&unix.LANDLOCK_ACCESS_FS_WRITE_FILE == 0 {
		t.Errorf("/tmp missing write access: %#x", access["/tmp"])
	}
	if access["/usr"]&unix.LANDLOCK_ACCESS_FS_WRITE_FILE != 0 {
		t.Errorf("/usr unexpectedly has write access: %#x", access["/usr"])
	}
	if access["/bin"]&unix.LANDLOCK_ACCESS_FS_EXECUTE == 0 {
		t.Errorf("/bin missing execute access: %#x", access["/bin"])
	}
}

func TestSupportedAccessFS(t *testing.T) {
	if supportedAccessFS(0) != 0 {
		t.Errorf("abi 0 should report no access")
	}
	if supportedAccessFS(1)&unix.LANDLOCK_ACCESS_FS_REFER != 0 {
		t.Errorf("abi 1 should not include REFER")
	}
	if supportedAccessFS(2)&unix.LANDLOCK_ACCESS_FS_REFER == 0 {
		t.Errorf("abi 2 should include REFER")
	}
	if supportedAccessFS(3)&unix.LANDLOCK_ACCESS_FS_TRUNCATE == 0 {
		t.Errorf("abi 3 should include TRUNCATE")
	}
}
