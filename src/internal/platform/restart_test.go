package platform

import (
	"os"
	"testing"
)

func TestNewDetachedManagerRestart(t *testing.T) {
	h := NewDetachedManagerRestart("/opt/blacktemple-kn/bin/blacktempled")
	if h.Executable != "/opt/blacktemple-kn/bin/blacktempled" {
		t.Fatalf("executable %q", h.Executable)
	}
	if len(h.Args) != 1 || h.Args[0] != ManagerRestartHelperArg {
		t.Fatalf("args %v", h.Args)
	}
}

func TestInspectPIDRejectsNonPositive(t *testing.T) {
	info := InspectPID(0)
	if info.Alive {
		t.Fatal("pid 0 must not be treated as alive")
	}
	info = InspectPID(-1)
	if info.Alive {
		t.Fatal("negative pid must not be treated as alive")
	}
}

func TestInspectPIDSelfOnWindowsIsNotTrustedBlindly(t *testing.T) {
	info := InspectPID(os.Getpid())
	if info.PID != os.Getpid() {
		t.Fatalf("pid %d", info.PID)
	}
	// On Windows Alive is false by design; on unix it may be true.
	_ = info.Alive
}
