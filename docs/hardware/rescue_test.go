package hardware_test

import (
	"strings"
	"testing"
)

func readRescueScript(t *testing.T) string {
	t.Helper()
	return readRepoFile(t, "scripts", "btkn-rescue.sh")
}

func TestRescueArmWatchDisarm(t *testing.T) {
	s := readRescueScript(t)
	if !strings.HasPrefix(s, "#!/bin/sh") {
		t.Fatal("rescue shebang")
	}
	if strings.Contains(s, "\r") {
		t.Fatal("rescue must be LF-only")
	}
	for _, tok := range []string{"arm)", "watch)", "disarm)", "recover)"} {
		if !strings.Contains(s, tok) {
			t.Fatalf("missing %s", tok)
		}
	}
}

func TestRescueCleanupBTKNOnly(t *testing.T) {
	s := readRescueScript(t)
	for _, tok := range []string{
		"BTKN_PRE",
		"BTKN_TCP",
		"BTKN_UDP",
		"btkn_clients_v4",
		"0x42544b4e",
		"4254",
		"/opt/blacktemple-kn/bin/xray",
	} {
		if !strings.Contains(s, tok) {
			t.Fatalf("recover must name owned object %s", tok)
		}
	}
}

func TestRescueNeverTouchesXKeenNamespace(t *testing.T) {
	s := readRescueScript(t)
	forbidden := []string{
		"killall",
		"pkill",
		"iptables -F\n",
		"iptables -t nat -F\n",
		"ip rule flush",
		"ip route flush",
		"rmmod",
		"reboot",
		"-j xkeen",
		"S05xkeen stop",
	}
	for _, tok := range forbidden {
		if strings.Contains(s, tok) {
			t.Fatalf("rescue contains forbidden %q", tok)
		}
	}
	if !strings.Contains(s, "S05xkeen") || !strings.Contains(s, "start") {
		t.Fatal("rescue must restore XKeen via S05xkeen start")
	}
}

func TestStaleRescueWatcherCannotRecoverNewerRun(t *testing.T) {
	s := readRescueScript(t)
	if strings.Contains(s, `ARMED="$RUN/btkn-rescue.armed"`) && strings.Contains(s, `DISARM="$RUN/btkn-rescue.disarm"`) {
		t.Fatal("global armed/disarm files let watcher A recover after run B arms")
	}
	if !strings.Contains(s, "btkn-rescue.current") {
		t.Fatal("rescue must persist a current run token")
	}
	if !strings.Contains(s, "rescue_stale") {
		t.Fatal("stale watcher must exit as rescue_stale instead of recover")
	}
}

func TestDisarmBDoesNotControlRunA(t *testing.T) {
	s := readRescueScript(t)
	if !strings.Contains(s, "disarm)") {
		t.Fatal("missing disarm")
	}
	if strings.Contains(s, `echo "disarm" > "$DISARM"`) && strings.Contains(s, `rm -f "$ARMED"`) {
		t.Fatal("global disarm must not control every run")
	}
	if !strings.Contains(s, "btkn-rescue.") || !strings.Contains(s, ".disarm") {
		t.Fatal("disarm must be per run_id")
	}
}

func TestRecoverRequiresCurrentToken(t *testing.T) {
	s := readRescueScript(t)
	idx := strings.Index(s, "cmd_recover()")
	if idx < 0 {
		t.Fatal("cmd_recover missing")
	}
	body := s[idx:]
	if end := strings.Index(body, "\ncmd_"); end > 0 {
		body = body[:end]
	}
	if !strings.Contains(body, "read_current") {
		t.Fatal("recover must reread the current token")
	}
	if !strings.Contains(body, "rescue_stale") {
		t.Fatal("recover must skip when token mismatches")
	}
	if strings.Index(body, "read_current") > strings.Index(body, "detach_jump") && strings.Contains(body, "detach_jump") {
		t.Fatal("token check must run before BTKN mutation")
	}
}

func TestRescueSkipsXKeenStartWhenHealthy(t *testing.T) {
	s := readRescueScript(t)
	if !strings.Contains(s, "rescue_xkeen=ALREADY_HEALTHY") {
		t.Fatal("healthy XKeen must be reported ALREADY_HEALTHY")
	}
	idx := strings.Index(s, "restore_xkeen()")
	if idx < 0 {
		t.Fatal("restore_xkeen missing")
	}
	body := s[idx:]
	if end := strings.Index(body, "\ncmd_"); end > 0 {
		body = body[:end]
	}
	startIdx := strings.Index(body, `"$XKEEN_INIT" start`)
	if startIdx < 0 {
		t.Fatal("unhealthy path must still call S05xkeen start")
	}
	healthyIdx := strings.Index(body, "ALREADY_HEALTHY")
	if healthyIdx < 0 || healthyIdx > startIdx {
		t.Fatal("ALREADY_HEALTHY must be decided before S05xkeen start")
	}
	if strings.Contains(body, `"$XKEEN_INIT" restart`) || strings.Contains(body, `"$XKEEN_INIT" stop`) {
		t.Fatal("rescue must not restart or stop XKeen")
	}
}
