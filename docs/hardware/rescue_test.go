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
