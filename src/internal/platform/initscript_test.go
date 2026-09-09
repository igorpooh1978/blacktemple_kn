package platform

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitScriptFailClosedAndEntware(t *testing.T) {
	p := filepath.Join("..", "..", "..", "packaging", "init", "S99blacktemple-kn")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if !strings.HasPrefix(text, "#!/bin/sh") {
		t.Fatal("expected POSIX sh shebang")
	}
	if bytes.Contains(b, []byte("0.0.0.0")) {
		t.Fatal("init must not mention all-interfaces listen")
	}
	if bytes.Contains(b, []byte("iptables")) || bytes.Contains(b, []byte("ip6tables")) || bytes.Contains(b, []byte("nft ")) {
		t.Fatal("init must not touch firewall")
	}
	if bytes.Contains(b, []byte("systemctl")) || bytes.Contains(b, []byte("[Unit]")) {
		t.Fatal("init must not be a systemd unit")
	}
	for _, cmd := range []string{"start)", "stop)", "restart)", "status)", "reload)"} {
		if !strings.Contains(text, cmd) {
			t.Fatalf("missing command %s", cmd)
		}
	}
	if !strings.Contains(text, "/opt/etc/init.d/rc.func") {
		t.Fatal("must use rc.func when present")
	}
	if !strings.Contains(text, "-listen-mode auto-lan") {
		t.Fatal("init must bind HTTP via auto-lan (LAN DHCP/br0), not loopback-only")
	}
	if !strings.Contains(text, "127.0.0.1:7480") {
		t.Fatal("auto-lan fallback port/host must remain loopback when br0 is missing")
	}
	if !strings.Contains(text, "do_start") || !strings.Contains(text, "do_stop") {
		t.Fatal("fallback start/stop missing")
	}
	if !strings.Contains(text, "wait_network_ready") {
		t.Fatal("start must wait for network-ready conditions")
	}
	calls := strings.Count(text, "wait_network_ready ||")
	if calls != 1 {
		t.Fatalf("exactly one wait_network_ready invocation, got %d", calls)
	}
	if strings.Contains(text, "sleep 30") {
		t.Fatal("must not use a fixed sleep 30 as the only wait")
	}
}

func TestInitScriptAutoLANBind(t *testing.T) {
	p := filepath.Join("..", "..", "..", "packaging", "init", "S99blacktemple-kn")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if !strings.Contains(text, "-listen-mode auto-lan") {
		t.Fatal("S99 must start with -listen-mode auto-lan")
	}
	if bytes.Contains(b, []byte("0.0.0.0")) {
		t.Fatal("init must not bind all interfaces")
	}
	if strings.Contains(text, "ARGS=\"-listen 127.0.0.1:7480\"") && !strings.Contains(text, "auto-lan") {
		t.Fatal("loopback-only ARGS leaves the UI unreachable from LAN")
	}
}

func TestInitScriptAbsoluteDataDir(t *testing.T) {
	p := filepath.Join("..", "..", "..", "packaging", "init", "S99blacktemple-kn")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if !strings.Contains(text, `-data-dir /opt/blacktemple-kn/data`) {
		t.Fatal("init must pass absolute -data-dir /opt/blacktemple-kn/data")
	}
	if !strings.Contains(text, `"$PREFIX/data"`) {
		t.Fatal("init must create the canonical data directory")
	}
}

func TestInitCleansCaptureBeforeStop(t *testing.T) {
	p := filepath.Join("..", "..", "..", "packaging", "init", "S99blacktemple-kn")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	idxStop := strings.Index(text, `"$BIN" netfilter-reconcile stop`)
	if idxStop < 0 {
		t.Fatal("stop must invoke netfilter-reconcile stop while manager exists")
	}
	idxRc := strings.Index(text, ". /opt/etc/init.d/rc.func")
	if idxRc < 0 {
		t.Fatal("init must source rc.func")
	}
	if idxStop > idxRc {
		t.Fatal("capture cleanup must run before rc.func stop")
	}
	if strings.Contains(text, "iptables") {
		t.Fatal("init must not contain iptables; manager CLI owns cleanup")
	}
}
