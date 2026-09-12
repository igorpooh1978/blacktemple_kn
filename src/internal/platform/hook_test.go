package platform

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNDMHookPresentAndStatic(t *testing.T) {
	p := filepath.Join("..", "..", "..", "packaging", "keenetic", "netfilter.d", "blacktemple-kn.sh")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if !strings.HasPrefix(text, "#!/bin/sh") {
		t.Fatal("expected POSIX sh shebang")
	}
	if !strings.Contains(text, NetfilterHookInstalled) {
		t.Fatal("hook must document installed path")
	}
	if !strings.Contains(text, DefaultManagerPath) {
		t.Fatal("hook must use fixed manager path")
	}
	if !strings.Contains(text, NetfilterReconcileArg) {
		t.Fatal("hook must exec netfilter-reconcile")
	}
	if strings.Contains(text, "proxy.sh") {
		t.Fatal("must not generate or name XKeen proxy.sh")
	}
	if strings.Contains(text, "iptables") || strings.Contains(text, "ip6tables") || strings.Contains(text, "nft ") {
		t.Fatal("hook must not run firewall commands")
	}
	if strings.Contains(text, "$USER_INPUT") {
		t.Fatal("hook must not reference user strings")
	}
	if strings.Contains(text, "eval ") || strings.Contains(text, "eval\t") {
		t.Fatal("hook must not eval")
	}
	if strings.Contains(text, ":53") || strings.Contains(text, "swappiness") {
		t.Fatal("hook must not touch DNS :53 or swappiness")
	}
	if bytes.Contains(b, []byte("OUTPUT")) && strings.Contains(text, "-A OUTPUT") {
		t.Fatal("must not capture OUTPUT")
	}
}

func TestNDMHookNoUserStringInterpolation(t *testing.T) {
	p := filepath.Join("..", "..", "..", "packaging", "keenetic", "netfilter.d", "blacktemple-kn.sh")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	forbidden := []string{
		"$USER_INPUT",
		"${USER",
		"`",
		"$(",
		"eval",
		"$1",
		"$2",
		"$QUERY",
		"$CONFIG",
		"$BLACKKEY",
	}
	for _, tok := range forbidden {
		if strings.Contains(text, tok) {
			t.Fatalf("hook contains forbidden token %q", tok)
		}
	}
	if !strings.Contains(text, "[ -x \"$BIN\" ] || exit 0") {
		t.Fatal("manager missing must fail-open (exit 0, no capture)")
	}
}

func TestNDMHookExportsOriginEnv(t *testing.T) {
	p := filepath.Join("..", "..", "..", "packaging", "keenetic", "netfilter.d", "blacktemple-kn.sh")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if !strings.Contains(text, NDMHookEnv+"=1") {
		t.Fatal("hook must set BTKN_NDM_HOOK=1")
	}
	if !strings.Contains(text, "export "+NDMHookEnv) {
		t.Fatal("hook must export BTKN_NDM_HOOK")
	}
	if !strings.Contains(text, "exec \"$BIN\" "+NetfilterReconcileArg) {
		t.Fatal("hook must still exec netfilter-reconcile")
	}
}

func TestNDMHookExportsIPRoute2(t *testing.T) {
	p := filepath.Join("..", "..", "..", "packaging", "keenetic", "netfilter.d", "blacktemple-kn.sh")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if !strings.Contains(text, "BTKN_IPROUTE2=/opt/libexec/ip-full") {
		t.Fatal("hook must export BTKN_IPROUTE2 when ip-full exists")
	}
	if !strings.Contains(text, "export BTKN_IPROUTE2") {
		t.Fatal("hook must export BTKN_IPROUTE2")
	}
}

func TestNDMLateHookSortsAfterXKeenProxy(t *testing.T) {
	late := filepath.Base(NetfilterHookInstalledLate)
	if late <= "proxy.sh" {
		t.Fatalf("late hook %q must sort after proxy.sh", late)
	}
	p := filepath.Join("..", "..", "..", NetfilterHookSourceLate)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if !strings.HasPrefix(text, "#!/bin/sh") {
		t.Fatal("expected POSIX sh shebang")
	}
	if !strings.Contains(text, NetfilterHookInstalledLate) {
		t.Fatal("late hook must document installed path")
	}
	if !strings.Contains(text, DefaultManagerPath) {
		t.Fatal("late hook must use fixed manager path")
	}
	if !strings.Contains(text, NetfilterReconcileArg) {
		t.Fatal("late hook must exec netfilter-reconcile")
	}
	if strings.Contains(text, "iptables") || strings.Contains(text, "ip6tables") || strings.Contains(text, "nft ") {
		t.Fatal("late hook must not run firewall commands")
	}
	if strings.Contains(text, "S05xkeen") || strings.Contains(text, "/opt/etc/xkeen") {
		t.Fatal("must not invoke XKeen")
	}
	if !strings.Contains(text, "BTKN_IPROUTE2=/opt/libexec/ip-full") {
		t.Fatal("late hook must export BTKN_IPROUTE2 when ip-full exists")
	}
}

func TestNDMLateHookStagedInBuild(t *testing.T) {
	p := filepath.Join("..", "..", "..", "build.ps1")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if !strings.Contains(text, "zz-blacktemple-kn.sh") {
		t.Fatal("build.ps1 must stage zz-blacktemple-kn.sh")
	}
}
