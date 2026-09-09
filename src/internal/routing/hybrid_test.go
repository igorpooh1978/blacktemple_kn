package routing

import (
	"context"
	"errors"
	"go/parser"
	"go/token"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"
)

func testClient() netip.Addr {
	return netip.MustParseAddr("10.10.10.50")
}

func newTestEngine(t *testing.T, fx *fakeExecutor) *HybridIptablesEngine {
	t.Helper()
	eng, err := NewHybridIptablesEngine(testClient(), fx, PermitAllGuard{})
	if err != nil {
		t.Fatal(err)
	}
	return eng
}

func TestCapturePlanDeterministic(t *testing.T) {
	fx := newFakeExecutor()
	eng := newTestEngine(t, fx)
	p1, err := eng.Plan()
	if err != nil {
		t.Fatal(err)
	}
	p2, err := eng.Plan()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p1, p2) {
		t.Fatal("Plan() must be deterministic")
	}
	d1, err := eng.DryRun()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p1, d1) {
		t.Fatal("DryRun must match Plan")
	}
	if len(p1.Install) == 0 || len(p1.Uninstall) == 0 {
		t.Fatal("empty plan")
	}
}

func TestCapturePrivateDirectExclude(t *testing.T) {
	eng := newTestEngine(t, newFakeExecutor())
	p, err := eng.Plan()
	if err != nil {
		t.Fatal(err)
	}
	need := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "127.0.0.0/8", "224.0.0.0/4", "255.255.255.255/32"}
	for _, cidr := range need {
		if !planHasIPSetAdd(p.Install, SetExcludeV4, cidr) {
			t.Errorf("exclude set missing %s", cidr)
		}
	}
	if planHasIPSetAdd(p.Install, SetExcludeV4, "8.8.8.8") || planHasIPSetAdd(p.Install, SetExcludeV4, "8.8.8.8/32") {
		t.Fatal("public IPv4 must not be in exclude set")
	}
}

func TestSelectedClientOnly(t *testing.T) {
	eng := newTestEngine(t, newFakeExecutor())
	p, err := eng.Plan()
	if err != nil {
		t.Fatal(err)
	}
	adds := ipsetAdds(p.Install, SetClientsV4)
	if len(adds) != 1 || adds[0] != testClient().String() {
		t.Fatalf("clients set %v", adds)
	}
	for _, a := range adds {
		if strings.Contains(a, "/") {
			t.Fatal("clients set must be host IPs, never a LAN CIDR")
		}
	}
	if !planHasSeq(p.Install, "-m", "set", "!", "--match-set", SetClientsV4, "src", "-j", "RETURN") {
		t.Fatal("non-selected sources must RETURN (not captured)")
	}
	if planHasSeq(p.Install, "-s", "192.168.0.0/16") || planHasSeq(p.Install, "-s", "10.0.0.0/8") {
		t.Fatal("must never capture whole LAN by source CIDR")
	}
}

func TestEmptyClientRejected(t *testing.T) {
	fx := newFakeExecutor()
	eng, err := NewHybridIptablesEngine(netip.Addr{}, fx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Plan(); !errors.Is(err, ErrClientRequired) {
		t.Fatalf("empty Plan: %v", err)
	}
	if err := eng.Apply(context.Background()); !errors.Is(err, ErrClientRequired) {
		t.Fatalf("empty Apply: %v", err)
	}
	v6, err := NewHybridIptablesEngine(netip.MustParseAddr("::1"), fx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v6.DryRun(); !errors.Is(err, ErrClientRequired) {
		t.Fatalf("IPv6 client: %v", err)
	}
}

func TestTCPRedirectPlan(t *testing.T) {
	eng := newTestEngine(t, newFakeExecutor())
	p, err := eng.Plan()
	if err != nil {
		t.Fatal(err)
	}
	if !planHasSeq(p.Install, "-t", "nat", "-A", ChainTCP, "-p", "tcp", "-j", "REDIRECT", "--to-ports", "11820") {
		t.Fatal("TCP REDIRECT to 11820 missing")
	}
	if !planHasSeq(p.Install, "-t", "nat", "-A", "PREROUTING", "-j", ChainPRE) {
		t.Fatal("nat PREROUTING jump missing")
	}
	if planHasSeq(p.Install, "-t", "mangle", "-j", "REDIRECT") {
		t.Fatal("TCP REDIRECT must not live in mangle")
	}
}

func TestUDPTProxyPlan(t *testing.T) {
	eng := newTestEngine(t, newFakeExecutor())
	p, err := eng.Plan()
	if err != nil {
		t.Fatal(err)
	}
	if !planHasSeq(p.Install, "-t", "mangle", "-A", ChainUDP, "-p", "udp", "-j", "TPROXY", "--on-ip", "127.0.0.1", "--on-port", "11820", "--tproxy-mark", "0x42544b4e/0xffffffff") {
		t.Fatal("UDP TPROXY missing")
	}
	if !planHasSeq(p.Install, "-p", "udp", "-m", "socket", "--transparent", "-j", "RETURN") {
		t.Fatal("socket-transparent guard missing")
	}
	if !planHasSeq(p.Install, "-4", "rule", "add", "fwmark", "0x42544b4e/0xffffffff", "lookup", "4254") {
		t.Fatal("ip rule lookup 4254 missing")
	}
	if !planHasSeq(p.Install, "-4", "route", "add", "local", "default", "dev", "lo", "table", "4254") {
		t.Fatal("table 4254 local lo missing")
	}
	if !planHasSeq(p.Install, "-t", "mangle", "-A", "PREROUTING", "-j", ChainPRE) {
		t.Fatal("mangle PREROUTING jump missing")
	}
	if !planHasToken(p.Install, "CONNMARK") {
		t.Fatal("CONNMARK required (PRESENT on KN-1011)")
	}
}

func TestMarkTableCollision(t *testing.T) {
	t.Run("mark", func(t *testing.T) {
		fx := newFakeExecutor()
		fx.ipRule = "32765:\tfrom all fwmark 0x42544b4e lookup 4254"
		eng := newTestEngine(t, fx)
		rep, err := eng.Preflight(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if rep.OK {
			t.Fatal("mark collision must FAIL preflight")
		}
		if !hasKind(rep, CollisionMark) {
			t.Fatal("expected mark collision")
		}
		if err := eng.Apply(context.Background()); !errors.Is(err, ErrCaptureCollision) {
			t.Fatalf("Apply: %v", err)
		}
		p, err := eng.Plan()
		if err != nil {
			t.Fatal(err)
		}
		if !planHasToken(p.Install, "0x42544b4e/0xffffffff") {
			t.Fatal("must not auto-pick another mark")
		}
	})
	t.Run("table", func(t *testing.T) {
		fx := newFakeExecutor()
		fx.tableOut = "local default dev lo table 4254 scope host"
		eng := newTestEngine(t, fx)
		rep, err := eng.Preflight(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if rep.OK || !hasKind(rep, CollisionTable) {
			t.Fatalf("table collision: %+v", rep)
		}
		if err := eng.Apply(context.Background()); !errors.Is(err, ErrCaptureCollision) {
			t.Fatalf("Apply: %v", err)
		}
	})
}

func TestPortCollision(t *testing.T) {
	fx := newFakeExecutor()
	fx.ssOut = "tcp LISTEN 0 128 127.0.0.1:11820 0.0.0.0:*"
	eng := newTestEngine(t, fx)
	rep, err := eng.Preflight(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK || !hasKind(rep, CollisionPort) {
		t.Fatalf("port collision: %+v", rep)
	}
	if err := eng.Apply(context.Background()); !errors.Is(err, ErrCaptureCollision) {
		t.Fatalf("Apply: %v", err)
	}
}

func TestXKeenCollision(t *testing.T) {
	fx := newFakeExecutor()
	fx.natS = "-N xkeen\n-A PREROUTING -j xkeen\n-A xkeen -m comment --comment xkeen_rule -p tcp -j REDIRECT --to-ports 1181"
	fx.mangleS = "-N xkeen\n-A PREROUTING -j xkeen\n-A xkeen -p udp -m socket --transparent -j RETURN\n-A xkeen -p udp -j TPROXY --on-port 1181 --on-ip 127.0.0.1 --tproxy-mark 0x111"
	fx.pidofOut = "25942"
	fx.pidofErr = nil
	eng := newTestEngine(t, fx)

	if _, err := eng.Plan(); err != nil {
		t.Fatalf("Plan must work with XKeen: %v", err)
	}
	if _, err := eng.DryRun(); err != nil {
		t.Fatalf("DryRun must work with XKeen: %v", err)
	}
	rep, err := eng.Preflight(context.Background())
	if err != nil {
		t.Fatalf("Preflight must work with XKeen: %v", err)
	}
	if !rep.XKeenActive || !hasKind(rep, CollisionXKeen) {
		t.Fatalf("xkeen not reported: %+v", rep)
	}
	if err := eng.Apply(context.Background()); !errors.Is(err, ErrExistingCaptureEngine) {
		t.Fatalf("Apply: %v", err)
	}
}

func TestApply(t *testing.T) {
	fx := newFakeExecutor()
	eng := newTestEngine(t, fx)
	if err := eng.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	calls := fx.snapshot()
	if !callsHaveSeq(calls, "-t", "nat", "-A", "PREROUTING", "-j", ChainPRE) {
		t.Fatal("Apply did not attach nat hook")
	}
	if !callsHaveSeq(calls, "-t", "mangle", "-A", "PREROUTING", "-j", ChainPRE) {
		t.Fatal("Apply did not attach mangle hook")
	}
	if !eng.applied {
		t.Fatal("applied flag")
	}
}

func TestIdempotentApply(t *testing.T) {
	fx := newFakeExecutor()
	eng := newTestEngine(t, fx)
	if err := eng.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	afterFirst := countMutating(fx.snapshot())
	if err := eng.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	afterSecond := countMutating(fx.snapshot())
	if afterSecond != afterFirst {
		t.Fatalf("idempotent Apply must not reinstall: %d then %d", afterFirst, afterSecond)
	}
}

func TestRemove(t *testing.T) {
	fx := newFakeExecutor()
	eng := newTestEngine(t, fx)
	if err := eng.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := eng.Remove(context.Background()); err != nil {
		t.Fatal(err)
	}
	if eng.applied {
		t.Fatal("applied after Remove")
	}
	if !callsHaveSeq(fx.snapshot(), "-t", "nat", "-D", "PREROUTING", "-j", ChainPRE) {
		t.Fatal("Remove must detach nat jump")
	}
	if !callsHaveSeq(fx.snapshot(), "-t", "mangle", "-D", "PREROUTING", "-j", ChainPRE) {
		t.Fatal("Remove must detach mangle jump")
	}
}

func TestDoubleRemove(t *testing.T) {
	fx := newFakeExecutor()
	eng := newTestEngine(t, fx)
	if err := eng.Remove(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := eng.Remove(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestPartialApplyRollback(t *testing.T) {
	fx := newFakeExecutor()
	fx.failAtMut = 3
	eng := newTestEngine(t, fx)
	err := eng.Apply(context.Background())
	if err == nil {
		t.Fatal("expected injected failure")
	}
	if eng.applied {
		t.Fatal("partial Apply must not set applied")
	}
	if !callsHaveSeq(fx.snapshot(), "-t", "nat", "-D", "PREROUTING", "-j", ChainPRE) {
		t.Fatal("rollback must run Remove")
	}
}

func TestXrayFailureFailOpen(t *testing.T) {
	fx := newFakeExecutor()
	eng := newTestEngine(t, fx)
	if err := eng.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := eng.FailOpen(context.Background()); err != nil {
		t.Fatal(err)
	}
	if eng.applied {
		t.Fatal("fail-open must uninstall")
	}
	if !callsHaveSeq(fx.snapshot(), "-t", "nat", "-D", "PREROUTING", "-j", ChainPRE) {
		t.Fatal("fail-open must detach BTKN hooks")
	}
}

func TestNoGlobalFlush(t *testing.T) {
	eng := newTestEngine(t, newFakeExecutor())
	p, err := eng.Plan()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range append(append([]Argv{}, p.Install...), p.Uninstall...) {
		if isGlobalFlush(c) {
			t.Fatalf("global flush: %s", argvLine(c))
		}
		if c.Name == "ip6tables" {
			t.Fatal("IPv6 capture is UNVERIFIED; no ip6tables")
		}
		if c.Name == "sysctl" {
			t.Fatal("must not change sysctl")
		}
	}
}

func TestNoForeignChainMutation(t *testing.T) {
	eng := newTestEngine(t, newFakeExecutor())
	p, err := eng.Plan()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range append(append([]Argv{}, p.Install...), p.Uninstall...) {
		if err := checkForeignChain(c); err != nil {
			t.Fatal(err)
		}
		if hasTokenArgs(c, "xkeen") {
			t.Fatalf("must not mention xkeen: %s", argvLine(c))
		}
		if hasTokenArgs(c, "0x111") || hasTokenArgs(c, "0xffffaaa") || hasTokenArgs(c, "1181") {
			t.Fatalf("XKeen mark/port reused: %s", argvLine(c))
		}
		if hasTokenArgs(c, "0x42544b4f") {
			t.Fatal("reserved mark 0x42544b4f must stay unused")
		}
	}
}

func TestXrayOutboundNotRecaptured(t *testing.T) {
	// R6 is PREROUTING-only. Xray outbound is locally generated (OUTPUT) and
	// must not be jumped into BTKN_OUT. Creating the reserved chain is OK.
	eng := newTestEngine(t, newFakeExecutor())
	p, err := eng.Plan()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range append(append([]Argv{}, p.Install...), p.Uninstall...) {
		if touchesOUTPUT(c) {
			t.Fatalf("OUTPUT capture forbidden in R6: %s", argvLine(c))
		}
		if hasJump(c, ChainOUT) {
			t.Fatalf("BTKN_OUT must not be jumped to: %s", argvLine(c))
		}
	}
	if !planHasSeq(p.Install, "-t", "nat", "-N", ChainOUT) {
		t.Fatal("reserved BTKN_OUT should still be created")
	}
}

func TestIPv6CaptureUnverified(t *testing.T) {
	eng := newTestEngine(t, newFakeExecutor())
	rep, err := eng.Preflight(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rep.IPv6Capture != IPv6CaptureUnverified {
		t.Fatalf("IPv6 %q", rep.IPv6Capture)
	}
}

func TestNoXrayImport(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(info os.FileInfo) bool {
		return !strings.HasSuffix(info.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, pkg := range pkgs {
		for name, f := range pkg.Files {
			for _, spec := range f.Imports {
				path := strings.Trim(spec.Path.Value, `"`)
				if strings.Contains(path, "/internal/xray") || strings.Contains(path, "/internal/supervisor") {
					t.Fatalf("%s must not import %s", name, path)
				}
			}
		}
	}
}

func TestNilExecutorRejected(t *testing.T) {
	_, err := NewHybridIptablesEngine(testClient(), nil, nil)
	if !errors.Is(err, ErrNilExecutor) {
		t.Fatalf("got %v", err)
	}
}

func planHasIPSetAdd(cmds []Argv, set, member string) bool {
	for _, c := range cmds {
		if c.Name == "ipset" && hasSeq(c.Args, "add", set, member) {
			return true
		}
	}
	return false
}

func ipsetAdds(cmds []Argv, set string) []string {
	var out []string
	for _, c := range cmds {
		if c.Name == "ipset" && len(c.Args) >= 3 && c.Args[0] == "add" && c.Args[1] == set {
			out = append(out, c.Args[2])
		}
	}
	return out
}

func planHasSeq(cmds []Argv, seq ...string) bool {
	for _, c := range cmds {
		if hasSeq(c.Args, seq...) {
			return true
		}
	}
	return false
}

func planHasToken(cmds []Argv, tok string) bool {
	for _, c := range cmds {
		if c.Name == tok || hasTokenArgs(c, tok) {
			return true
		}
	}
	return false
}

func callsHaveSeq(calls []Argv, seq ...string) bool {
	return planHasSeq(calls, seq...)
}

func hasTokenArgs(c Argv, tok string) bool {
	if c.Name == tok {
		return true
	}
	return hasToken(c.Args, tok)
}

func hasKind(r PreflightReport, k CollisionKind) bool {
	for _, c := range r.Collisions {
		if c.Kind == k {
			return true
		}
	}
	return false
}

func countMutating(calls []Argv) int {
	n := 0
	for _, c := range calls {
		if !isProbe(c.Name, c.Args) {
			n++
		}
	}
	return n
}

func isGlobalFlush(c Argv) bool {
	if c.Name != "iptables" && c.Name != "ip6tables" {
		return false
	}
	for i, a := range c.Args {
		if a != "-F" && a != "--flush" && a != "-X" && a != "--delete-chain" {
			continue
		}
		rest := c.Args[i+1:]
		if len(rest) == 0 || strings.HasPrefix(rest[0], "-") {
			return true
		}
		if !strings.HasPrefix(rest[0], "BTKN_") {
			return true
		}
	}
	return false
}

func checkForeignChain(c Argv) error {
	if c.Name != "iptables" {
		return nil
	}
	mut := ""
	idx := -1
	for i, a := range c.Args {
		switch a {
		case "-A", "-I", "-R", "-D", "-F", "-X", "-N", "--append", "--insert", "--replace", "--delete", "--flush", "--delete-chain", "--new-chain":
			mut = a
			idx = i
		}
	}
	if mut == "" || idx+1 >= len(c.Args) {
		return nil
	}
	chain := c.Args[idx+1]
	if strings.HasPrefix(chain, "BTKN_") {
		return nil
	}
	if chain == "PREROUTING" && (mut == "-A" || mut == "-D" || mut == "--append" || mut == "--delete") {
		if hasSeq(c.Args, "-j", ChainPRE) {
			return nil
		}
		return errors.New("PREROUTING mutated without -j BTKN_PRE: " + argvLine(c))
	}
	return errors.New("foreign chain mutation: " + argvLine(c))
}

func touchesOUTPUT(c Argv) bool {
	if c.Name != "iptables" {
		return false
	}
	for i, a := range c.Args {
		if a != "-A" && a != "-I" && a != "-D" && a != "-R" && a != "--append" && a != "--insert" && a != "--delete" && a != "--replace" {
			continue
		}
		if i+1 < len(c.Args) && c.Args[i+1] == "OUTPUT" {
			return true
		}
	}
	return false
}

func hasJump(c Argv, chain string) bool {
	return hasSeq(c.Args, "-j", chain)
}
