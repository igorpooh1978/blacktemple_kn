package routing

import (
	"context"
	"errors"
	"go/parser"
	"go/token"
	"net/netip"
	"os"
	"path/filepath"
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
	eng.SetRoutingCaps("ip", true, true)
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
	if !planHasSeq(p.Install, "-t", "nat", "-I", "PREROUTING", "1", "-j", ChainPRE) {
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
	if planHasSeq(p.Install, "-p", "udp", "-m", "socket", "--transparent", "-j", "RETURN") {
		t.Fatal("socket --transparent must MARK, not RETURN without mark")
	}
	if !planHasSeq(p.Install, "-p", "udp", "-m", "socket", "--transparent", "-j", "MARK", "--set-xmark", "0x42544b4e/0xffffffff") {
		t.Fatal("socket-transparent MARK missing")
	}
	if !planHasSeq(p.Install, "-4", "rule", "add", "fwmark", "0x42544b4e/0xffffffff", "lookup", "4254") {
		t.Fatal("ip rule lookup 4254 missing")
	}
	if !planHasSeq(p.Install, "-4", "route", "add", "local", "default", "dev", "lo", "table", "4254") {
		t.Fatal("table 4254 local lo missing")
	}
	if !planHasSeq(p.Install, "-t", "mangle", "-I", "PREROUTING", "1", "-j", ChainPRE) {
		t.Fatal("mangle PREROUTING jump missing")
	}
	if err := assertUDPOrder(p.Install); err != nil {
		t.Fatal(err)
	}
}

func TestUDPTProxyPlanReachesCapturePort(t *testing.T) {
	eng := newTestEngine(t, newFakeExecutor())
	eng.SetRoutingCaps(IPRoute2FullBinary, true, true)
	p, err := eng.Plan()
	if err != nil {
		t.Fatal(err)
	}
	if !planHasSeq(p.Install, "-t", "mangle", "-A", ChainUDP, "-p", "udp", "-j", "TPROXY", "--on-ip", "127.0.0.1", "--on-port", "11820", "--tproxy-mark", "0x42544b4e/0xffffffff") {
		t.Fatal("UDP TPROXY to 11820 missing")
	}
}

func TestFullIPRoute2InstallsTable4254(t *testing.T) {
	fx := newFakeExecutor()
	fx.natS = "-N xkeen\n-A PREROUTING -j xkeen\n-A xkeen -p tcp -j REDIRECT --to-ports 1181"
	fx.mangleS = "-N xkeen\n-A PREROUTING -j xkeen"
	fx.pidofOut = "25942"
	fx.pidofErr = nil
	fx.ssOut = "udp UNCONN 0 0 0.0.0.0:1181 0.0.0.0:* users:((\"xray\",pid=25942,fd=8))\ntcp LISTEN 0 0 0.0.0.0:1181 0.0.0.0:* users:((\"xray\",pid=25942,fd=7))"
	eng := newTestEngine(t, fx)
	eng.SetRoutingCaps(IPRoute2FullBinary, true, true)
	if err := eng.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	snap := fx.snapshot()
	if !planHasSeq(snap, "-4", "rule", "add", "fwmark", "0x42544b4e/0xffffffff", "lookup", "4254") {
		t.Fatal("fwmark lookup 4254 missing")
	}
	if !planHasSeq(snap, "-4", "route", "add", "local", "default", "dev", "lo", "table", "4254") {
		t.Fatal("table 4254 local default missing")
	}
	found := false
	for _, c := range snap {
		if c.Name == IPRoute2FullBinary && hasToken(c.Args, "lookup") {
			found = true
		}
		if hasToken(c.Args, "del") && hasToken(c.Args, "0x111") {
			t.Fatal("must not delete XKeen mark 0x111")
		}
	}
	if !found {
		t.Fatal("policy routing must exec /opt/libexec/ip-full")
	}
}

func TestMissingFullIPRoute2FailsUDPExplicitly(t *testing.T) {
	fx := newFakeExecutor()
	fx.pathIPBusyBox = true
	fx.busyBoxTable = true
	fx.natS = "-N xkeen\n-A PREROUTING -j xkeen\n-A xkeen -p tcp -j REDIRECT --to-ports 1181"
	fx.mangleS = "-N xkeen\n-A PREROUTING -j xkeen"
	fx.pidofOut = "25942"
	fx.pidofErr = nil
	fx.ssOut = "udp UNCONN 0 0 0.0.0.0:1181 0.0.0.0:* users:((\"xray\",pid=25942,fd=8))\ntcp LISTEN 0 0 0.0.0.0:1181 0.0.0.0:* users:((\"xray\",pid=25942,fd=7))"
	eng := newTestEngine(t, fx)
	eng.SetRoutingCaps("", false, true)
	rep, err := eng.Preflight(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rep.UDPCapture != UDPCaptureUnsupported || rep.IPRoute2 != ClassIPRoute2FullRequired {
		t.Fatalf("UDP must fail closed: %+v", rep)
	}
	if err := eng.Apply(context.Background()); err != nil {
		t.Fatalf("TCP Apply: %v", err)
	}
	snap := fx.snapshot()
	if planHasSeq(snap, "-j", "TPROXY") || planHasSeq(snap, "lookup", "4254") {
		t.Fatal("must not install half-working UDP TPROXY without full iproute2")
	}
	if !planHasSeq(snap, "-t", "nat", "-A", ChainTCP, "-p", "tcp", "-j", "REDIRECT", "--to-ports", "11820") {
		t.Fatal("TCP REDIRECT must remain")
	}
}

func TestMissingAddrtypeUsesExcludeFallback(t *testing.T) {
	eng := newTestEngine(t, newFakeExecutor())
	eng.SetRoutingCaps("ip", true, false)
	p, err := eng.Plan()
	if err != nil {
		t.Fatal(err)
	}
	if planHasSeq(p.Install, "addrtype") {
		t.Fatal("addrtype must be absent from the KN plan")
	}
	if !planHasIPSetAdd(p.Install, SetExcludeV4, "172.16.0.0/12") {
		t.Fatal("RFC1918 exclude missing")
	}
	if !planHasSeq(p.Install, "-t", "nat", "-A", ChainTCP, "-p", "tcp", "-j", "REDIRECT", "--to-ports", "11820") {
		t.Fatal("TCP REDIRECT missing")
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

func TestPREROUTINGInsertedAtHead(t *testing.T) {
	eng := newTestEngine(t, newFakeExecutor())
	p, err := eng.Plan()
	if err != nil {
		t.Fatal(err)
	}
	if !planHasSeq(p.Install, "-t", "nat", "-I", "PREROUTING", "1", "-j", ChainPRE) {
		t.Fatal("nat BTKN jump must insert at PREROUTING head")
	}
	if !planHasSeq(p.Install, "-t", "mangle", "-I", "PREROUTING", "1", "-j", ChainPRE) {
		t.Fatal("mangle BTKN jump must insert at PREROUTING head")
	}
	if planHasSeq(p.Install, "-t", "nat", "-A", "PREROUTING", "-j", ChainPRE) {
		t.Fatal("nat BTKN jump must not append after foreign PREROUTING")
	}
	if planHasSeq(p.Install, "-t", "mangle", "-A", "PREROUTING", "-j", ChainPRE) {
		t.Fatal("mangle BTKN jump must not append after foreign PREROUTING")
	}
}

func TestBusyBoxTable4254DoesNotBlockApply(t *testing.T) {
	fx := newFakeExecutor()
	fx.busyBoxTable = true
	fx.natS = "-N xkeen\n-A PREROUTING -j xkeen\n-A xkeen -p tcp -j REDIRECT --to-ports 1181"
	fx.mangleS = "-N xkeen\n-A PREROUTING -j xkeen"
	fx.pidofOut = "25942"
	fx.pidofErr = nil
	fx.ssOut = "udp UNCONN 0 0 0.0.0.0:1181 0.0.0.0:* users:((\"xray\",pid=25942,fd=8))\ntcp LISTEN 0 0 0.0.0.0:1181 0.0.0.0:* users:((\"xray\",pid=25942,fd=7))"
	eng := newTestEngine(t, fx)
	eng.SetRoutingCaps("ip", false, true)
	if err := eng.Apply(context.Background()); err != nil {
		t.Fatalf("BusyBox ip rejecting table 4254 must still Apply TCP capture: %v", err)
	}
	if !eng.applied {
		t.Fatal("applied")
	}
	if !planHasSeq(fx.snapshot(), "-t", "nat", "-I", "PREROUTING", "1", "-j", ChainPRE) {
		t.Fatal("nat BTKN jump missing after BusyBox table skip")
	}
	if planHasSeq(fx.snapshot(), "-j", "TPROXY") {
		t.Fatal("UDP TPROXY must be omitted without full iproute2")
	}
	for _, c := range fx.snapshot() {
		if c.Name == "ip" && hasToken(c.Args, "del") && hasToken(c.Args, "0x111") {
			t.Fatal("must not delete XKeen mark 0x111")
		}
	}
}

func TestBusyBoxTable4254RemoveIsIdempotent(t *testing.T) {
	fx := newFakeExecutor()
	fx.busyBoxTable = true
	eng := newTestEngine(t, fx)
	if err := eng.Remove(context.Background()); err != nil {
		t.Fatalf("Remove on BusyBox without table 4254: %v", err)
	}
}

func TestAddrtypeMatchUnavailableDoesNotBlockApply(t *testing.T) {
	fx := newFakeExecutor()
	fx.busyBoxTable = true
	fx.natS = "-N xkeen\n-A PREROUTING -j xkeen\n-A xkeen -p tcp -j REDIRECT --to-ports 1181"
	fx.mangleS = "-N xkeen\n-A PREROUTING -j xkeen"
	fx.pidofOut = "25942"
	fx.pidofErr = nil
	fx.ssOut = "udp UNCONN 0 0 0.0.0.0:1181 0.0.0.0:* users:((\"xray\",pid=25942,fd=8))\ntcp LISTEN 0 0 0.0.0.0:1181 0.0.0.0:* users:((\"xray\",pid=25942,fd=7))"
	eng := newTestEngine(t, fx)
	eng.SetRoutingCaps("ip", false, false)
	if err := eng.Apply(context.Background()); err != nil {
		t.Fatalf("iptables addrtype unavailable must still Apply TCP capture: %v", err)
	}
	if !eng.applied {
		t.Fatal("applied")
	}
	snap := fx.snapshot()
	if !planHasSeq(snap, "-t", "nat", "-I", "PREROUTING", "1", "-j", ChainPRE) {
		t.Fatal("nat BTKN jump missing after addrtype skip")
	}
	if !planHasSeq(snap, "-t", "nat", "-A", ChainTCP, "-p", "tcp", "-j", "REDIRECT", "--to-ports", "11820") {
		t.Fatal("TCP REDIRECT 11820 missing after addrtype skip")
	}
	if planHasSeq(snap, "addrtype") {
		t.Fatal("addrtype must be omitted from the KN plan")
	}
	if !planHasSeq(snap, "add", SetExcludeV4, "172.16.0.0/12", "-exist") {
		t.Fatal("RFC1918 exclude missing; addrtype skip must not drop ipset RETURN")
	}
	for _, c := range snap {
		if c.Name == "ip" && hasToken(c.Args, "del") && hasToken(c.Args, "0x111") {
			t.Fatal("must not delete XKeen mark 0x111")
		}
	}
}

func TestBusyBoxTable4254IsNotPreflightCollision(t *testing.T) {
	fx := newFakeExecutor()
	fx.busyBoxTable = true
	eng := newTestEngine(t, fx)
	rep, err := eng.Preflight(context.Background())
	if err != nil {
		t.Fatalf("Preflight: %v", err)
	}
	if hasKind(rep, CollisionTable) {
		t.Fatalf("unsupported table 4254 must not collide: %+v", rep)
	}
}

func TestXKeenIPv6WildcardListenIsLive(t *testing.T) {
	fx := newFakeExecutor()
	fx.ssErr = errors.New("ss: not found")
	fx.tcpOut = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	fx.udpOut = fx.tcpOut
	fx.tcp6Out = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 00000000000000000000000000000000:049D 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1"
	fx.udp6Out = fx.tcp6Out
	fx.natS = "-N xkeen\n-A PREROUTING -j xkeen\n-A xkeen -p tcp -j REDIRECT --to-ports 1181"
	fx.mangleS = "-N xkeen\n-A PREROUTING -j xkeen"
	fx.busyBoxTable = true
	eng := newTestEngine(t, fx)
	eng.SetRoutingCaps("ip", false, true)
	rep, err := eng.Preflight(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rep.XKeenState != XKeenLive {
		t.Fatalf(":::1181 in tcp6 must be XKeenLive, got %s", rep.XKeenState)
	}
	if err := eng.Apply(context.Background()); err != nil {
		t.Fatalf("Apply beside tcp6 XKeen: %v", err)
	}
}

func TestProcNet11820WithExpectedPIDIsOurs(t *testing.T) {
	fx := newFakeExecutor()
	fx.ssErr = errors.New("ss: not found")
	fx.tcpOut = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 00000000:2E2C 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0000000000000000 100 0 0 10 0"
	fx.udpOut = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	fx.busyBoxTable = true
	fx.natS = "-N xkeen\n-A PREROUTING -j xkeen\n-A xkeen -p tcp -j REDIRECT --to-ports 1181"
	fx.pidofOut = "25942"
	fx.pidofErr = nil
	fx.ssOut = "udp UNCONN 0 0 0.0.0.0:1181 0.0.0.0:*\n"
	fx.exeByPID = map[int]string{42: OurXrayExecutable}
	eng := newTestEngine(t, fx)
	eng.SetRoutingCaps("ip", false, true)
	eng.SetExpectedListener(ExpectedListener{Executable: OurXrayExecutable, PID: 42})
	if err := eng.Apply(context.Background()); err != nil {
		t.Fatalf("OUR Xray on 11820 without ss pid must Apply: %v", err)
	}
}

func TestXKeenLiveAllowsApplyWithoutMutatingXKeen(t *testing.T) {
	fx := newFakeExecutor()
	fx.natS = "-N xkeen\n-A PREROUTING -j xkeen\n-A xkeen -m comment --comment xkeen_rule -p tcp -j REDIRECT --to-ports 1181"
	fx.mangleS = "-N xkeen\n-A PREROUTING -j xkeen\n-A xkeen -p udp -m socket --transparent -j RETURN\n-A xkeen -p udp -j TPROXY --on-port 1181 --on-ip 127.0.0.1 --tproxy-mark 0x111"
	fx.pidofOut = "25942"
	fx.pidofErr = nil
	fx.ssOut = "udp UNCONN 0 0 0.0.0.0:1181 0.0.0.0:* users:((\"xray\",pid=25942,fd=8))\ntcp LISTEN 0 0 0.0.0.0:1181 0.0.0.0:* users:((\"xray\",pid=25942,fd=7))"
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
	if rep.XKeenState != XKeenLive {
		t.Fatalf("state=%s want XKEEN_LIVE", rep.XKeenState)
	}
	if !rep.XKeenActive {
		t.Fatal("live XKeen must be reported active")
	}
	if hasKind(rep, CollisionXKeen) {
		t.Fatal("live XKeen must not be a blocking collision")
	}
	if !rep.OK {
		t.Fatalf("live XKeen must allow Apply: %+v", rep)
	}
	if err := eng.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	after := fx.snapshot()
	if !callsHaveSeq(after, "-t", "nat", "-I", "PREROUTING", "1", "-j", ChainPRE) {
		t.Fatal("Apply must insert nat BTKN jump first")
	}
	for _, c := range after {
		if isProbe(c.Name, c.Args) {
			continue
		}
		line := argvLine(c)
		if hasTokenArgs(c, "xkeen") {
			t.Fatalf("must not mutate XKeen: %s", line)
		}
		if hasTokenArgs(c, "0x111") || hasTokenArgs(c, "1181") {
			t.Fatalf("must not touch XKeen mark/port: %s", line)
		}
		args := strings.Join(c.Args, " ")
		if strings.Contains(args, "lookup 111") || strings.Contains(args, "table 111") {
			t.Fatalf("must not touch table 111: %s", line)
		}
	}
}

func TestResidualXKeenCaptureRefusesApply(t *testing.T) {
	fx := newFakeExecutor()
	fx.natS = "-N xkeen\n-A PREROUTING -j xkeen\n-A xkeen -p tcp -j REDIRECT --to-ports 1181"
	fx.mangleS = "-N xkeen\n-A PREROUTING -j xkeen\n-A xkeen -p udp -j TPROXY --on-port 1181 --on-ip 127.0.0.1 --tproxy-mark 0x111"
	fx.ssOut = ""
	fx.pidofOut = ""
	fx.pidofErr = errors.New("fake: no xkeen process")
	eng := newTestEngine(t, fx)
	rep, err := eng.Preflight(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rep.XKeenState != XKeenResidual {
		t.Fatalf("state=%s want XKEEN_RESIDUAL_CAPTURE", rep.XKeenState)
	}
	before := countMutating(fx.snapshot())
	if err := eng.Apply(context.Background()); !errors.Is(err, ErrExistingCaptureEngine) {
		t.Fatalf("Apply: %v", err)
	}
	after := countMutating(fx.snapshot())
	if after != before {
		t.Fatalf("residual XKeen must not mutate BTKN: %d then %d", before, after)
	}
	for _, c := range fx.snapshot() {
		line := argvLine(c)
		if strings.Contains(line, " -D ") && strings.Contains(line, "xkeen") {
			t.Fatalf("must not delete XKeen: %s", line)
		}
	}
}

func TestDisabledRemoveOwnedNeverTouchesXKeen(t *testing.T) {
	fx := newFakeExecutor()
	fx.natS = "-N xkeen\n-A PREROUTING -j xkeen\n-A xkeen -p tcp -j REDIRECT --to-ports 1181\n-N BTKN_PRE"
	fx.mangleS = "-N xkeen\n-A PREROUTING -j xkeen\n-A xkeen -p udp -j TPROXY --on-port 1181 --on-ip 127.0.0.1 --tproxy-mark 0x111"
	fx.ipRule = "99:\tfrom all fwmark 0x111 lookup 111\n"
	eng := newTestEngine(t, fx)
	if err := eng.Reconcile(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	for _, c := range fx.snapshot() {
		line := argvLine(c)
		if hasTokenArgs(c, "xkeen") {
			t.Fatalf("RemoveOwned must not name xkeen: %s", line)
		}
		if hasTokenArgs(c, "0x111") || hasTokenArgs(c, "1181") {
			t.Fatalf("RemoveOwned must not touch XKeen mark/port: %s", line)
		}
		args := strings.Join(c.Args, " ")
		if strings.Contains(args, "lookup 111") || strings.Contains(args, "table 111") {
			t.Fatalf("RemoveOwned must not touch table 111: %s", line)
		}
		if c.Name == "iptables" && (hasTokenArgs(c, "-A") || hasTokenArgs(c, "-I")) && hasTokenArgs(c, "BTKN_PRE") && hasTokenArgs(c, "PREROUTING") {
			t.Fatalf("disabled Reconcile must not Apply BTKN jump: %s", line)
		}
	}
}

func TestApply(t *testing.T) {
	fx := newFakeExecutor()
	eng := newTestEngine(t, fx)
	if err := eng.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	calls := fx.snapshot()
	if !callsHaveSeq(calls, "-t", "nat", "-I", "PREROUTING", "1", "-j", ChainPRE) {
		t.Fatal("Apply did not attach nat hook")
	}
	if !callsHaveSeq(calls, "-t", "mangle", "-I", "PREROUTING", "1", "-j", ChainPRE) {
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

func TestIsAbsentObjectFailureRealisticExitError(t *testing.T) {
	badRule := "iptables: Bad rule (does a matching rule exist in that chain?)."
	exit1 := errors.New("exit status 1")
	if !isAbsentObjectFailure(badRule, exit1) {
		t.Fatal("Bad rule in CombinedOutput + exit status 1 must be absent/acceptable")
	}
	if isAbsentObjectFailure("Permission denied", exit1) {
		t.Fatal("Permission denied + exit status 1 must not be classified absent")
	}
	if isAbsentObjectFailure("", exit1) {
		t.Fatal("bare exit status 1 must not be classified absent")
	}
}

func TestRemovePermissionDeniedIsIncomplete(t *testing.T) {
	fx := newFakeExecutor()
	fx.failPermission = true
	fx.natS = "-A PREROUTING -j BTKN_PRE"
	fx.mangleS = "-A PREROUTING -j BTKN_PRE"
	eng := newTestEngine(t, fx)
	err := eng.Remove(context.Background())
	if err == nil {
		t.Fatal("Permission denied cleanup must fail")
	}
	if !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("got %v want ErrCleanupIncomplete", err)
	}
}

func TestReconcileFromCleanSystem(t *testing.T) {
	fx := newFakeExecutor()
	fx.ssOut = `tcp LISTEN 0 128 0.0.0.0:11820 0.0.0.0:* users:(("xray",pid=99,fd=8))`
	fx.exeByPID = map[int]string{99: OurXrayExecutable}
	eng := newTestEngine(t, fx)
	eng.SetExpectedListener(ExpectedListener{Executable: OurXrayExecutable, PID: 99})
	if err := eng.Reconcile(context.Background(), true); err != nil {
		t.Fatalf("clean desired Reconcile must Remove absent then Apply, got %v", err)
	}
	if !eng.applied {
		t.Fatal("desired reconcile from clean system must Apply")
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

func assertUDPOrder(install []Argv) error {
	idxRestore, idxExclude, idxMark, idxSave, idxTproxy := -1, -1, -1, -1, -1
	for i, c := range install {
		if hasSeq(c.Args, "--restore-mark") {
			idxRestore = i
		}
		if hasSeq(c.Args, ChainUDP, "-m", "set", "--match-set", SetExcludeV4) {
			idxExclude = i
		}
		if hasSeq(c.Args, "-m", "socket", "--transparent", "-j", "MARK") {
			idxMark = i
		}
		if hasSeq(c.Args, "--save-mark") {
			idxSave = i
		}
		if hasSeq(c.Args, "-j", "TPROXY") {
			idxTproxy = i
		}
	}
	if idxRestore < 0 || idxExclude < 0 || idxMark < 0 || idxSave < 0 || idxTproxy < 0 {
		return errors.New("UDP path missing restore/exclude/socket MARK/save/TPROXY")
	}
	if !(idxRestore < idxExclude && idxExclude < idxMark && idxMark < idxSave && idxSave < idxTproxy) {
		return errors.New("UDP order must be restore → exclusions → socket MARK → CONNMARK save → TPROXY")
	}
	return nil
}

func TestFailOpenIncomplete(t *testing.T) {
	fx := newFakeExecutor()
	eng := newTestEngine(t, fx)
	if err := eng.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	fx.failDetach = true
	fx.natS = "-A PREROUTING -j BTKN_PRE"
	fx.mangleS = "-A PREROUTING -j BTKN_PRE"
	fx.ipRule = "32765:\tfrom all fwmark 0x42544b4e lookup 4254"
	fx.tableOut = "local default dev lo scope host"
	err := eng.FailOpen(context.Background())
	if err == nil {
		t.Fatal("FailOpen must not return nil when detach fails with leftover hooks")
	}
	if !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("got %v want ErrCleanupIncomplete", err)
	}
}

func TestPartialApplyRollbackJoinsCleanupError(t *testing.T) {
	fx := newFakeExecutor()
	fx.failAtMut = 3
	fx.failDetach = true
	eng := newTestEngine(t, fx)
	err := eng.Apply(context.Background())
	if err == nil {
		t.Fatal("expected injected failure")
	}
	if !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("rollback failure must join ErrCleanupIncomplete, got %v", err)
	}
	if eng.applied {
		t.Fatal("partial Apply must not set applied")
	}
}

func TestPreflightToolFailure(t *testing.T) {
	fx := newFakeExecutor()
	fx.natErr = errors.New("iptables: permission denied")
	eng := newTestEngine(t, fx)
	_, err := eng.Preflight(context.Background())
	if !errors.Is(err, ErrPreflightProbe) {
		t.Fatalf("got %v", err)
	}
}

func TestPreflightUnknownTableError(t *testing.T) {
	fx := newFakeExecutor()
	fx.tableErr = errors.New("ip: RTNETLINK answers: Operation not permitted")
	eng := newTestEngine(t, fx)
	_, err := eng.Preflight(context.Background())
	if !errors.Is(err, ErrPreflightProbe) {
		t.Fatalf("unknown table 4254 error must be preflight failure, got %v", err)
	}
}

func TestProcNetHexPortCollision(t *testing.T) {
	fx := newFakeExecutor()
	fx.ssErr = errors.New("ss: not found")
	fx.tcpOut = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 00000000:2E2C 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0000000000000000 100 0 0 10 0"
	fx.udpOut = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	eng := newTestEngine(t, fx)
	rep, err := eng.Preflight(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK || !hasKind(rep, CollisionPort) {
		t.Fatalf("hex /proc/net/tcp port 11820 (2E2C) must collide: %+v", rep)
	}
}

func TestExpectedXrayOwnerNotCollision(t *testing.T) {
	fx := newFakeExecutor()
	fx.ssOut = `tcp LISTEN 0 128 0.0.0.0:11820 0.0.0.0:* users:(("xray",pid=99,fd=8))`
	fx.exeByPID = map[int]string{99: OurXrayExecutable}
	eng := newTestEngine(t, fx)
	eng.SetExpectedListener(ExpectedListener{Executable: OurXrayExecutable, PID: 99})
	rep, err := eng.Preflight(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK || hasKind(rep, CollisionPort) {
		t.Fatalf("our xray owning 11820 is not a collision: %+v", rep)
	}
}

func TestForeignXrayOwnerCollision(t *testing.T) {
	fx := newFakeExecutor()
	fx.ssOut = `tcp LISTEN 0 128 0.0.0.0:11820 0.0.0.0:* users:(("xray",pid=7,fd=8))`
	fx.exeByPID = map[int]string{7: "/opt/sbin/xray"}
	eng := newTestEngine(t, fx)
	rep, err := eng.Preflight(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK || !hasKind(rep, CollisionPort) {
		t.Fatalf("/opt/sbin/xray must collide: %+v", rep)
	}
}

func TestReconcileManagerRestart(t *testing.T) {
	fx := newFakeExecutor()
	fx.natS = "-A PREROUTING -j BTKN_PRE\n-N BTKN_PRE"
	fx.mangleS = "-A PREROUTING -j BTKN_PRE\n-N BTKN_PRE"
	fx.ipRule = "32765:\tfrom all fwmark 0x42544b4e lookup 4254"
	fx.tableOut = "local default dev lo scope host"
	eng := newTestEngine(t, fx)
	eng.applied = false
	if err := eng.Reconcile(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if !eng.applied {
		t.Fatal("desired reconcile must Apply fresh after removing stale BTKN")
	}
}

func TestReconcileNDMPartialLeftovers(t *testing.T) {
	t.Run("chains gone rule remains", func(t *testing.T) {
		fx := newFakeExecutor()
		fx.ipRule = "from all fwmark 0x42544b4e lookup 4254"
		fx.tableOut = "local default dev lo scope host"
		eng := newTestEngine(t, fx)
		if err := eng.Reconcile(context.Background(), true); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("chain remains rule gone", func(t *testing.T) {
		fx := newFakeExecutor()
		fx.natS = "-A PREROUTING -j BTKN_PRE\n-N BTKN_PRE"
		fx.tableErr = errors.New("FIB table does not exist")
		eng := newTestEngine(t, fx)
		if err := eng.Reconcile(context.Background(), true); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("only PREROUTING jump", func(t *testing.T) {
		fx := newFakeExecutor()
		fx.natS = "-A PREROUTING -j BTKN_PRE"
		eng := newTestEngine(t, fx)
		if err := eng.Reconcile(context.Background(), true); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("only table exists", func(t *testing.T) {
		fx := newFakeExecutor()
		fx.tableOut = "local default dev lo scope host"
		eng := newTestEngine(t, fx)
		if err := eng.Reconcile(context.Background(), true); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("only fwmark rule exists", func(t *testing.T) {
		fx := newFakeExecutor()
		fx.ipRule = "from all fwmark 0x42544b4e lookup 4254"
		eng := newTestEngine(t, fx)
		if err := eng.Reconcile(context.Background(), true); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("only ipset exists", func(t *testing.T) {
		fx := newFakeExecutor()
		fx.ipsetPresent = true
		eng := newTestEngine(t, fx)
		if err := eng.Reconcile(context.Background(), true); err != nil {
			t.Fatal(err)
		}
		if !callsHaveSeq(fx.snapshot(), "destroy", SetClientsV4) {
			t.Fatal("Reconcile must destroy leftover owned ipset")
		}
	})
	t.Run("only chains exist", func(t *testing.T) {
		fx := newFakeExecutor()
		fx.natS = "-N BTKN_PRE\n-N BTKN_TCP"
		fx.mangleS = "-N BTKN_PRE\n-N BTKN_UDP"
		eng := newTestEngine(t, fx)
		if err := eng.Reconcile(context.Background(), true); err != nil {
			t.Fatal(err)
		}
		if !callsHaveSeq(fx.snapshot(), "-X", ChainPRE) {
			t.Fatal("Reconcile must delete leftover owned chains")
		}
	})
}

func TestForeignCollisionNoAutopick(t *testing.T) {
	fx := newFakeExecutor()
	fx.tableOut = "local default dev lo table 4254 scope host"
	fx.ipRule = "from all fwmark 0x42544b4e lookup 9999"
	fx.ssOut = `tcp LISTEN 0 128 0.0.0.0:11820 0.0.0.0:* users:(("xray",pid=7,fd=8))`
	fx.exeByPID = map[int]string{7: "/opt/sbin/xray"}
	eng := newTestEngine(t, fx)
	rep, err := eng.Preflight(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK {
		t.Fatal("foreign mark/table/port must FAIL")
	}
	if err := eng.Apply(context.Background()); !errors.Is(err, ErrCaptureCollision) {
		t.Fatalf("Apply: %v", err)
	}
	p, err := eng.Plan()
	if err != nil {
		t.Fatal(err)
	}
	if !planHasToken(p.Install, "0x42544b4e/0xffffffff") || !planHasToken(p.Install, "11820") || !planHasToken(p.Install, "4254") {
		t.Fatal("must not auto-pick another port/mark/table")
	}
}

func TestProductionForbidsGlobalMutation(t *testing.T) {
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		s := string(b)
		for _, bad := range []string{
			"iptables -t nat -F\n",
			"iptables -t mangle -F\n",
			"ip rule flush",
			"ip route flush",
			"sysctl -w",
			"swapoff",
			"swapon",
			"rmmod",
			"modprobe -r",
		} {
			if strings.Contains(s, bad) {
				t.Errorf("%s contains forbidden %q", path, strings.TrimSpace(bad))
			}
		}
		if strings.Contains(s, `"iptables"`) && strings.Contains(s, `"-F"`) {
			// allowed only with BTKN_ chain in the same argv helper; plan tests cover that.
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
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
	if chain == "PREROUTING" && (mut == "-A" || mut == "-I" || mut == "-D" || mut == "--append" || mut == "--insert" || mut == "--delete") {
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
