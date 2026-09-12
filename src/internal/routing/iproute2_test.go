package routing

import (
	"context"
	"errors"
	"testing"
)

func TestResolveIPRoute2PrefersFullOverBusyBox(t *testing.T) {
	fx := newFakeExecutor()
	fx.pathIPBusyBox = true
	fx.busyBoxTable = true
	path, ok := ResolveIPRoute2(context.Background(), fx, "")
	if !ok {
		t.Fatal("full iproute2 must be selected")
	}
	if path != IPRoute2FullBinary {
		t.Fatalf("got %q want %s", path, IPRoute2FullBinary)
	}
	for _, c := range fx.snapshot() {
		if c.Name == "ip" && hasToken(c.Args, "rule") && hasToken(c.Args, "add") {
			t.Fatal("BusyBox PATH ip must not be used for BTKN policy routing")
		}
	}
}

func TestResolveIPRoute2ConfiguredWins(t *testing.T) {
	fx := newFakeExecutor()
	fx.pathIPBusyBox = true
	fx.busyBoxTable = true
	path, ok := ResolveIPRoute2(context.Background(), fx, IPRoute2FullBinary)
	if !ok || path != IPRoute2FullBinary {
		t.Fatalf("configured path: ok=%v path=%q", ok, path)
	}
}

func TestResolveIPRoute2MissingFull(t *testing.T) {
	path, ok := ResolveIPRoute2(context.Background(), busyBoxOnly{}, "")
	if ok {
		t.Fatalf("BusyBox must not be selected, got %q", path)
	}
}

type busyBoxOnly struct{}

func (busyBoxOnly) Run(_ context.Context, _ string, _ ...string) (string, error) {
	return "BusyBox v1.37.0 multi-call binary.\nip: invalid argument '4254' to 'table'\n", errors.New("exit status 1")
}

func TestArgv0ForIPFull(t *testing.T) {
	if argv0For(IPRoute2FullBinary) != "ip" {
		t.Fatal("ip-full must be invoked as argv0 ip")
	}
	if argv0For("ip") != "ip" {
		t.Fatal("ip argv0")
	}
	if argv0For("iptables") != "iptables" {
		t.Fatal("iptables argv0 must stay")
	}
}
