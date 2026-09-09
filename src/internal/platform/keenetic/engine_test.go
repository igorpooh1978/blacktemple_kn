package keenetic

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/igorpooh1978/blacktemple_kn/src/internal/routing"
)

type fakeRunner struct {
	mu    sync.Mutex
	files map[string]string
	cmds  map[string]cmdResult
}

type cmdResult struct {
	out string
	err error
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{
		files: map[string]string{},
		cmds:  map[string]cmdResult{},
	}
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := strings.Join(append([]string{name}, args...), " ")
	if name == "test" && len(args) == 2 && args[0] == "-e" {
		_, ok := f.files[args[1]]
		if ok {
			return "", nil
		}
		return "", errMissing
	}
	if name == "cat" && len(args) == 1 {
		if v, ok := f.files[args[0]]; ok {
			return v, nil
		}
		return "", errMissing
	}
	if res, ok := f.cmds[key]; ok {
		return res.out, res.err
	}
	if res, ok := f.cmds[name]; ok {
		return res.out, res.err
	}
	return "", errMissing
}

var errMissing = errString("not found")

type errString string

func (e errString) Error() string { return string(e) }

func hybridPresent(f *fakeRunner) {
	f.files["/opt/sbin/ip"] = ""
	f.files["/opt/sbin/iptables"] = ""
	f.files["/opt/sbin/ipset"] = ""
	f.files["/proc/net/ip_tables_targets"] = "TPROXY REDIRECT MARK CONNMARK"
	f.files["/proc/net/ip_tables_matches"] = "socket set addrtype conntrack"
	f.files["/proc/modules"] = "xt_TPROXY xt_socket xt_mark xt_connmark xt_set xt_addrtype xt_conntrack"
	f.cmds["ip -4 rule show"] = cmdResult{out: "0:\tfrom all lookup local\n", err: nil}
	f.cmds["ipset --version"] = cmdResult{out: "ipset v7", err: nil}
}

func TestXKeenNotRequiredForHybridReady(t *testing.T) {
	f := newFakeRunner()
	hybridPresent(f)
	rep, err := Detect(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if rep.XKeenInstalled {
		t.Fatal("XKeenInstalled must be false")
	}
	if !rep.HybridOK || rep.Engine != EngineHybridReady {
		t.Fatalf("want HYBRID_READY without XKeen: %+v", rep)
	}
}

func TestXKeenDoesNotSubstituteTPROXY(t *testing.T) {
	f := newFakeRunner()
	hybridPresent(f)
	f.files["/opt/sbin/xkeen"] = ""
	f.files["/proc/net/ip_tables_targets"] = "REDIRECT MARK CONNMARK"
	delete(f.files, "/proc/modules")
	f.files["/proc/modules"] = "xt_socket"
	rep, err := Detect(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.XKeenInstalled {
		t.Fatal("XKeen should be detected")
	}
	if rep.HybridOK || rep.Engine == EngineHybridReady {
		t.Fatalf("XKeen must not imply HYBRID_READY without TPROXY: engine=%s", rep.Engine)
	}
}

func TestTUNIsCandidateNotReady(t *testing.T) {
	f := newFakeRunner()
	f.files["/dev/net/tun"] = ""
	rep, err := Detect(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Engine != EngineTUNCandidate {
		t.Fatalf("got %s", rep.Engine)
	}
	if rep.Engine == "TUN_READY" {
		t.Fatal("must not report TUN_READY")
	}
}

func TestRequirementsComeFromRouting(t *testing.T) {
	req := routing.HybridRequirements()
	if len(req.UserlandTools) == 0 || !req.NeedIPSet || !req.NeedPolicyRouting {
		t.Fatalf("HybridRequirements empty: %+v", req)
	}
	want := map[string]bool{"ip": true, "iptables": true, "ipset": true}
	for _, tname := range req.UserlandTools {
		delete(want, tname)
	}
	if len(want) != 0 {
		t.Fatalf("missing tools %v", want)
	}
}

func TestPrepareDoesNotApplyCapture(t *testing.T) {
	f := newFakeRunner()
	hybridPresent(f)
	var sawIPT, sawRule bool
	wrapped := &recordingRunner{inner: f, onRun: func(name string, args []string) {
		if name == "iptables" {
			sawIPT = true
		}
		if name == "ip" && len(args) > 0 && (args[0] == "rule" || args[0] == "route") && hasArg(args, "add") {
			sawRule = true
		}
	}}
	if _, err := Prepare(context.Background(), wrapped); err != nil {
		t.Fatal(err)
	}
	if sawIPT || sawRule {
		t.Fatal("Prepare must not create BTKN rules")
	}
}

type recordingRunner struct {
	inner *fakeRunner
	onRun func(name string, args []string)
}

func (r *recordingRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	if r.onRun != nil {
		r.onRun(name, args)
	}
	return r.inner.Run(ctx, name, args...)
}

func hasArg(args []string, tok string) bool {
	for _, a := range args {
		if a == tok {
			return true
		}
	}
	return false
}

func TestValidateModulePath(t *testing.T) {
	if err := validateModulePath("/tmp/evil.ko"); err == nil {
		t.Fatal("escaped path must fail")
	}
	if err := validateModulePath("/lib/modules/4.9-ndm-5/xt_TPROXY.ko"); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyPreservationNotImplementedClaim(t *testing.T) {
	if PolicyPreservationStatus != "DESIGN INVARIANT / NOT VERIFIED" {
		t.Fatalf("%s", PolicyPreservationStatus)
	}
}
