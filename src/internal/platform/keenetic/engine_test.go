package keenetic

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/igorpooh1978/blacktemple_kn/src/internal/routing"
)

type fakeRunner struct {
	mu       sync.Mutex
	files    map[string]string
	cmds     map[string]cmdResult
	symlinks map[string]string
}

type cmdResult struct {
	out string
	err error
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{
		files:    map[string]string{},
		cmds:     map[string]cmdResult{},
		symlinks: map[string]string{},
	}
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := strings.Join(append([]string{name}, args...), " ")
	if name == "test" && len(args) == 2 {
		p := args[1]
		switch args[0] {
		case "-e":
			if _, ok := f.files[p]; ok {
				return "", nil
			}
			if _, ok := f.symlinks[p]; ok {
				return "", nil
			}
			return "", errMissing
		case "-L":
			if _, ok := f.symlinks[p]; ok {
				return "", nil
			}
			return "", errMissing
		case "-f":
			if _, ok := f.symlinks[p]; ok {
				return "", errMissing
			}
			if _, ok := f.files[p]; ok {
				return "", nil
			}
			return "", errMissing
		}
	}
	if name == "cat" && len(args) == 1 {
		if v, ok := f.files[args[0]]; ok {
			return v, nil
		}
		return "", errMissing
	}
	if name == "command" && len(args) == 2 && args[0] == "-v" {
		if res, ok := f.cmds[key]; ok {
			return res.out, res.err
		}
		if args[1] == "modprobe" {
			if _, ok := f.files["/sbin/modprobe"]; ok {
				return "/sbin/modprobe", nil
			}
			return "", errMissing
		}
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
	cases := []struct {
		path string
		ok   bool
	}{
		{"/lib/modules/4.9-ndm-5/xt_TPROXY.ko", true},
		{"/lib/modules-evil/xt_TPROXY.ko", false},
		{"/tmp/xt_TPROXY.ko", false},
		{"/opt/lib/modules/../../tmp/xt_TPROXY.ko", false},
		{"/lib/modules/4.9-ndm-5/evil.ko", false},
	}
	for _, tc := range cases {
		err := validateModulePath(tc.path)
		if tc.ok && err != nil {
			t.Fatalf("%s: want allow, got %v", tc.path, err)
		}
		if !tc.ok && err == nil {
			t.Fatalf("%s: want reject", tc.path)
		}
	}
}

func TestLoadAllowlistedRejectsSymlink(t *testing.T) {
	f := newFakeRunner()
	p := "/lib/modules/4.9-ndm-5/xt_TPROXY.ko"
	f.symlinks[p] = "/tmp/evil.ko"
	err := loadAllowlisted(context.Background(), f, p)
	if err == nil {
		t.Fatal("symlink under allowed root must be rejected")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("got %v", err)
	}
}

func TestLoadAllowlistedRejectsNonRegular(t *testing.T) {
	f := newFakeRunner()
	p := "/lib/modules/4.9-ndm-5/xt_TPROXY.ko"
	err := loadAllowlisted(context.Background(), f, p)
	if err == nil {
		t.Fatal("missing/non-regular module must be rejected")
	}
	if !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("got %v", err)
	}
}

func TestPrepareFailsWhenInsmodOrderUnverified(t *testing.T) {
	f := newFakeRunner()
	f.files["/opt/sbin/ip"] = ""
	f.files["/opt/sbin/iptables"] = ""
	f.files["/opt/sbin/ipset"] = ""
	f.files["/proc/net/ip_tables_targets"] = "REDIRECT MARK CONNMARK"
	f.files["/proc/net/ip_tables_matches"] = "socket set addrtype conntrack"
	f.files["/proc/modules"] = "xt_socket"
	f.files["/proc/sys/kernel/osrelease"] = "4.9-ndm-5"
	f.files["/lib/modules/4.9-ndm-5/xt_TPROXY.ko"] = ""
	f.cmds["ip -4 rule show"] = cmdResult{out: "0:\tfrom all lookup local\n", err: nil}
	f.cmds["ipset --version"] = cmdResult{out: "ipset v7", err: nil}
	var sawInsmod, sawIPT, sawSysctl, sawOpkgMut, sawRmmod bool
	wrapped := &recordingRunner{inner: f, onRun: func(name string, args []string) {
		if name == "insmod" {
			sawInsmod = true
		}
		if name == "iptables" {
			sawIPT = true
		}
		if name == "sysctl" {
			sawSysctl = true
		}
		if name == "opkg" && len(args) > 0 {
			switch args[0] {
			case "install", "remove", "update", "upgrade":
				sawOpkgMut = true
			}
		}
		if name == "rmmod" {
			sawRmmod = true
		}
	}}
	_, err := Prepare(context.Background(), wrapped)
	if err == nil {
		t.Fatal("Prepare must fail without verified insmod order")
	}
	if !strings.Contains(err.Error(), InsmodOrderUnverified) {
		t.Fatalf("got %v", err)
	}
	if sawInsmod || sawIPT || sawSysctl || sawOpkgMut || sawRmmod {
		t.Fatal("failed Prepare must not mutate routing, sysctl, packages, or unload modules")
	}
}

func TestPolicyPreservationNotImplementedClaim(t *testing.T) {
	if PolicyPreservationStatus != "DESIGN INVARIANT / NOT VERIFIED" {
		t.Fatalf("%s", PolicyPreservationStatus)
	}
}
