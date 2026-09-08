package geodata

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/igorpooh1978/blacktemple_kn/src/internal/atomicfile"
)

type fakeValidator struct {
	err error
	n   int
}

func (f *fakeValidator) Validate(ctx context.Context, geoIPPath, geoSitePath string) error {
	f.n++
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if geoIPPath == "" || geoSitePath == "" {
		return errors.New("empty path")
	}
	return f.err
}

func writeTempPair(t *testing.T, dir, ipBody, siteBody string) (ipPath, sitePath, ipSum, siteSum string) {
	t.Helper()
	ipPath = filepath.Join(dir, "src-geoip.dat")
	sitePath = filepath.Join(dir, "src-geosite.dat")
	if err := os.WriteFile(ipPath, []byte(ipBody), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sitePath, []byte(siteBody), 0o644); err != nil {
		t.Fatal(err)
	}
	return ipPath, sitePath, sumStr(ipBody), sumStr(siteBody)
}

func sumStr(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func newTestManager(t *testing.T, v Validator, maxBytes int64) *Manager {
	t.Helper()
	m, err := NewManager(t.TempDir(), v, Options{
		MaxFileBytes: maxBytes,
		MaxSets:      3,
		Now:          func() time.Time { return time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(filepath.ToSlash(m.dataDir), "opt/blacktemple-kn") {
		t.Fatal("tests must not use the production data dir")
	}
	return m
}

func installPair(t *testing.T, m *Manager, src, ipBody, siteBody, version string) {
	t.Helper()
	ip, site, ipSum, siteSum := writeTempPair(t, src, ipBody, siteBody)
	if err := m.Install(context.Background(), Candidate{
		GeoIPPath: ip, GeoSitePath: site, Source: "manual", Version: version,
		GeoIPSHA256: ipSum, GeoSiteSHA256: siteSum,
	}); err != nil {
		t.Fatal(err)
	}
}

func activeGeoIP(t *testing.T, m *Manager) string {
	t.Helper()
	p, err := m.ActivePaths()
	if err != nil && !errors.Is(err, ErrMissingActiveSet) {
		t.Fatal(err)
	}
	if p.GeoIPPath == "" {
		return ""
	}
	got, err := os.ReadFile(p.GeoIPPath)
	if err != nil {
		t.Fatal(err)
	}
	return string(got)
}

func TestAtomicReplace(t *testing.T) {
	v := &fakeValidator{}
	m := newTestManager(t, v, 1024)
	src := t.TempDir()
	installPair(t, m, src, "geoip-v1", "geosite-v1", "1")
	snap := m.Active()
	if snap.GeoIP.Status != StatusActive || snap.GeoSite.Status != StatusActive {
		t.Fatalf("status %+v", snap)
	}
	if activeGeoIP(t, m) != "geoip-v1" {
		t.Fatalf("active geoip %q", activeGeoIP(t, m))
	}

	installPair(t, m, src, "geoip-v2", "geosite-v2", "2")
	if activeGeoIP(t, m) != "geoip-v2" {
		t.Fatalf("replaced %q", activeGeoIP(t, m))
	}
	st, err := m.loadState()
	if err != nil {
		t.Fatal(err)
	}
	prev, err := os.ReadFile(filepath.Join(m.setDir(st.Previous), fileGeoIP))
	if err != nil || string(prev) != "geoip-v1" {
		t.Fatalf("previous %q %v", prev, err)
	}
	v1Path := filepath.Join(m.setDir(st.Previous), fileGeoIP)
	v2Path, _ := m.ActivePaths()
	if v1Path == v2Path.GeoIPPath {
		t.Fatal("sets must be distinct directories")
	}
}

func TestFailedValidatorLeavesWorkingUntouched(t *testing.T) {
	ok := &fakeValidator{}
	m := newTestManager(t, ok, 1024)
	src := t.TempDir()
	installPair(t, m, src, "good-ip", "good-site", "1")
	before, err := os.ReadFile(m.statePath())
	if err != nil {
		t.Fatal(err)
	}

	m.validate = &fakeValidator{err: errors.New("dat header bogus")}
	ip2, site2, ipSum2, siteSum2 := writeTempPair(t, src, "bad-ip", "bad-site")
	err = m.Install(context.Background(), Candidate{
		GeoIPPath: ip2, GeoSitePath: site2, Source: "manual", Version: "2",
		GeoIPSHA256: ipSum2, GeoSiteSHA256: siteSum2,
	})
	if !errors.Is(err, ErrValidate) {
		t.Fatalf("got %v", err)
	}
	if activeGeoIP(t, m) != "good-ip" {
		t.Fatalf("working file changed: %q", activeGeoIP(t, m))
	}
	if m.Active().GeoIP.Version != "1" {
		t.Fatalf("active metadata mutated: %+v", m.Active())
	}
	after, _ := os.ReadFile(m.statePath())
	if string(after) != string(before) {
		t.Fatalf("state pointer changed on validator fail")
	}
}

func TestChecksumMismatch(t *testing.T) {
	m := newTestManager(t, &fakeValidator{}, 1024)
	src := t.TempDir()
	ip, site, _, siteSum := writeTempPair(t, src, "ip", "site")
	err := m.Install(context.Background(), Candidate{
		GeoIPPath: ip, GeoSitePath: site, Source: "manual", Version: "1",
		GeoIPSHA256: strings.Repeat("ab", 32), GeoSiteSHA256: siteSum,
	})
	if !errors.Is(err, ErrChecksum) {
		t.Fatalf("got %v", err)
	}
	if _, err := m.ActivePaths(); !errors.Is(err, ErrMissingActiveSet) {
		t.Fatalf("active must not be created on checksum mismatch: %v", err)
	}
}

func TestChecksumMismatchLeavesExisting(t *testing.T) {
	m := newTestManager(t, &fakeValidator{}, 1024)
	src := t.TempDir()
	installPair(t, m, src, "good-ip", "good-site", "1")
	before, _ := os.ReadFile(m.statePath())
	ip, site, _, siteSum := writeTempPair(t, src, "bad-ip", "bad-site")
	err := m.Install(context.Background(), Candidate{
		GeoIPPath: ip, GeoSitePath: site, Source: "manual", Version: "2",
		GeoIPSHA256: strings.Repeat("ab", 32), GeoSiteSHA256: siteSum,
	})
	if !errors.Is(err, ErrChecksum) {
		t.Fatalf("got %v", err)
	}
	if activeGeoIP(t, m) != "good-ip" {
		t.Fatalf("active mutated: %q", activeGeoIP(t, m))
	}
	after, _ := os.ReadFile(m.statePath())
	if string(after) != string(before) {
		t.Fatal("state changed on checksum fail")
	}
}

func TestOversizedCandidate(t *testing.T) {
	m := newTestManager(t, &fakeValidator{}, 4)
	src := t.TempDir()
	ip, site, ipSum, siteSum := writeTempPair(t, src, "too-big-payload", "x")
	err := m.Install(context.Background(), Candidate{
		GeoIPPath: ip, GeoSitePath: site, Source: "manual", Version: "1",
		GeoIPSHA256: ipSum, GeoSiteSHA256: siteSum,
	})
	if !errors.Is(err, ErrOversized) {
		t.Fatalf("got %v", err)
	}
	if _, err := m.ActivePaths(); !errors.Is(err, ErrMissingActiveSet) {
		t.Fatal("active must not be created when oversized")
	}
}

func TestBackupRetention(t *testing.T) {
	m := newTestManager(t, &fakeValidator{}, 1024)
	src := t.TempDir()
	for i, body := range []string{"v1", "v2", "v3", "v4"} {
		installPair(t, m, src, "ip-"+body, "site-"+body, body)
		_ = i
	}
	ids := m.retainedSetIDs()
	if len(ids) < 2 || len(ids) > 3 {
		t.Fatalf("retained %v want 2-3", ids)
	}
	if activeGeoIP(t, m) != "ip-v4" {
		t.Fatalf("active %s", activeGeoIP(t, m))
	}
	st, _ := m.loadState()
	prev, _ := os.ReadFile(filepath.Join(m.setDir(st.Previous), fileGeoIP))
	if string(prev) != "ip-v3" {
		t.Fatalf("previous %s", prev)
	}
	entries, _ := os.ReadDir(m.setsDir())
	if len(entries) > 3 {
		t.Fatalf("too many sets: %d", len(entries))
	}
	if _, err := os.Stat(filepath.Join(m.root, "geoip.dat.bak")); err == nil {
		t.Fatal("unbounded .bak must not exist")
	}
}

func TestRollbackPrevious(t *testing.T) {
	m := newTestManager(t, &fakeValidator{}, 1024)
	src := t.TempDir()
	installPair(t, m, src, "first", "first-site", "1")
	p1, _ := m.ActivePaths()
	installPair(t, m, src, "second", "second-site", "2")
	p2, _ := m.ActivePaths()
	if err := m.Rollback(); err != nil {
		t.Fatal(err)
	}
	if activeGeoIP(t, m) != "first" {
		t.Fatalf("rollback %q", activeGeoIP(t, m))
	}
	after, _ := m.ActivePaths()
	if after.SetID != p1.SetID {
		t.Fatalf("rollback set %s want %s", after.SetID, p1.SetID)
	}
	if _, err := os.Stat(p2.GeoIPPath); err != nil {
		t.Fatal("rollback must not delete the former active set")
	}
}

func TestSourceDisabled(t *testing.T) {
	if SourceEnabled() {
		t.Fatal("no geodata source may be enabled")
	}
}

func TestBuiltinCatalog(t *testing.T) {
	a := BuiltinCatalog{}.Tags()
	b := BuiltinCatalog{}.Tags()
	if len(a) != 6 {
		t.Fatalf("len %d", len(a))
	}
	want := []string{"youtube", "telegram", "google", "discord", "netflix", "category-ads-all"}
	for i, id := range want {
		if a[i].ID != id || b[i].ID != id {
			t.Fatalf("order %v", a)
		}
	}
	a[0].ID = "mutated"
	copied := BuiltinCatalog{}.Tags()
	if copied[0].ID != "youtube" {
		t.Fatal("catalog must copy")
	}
}

func TestNewManagerRejectsEmptyDirAndNilValidator(t *testing.T) {
	if _, err := NewManager("", &fakeValidator{}, Options{}); !errors.Is(err, ErrEmptyDataDir) {
		t.Fatalf("empty dir: %v", err)
	}
	if _, err := NewManager(t.TempDir(), nil, Options{}); !errors.Is(err, ErrNilValidator) {
		t.Fatalf("nil validator: %v", err)
	}
}

func TestDefaultDataDirIsDocumentedOnly(t *testing.T) {
	if DefaultDataDir == "" {
		t.Fatal("conceptual DefaultDataDir must be documented")
	}
	m := newTestManager(t, &fakeValidator{}, 1024)
	if m.dataDir == DefaultDataDir {
		t.Fatal("test manager used DefaultDataDir")
	}
}

func TestStatePointerWriteFailLeavesActive(t *testing.T) {
	m := newTestManager(t, &fakeValidator{}, 1024)
	src := t.TempDir()
	installPair(t, m, src, "good-ip", "good-site", "1")
	before := activeGeoIP(t, m)
	beforeState, _ := os.ReadFile(m.statePath())
	injected := errors.New("pointer write fail")
	m.pointer = &atomicfile.Writer{Replace: func(tmp, dest string) error {
		return injected
	}}
	ip2, site2, ipSum2, siteSum2 := writeTempPair(t, src, "new-ip", "new-site")
	err := m.Install(context.Background(), Candidate{
		GeoIPPath: ip2, GeoSitePath: site2, Source: "manual", Version: "2",
		GeoIPSHA256: ipSum2, GeoSiteSHA256: siteSum2,
	})
	if !errors.Is(err, injected) {
		t.Fatalf("got %v", err)
	}
	if activeGeoIP(t, m) != before {
		t.Fatalf("active mutated: %q", activeGeoIP(t, m))
	}
	afterState, _ := os.ReadFile(m.statePath())
	if string(afterState) != string(beforeState) {
		t.Fatal("state.json changed despite pointer failure")
	}
}

func TestMetadataWriteFailLeavesActive(t *testing.T) {
	m := newTestManager(t, &fakeValidator{}, 1024)
	src := t.TempDir()
	installPair(t, m, src, "good-ip", "good-site", "1")
	beforeState, _ := os.ReadFile(m.statePath())
	m.writeMeta = func(path string, data []byte, perm os.FileMode) error {
		return errors.New("meta write fail")
	}
	ip2, site2, ipSum2, siteSum2 := writeTempPair(t, src, "new-ip", "new-site")
	err := m.Install(context.Background(), Candidate{
		GeoIPPath: ip2, GeoSitePath: site2, Source: "manual", Version: "2",
		GeoIPSHA256: ipSum2, GeoSiteSHA256: siteSum2,
	})
	if err == nil {
		t.Fatal("expected metadata write failure")
	}
	if activeGeoIP(t, m) != "good-ip" {
		t.Fatalf("active mutated: %q", activeGeoIP(t, m))
	}
	afterState, _ := os.ReadFile(m.statePath())
	if string(afterState) != string(beforeState) {
		t.Fatal("state.json changed despite metadata failure")
	}
}

func TestCopyFailLeavesActive(t *testing.T) {
	m := newTestManager(t, &fakeValidator{}, 1024)
	src := t.TempDir()
	installPair(t, m, src, "good-ip", "good-site", "1")
	beforeState, _ := os.ReadFile(m.statePath())
	m.copyFile = func(src, dest string) (int64, string, error) {
		return 0, "", errors.New("disk write fail")
	}
	ip2, site2, ipSum2, siteSum2 := writeTempPair(t, src, "new-ip", "new-site")
	err := m.Install(context.Background(), Candidate{
		GeoIPPath: ip2, GeoSitePath: site2, Source: "manual", Version: "2",
		GeoIPSHA256: ipSum2, GeoSiteSHA256: siteSum2,
	})
	if err == nil {
		t.Fatal("expected copy failure")
	}
	if activeGeoIP(t, m) != "good-ip" {
		t.Fatalf("active mutated: %q", activeGeoIP(t, m))
	}
	afterState, _ := os.ReadFile(m.statePath())
	if string(afterState) != string(beforeState) {
		t.Fatal("state.json changed despite copy failure")
	}
}

func TestRollbackPointerFailLeavesActive(t *testing.T) {
	m := newTestManager(t, &fakeValidator{}, 1024)
	src := t.TempDir()
	installPair(t, m, src, "first", "first-site", "1")
	installPair(t, m, src, "second", "second-site", "2")
	injected := errors.New("rollback pointer fail")
	m.pointer = &atomicfile.Writer{Replace: func(tmp, dest string) error {
		return injected
	}}
	if err := m.Rollback(); !errors.Is(err, injected) {
		t.Fatalf("got %v", err)
	}
	if activeGeoIP(t, m) != "second" {
		t.Fatalf("active mutated: %q", activeGeoIP(t, m))
	}
}

func TestGCFailureDoesNotBreakActive(t *testing.T) {
	m := newTestManager(t, &fakeValidator{}, 1024)
	src := t.TempDir()
	installPair(t, m, src, "a", "as", "1")
	installPair(t, m, src, "b", "bs", "2")
	m.removeAll = func(string) error {
		return errors.New("gc fail")
	}
	installPair(t, m, src, "c", "cs", "3")
	if activeGeoIP(t, m) != "c" {
		t.Fatalf("active %q", activeGeoIP(t, m))
	}
}

func TestRecoverOrphanNotActivated(t *testing.T) {
	m := newTestManager(t, &fakeValidator{}, 1024)
	src := t.TempDir()
	installPair(t, m, src, "good-ip", "good-site", "1")
	active, _ := m.ActivePaths()
	orphan := filepath.Join(m.setsDir(), "set-orphan-crash")
	if err := os.MkdirAll(orphan, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(orphan, fileGeoIP), []byte("orphan-ip"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(m.root, ".atomic-crash.tmp"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := m.Recover(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Fatal("orphan set must not remain as live data")
	}
	if _, err := os.Stat(filepath.Join(m.root, ".atomic-crash.tmp")); !os.IsNotExist(err) {
		t.Fatal("tmp leftover")
	}
	after, _ := m.ActivePaths()
	if after.SetID != active.SetID || activeGeoIP(t, m) != "good-ip" {
		t.Fatalf("active changed to %s", after.SetID)
	}
}

func TestMissingActiveFallsBackToPrevious(t *testing.T) {
	m := newTestManager(t, &fakeValidator{}, 1024)
	src := t.TempDir()
	installPair(t, m, src, "first", "first-site", "1")
	installPair(t, m, src, "second", "second-site", "2")
	st, _ := m.loadState()
	if err := os.RemoveAll(m.setDir(st.Active)); err != nil {
		t.Fatal(err)
	}
	p, err := m.ActivePaths()
	if !errors.Is(err, ErrMissingActiveSet) {
		t.Fatalf("got %v", err)
	}
	if p.SetID != st.Previous {
		t.Fatalf("fallback set %s want %s", p.SetID, st.Previous)
	}
	got, _ := os.ReadFile(p.GeoIPPath)
	if string(got) != "first" {
		t.Fatalf("fallback body %q", got)
	}
}

func TestActivePathsAPI(t *testing.T) {
	m := newTestManager(t, &fakeValidator{}, 1024)
	src := t.TempDir()
	installPair(t, m, src, "ip-body", "site-body", "9")
	p, err := m.ActivePaths()
	if err != nil {
		t.Fatal(err)
	}
	if p.SetID == "" || p.Version != "9" || p.GeoIPSHA256 == "" || p.GeoSiteSHA256 == "" {
		t.Fatalf("%+v", p)
	}
	if !strings.Contains(p.GeoIPPath, fileGeoIP) || !strings.Contains(p.GeoSitePath, fileGeoSite) {
		t.Fatalf("paths %+v", p)
	}
	raw, err := os.ReadFile(m.statePath())
	if err != nil {
		t.Fatal(err)
	}
	var st pointerState
	if err := json.Unmarshal(raw, &st); err != nil || st.Active != p.SetID {
		t.Fatalf("state %s err %v", raw, err)
	}
}

func TestDoesNotReadDatFullyIntoMemory(t *testing.T) {
	src, err := os.ReadFile("stream.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(src), "os.ReadFile(") && strings.Contains(string(src), "geoip.dat") {
		t.Fatal("stream path must not ReadFile DAT")
	}
	mgr, err := os.ReadFile("manager.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(mgr), "os.ReadFile(src)") {
		t.Fatal("manager must not slurp candidate DAT")
	}
}
