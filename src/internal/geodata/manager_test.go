package geodata

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
		MaxBackups:   2,
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

func TestAtomicReplace(t *testing.T) {
	v := &fakeValidator{}
	m := newTestManager(t, v, 1024)
	src := t.TempDir()
	ip, site, ipSum, siteSum := writeTempPair(t, src, "geoip-v1", "geosite-v1")
	if err := m.Install(context.Background(), Candidate{
		GeoIPPath: ip, GeoSitePath: site, Source: "manual", Version: "1",
		GeoIPSHA256: ipSum, GeoSiteSHA256: siteSum,
	}); err != nil {
		t.Fatal(err)
	}
	snap := m.Active()
	if snap.GeoIP.Status != StatusActive || snap.GeoSite.Status != StatusActive {
		t.Fatalf("status %+v", snap)
	}
	got, err := os.ReadFile(filepath.Join(m.slotPath(slotActive), fileGeoIP))
	if err != nil || string(got) != "geoip-v1" {
		t.Fatalf("active geoip %q %v", got, err)
	}

	ip2, site2, ipSum2, siteSum2 := writeTempPair(t, src, "geoip-v2", "geosite-v2")
	if err := m.Install(context.Background(), Candidate{
		GeoIPPath: ip2, GeoSitePath: site2, Source: "manual", Version: "2",
		GeoIPSHA256: ipSum2, GeoSiteSHA256: siteSum2,
	}); err != nil {
		t.Fatal(err)
	}
	got, err = os.ReadFile(filepath.Join(m.slotPath(slotActive), fileGeoIP))
	if err != nil || string(got) != "geoip-v2" {
		t.Fatalf("replaced %q %v", got, err)
	}
	prev, err := os.ReadFile(filepath.Join(m.slotPath(slotPrevious), fileGeoIP))
	if err != nil || string(prev) != "geoip-v1" {
		t.Fatalf("previous %q %v", prev, err)
	}
}

func TestFailedValidatorLeavesWorkingUntouched(t *testing.T) {
	ok := &fakeValidator{}
	m := newTestManager(t, ok, 1024)
	src := t.TempDir()
	ip, site, ipSum, siteSum := writeTempPair(t, src, "good-ip", "good-site")
	if err := m.Install(context.Background(), Candidate{
		GeoIPPath: ip, GeoSitePath: site, Source: "manual", Version: "1",
		GeoIPSHA256: ipSum, GeoSiteSHA256: siteSum,
	}); err != nil {
		t.Fatal(err)
	}

	m.validate = &fakeValidator{err: errors.New("dat header bogus")}
	ip2, site2, ipSum2, siteSum2 := writeTempPair(t, src, "bad-ip", "bad-site")
	err := m.Install(context.Background(), Candidate{
		GeoIPPath: ip2, GeoSitePath: site2, Source: "manual", Version: "2",
		GeoIPSHA256: ipSum2, GeoSiteSHA256: siteSum2,
	})
	if !errors.Is(err, ErrValidate) {
		t.Fatalf("got %v", err)
	}
	got, err := os.ReadFile(filepath.Join(m.slotPath(slotActive), fileGeoIP))
	if err != nil || string(got) != "good-ip" {
		t.Fatalf("working file changed: %q %v", got, err)
	}
	if m.Active().GeoIP.Version != "1" {
		t.Fatalf("active metadata mutated: %+v", m.Active())
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
	if m.fileExists(slotActive, fileGeoIP) {
		t.Fatal("active must not be created on checksum mismatch")
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
	if m.fileExists(slotActive, fileGeoIP) {
		t.Fatal("active must not be created when oversized")
	}
}

func TestBackupRetention(t *testing.T) {
	m := newTestManager(t, &fakeValidator{}, 1024)
	src := t.TempDir()
	for i, body := range []string{"v1", "v2", "v3", "v4"} {
		ip, site, ipSum, siteSum := writeTempPair(t, src, "ip-"+body, "site-"+body)
		if err := m.Install(context.Background(), Candidate{
			GeoIPPath: ip, GeoSitePath: site, Source: "manual", Version: body,
			GeoIPSHA256: ipSum, GeoSiteSHA256: siteSum,
		}); err != nil {
			t.Fatalf("install %d: %v", i, err)
		}
	}
	slots := m.backupSlots()
	if len(slots) != 2 {
		t.Fatalf("backups %v want 2", slots)
	}
	active, _ := os.ReadFile(filepath.Join(m.slotPath(slotActive), fileGeoIP))
	prev, _ := os.ReadFile(filepath.Join(m.slotPath(slotPrevious), fileGeoIP))
	prev2, _ := os.ReadFile(filepath.Join(m.slotPath(slotPrevious2), fileGeoIP))
	if string(active) != "ip-v4" || string(prev) != "ip-v3" || string(prev2) != "ip-v2" {
		t.Fatalf("retention active=%s prev=%s prev2=%s", active, prev, prev2)
	}
	if _, err := os.Stat(filepath.Join(m.root, "geoip.dat.bak")); err == nil {
		t.Fatal("unbounded .bak must not exist")
	}
}

func TestRollbackPrevious(t *testing.T) {
	m := newTestManager(t, &fakeValidator{}, 1024)
	src := t.TempDir()
	ip, site, ipSum, siteSum := writeTempPair(t, src, "first", "first-site")
	if err := m.Install(context.Background(), Candidate{
		GeoIPPath: ip, GeoSitePath: site, Source: "manual", Version: "1",
		GeoIPSHA256: ipSum, GeoSiteSHA256: siteSum,
	}); err != nil {
		t.Fatal(err)
	}
	ip2, site2, ipSum2, siteSum2 := writeTempPair(t, src, "second", "second-site")
	if err := m.Install(context.Background(), Candidate{
		GeoIPPath: ip2, GeoSitePath: site2, Source: "manual", Version: "2",
		GeoIPSHA256: ipSum2, GeoSiteSHA256: siteSum2,
	}); err != nil {
		t.Fatal(err)
	}
	if err := m.Rollback(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(m.slotPath(slotActive), fileGeoIP))
	if err != nil || string(got) != "first" {
		t.Fatalf("rollback %q %v", got, err)
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
