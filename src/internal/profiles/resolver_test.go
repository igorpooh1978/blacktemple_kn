package profiles

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/igorpooh1978/blacktemple_kn/src/internal/atomicfile"
	"github.com/igorpooh1978/blacktemple_kn/src/internal/subscription"
	"github.com/igorpooh1978/blacktemple_kn/src/internal/xray"
)

type fakeResolver struct {
	entries []subscription.ParsedShare
	err     error
	hits    int
}

func (f *fakeResolver) Resolve(_ context.Context, source Source) ([]subscription.ParsedShare, error) {
	f.hits++
	_ = source.Raw()
	if f.err != nil {
		return nil, f.err
	}
	return f.entries, nil
}

func parseShares(t *testing.T, body string) []subscription.ParsedShare {
	t.Helper()
	parsed, err := subscription.Parse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	return parsed.Entries
}

func bootstrapHTTP(t *testing.T, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(body))
	}))
}

func TestFreshBlackKeyResolutionReturnsRunnableCandidates(t *testing.T) {
	srv := bootstrapHTTP(t, bootstrapRealityShare())
	defer srv.Close()
	res := &fakeResolver{entries: parseShares(t, resolvedWSTLSShare())}
	svc := New(Config{Client: srv.Client(), Resolver: res})
	p, err := svc.Import(context.Background(), ImportRequest{BlackKey: srv.URL + "/sub?token=fixture", Name: "bk"})
	if err != nil {
		t.Fatal(err)
	}
	if res.hits == 0 {
		t.Fatal("resolver was not invoked")
	}
	if p.ResolutionState != ResolutionResolved {
		t.Fatalf("ResolutionState=%q", p.ResolutionState)
	}
	ks, err := svc.Keys(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(ks) == 0 {
		t.Fatal("expected runnable candidates")
	}
}

func TestRawBootstrapNeverBecomesRunnableAfterResolve(t *testing.T) {
	srv := bootstrapHTTP(t, bootstrapRealityShare())
	defer srv.Close()
	res := &fakeResolver{entries: parseShares(t, resolvedWSTLSShare())}
	svc := New(Config{Client: srv.Client(), Resolver: res})
	p, err := svc.Import(context.Background(), ImportRequest{BlackKey: srv.URL + "/sub", Name: "bk"})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Resolve(context.Background(), p.ID); err != nil {
		t.Fatal(err)
	}
	ks, err := svc.Keys(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range ks {
		if len(k.Material()) == 4 {
			t.Fatal("bootstrap id published as runnable")
		}
		if strings.EqualFold(k.Params().RealityPublicKey, "abcde") {
			t.Fatal("bootstrap pbk published")
		}
	}
}

func TestResolvedVLESSWSTLSNormalizes(t *testing.T) {
	entries := parseShares(t, resolvedWSTLSShare())
	if len(entries) != 1 {
		t.Fatalf("entries=%d", len(entries))
	}
	e := entries[0]
	if !strings.EqualFold(e.Protocol, "vless") || !strings.EqualFold(e.Transport, "ws") || !strings.EqualFold(e.Security, "tls") {
		t.Fatalf("got %s %s %s", e.Protocol, e.Transport, e.Security)
	}
	if !xray.InspectVLESSUserID(e.Material()).CanonicalUUID {
		t.Fatal("canonical UUID required")
	}
	if strings.EqualFold(e.Security, "reality") {
		t.Fatal("Reality must be absent")
	}
}

func TestResolverFailurePreservesOldResolvedSet(t *testing.T) {
	dir := t.TempDir()
	svc := New(Config{DataDir: dir})
	p, err := svc.CreateBlackKeyShell("bk")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ImportResolvedJSON(p.ID, []byte(startLoopFixture)); err != nil {
		t.Fatal(err)
	}
	before, err := svc.Keys(p.ID)
	if err != nil || len(before) == 0 {
		t.Fatal(err)
	}
	fail := &fakeResolver{err: errors.New("resolver down")}
	svc2 := New(Config{DataDir: dir, Resolver: fail})
	if err := svc2.Resolve(context.Background(), p.ID); err == nil {
		t.Fatal("expected resolver error")
	}
	after, err := svc2.Keys(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("keys mutated on failure got=%d want %d", len(after), len(before))
	}
}

func TestResolverFailurePreservesLKG(t *testing.T) {
	dir := t.TempDir()
	svc := New(Config{DataDir: dir})
	p, err := svc.CreateBlackKeyShell("bk")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ImportResolvedJSON(p.ID, []byte(startLoopFixture)); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CommitLastKnownGood(p.ID); err != nil {
		t.Fatal(err)
	}
	lkg, err := svc.LastKnownGood(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	fail := New(Config{DataDir: dir, Resolver: &fakeResolver{err: errors.New("resolver down")}})
	if err := fail.Resolve(context.Background(), p.ID); err == nil {
		t.Fatal("expected resolver error")
	}
	got, err := fail.LastKnownGood(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.KeyID != lkg.KeyID || got.ServerID != lkg.ServerID {
		t.Fatal("LKG changed after resolver failure")
	}
}

func TestResolverResultPersistsAtomically(t *testing.T) {
	dir := t.TempDir()
	svc := New(Config{DataDir: dir})
	p, err := svc.CreateBlackKeyShell("bk")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ImportResolvedJSON(p.ID, []byte(startLoopFixture)); err != nil {
		t.Fatal(err)
	}
	good, err := os.ReadFile(filepath.Join(dir, "profiles.json"))
	if err != nil {
		t.Fatal(err)
	}
	fail := New(Config{
		DataDir:  dir,
		Resolver: &fakeResolver{entries: parseShares(t, resolvedWSTLSShare()+"\n"+resolvedWSTLSShare())},
		Writer:   &atomicfile.Writer{Replace: func(tmp, dest string) error { return errors.New("injected") }},
	})
	if err := fail.Resolve(context.Background(), p.ID); err == nil {
		t.Fatal("persist must fail")
	}
	now, err := os.ReadFile(filepath.Join(dir, "profiles.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(now) != string(good) {
		t.Fatal("disk replaced on persist failure")
	}
	ks, err := fail.Keys(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	svcGood := New(Config{DataDir: dir})
	want, err := svcGood.Keys(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(ks) != len(want) {
		t.Fatalf("memory mutated keys=%d want %d", len(ks), len(want))
	}
}

func TestRestartRestoresAutomaticResolvedWithoutProvider(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(bootstrapRealityShare()))
	}))
	defer srv.Close()
	dir := t.TempDir()
	res := &fakeResolver{entries: parseShares(t, resolvedWSTLSShare())}
	svc := New(Config{Client: srv.Client(), DataDir: dir, Resolver: res})
	p, err := svc.Import(context.Background(), ImportRequest{BlackKey: srv.URL + "/sub", Name: "bk"})
	if err != nil {
		t.Fatal(err)
	}
	ks, err := svc.Keys(p.ID)
	if err != nil || len(ks) == 0 {
		t.Fatalf("resolved keys=%d %v", len(ks), err)
	}
	before := hits
	srv.Close()
	svc2 := New(Config{DataDir: dir})
	ks2, err := svc2.Keys(p.ID)
	if err != nil || len(ks2) != len(ks) {
		t.Fatalf("restored=%d want %d %v", len(ks2), len(ks), err)
	}
	if hits != before {
		t.Fatalf("provider refetch hits=%d", hits)
	}
}

func TestResolverSecretsAbsentFromDiagnostics(t *testing.T) {
	srv := bootstrapHTTP(t, bootstrapRealityShare())
	defer srv.Close()
	res := &fakeResolver{entries: parseShares(t, resolvedWSTLSShare())}
	svc := New(Config{Client: srv.Client(), Resolver: res})
	p, err := svc.Import(context.Background(), ImportRequest{BlackKey: srv.URL + "/secret-token", Name: "bk"})
	if err != nil {
		t.Fatal(err)
	}
	dump := p.String() + p.GoString() + NewSource("url", srv.URL).String()
	for _, secret := range []string{resolvedUUID, "secret-token", "abcde", "/vless"} {
		if strings.Contains(dump, secret) {
			t.Fatalf("leaked %s", secret)
		}
	}
}

func TestResolverSourcesNeverTouchNetfilter(t *testing.T) {
	files := []string{"resolver.go", "service.go", "resolved.go", "signed_sub.go"}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		for _, bad := range []string{"ExecuteNetfilterReconcile", "S05xkeen", "iptables", "ipset"} {
			if strings.Contains(s, bad) {
				t.Errorf("%s contains %s", f, bad)
			}
		}
	}
}
