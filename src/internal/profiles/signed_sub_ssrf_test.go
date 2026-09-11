package profiles

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
)

func testHTTPResolver(t *testing.T, srv *httptest.Server) *HTTPResolver {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return NewHTTPResolver(HTTPResolverConfig{
		Client:       srv.Client(),
		HMACKey:      []byte(fixtureHMACKey),
		AllowedHosts: []string{u.Hostname()},
		AllowHTTP:    true,
		PermitLocal:  true,
	})
}

func TestHTTPResolverRejectsHTTPURL(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	res := NewHTTPResolver(HTTPResolverConfig{
		Client:       srv.Client(),
		HMACKey:      []byte(fixtureHMACKey),
		AllowedHosts: []string{u.Hostname()},
		PermitLocal:  true,
	})
	_, err = res.Resolve(context.Background(), NewSource("url", srv.URL+"/sub/fixture-token"))
	if !errors.Is(err, ErrResolverRejected) {
		t.Fatalf("got %v", err)
	}
	if hits.Load() != 0 {
		t.Fatal("http request was sent")
	}
}

func TestHTTPResolverRejectsUntrustedHost(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	res := NewHTTPResolver(HTTPResolverConfig{
		Client:       srv.Client(),
		HMACKey:      []byte(fixtureHMACKey),
		AllowedHosts: []string{"provider.example.test"},
		AllowHTTP:    true,
		PermitLocal:  true,
	})
	_, err := res.Resolve(context.Background(), NewSource("url", srv.URL+"/sub/fixture-token"))
	if !errors.Is(err, ErrResolverRejected) {
		t.Fatalf("got %v", err)
	}
	if hits.Load() != 0 {
		t.Fatal("signed request sent to untrusted host")
	}
}

func TestHTTPResolverRejectsCrossHostRedirect(t *testing.T) {
	var evilHits atomic.Int32
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		evilHits.Add(1)
		_, _ = io.WriteString(w, "stolen")
	}))
	defer evil.Close()
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+"/x", http.StatusFound)
	}))
	defer good.Close()
	res := testHTTPResolver(t, good)
	_, err := res.Resolve(context.Background(), NewSource("url", good.URL+"/sub/fixture-token"))
	if !errors.Is(err, ErrResolverRejected) {
		t.Fatalf("got %v", err)
	}
	if evilHits.Load() != 0 {
		t.Fatal("signature followed redirect to foreign host")
	}
}

func TestMissingHMACPreservesLKG(t *testing.T) {
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
	fail := New(Config{DataDir: dir, Resolver: LoadBlackKeyResolver(dir, NewResolverHTTPClient())})
	if err := fail.Resolve(context.Background(), p.ID); err == nil {
		t.Fatal("expected missing secret to fail")
	}
	got, err := fail.LastKnownGood(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.KeyID != lkg.KeyID || got.ServerID != lkg.ServerID {
		t.Fatal("LKG changed after missing HMAC")
	}
}

func TestHTTPResolverRejectsURLAbuse(t *testing.T) {
	res := NewHTTPResolver(HTTPResolverConfig{
		HMACKey:      []byte(fixtureHMACKey),
		AllowedHosts: []string{"provider.example.test"},
	})
	cases := []string{
		"https://user:pass@provider.example.test/sub/token",
		"https://provider.example.test/sub/token?x=1",
		"https://provider.example.test/sub/token#frag",
		"https://provider.example.test/api/sub/token",
		"https://provider.example.test/sub/token/extra",
		"https://provider.example.test/sub/",
		"https://provider.example.test/sub/..%2ftoken",
		"https://localhost/sub/token",
		"https://127.0.0.1/sub/token",
		"https://10.0.0.1/sub/token",
		"https://192.168.1.1/sub/token",
		"https://169.254.1.1/sub/token",
	}
	for _, raw := range cases {
		_, err := res.Resolve(context.Background(), NewSource("url", raw))
		if !errors.Is(err, ErrResolverRejected) {
			t.Fatalf("%s: got %v", raw, err)
		}
	}
}

func TestHTTPResolverAllowlistHTTPSWorks(t *testing.T) {
	share := resolvedWSTLSShare()
	payload, err := json.Marshal(map[string]any{"servers": []map[string]string{{"key": share}}})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(payload)
	}))
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	res := NewHTTPResolver(HTTPResolverConfig{
		Client:       srv.Client(),
		HMACKey:      []byte(fixtureHMACKey),
		AllowedHosts: []string{u.Hostname()},
		PermitLocal:  true,
	})
	got, err := res.Resolve(context.Background(), NewSource("url", srv.URL+"/sub/fixture-token"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("entries=%d", len(got))
	}
}

func TestLoadBlackKeyResolverReadsLocalFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "secrets"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "secrets", "blackkey-hmac.key"), []byte(fixtureHMACKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "provider.json"), []byte(`{"allowedHosts":["provider.example.test"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	res := LoadBlackKeyResolver(dir, NewResolverHTTPClient())
	if _, ok := res.(*HTTPResolver); !ok {
		t.Fatalf("got %T", res)
	}
	info, err := os.Stat(filepath.Join(dir, "secrets", "blackkey-hmac.key"))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("hmac mode %o", info.Mode().Perm())
	}
}

func TestHTTPResolverNotConfiguredWithoutKey(t *testing.T) {
	res := NewHTTPResolver(HTTPResolverConfig{AllowedHosts: []string{"provider.example.test"}})
	_, err := res.Resolve(context.Background(), NewSource("url", "https://provider.example.test/sub/token"))
	if !errors.Is(err, ErrResolverNotConfigured) {
		t.Fatalf("got %v", err)
	}
}

func TestRedirectPolicyIsSetOnDefaultClient(t *testing.T) {
	c := NewResolverHTTPClient()
	if c.CheckRedirect == nil {
		t.Fatal("CheckRedirect required")
	}
	orig, err := http.NewRequest(http.MethodGet, "https://provider.example.test/sub/token", nil)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := http.NewRequest(http.MethodGet, "https://evil.example.test/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.CheckRedirect(foreign, []*http.Request{orig}); !errors.Is(err, errResolverRedirect) {
		t.Fatalf("foreign: %v", err)
	}
	same, err := http.NewRequest(http.MethodGet, "https://provider.example.test/other", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.CheckRedirect(same, []*http.Request{orig}); err != nil {
		t.Fatalf("same host: %v", err)
	}
	httpNext, err := http.NewRequest(http.MethodGet, "http://provider.example.test/sub/token", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.CheckRedirect(httpNext, []*http.Request{orig}); !errors.Is(err, errResolverRedirect) {
		t.Fatalf("http redirect: %v", err)
	}
}

func TestLoadBlackKeyResolverSkipsLoopbackAllowlist(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "secrets"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "secrets", "blackkey-hmac.key"), []byte(fixtureHMACKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "provider.json"), []byte(`{"allowedHosts":["localhost","127.0.0.1"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	res := LoadBlackKeyResolver(dir, NewResolverHTTPClient())
	if _, ok := res.(notConfiguredResolver); !ok {
		t.Fatalf("got %T", res)
	}
}
