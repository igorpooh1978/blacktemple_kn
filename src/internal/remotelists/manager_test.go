package remotelists

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type constBackoff time.Duration

func (c constBackoff) Next(int) time.Duration { return time.Duration(c) }

func testManager(t *testing.T, srv *httptest.Server) *Manager {
	t.Helper()
	m, err := NewManager(t.TempDir(), &Guard{})
	if err != nil {
		t.Fatal(err)
	}
	m.Client = srv.Client()
	m.Backoff = constBackoff(0)
	m.Sleep = func(ctx context.Context, d time.Duration) error { return ctx.Err() }
	m.Attempts = 3
	return m
}

func domainDesc(id, rawURL string) Descriptor {
	return Descriptor{
		ID:            id,
		Type:          TypeDomains,
		URL:           rawURL,
		TrustedOrigin: true,
	}
}

func TestUpdateHTTP200Download(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "example.com\ncdn.example.net\n")
	}))
	t.Cleanup(srv.Close)
	m := testManager(t, srv)
	res, err := m.Update(context.Background(), domainDesc("dom", srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusUpdated || res.Parsed.Entries != 2 {
		t.Fatalf("res=%s parsed=%s err=%v", res, res.Parsed, res.ParseError)
	}
}

func TestUpdateHTTP304CacheAndETag(t *testing.T) {
	var gotIfNone atomic.Int32
	const etag = `"v1"`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == etag {
			gotIfNone.Add(1)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		io.WriteString(w, "ok.example\n")
	}))
	t.Cleanup(srv.Close)
	m := testManager(t, srv)
	desc := domainDesc("etag", srv.URL)
	first, err := m.Update(context.Background(), desc)
	if err != nil || first.ETag != etag {
		t.Fatalf("first=%s err=%v", first, err)
	}
	second, err := m.Update(context.Background(), desc)
	if err != nil {
		t.Fatal(err)
	}
	if second.Status != StatusNotModified {
		t.Fatalf("status=%s", second.Status)
	}
	if gotIfNone.Load() < 1 {
		t.Fatal("If-None-Match not sent")
	}
	if string(second.Body) != "ok.example\n" {
		t.Fatalf("body=%q", second.Body)
	}
}

func TestUpdateLastModifiedConditional(t *testing.T) {
	const lm = "Wed, 21 Oct 2015 07:28:00 GMT"
	var gotIMS atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-Modified-Since") == lm {
			gotIMS.Add(1)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Last-Modified", lm)
		io.WriteString(w, "lm.example\n")
	}))
	t.Cleanup(srv.Close)
	m := testManager(t, srv)
	desc := domainDesc("lm", srv.URL)
	if _, err := m.Update(context.Background(), desc); err != nil {
		t.Fatal(err)
	}
	res, err := m.Update(context.Background(), desc)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusNotModified || gotIMS.Load() < 1 {
		t.Fatalf("status=%s ims=%d", res.Status, gotIMS.Load())
	}
	if res.LastModified != lm {
		t.Fatalf("last-modified=%q", res.LastModified)
	}
}

func TestUpdateTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	t.Cleanup(func() {
		close(release)
		srv.Close()
	})
	m := testManager(t, srv)
	m.Timeout = 50 * time.Millisecond
	m.Attempts = 1
	_, err := m.Update(context.Background(), domainDesc("to", srv.URL))
	if err != ErrTimeout {
		t.Fatalf("got %v", err)
	}
}

func TestUpdateRetryBackoff(t *testing.T) {
	var hits atomic.Int32
	var sleeps []time.Duration
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		io.WriteString(w, "retry.example\n")
	}))
	t.Cleanup(srv.Close)
	m := testManager(t, srv)
	m.Backoff = constBackoff(5 * time.Millisecond)
	m.Sleep = func(ctx context.Context, d time.Duration) error {
		sleeps = append(sleeps, d)
		return nil
	}
	res, err := m.Update(context.Background(), domainDesc("retry", srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusUpdated || hits.Load() != 3 {
		t.Fatalf("hits=%d status=%s", hits.Load(), res.Status)
	}
	if len(sleeps) != 2 {
		t.Fatalf("sleeps=%v", sleeps)
	}
}

func TestUpdateOversizedDownload(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, strings.Repeat("a.example\n", 40))
	}))
	t.Cleanup(srv.Close)
	m := testManager(t, srv)
	desc := domainDesc("big", srv.URL)
	desc.MaxBytes = 32
	_, err := m.Update(context.Background(), desc)
	if err != ErrTooLarge {
		t.Fatalf("got %v", err)
	}
}

func TestUpdateChecksumMismatch(t *testing.T) {
	body := []byte("pin.example\n")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	t.Cleanup(srv.Close)
	m := testManager(t, srv)
	desc := domainDesc("sum", srv.URL)
	desc.SHA256 = strings.Repeat("0", 64)
	_, err := m.Update(context.Background(), desc)
	if err != ErrChecksumMismatch {
		t.Fatalf("got %v", err)
	}
}

func TestUpdateChecksumPinnedOK(t *testing.T) {
	body := []byte("pin.example\n")
	sum := sha256.Sum256(body)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	t.Cleanup(srv.Close)
	m := testManager(t, srv)
	desc := domainDesc("sumok", srv.URL)
	desc.SHA256 = hex.EncodeToString(sum[:])
	res, err := m.Update(context.Background(), desc)
	if err != nil || res.SHA256 != desc.SHA256 {
		t.Fatalf("res=%s err=%v", res, err)
	}
}

func TestUpdateInvalidContentKeepsCache(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) == 1 {
			io.WriteString(w, "good.example\n")
			return
		}
		w.Write([]byte("bad\x00.com\n"))
	}))
	t.Cleanup(srv.Close)
	m := testManager(t, srv)
	desc := domainDesc("inv", srv.URL)
	if _, err := m.Update(context.Background(), desc); err != nil {
		t.Fatal(err)
	}
	res, err := m.Update(context.Background(), desc)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusLastKnownGood || string(res.Body) != "good.example\n" {
		t.Fatalf("status=%s body=%q err=%v", res.Status, res.Body, err)
	}
}

func TestAtomicReplaceAndLastKnownGood(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch n.Add(1) {
		case 1:
			io.WriteString(w, "one.example\n")
		case 2:
			io.WriteString(w, "two.example\n")
		default:
			w.WriteHeader(http.StatusBadGateway)
		}
	}))
	t.Cleanup(srv.Close)
	m := testManager(t, srv)
	desc := domainDesc("atom", srv.URL)
	if _, err := m.Update(context.Background(), desc); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Update(context.Background(), desc); err != nil {
		t.Fatal(err)
	}
	dir, err := listDir(m.Dir, desc.ID)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(bodyPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "two.example\n" {
		t.Fatalf("on disk %q", raw)
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "list-*.tmp"))
	if len(matches) != 0 {
		t.Fatalf("tmp leftovers %v", matches)
	}
	res, err := m.Update(context.Background(), desc)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusLastKnownGood || string(res.Body) != "two.example\n" {
		t.Fatalf("lkg=%s body=%q", res.Status, res.Body)
	}
}

func TestBadRedirectBlocked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "file:///etc/passwd", http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	m := testManager(t, srv)
	m.Attempts = 1
	_, err := m.Update(context.Background(), domainDesc("redir", srv.URL))
	if err != ErrRedirect && !isRedirect(err) {
		t.Fatalf("got %v", err)
	}
}

func isRedirect(err error) bool {
	if err == nil {
		return false
	}
	return err == ErrRedirect || strings.Contains(err.Error(), "redirect")
}

func TestLoopbackBlockedWithoutTrust(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("must not be reached")
	}))
	t.Cleanup(srv.Close)
	m, err := NewManager(t.TempDir(), &Guard{})
	if err != nil {
		t.Fatal(err)
	}
	m.Attempts = 1
	desc := Descriptor{ID: "lb", Type: TypeDomains, URL: srv.URL, TrustedOrigin: false}
	_, err = m.Update(context.Background(), desc)
	if err != ErrBlockedDestination {
		t.Fatalf("got %v url=%s", err, srv.URL)
	}
}

func TestPrivateIPSSRFBlocked(t *testing.T) {
	m, err := NewManager(t.TempDir(), &Guard{})
	if err != nil {
		t.Fatal(err)
	}
	m.Attempts = 1
	desc := Descriptor{
		ID:            "priv",
		Type:          TypeDomains,
		URL:           "https://192.168.0.55/list",
		TrustedOrigin: false,
	}
	_, err = m.Update(context.Background(), desc)
	if err != ErrBlockedDestination {
		t.Fatalf("got %v", err)
	}
}

func TestCountriesCacheWithoutParser(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"countries":[]}`)
	}))
	t.Cleanup(srv.Close)
	m := testManager(t, srv)
	desc := Descriptor{ID: "countries", Type: TypeCountries, URL: srv.URL, TrustedOrigin: true}
	res, err := m.Update(context.Background(), desc)
	if err != nil {
		t.Fatal(err)
	}
	if res.ParseError != ErrProviderFormatNotImplemented {
		t.Fatalf("parse=%v", res.ParseError)
	}
	if len(res.Body) == 0 {
		t.Fatal("body must be cached")
	}
}
