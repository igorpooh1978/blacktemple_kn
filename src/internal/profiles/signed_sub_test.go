package profiles

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const fixtureHMACKey = "fixture-blackkey-hmac-test-key-not-production"

func TestHTTPResolverSignedGETReturnsWSCandidates(t *testing.T) {
	const token = "fixture-token"
	fixedNow := time.Unix(1700000000, 0).UTC()
	appID := "11111111-1111-4111-8111-111111111111"
	share := resolvedWSTLSShare()
	body, _ := json.Marshal(map[string]any{
		"status":         "success",
		"all_countries":  []string{"DE"},
		"role_countries": []string{"DE"},
		"servers":        []map[string]string{{"country": "DE", "server_class": "standart", "key": share}},
	})
	var saw struct {
		method string
		path   string
		query  string
		ua     string
		sig    string
		ts     string
		app    string
		hwid   string
		device string
		auth   bool
		cookie bool
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		saw.method = r.Method
		saw.path = r.URL.Path
		saw.query = r.URL.RawQuery
		saw.ua = r.Header.Get("User-Agent")
		saw.sig = r.Header.Get("X-Signature")
		saw.ts = r.Header.Get("X-Timestamp")
		saw.app = r.Header.Get("X-App-Id")
		saw.hwid = r.Header.Get("X-hwid")
		saw.device = r.Header.Get("device")
		saw.auth = r.Header.Get("Authorization") != ""
		saw.cookie = r.Header.Get("Cookie") != ""
		if r.Header.Get("X-Signature") == "" {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte(bootstrapRealityShare()))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	res := testHTTPResolver(t, srv)
	res.now = func() time.Time { return fixedNow }
	n := 0
	res.newID = func() string {
		n++
		if n == 1 {
			return appID
		}
		return "22222222-2222-4222-8222-222222222222"
	}
	got, err := res.Resolve(context.Background(), NewSource("url", srv.URL+"/sub/"+token))
	if err != nil {
		t.Fatal(err)
	}
	if saw.method != http.MethodGet {
		t.Fatalf("method=%q", saw.method)
	}
	if saw.path != "/sub/"+token {
		t.Fatalf("path=%q", saw.path)
	}
	if saw.query != "" {
		t.Fatalf("query=%q", saw.query)
	}
	if saw.ua != blackKeyUserAgent {
		t.Fatalf("ua=%q", saw.ua)
	}
	if saw.auth || saw.cookie {
		t.Fatal("Authorization or Cookie present")
	}
	if saw.device != blackKeyDevice {
		t.Fatalf("device=%q", saw.device)
	}
	wantSig := blackKeySignature([]byte(fixtureHMACKey), blackKeyStringToSign("/sub/"+token, "1700000000", appID))
	if saw.sig != wantSig {
		t.Fatal("HMAC mismatch")
	}
	if saw.ts != "1700000000" || saw.app != appID {
		t.Fatalf("ts=%q app=%q", saw.ts, saw.app)
	}
	if len(got) != 1 {
		t.Fatalf("entries=%d", len(got))
	}
	if !strings.EqualFold(got[0].Protocol, "vless") || !strings.EqualFold(got[0].Transport, "ws") || !strings.EqualFold(got[0].Security, "tls") {
		t.Fatalf("got %s %s %s", got[0].Protocol, got[0].Transport, got[0].Security)
	}
	if strings.EqualFold(got[0].Security, "reality") {
		t.Fatal("reality must be absent")
	}
}

func TestHTTPResolverUnsignedResponseIsNotUsedAsJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(bootstrapRealityShare()))
	}))
	defer srv.Close()
	res := testHTTPResolver(t, srv)
	got, err := res.Resolve(context.Background(), NewSource("url", srv.URL+"/sub/fixture-token"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("entries=%d", len(got))
	}
	if !strings.EqualFold(got[0].Security, "reality") {
		t.Fatalf("security=%q", got[0].Security)
	}
}

func TestHTTPResolverImportUsesSignedFixture(t *testing.T) {
	share := resolvedWSTLSShare()
	payload, _ := json.Marshal(map[string]any{
		"servers": []map[string]string{{"key": share, "country": "DE", "server_class": "standart"}},
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Signature") == "" {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, bootstrapRealityShare())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(payload)
	}))
	defer srv.Close()
	res := testHTTPResolver(t, srv)
	svc := New(Config{Client: srv.Client(), Resolver: res})
	p, err := svc.Import(context.Background(), ImportRequest{BlackKey: srv.URL + "/sub/fixture-token", Name: "bk"})
	if err != nil {
		t.Fatal(err)
	}
	if p.ResolutionState != ResolutionResolved {
		t.Fatalf("ResolutionState=%q", p.ResolutionState)
	}
	ks, err := svc.Keys(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(ks) == 0 {
		t.Fatal("expected signed JSON candidates")
	}
	for _, k := range ks {
		if strings.EqualFold(k.Params().RealityPublicKey, "abcde") {
			t.Fatal("bootstrap published")
		}
	}
}

func TestHTTPResolverRejectsMissingToken(t *testing.T) {
	res := NewHTTPResolver(HTTPResolverConfig{
		HMACKey:      []byte(fixtureHMACKey),
		AllowedHosts: []string{"example.com"},
	})
	_, err := res.Resolve(context.Background(), NewSource("url", "https://example.com/"))
	if !errors.Is(err, ErrResolverRejected) {
		t.Fatalf("got %v", err)
	}
}

func TestParseBlackSubBodyRequiresServersKey(t *testing.T) {
	_, err := parseBlackSubBody([]byte(`{"status":"success","servers":[]}`))
	if err != ErrResolverInvalidResponse {
		t.Fatalf("got %v", err)
	}
}

func TestHTTPResolverSecretsStayOutOfErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "token=super-secret", http.StatusBadGateway)
	}))
	defer srv.Close()
	res := testHTTPResolver(t, srv)
	_, err := res.Resolve(context.Background(), NewSource("url", srv.URL+"/sub/super-secret"))
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "super-secret") {
		t.Fatalf("leaked: %v", err)
	}
}
