package subscription

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProbeHttptest(t *testing.T) {
	plain := fixtureVLESS() + "\n" + fixtureVLESSNL() + "\n" + fixtureTrojan()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("subscription-userinfo", "upload=0; download=0")
		_, _ = w.Write([]byte(plain))
	}))
	defer srv.Close()

	got, err := Probe(context.Background(), srv.Client(), srv.URL+"/sub?token="+fixtureUUID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ContentType != "text/plain" {
		t.Fatalf("content-type=%s", got.ContentType)
	}
	if got.Encoding != encIdentity {
		t.Fatalf("encoding=%s", got.Encoding)
	}
	if got.EntryCount != 3 {
		t.Fatalf("entries=%d", got.EntryCount)
	}
	if got.Protocols["vless"] != 2 || got.Protocols["trojan"] != 1 {
		t.Fatalf("protocols=%v", got.Protocols)
	}
	if !got.UserInfoHeader {
		t.Fatal("userinfo header")
	}
	foundNL := false
	for _, h := range got.CountryHints {
		if h == "NL" {
			foundNL = true
		}
	}
	if !foundNL {
		t.Fatalf("country hints=%v", got.CountryHints)
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecret(t, string(raw))
	assertNoSecret(t, got.String())
	assertNoSecret(t, fmt.Sprintf("%#v", got))
}

func TestProbeEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
	}))
	defer srv.Close()
	_, err := Probe(context.Background(), srv.Client(), srv.URL)
	if err != ErrEmpty {
		t.Fatalf("got %v", err)
	}
}

func TestProbeMalformed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("garbage " + fixtureUUID))
	}))
	defer srv.Close()
	got, err := Probe(context.Background(), srv.Client(), srv.URL)
	if err == nil {
		t.Fatal("expected error")
	}
	assertNoSecret(t, err.Error())
	assertNoSecret(t, fmt.Sprintf("%v", got))
}

func TestFetchRejectsNonHTTP(t *testing.T) {
	_, err := Fetch(context.Background(), nil, "file:///tmp/x")
	if err != ErrUnsupportedURL {
		t.Fatalf("got %v", err)
	}
}

func TestFetchedStringRedactsQuery(t *testing.T) {
	f := Fetched{origin: sanitizeURL("https://example.test/sub?token=" + fixtureUUID), ContentType: "text/plain", Body: []byte(fixtureVLESS())}
	assertNoSecret(t, f.String())
	if strings.Contains(f.String(), "token=") {
		t.Fatal("query must be stripped")
	}
	if strings.Contains(f.String(), "/sub") {
		t.Fatal("path must not appear in diagnostics")
	}
}
