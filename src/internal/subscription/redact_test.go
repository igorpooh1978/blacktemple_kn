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

const (
	pathSecretMarker         = "PATH_SECRET_MARKER"
	querySecretMarker        = "QUERY_SECRET_MARKER"
	fragmentSecretMarker     = "FRAGMENT_SECRET_MARKER"
	userinfoSecretMarker     = "USERINFO_SECRET_MARKER"
	percentEncodedPathSecret = "%50%41%54%48%5F%53%45%43%52%45%54%5F%4D%41%52%4B%45%52"
)

func pathCredentialURL() string {
	return "https://" + userinfoSecretMarker + "@provider.invalid/sub/" +
		pathSecretMarker + "/" + percentEncodedPathSecret +
		"?token=" + querySecretMarker + "#" + fragmentSecretMarker
}

func urlSecretMarkers() []string {
	return []string{
		pathSecretMarker,
		querySecretMarker,
		fragmentSecretMarker,
		userinfoSecretMarker,
		percentEncodedPathSecret,
	}
}

func assertNoURLSecrets(t *testing.T, text string) {
	t.Helper()
	for _, m := range urlSecretMarkers() {
		if strings.Contains(text, m) {
			t.Fatalf("diagnostic leaked %q in %q", m, text)
		}
	}
	if strings.Contains(text, "/sub/") {
		t.Fatalf("diagnostic kept subscription path: %q", text)
	}
}

func formatters(v any) []string {
	return []string{
		fmt.Sprint(v),
		fmt.Sprintf("%v", v),
		fmt.Sprintf("%+v", v),
		fmt.Sprintf("%#v", v),
	}
}

func TestFetchedPathSecretsNeverAppearInDiagnostics(t *testing.T) {
	raw := pathCredentialURL()
	assertNoURLSecrets(t, sanitizeURL(raw))

	f := Fetched{origin: sanitizeURL(raw), ContentType: "text/plain", Body: []byte("ok")}
	for _, s := range formatters(f) {
		assertNoURLSecrets(t, s)
	}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	assertNoURLSecrets(t, string(b))
	if strings.Contains(string(b), "provider.invalid/sub/") {
		t.Fatal("JSON exposed raw subscription URL")
	}

	sub := WithSource(Subscription{Kind: "url", EntryCount: 1}, raw)
	for _, s := range formatters(sub) {
		assertNoURLSecrets(t, s)
	}

	parsed, err := Parse([]byte(fixtureVLESS()))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range formatters(parsed) {
		assertNoURLSecrets(t, s)
	}
	for _, e := range parsed.Entries {
		for _, s := range formatters(e) {
			assertNoURLSecrets(t, s)
		}
	}

	ce := ClassifyParse(ErrMalformed)
	for _, s := range formatters(ce) {
		assertNoURLSecrets(t, s)
	}

	want := "https://provider.invalid/[redacted]"
	if got := sanitizeURL(raw); got != want {
		t.Fatalf("sanitizeURL=%q want %s", got, want)
	}
	if strings.Contains(sanitizeURL(pathSecretMarker), pathSecretMarker) {
		t.Fatal("invalid URL must not echo the raw secret")
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(fixtureVLESS()))
	}))
	t.Cleanup(srv.Close)
	fetched, err := Fetch(context.Background(), srv.Client(), srv.URL+"/sub/"+pathSecretMarker+"?token="+querySecretMarker)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range formatters(fetched) {
		assertNoURLSecrets(t, s)
	}
	fb, err := json.Marshal(fetched)
	if err != nil {
		t.Fatal(err)
	}
	assertNoURLSecrets(t, string(fb))
}
