package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"github.com/igorpooh1978/blacktemple_kn/src/internal/app"
)

func testApp(t *testing.T) *app.App {
	t.Helper()
	a, err := app.New(app.Config{
		Listen:     "127.0.0.1:7480",
		ListenMode: "loopback",
		DataDir:    t.TempDir(),
		Version:    version,
		UI:         fstest.MapFS{"index.html": {Data: []byte("ok")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestHealth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	testApp(t).Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var body map[string]bool
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body["ok"] {
		t.Fatalf("unexpected body %s", rec.Body.String())
	}
}

func TestStatusContractKeys(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	rec := httptest.NewRecorder()
	testApp(t).Handler().ServeHTTP(rec, req)
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"connection", "routing", "serverMode", "key", "geodata", "xray"} {
		if _, ok := body[k]; !ok {
			t.Fatalf("missing key %s", k)
		}
	}
}
