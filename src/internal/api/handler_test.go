package api_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/igorpooh1978/blacktemple_kn/src/internal/api"
	"github.com/igorpooh1978/blacktemple_kn/src/internal/app"
	"github.com/igorpooh1978/blacktemple_kn/src/internal/auth"
)

const testPassword = "test-pass-9"

type stubStatus struct{}

func (stubStatus) Status() api.Status {
	return api.Status{
		Connection: "disconnected",
		Country:    "",
		Routing:    "smart",
		ServerMode: "auto",
		Key:        "missing",
		Geodata:    "missing",
		Xray: api.XrayProcess{
			State: "STOPPED",
			PID:   nil,
		},
	}
}

func newServer(t *testing.T, ttl time.Duration) (*api.Server, *auth.Service, string) {
	t.Helper()
	return newServerFromDir(t, t.TempDir(), ttl)
}

func newServerFromDir(t *testing.T, dir string, ttl time.Duration) (*api.Server, *auth.Service, string) {
	t.Helper()
	svc, err := auth.New(auth.Config{DataDir: dir, Iterations: 20000, SessionTTL: ttl})
	if err != nil {
		t.Fatal(err)
	}
	h := api.New(api.Config{
		Auth:    svc,
		Status:  stubStatus{},
		Version: api.VersionInfo{Version: "test"},
		UI:      fstest.MapFS{"index.html": {Data: []byte("ok")}},
	})
	return h, svc, dir
}

func doJSON(t *testing.T, h http.Handler, method, path string, body any, cookies []*http.Cookie, origin string) *httptest.ResponseRecorder {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rdr = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rdr)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestSetupOnceThenConflict(t *testing.T) {
	h, _, dir := newServer(t, time.Hour)
	rec := doJSON(t, h, http.MethodPost, "/api/v1/auth/setup", map[string]string{"password": testPassword}, nil, "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("setup status %d body %s", rec.Code, rec.Body.String())
	}
	raw, err := os.ReadFile(filepath.Join(dir, "auth.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), testPassword) {
		t.Fatal("password file has plaintext")
	}
	rec = doJSON(t, h, http.MethodPost, "/api/v1/auth/setup", map[string]string{"password": testPassword}, nil, "")
	if rec.Code != http.StatusConflict {
		t.Fatalf("second setup status %d", rec.Code)
	}
}

func TestLoginSuccessAndFail(t *testing.T) {
	h, _, _ := newServer(t, time.Hour)
	if rec := doJSON(t, h, http.MethodPost, "/api/v1/auth/setup", map[string]string{"password": testPassword}, nil, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("setup %d", rec.Code)
	}
	rec := doJSON(t, h, http.MethodPost, "/api/v1/auth/login", map[string]string{"password": testPassword}, nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("login %d %s", rec.Code, rec.Body.String())
	}
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("missing session cookie")
	}
	c := cookies[0]
	if !c.HttpOnly {
		t.Fatal("cookie must be HttpOnly")
	}
	if c.Secure {
		t.Fatal("Secure must be off without TLS")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Fatalf("SameSite %v", c.SameSite)
	}
	rec = doJSON(t, h, http.MethodPost, "/api/v1/auth/login", map[string]string{"password": "wrong-pass"}, nil, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad login %d", rec.Code)
	}
}

func TestLogout(t *testing.T) {
	h, _, _ := newServer(t, time.Hour)
	doJSON(t, h, http.MethodPost, "/api/v1/auth/setup", map[string]string{"password": testPassword}, nil, "")
	rec := doJSON(t, h, http.MethodPost, "/api/v1/auth/login", map[string]string{"password": testPassword}, nil, "")
	cookies := rec.Result().Cookies()
	rec = doJSON(t, h, http.MethodPost, "/api/v1/auth/logout", nil, cookies, "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("logout %d", rec.Code)
	}
	rec = doJSON(t, h, http.MethodPost, "/api/v1/connection", map[string]string{"op": "connect"}, cookies, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("after logout expected 401, got %d", rec.Code)
	}
}

func TestSessionExpiryHTTP(t *testing.T) {
	h, _, _ := newServer(t, 50*time.Millisecond)
	doJSON(t, h, http.MethodPost, "/api/v1/auth/setup", map[string]string{"password": testPassword}, nil, "")
	rec := doJSON(t, h, http.MethodPost, "/api/v1/auth/login", map[string]string{"password": testPassword}, nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("login %d", rec.Code)
	}
	cookies := rec.Result().Cookies()
	time.Sleep(80 * time.Millisecond)
	rec = doJSON(t, h, http.MethodPost, "/api/v1/connection", map[string]string{"op": "connect"}, cookies, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expired session expected 401, got %d", rec.Code)
	}
}

func TestUnauthenticatedConnectionBlocked(t *testing.T) {
	h, _, _ := newServer(t, time.Hour)
	doJSON(t, h, http.MethodPost, "/api/v1/auth/setup", map[string]string{"password": testPassword}, nil, "")
	rec := doJSON(t, h, http.MethodPost, "/api/v1/connection", map[string]string{"op": "connect"}, nil, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d body %s", rec.Code, rec.Body.String())
	}
}

func TestAuthenticatedConnectionNotImplemented(t *testing.T) {
	h, _, _ := newServer(t, time.Hour)
	doJSON(t, h, http.MethodPost, "/api/v1/auth/setup", map[string]string{"password": testPassword}, nil, "")
	rec := doJSON(t, h, http.MethodPost, "/api/v1/auth/login", map[string]string{"password": testPassword}, nil, "")
	cookies := rec.Result().Cookies()
	rec = doJSON(t, h, http.MethodPost, "/api/v1/connection", map[string]string{"op": "connect"}, cookies, "")
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501, got %d", rec.Code)
	}
}

func TestStatusFromProvider(t *testing.T) {
	h, _, _ := newServer(t, time.Hour)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"connection", "routing", "serverMode", "key", "geodata", "xray"} {
		if _, ok := body[k]; !ok {
			t.Fatalf("missing key %s", k)
		}
	}
	if body["connection"] != "disconnected" {
		t.Fatalf("connection %v", body["connection"])
	}
	xray, _ := body["xray"].(map[string]any)
	if xray["state"] != "STOPPED" {
		t.Fatalf("xray %v", xray)
	}
	if xray["pid"] != nil {
		t.Fatalf("pid %v", xray["pid"])
	}
}

func TestCSRFRejectsCrossSitePOST(t *testing.T) {
	h, _, _ := newServer(t, time.Hour)
	rec := doJSON(t, h, http.MethodPost, "/api/v1/auth/setup", map[string]string{"password": testPassword}, nil, "http://evil.example")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("csrf expected 403, got %d", rec.Code)
	}
}

func TestHealth(t *testing.T) {
	h, _, _ := newServer(t, time.Hour)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestAppNewWiresNilServices(t *testing.T) {
	a, err := app.New(app.Config{
		Listen:     "127.0.0.1:7480",
		ListenMode: "loopback",
		DataDir:    t.TempDir(),
		Version:    "test",
		UI:         fstest.MapFS{"index.html": {Data: []byte("ok")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if a.Addr() != "127.0.0.1:7480" {
		t.Fatalf("addr %s", a.Addr())
	}
}

func TestChangePasswordThenLogin(t *testing.T) {
	h, _, _ := newServer(t, time.Hour)
	const next = "new-pass-88"
	if rec := doJSON(t, h, http.MethodPost, "/api/v1/auth/setup", map[string]string{"password": testPassword}, nil, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("setup %d", rec.Code)
	}
	login := doJSON(t, h, http.MethodPost, "/api/v1/auth/login", map[string]string{"password": testPassword}, nil, "")
	if login.Code != http.StatusOK {
		t.Fatalf("login %d", login.Code)
	}
	cookies := login.Result().Cookies()
	rec := doJSON(t, h, http.MethodPost, "/api/v1/auth/password", map[string]string{"current": testPassword, "new": next}, cookies, "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("change %d %s", rec.Code, rec.Body.String())
	}
	if rec := doJSON(t, h, http.MethodPost, "/api/v1/auth/login", map[string]string{"password": testPassword}, nil, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("old password %d", rec.Code)
	}
	if rec := doJSON(t, h, http.MethodPost, "/api/v1/auth/login", map[string]string{"password": next}, nil, ""); rec.Code != http.StatusOK {
		t.Fatalf("new password %d %s", rec.Code, rec.Body.String())
	}
}
