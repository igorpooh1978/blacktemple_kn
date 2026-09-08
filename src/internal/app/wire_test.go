package app_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"testing/fstest"

	"github.com/igorpooh1978/blacktemple_kn/src/internal/app"
	"github.com/igorpooh1978/blacktemple_kn/src/internal/connection"
	"github.com/igorpooh1978/blacktemple_kn/src/internal/profiles"
)

const (
	httpPassword = "test-pass-9"
	httpUUID     = "11111111-1111-4111-8111-111111111111"
)

func httpVLESS() string {
	return "vless://" + httpUUID + "@example.com:443?type=tcp&security=tls&sni=www.example.com&fp=chrome#lab"
}

type fakeEngine struct {
	mu      sync.Mutex
	pid     int
	nextPID int
	waitCh  chan error
	started bool
}

func (f *fakeEngine) Start(_ context.Context, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextPID++
	f.pid = f.nextPID
	f.started = true
	f.waitCh = make(chan error, 1)
	return nil
}

func (f *fakeEngine) Stop(_ context.Context) error {
	f.mu.Lock()
	ch := f.waitCh
	f.started = false
	f.pid = 0
	f.waitCh = nil
	f.mu.Unlock()
	if ch != nil {
		select {
		case ch <- nil:
		default:
		}
	}
	return nil
}

func (f *fakeEngine) Wait(_ context.Context) error {
	f.mu.Lock()
	ch := f.waitCh
	f.mu.Unlock()
	if ch == nil {
		return errors.New("not started")
	}
	return <-ch
}

func (f *fakeEngine) ValidateConfig(_ context.Context, path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !json.Valid(b) {
		return errors.New("invalid json")
	}
	return nil
}

func (f *fakeEngine) Version(_ context.Context) (string, error) {
	return "Xray 26.7.28 (go1.22)", nil
}

func (f *fakeEngine) PID() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pid
}

func (f *fakeEngine) Path() string { return "fake-xray" }

func TestHTTPProfilesAndConnection(t *testing.T) {
	dir := t.TempDir()
	ps := profiles.NewService(nil, nil)
	cs := connection.New(connection.Config{
		Profiles:    ps,
		Engine:      &fakeEngine{},
		DataDir:     dir,
		FastBackoff: true,
	})
	a, err := app.New(app.Config{
		Listen:     "127.0.0.1:0",
		ListenMode: "loopback",
		DataDir:    dir,
		Version:    "test",
		UI:         fstest.MapFS{"index.html": {Data: []byte("ok")}},
		Status:     cs,
		Connection: cs,
		Profiles:   connection.NewProfileAPI(ps),
	})
	if err != nil {
		t.Fatal(err)
	}
	h := a.Handler()

	rec := doJSON(t, h, http.MethodPost, "/api/v1/auth/setup", map[string]string{"password": httpPassword}, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("setup %d %s", rec.Code, rec.Body.String())
	}
	rec = doJSON(t, h, http.MethodPost, "/api/v1/auth/login", map[string]string{"password": httpPassword}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("login %d", rec.Code)
	}
	cookies := rec.Result().Cookies()

	rec = doJSON(t, h, http.MethodPost, "/api/v1/connection", map[string]string{"op": "connect"}, cookies)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("no profile expected 400 got %d %s", rec.Code, rec.Body.String())
	}

	rec = doJSON(t, h, http.MethodPost, "/api/v1/profiles", map[string]string{"blackKey": "", "name": "x"}, cookies)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty key %d", rec.Code)
	}
	rec = doJSON(t, h, http.MethodPost, "/api/v1/profiles", map[string]string{"blackKey": "not-a-key", "name": "x"}, cookies)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid key %d %s", rec.Code, rec.Body.String())
	}

	rec = doJSON(t, h, http.MethodPost, "/api/v1/profiles", map[string]string{"blackKey": httpVLESS(), "name": "lab"}, cookies)
	if rec.Code != http.StatusCreated {
		t.Fatalf("import %d %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, httpVLESS()) || strings.Contains(body, httpUUID) || strings.Contains(strings.ToLower(body), "blackkey") {
		t.Fatalf("import leaked secret: %s", body)
	}

	rec = doJSON(t, h, http.MethodGet, "/api/v1/profiles", nil, cookies)
	if rec.Code != http.StatusOK {
		t.Fatalf("list %d", rec.Code)
	}

	rec = doJSON(t, h, http.MethodPost, "/api/v1/connection", map[string]string{"op": "connect"}, cookies)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("connect %d %s", rec.Code, rec.Body.String())
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	stRec := httptest.NewRecorder()
	h.ServeHTTP(stRec, req)
	var status map[string]any
	if err := json.Unmarshal(stRec.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status["connection"] != "connected" {
		t.Fatalf("status %v", status)
	}
	if status["geodata"] != "missing" {
		t.Fatalf("geodata %v", status["geodata"])
	}

	rec = doJSON(t, h, http.MethodPost, "/api/v1/connection", map[string]string{"op": "disconnect"}, cookies)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("disconnect %d", rec.Code)
	}
	rec = doJSON(t, h, http.MethodPost, "/api/v1/connection", map[string]string{"op": "restart-manager"}, cookies)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("restart-manager %d %s", rec.Code, rec.Body.String())
	}
	rec = doJSON(t, h, http.MethodPost, "/api/v1/connection", map[string]string{"op": "connect"}, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauth mutation %d", rec.Code)
	}
}

func doJSON(t *testing.T, h http.Handler, method, path string, body any, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	payload := ""
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		payload = string(b)
	}
	req := httptest.NewRequest(method, path, strings.NewReader(payload))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}
