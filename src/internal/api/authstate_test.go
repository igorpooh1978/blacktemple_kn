package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAuthStateFreshSetup(t *testing.T) {
	h, _, _ := newServer(t, time.Hour)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/state", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	var body map[string]bool
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["initialized"] || body["authenticated"] {
		t.Fatalf("fresh setup want initialized=false authenticated=false got %v", body)
	}
}

func TestAuthStateLoginAndSession(t *testing.T) {
	h, _, _ := newServer(t, time.Hour)
	if rec := doJSON(t, h, http.MethodPost, "/api/v1/auth/setup", map[string]string{"password": testPassword}, nil, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("setup %d", rec.Code)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/state", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var body map[string]bool
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body["initialized"] || body["authenticated"] {
		t.Fatalf("password without session: %v", body)
	}

	login := doJSON(t, h, http.MethodPost, "/api/v1/auth/login", map[string]string{"password": testPassword}, nil, "")
	if login.Code != http.StatusOK {
		t.Fatalf("login %d", login.Code)
	}
	req = httptest.NewRequest(http.MethodGet, "/api/v1/auth/state", nil)
	for _, c := range login.Result().Cookies() {
		req.AddCookie(c)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body["initialized"] || !body["authenticated"] {
		t.Fatalf("valid session: %v", body)
	}
}

func TestAuthStateAfterNewAuthService(t *testing.T) {
	h, _, dir := newServer(t, time.Hour)
	doJSON(t, h, http.MethodPost, "/api/v1/auth/setup", map[string]string{"password": testPassword}, nil, "")
	login := doJSON(t, h, http.MethodPost, "/api/v1/auth/login", map[string]string{"password": testPassword}, nil, "")
	cookies := login.Result().Cookies()

	h2, _, _ := newServerFromDir(t, dir, time.Hour)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/state", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h2.ServeHTTP(rec, req)
	var body map[string]bool
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body["initialized"] || body["authenticated"] {
		t.Fatalf("RAM session must not survive new process: %v", body)
	}
}
