package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/igorpooh1978/blacktemple_kn/src/internal/auth"
)

const (
	sessionCookie = "btkn_session"
	maxJSONBody   = 64 << 10
	maxImportBody = 256 << 10
	loginMaxPerIP = 30
	loginWindow   = time.Minute
)

// StatusProvider supplies GET /api/v1/status from application state.
type StatusProvider interface {
	Status() Status
}

// ConnectionService executes frozen connection ops. Nil means 501.
type ConnectionService interface {
	Control(ctx context.Context, op string) error
}

// ProfileService lists and imports profiles. Nil means 501.
type ProfileService interface {
	List(ctx context.Context) ([]Profile, error)
	Import(ctx context.Context, blackKey, name string) (Profile, error)
}

// Status matches the frozen OpenAPI Status schema.
type Status struct {
	Connection string      `json:"connection"`
	Country    string      `json:"country"`
	LatencyMs  *int        `json:"latencyMs"`
	Routing    string      `json:"routing"`
	ServerMode string      `json:"serverMode"`
	Key        string      `json:"key"`
	Geodata    string      `json:"geodata"`
	ErrorClass string      `json:"errorClass,omitempty"`
	Xray       XrayProcess `json:"xray"`
}

// XrayProcess is the nested xray snapshot on Status.
type XrayProcess struct {
	State        string `json:"state"`
	PID          *int   `json:"pid"`
	Version      string `json:"version"`
	RestartCount int    `json:"restartCount"`
}

// Profile is a redacted profile list item. Never includes a BlackKey.
type Profile struct {
	ID     string `json:"id"`
	Name   string `json:"name,omitempty"`
	Status string `json:"status,omitempty"`
}

// VersionInfo is filled by the composition root.
type VersionInfo struct {
	Version string
	GOOS    string
	GOARCH  string
	GOMIPS  string
	CGO     string
}

// Config wires HTTP handlers. Connection and Profiles may be nil.
type Config struct {
	Auth       *auth.Service
	Status     StatusProvider
	Connection ConnectionService
	Profiles   ProfileService
	Version    VersionInfo
	UI         fs.FS
}

// Server is the frozen HTTP API.
type Server struct {
	h          http.Handler
	auth       *auth.Service
	status     StatusProvider
	connection ConnectionService
	profiles   ProfileService
	version    VersionInfo
	logins     *loginLimiter
}

var allowedConnectionOps = map[string]struct{}{
	"connect":         {},
	"disconnect":      {},
	"reconnect":       {},
	"restart-vpn":     {},
	"restart-manager": {},
	"full-restart":    {},
}

// New builds the API mux with security headers and CSRF checks.
func New(cfg Config) *Server {
	s := &Server{
		auth:       cfg.Auth,
		status:     cfg.Status,
		connection: cfg.Connection,
		profiles:   cfg.Profiles,
		version:    cfg.Version,
		logins:     newLoginLimiter(loginMaxPerIP, loginWindow),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /api/v1/version", s.handleVersion)
	mux.HandleFunc("GET /api/v1/status", s.handleStatus)
	mux.HandleFunc("GET /api/v1/auth/state", s.handleAuthState)
	mux.HandleFunc("POST /api/v1/auth/setup", s.handleSetup)
	mux.HandleFunc("POST /api/v1/auth/login", s.handleLogin)
	mux.HandleFunc("POST /api/v1/auth/logout", s.handleLogout)
	mux.HandleFunc("POST /api/v1/auth/password", s.handleChangePassword)
	mux.HandleFunc("POST /api/v1/connection", s.handleConnection)
	mux.HandleFunc("GET /api/v1/profiles", s.handleListProfiles)
	mux.HandleFunc("POST /api/v1/profiles", s.handleImportProfile)
	if cfg.UI != nil {
		mux.Handle("/", http.FileServer(http.FS(cfg.UI)))
	}
	s.h = withSecurityHeaders(withCSRF(mux))
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.h.ServeHTTP(w, r)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	v := s.version
	if v.Version == "" {
		v.Version = "0.1.0-dev"
	}
	if v.GOOS == "" {
		v.GOOS = runtime.GOOS
	}
	if v.GOARCH == "" {
		v.GOARCH = runtime.GOARCH
	}
	if v.GOMIPS == "" {
		v.GOMIPS = os.Getenv("GOMIPS")
	}
	if v.CGO == "" {
		v.CGO = cgoValue()
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"version": v.Version,
		"goos":    v.GOOS,
		"goarch":  v.GOARCH,
		"gomips":  v.GOMIPS,
		"cgo":     v.CGO,
	})
}

func (s *Server) handleAuthState(w http.ResponseWriter, r *http.Request) {
	initialized := s.auth != nil && s.auth.Initialized()
	authenticated := false
	if initialized && s.auth != nil {
		c, err := r.Cookie(sessionCookie)
		authenticated = err == nil && c.Value != "" && s.auth.Lookup(c.Value)
	}
	writeJSON(w, http.StatusOK, map[string]bool{
		"initialized":   initialized,
		"authenticated": authenticated,
	})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if s.status == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "status unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, s.status.Status())
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	if s.auth == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "auth unavailable"})
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := decodeJSON(r, maxJSONBody, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	if err := s.auth.Setup(body.Password); err != nil {
		switch {
		case errors.Is(err, auth.ErrAlreadyInitialized):
			writeJSON(w, http.StatusConflict, map[string]string{"error": "already initialized"})
		case errors.Is(err, auth.ErrPasswordTooShort):
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		default:
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "setup failed"})
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if s.auth == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "auth unavailable"})
		return
	}
	ip := requestIP(r)
	if !s.logins.allow(ip) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many requests"})
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := decodeJSON(r, maxJSONBody, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	id, expires, err := s.auth.Login(body.Password)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	http.SetCookie(w, sessionCookieValue(r, id, expires))
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	if !s.requireSession(w, r) {
		return
	}
	var body struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if err := decodeJSON(r, maxJSONBody, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	if err := s.auth.ChangePassword(body.Current, body.New); err != nil {
		switch {
		case errors.Is(err, auth.ErrInvalidPassword):
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "unauthorized"})
		case errors.Is(err, auth.ErrPasswordTooShort):
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		default:
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "change failed"})
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" || s.auth == nil || !s.auth.Lookup(c.Value) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	s.auth.Logout(c.Value)
	expired := sessionCookieValue(r, "", time.Unix(0, 0))
	expired.MaxAge = -1
	http.SetCookie(w, expired)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleConnection(w http.ResponseWriter, r *http.Request) {
	if !s.requireSession(w, r) {
		return
	}
	var body struct {
		Op string `json:"op"`
	}
	if err := decodeJSON(r, maxJSONBody, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	if _, ok := allowedConnectionOps[body.Op]; !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	if s.connection == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "not implemented"})
		return
	}
	if err := s.connection.Control(r.Context(), body.Op); err != nil {
		writePublicError(w, err, http.StatusInternalServerError, "control failed")
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) handleListProfiles(w http.ResponseWriter, r *http.Request) {
	if !s.requireSession(w, r) {
		return
	}
	if s.profiles == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "not implemented"})
		return
	}
	list, err := s.profiles.List(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "list failed"})
		return
	}
	if list == nil {
		list = []Profile{}
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleImportProfile(w http.ResponseWriter, r *http.Request) {
	if !s.requireSession(w, r) {
		return
	}
	var body struct {
		BlackKey string `json:"blackKey"`
		Name     string `json:"name"`
	}
	if err := decodeJSON(r, maxImportBody, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	if body.BlackKey == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	if s.profiles == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "not implemented"})
		return
	}
	created, err := s.profiles.Import(r.Context(), body.BlackKey, body.Name)
	if err != nil {
		writePublicError(w, err, http.StatusInternalServerError, "import failed")
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) requireSession(w http.ResponseWriter, r *http.Request) bool {
	if s.auth == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return false
	}
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" || !s.auth.Lookup(c.Value) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return false
	}
	return true
}

func sessionCookieValue(r *http.Request, id string, expires time.Time) *http.Cookie {
	c := &http.Cookie{
		Name:     sessionCookie,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
		Expires:  expires,
	}
	if id != "" && !expires.IsZero() {
		sec := int(time.Until(expires).Seconds())
		if sec < 1 {
			sec = 1
		}
		c.MaxAge = sec
	}
	return c
}

func decodeJSON(r *http.Request, max int64, dst any) error {
	defer r.Body.Close()
	limited := http.MaxBytesReader(nil, r.Body, max)
	dec := json.NewDecoder(limited)
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return errors.New("extra json")
	}
	return nil
}

type publicHTTPError interface {
	HTTPStatus() int
	PublicMessage() string
}

func writePublicError(w http.ResponseWriter, err error, fallback int, fallbackMsg string) {
	var pe publicHTTPError
	if errors.As(err, &pe) && pe.HTTPStatus() > 0 {
		msg := pe.PublicMessage()
		if msg == "" {
			msg = fallbackMsg
		}
		writeJSON(w, pe.HTTPStatus(), map[string]string{"error": msg})
		return
	}
	writeJSON(w, fallback, map[string]string{"error": fallbackMsg})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func withCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
			if !sameOrigin(r) {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func cgoValue() string {
	if strings.TrimSpace(os.Getenv("CGO_ENABLED")) == "1" {
		return "1"
	}
	return "0"
}

func requestIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

type loginLimiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	byIP   map[string][]time.Time
	now    func() time.Time
}

func newLoginLimiter(max int, window time.Duration) *loginLimiter {
	return &loginLimiter{
		max:    max,
		window: window,
		byIP:   make(map[string][]time.Time),
		now:    time.Now,
	}
}

func (l *loginLimiter) allow(ip string) bool {
	if ip == "" {
		ip = "unknown"
	}
	now := l.now()
	cutoff := now.Add(-l.window)
	l.mu.Lock()
	defer l.mu.Unlock()
	hits := l.byIP[ip]
	kept := hits[:0]
	for _, t := range hits {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= l.max {
		l.byIP[ip] = kept
		return false
	}
	l.byIP[ip] = append(kept, now)
	if len(l.byIP) > 256 {
		for k := range l.byIP {
			delete(l.byIP, k)
			if len(l.byIP) <= 128 {
				break
			}
		}
	}
	return true
}
