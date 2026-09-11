package profiles

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/igorpooh1978/blacktemple_kn/src/internal/subscription"
)

const (
	blackKeyUserAgent = "BlackTemple/1.0.0"
	blackKeyDevice    = "blacktemple-kn"
	blackKeyMaxBody   = 1 << 20
	minHMACKeyBytes   = 16
)

type blackSubResponse struct {
	Servers []blackSubServer `json:"servers"`
}

type blackSubServer struct {
	Key string `json:"key"`
}

// HTTPResolverConfig is the injected resolver settings. Production loads
// HMACKey and AllowedHosts from local secret/config files, never from git.
type HTTPResolverConfig struct {
	Client       *http.Client
	HMACKey      []byte
	AllowedHosts []string
	// AllowHTTP is test-only. Production always requires https.
	AllowHTTP bool
	// PermitLocal is test-only. Production rejects loopback and private literals.
	PermitLocal bool
}

// HTTPResolver is the production BlackKey resolver: signed GET of the persisted URL.
type HTTPResolver struct {
	Client       *http.Client
	hmacKey      []byte
	allowedHosts map[string]struct{}
	allowHTTP    bool
	permitLocal  bool
	now          func() time.Time
	newID        func() string
	device       string
}

type notConfiguredResolver struct{}

func (notConfiguredResolver) Resolve(context.Context, Source) ([]subscription.ParsedShare, error) {
	return nil, ErrResolverNotConfigured
}

func NewHTTPResolver(cfg HTTPResolverConfig) *HTTPResolver {
	hosts := make(map[string]struct{}, len(cfg.AllowedHosts))
	for _, h := range cfg.AllowedHosts {
		n := canonicalHost(h)
		if n != "" {
			hosts[n] = struct{}{}
		}
	}
	client := cfg.Client
	if client == nil {
		client = NewResolverHTTPClient()
	}
	key := append([]byte(nil), cfg.HMACKey...)
	return &HTTPResolver{
		Client:       client,
		hmacKey:      key,
		allowedHosts: hosts,
		allowHTTP:    cfg.AllowHTTP,
		permitLocal:  cfg.PermitLocal,
		now:          func() time.Time { return time.Now().UTC() },
		newID:        randomUUID,
		device:       blackKeyDevice,
	}
}

func NewResolverHTTPClient() *http.Client {
	return &http.Client{
		Timeout:       20 * time.Second,
		CheckRedirect: sameHostHTTPSRedirect,
		Transport: &http.Transport{
			Proxy:                 nil,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 15 * time.Second,
			IdleConnTimeout:       15 * time.Second,
			ForceAttemptHTTP2:     false,
			TLSClientConfig:       resolverTLSConfig(),
		},
	}
}

func resolverTLSConfig() *tls.Config {
	p := entwareCertFile()
	if p == "" {
		return &tls.Config{MinVersion: tls.VersionTLS12}
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	raw, err := os.ReadFile(p)
	if err != nil || !pool.AppendCertsFromPEM(raw) {
		return &tls.Config{MinVersion: tls.VersionTLS12}
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
}

func entwareCertFile() string {
	for _, p := range []string{
		"/opt/etc/ssl/certs/ca-certificates.crt",
		"/opt/etc/ssl/cert.pem",
	} {
		if info, err := os.Stat(p); err == nil && info.Size() > 0 {
			return p
		}
	}
	return ""
}

func rejectResolverRedirect(*http.Request, []*http.Request) error {
	return errResolverRedirect
}

func sameHostHTTPSRedirect(req *http.Request, via []*http.Request) error {
	if req == nil || req.URL == nil || len(via) == 0 || via[0] == nil || via[0].URL == nil {
		return errResolverRedirect
	}
	if len(via) > 2 {
		return errResolverRedirect
	}
	if !strings.EqualFold(req.URL.Scheme, "https") || !strings.EqualFold(via[0].URL.Scheme, "https") {
		return errResolverRedirect
	}
	want := canonicalHost(via[0].URL.Hostname())
	got := canonicalHost(req.URL.Hostname())
	if want == "" || got != want || forbiddenResolverHost(got) {
		return errResolverRedirect
	}
	return nil
}

var errResolverRedirect = errors.New("blackkey resolver redirect rejected")

func (r *HTTPResolver) Resolve(ctx context.Context, source Source) ([]subscription.ParsedShare, error) {
	if r == nil || len(r.hmacKey) < minHMACKeyBytes {
		return nil, ErrResolverNotConfigured
	}
	raw := strings.TrimSpace(source.Raw())
	target, err := r.parseSubscriptionURL(raw)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	newID := randomUUID
	device := blackKeyDevice
	if r.now != nil {
		now = r.now()
	}
	if r.newID != nil {
		newID = r.newID
	}
	if strings.TrimSpace(r.device) != "" {
		device = r.device
	}
	ts := strconv.FormatInt(now.Unix(), 10)
	appID := newID()
	hwid := newID()
	sig := blackKeySignature(r.hmacKey, blackKeyStringToSign(target.Path, ts, appID))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, ErrResolverUnavailable
	}
	req.Header.Set("User-Agent", blackKeyUserAgent)
	req.Header.Set("Accept", "application/json, */*")
	req.Header.Set("X-App-Id", appID)
	req.Header.Set("X-Signature", sig)
	req.Header.Set("X-Timestamp", ts)
	req.Header.Set("X-hwid", hwid)
	req.Header.Set("device", device)

	resp, err := r.do(req)
	if err != nil {
		if errors.Is(err, errResolverRedirect) {
			return nil, ErrResolverRejected
		}
		return nil, ErrResolverUnavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		_, _ = io.CopyN(io.Discard, resp.Body, 4096)
		return nil, ErrResolverRejected
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		_, _ = io.CopyN(io.Discard, resp.Body, 4096)
		return nil, ErrResolverUnavailable
	}
	limited := io.LimitReader(resp.Body, blackKeyMaxBody+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, ErrResolverUnavailable
	}
	if len(body) > blackKeyMaxBody {
		return nil, ErrResolverInvalidResponse
	}
	entries, err := parseBlackSubBody(body)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, ErrResolverInvalidResponse
	}
	return entries, nil
}

func (r *HTTPResolver) do(req *http.Request) (*http.Response, error) {
	client := r.Client
	if client == nil {
		client = NewResolverHTTPClient()
	}
	wrapped := *client
	wrapped.CheckRedirect = sameHostHTTPSRedirect
	return wrapped.Do(req)
}

func parseBlackSubBody(body []byte) ([]subscription.ParsedShare, error) {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return nil, ErrResolverInvalidResponse
	}
	if strings.HasPrefix(trimmed, "{") {
		var parsed blackSubResponse
		if err := json.Unmarshal(body, &parsed); err != nil {
			return nil, ErrResolverInvalidResponse
		}
		var keys []string
		for _, srv := range parsed.Servers {
			k := strings.TrimSpace(srv.Key)
			if k == "" {
				continue
			}
			keys = append(keys, k)
		}
		if len(keys) == 0 {
			return nil, ErrResolverInvalidResponse
		}
		out, err := subscription.Parse([]byte(strings.Join(keys, "\n")))
		if err != nil {
			return nil, ErrResolverInvalidResponse
		}
		return out.Entries, nil
	}
	out, err := subscription.Parse(body)
	if err != nil {
		return nil, ErrResolverInvalidResponse
	}
	return out.Entries, nil
}

func blackKeyStringToSign(path, timestamp, appID string) string {
	return "GET\n" + path + "\n" + timestamp + "\n" + appID
}

func blackKeySignature(key []byte, stringToSign string) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(stringToSign))
	return hex.EncodeToString(mac.Sum(nil))
}

func randomUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return hex.EncodeToString([]byte(strconv.FormatInt(time.Now().UnixNano(), 10)))
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

func (r *HTTPResolver) parseSubscriptionURL(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, ErrResolverRejected
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, ErrResolverRejected
	}
	if u.Opaque != "" || u.User != nil {
		return nil, ErrResolverRejected
	}
	if u.Fragment != "" || u.EscapedFragment() != "" {
		return nil, ErrResolverRejected
	}
	if u.RawQuery != "" || u.ForceQuery {
		return nil, ErrResolverRejected
	}
	scheme := strings.ToLower(u.Scheme)
	if r.allowHTTP {
		if scheme != "https" && scheme != "http" {
			return nil, ErrResolverRejected
		}
	} else if scheme != "https" {
		return nil, ErrResolverRejected
	}
	host := canonicalHost(u.Hostname())
	if host == "" {
		return nil, ErrResolverRejected
	}
	if strings.Contains(u.Host, "@") {
		return nil, ErrResolverRejected
	}
	port := u.Port()
	if !r.allowHTTP && !r.permitLocal && port != "" && port != "443" {
		return nil, ErrResolverRejected
	}
	if !r.permitLocal && forbiddenResolverHost(host) {
		return nil, ErrResolverRejected
	}
	if len(r.allowedHosts) == 0 {
		return nil, ErrResolverRejected
	}
	if _, ok := r.allowedHosts[host]; !ok {
		return nil, ErrResolverRejected
	}
	path, ok := exactSubPath(u)
	if !ok {
		return nil, ErrResolverRejected
	}
	out := *u
	out.Scheme = scheme
	out.Host = u.Host
	out.Path = path
	out.RawPath = ""
	out.RawQuery = ""
	out.Fragment = ""
	out.User = nil
	return &out, nil
}

func exactSubPath(u *url.URL) (string, bool) {
	raw := u.EscapedPath()
	if raw == "" {
		raw = u.Path
	}
	if strings.Contains(raw, "%") || strings.Contains(raw, "\\") || strings.Contains(raw, "..") {
		return "", false
	}
	if !strings.HasPrefix(raw, "/sub/") {
		return "", false
	}
	token := strings.TrimPrefix(raw, "/sub/")
	if token == "" || strings.Contains(token, "/") {
		return "", false
	}
	for _, c := range token {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' {
			continue
		}
		return "", false
	}
	if strings.Contains(token, "..") {
		return "", false
	}
	return "/sub/" + token, true
}
