package profiles

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/igorpooh1978/blacktemple_kn/src/internal/subscription"
)

// UTF-8 of this literal is the HMAC-SHA256 key for BlackKey GET /sub/{TOKEN}.
const blackKeyHMACKey = "Vy8Dpmn3wdMTaemIZiLDN8Knzw2cJaoNkcceOLooB3sPGtGkInMO8vBE1G/4AWKAq1t4BFFRY289aduMNxZr4A=="

const (
	blackKeyUserAgent = "BlackTemple/1.0.0"
	blackKeyDevice    = "blacktemple-kn"
	blackKeyMaxBody   = 1 << 20
)

type blackSubResponse struct {
	Servers []blackSubServer `json:"servers"`
}

type blackSubServer struct {
	Key string `json:"key"`
}

// HTTPResolver is the production BlackKey resolver: signed GET of the persisted URL.
type HTTPResolver struct {
	Client *http.Client
	now    func() time.Time
	newID  func() string
	device string
}

func NewHTTPResolver(client *http.Client) *HTTPResolver {
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	return &HTTPResolver{
		Client: client,
		now:    func() time.Time { return time.Now().UTC() },
		newID:  randomUUID,
		device: blackKeyDevice,
	}
}

func (r *HTTPResolver) Resolve(ctx context.Context, source Source) ([]subscription.ParsedShare, error) {
	raw := strings.TrimSpace(source.Raw())
	if raw == "" {
		return nil, ErrResolverRejected
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, ErrResolverRejected
	}
	signPath, tokenOK := blackKeySignPath(u.Path)
	if !tokenOK {
		return nil, ErrResolverRejected
	}
	now := time.Now().UTC()
	newID := randomUUID
	device := blackKeyDevice
	client := (*http.Client)(nil)
	if r != nil {
		if r.now != nil {
			now = r.now()
		}
		if r.newID != nil {
			newID = r.newID
		}
		if strings.TrimSpace(r.device) != "" {
			device = r.device
		}
		client = r.Client
	}
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	ts := strconv.FormatInt(now.Unix(), 10)
	appID := newID()
	hwid := newID()
	sig := blackKeySignature(blackKeyStringToSign(signPath, ts, appID))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
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

	resp, err := client.Do(req)
	if err != nil {
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

func blackKeySignPath(urlPath string) (string, bool) {
	parts := strings.Split(urlPath, "/")
	var last string
	for _, p := range parts {
		if p != "" {
			last = p
		}
	}
	if last == "" {
		return "", false
	}
	return "/sub/" + last, true
}

func blackKeyStringToSign(path, timestamp, appID string) string {
	return "GET\n" + path + "\n" + timestamp + "\n" + appID
}

func blackKeySignature(stringToSign string) string {
	mac := hmac.New(sha256.New, []byte(blackKeyHMACKey))
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
