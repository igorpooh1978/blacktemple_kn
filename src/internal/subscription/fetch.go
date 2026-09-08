package subscription

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

const maxBodyBytes = 1 << 20

var (
	ErrUnsupportedURL = errors.New("subscription URL must be http or https")
	ErrBodyTooLarge   = errors.New("subscription body exceeds 1MiB")
)

// Fetched is a downloaded body. Body is not included in String().
type Fetched struct {
	Body            []byte
	ContentType     string
	EncodingHint    string
	UserInfoPresent bool
	URL             string
}

func (f Fetched) String() string {
	return "Fetched{URL:" + sanitizeURL(f.URL) +
		" ContentType:" + f.ContentType +
		" Bytes:" + itoa(len(f.Body)) +
		" UserInfo:" + yesNo(f.UserInfoPresent) + "}"
}

func (f Fetched) GoString() string { return f.String() }

func defaultClient() *http.Client {
	return &http.Client{Timeout: 20 * time.Second}
}

// Fetch downloads a subscription URL. Query strings are stripped from logs.
func Fetch(ctx context.Context, client *http.Client, rawURL string) (Fetched, error) {
	u := strings.TrimSpace(rawURL)
	if !strings.HasPrefix(strings.ToLower(u), "http://") && !strings.HasPrefix(strings.ToLower(u), "https://") {
		return Fetched{}, ErrUnsupportedURL
	}
	if client == nil {
		client = defaultClient()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return Fetched{}, ErrUnsupportedURL
	}
	req.Header.Set("Accept", "text/plain, application/json, */*")
	resp, err := client.Do(req)
	if err != nil {
		return Fetched{}, errors.New("subscription fetch failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return Fetched{}, errors.New("subscription fetch HTTP " + itoa(resp.StatusCode))
	}
	limited := io.LimitReader(resp.Body, maxBodyBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return Fetched{}, err
	}
	if len(body) > maxBodyBytes {
		return Fetched{}, ErrBodyTooLarge
	}
	ct := resp.Header.Get("Content-Type")
	if i := strings.Index(ct, ";"); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	return Fetched{
		Body:            body,
		ContentType:     ct,
		UserInfoPresent: resp.Header.Get("subscription-userinfo") != "",
		URL:             u,
	}, nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func yesNo(v bool) string {
	if v {
		return "true"
	}
	return "false"
}
