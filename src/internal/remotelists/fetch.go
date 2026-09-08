package remotelists

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
)

type fetchOutcome struct {
	status       int
	body         []byte
	etag         string
	lastModified string
}

func (m *Manager) fetchOnce(ctx context.Context, desc Descriptor, etag, lastModified string) (fetchOutcome, error) {
	if err := m.guard.ValidateURL(desc.URL, desc.TrustedOrigin); err != nil {
		return fetchOutcome{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, desc.URL, nil)
	if err != nil {
		return fetchOutcome{}, err
	}
	req.Header.Set("Accept", "text/plain, application/json, */*")
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	if lastModified != "" {
		req.Header.Set("If-Modified-Since", lastModified)
	}
	client := m.clientFor(desc)
	resp, err := client.Do(req)
	if err != nil {
		return fetchOutcome{}, classifyFetchErr(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return fetchOutcome{
			status:       resp.StatusCode,
			etag:         firstNonEmpty(resp.Header.Get("ETag"), etag),
			lastModified: firstNonEmpty(resp.Header.Get("Last-Modified"), lastModified),
		}, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return fetchOutcome{status: resp.StatusCode}, errors.New("remote list HTTP " + itoa(resp.StatusCode))
	}

	max := EffectiveMaxBytes(desc.Type, desc.MaxBytes)
	if resp.ContentLength > max {
		return fetchOutcome{status: resp.StatusCode}, ErrTooLarge
	}
	limited := io.LimitReader(resp.Body, max+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return fetchOutcome{}, classifyFetchErr(err)
	}
	if int64(len(body)) > max {
		return fetchOutcome{status: resp.StatusCode}, ErrTooLarge
	}
	return fetchOutcome{
		status:       resp.StatusCode,
		body:         body,
		etag:         resp.Header.Get("ETag"),
		lastModified: resp.Header.Get("Last-Modified"),
	}, nil
}

func (m *Manager) clientFor(desc Descriptor) *http.Client {
	return newHTTPClient(m.guard, desc.TrustedOrigin, m.Timeout, m.Client)
}

func classifyFetchErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrBlockedDestination) ||
		errors.Is(err, ErrBlockedScheme) ||
		errors.Is(err, ErrHTTPSRequired) ||
		errors.Is(err, ErrRedirect) ||
		errors.Is(err, ErrTooManyRedirects) {
		return err
	}
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		return ErrTimeout
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ErrTimeout
	}
	msg := err.Error()
	if strings.Contains(strings.ToLower(msg), "timeout") {
		return ErrTimeout
	}
	return err
}

func retryable(err error, status int) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrTooLarge) ||
		errors.Is(err, ErrChecksumMismatch) ||
		errors.Is(err, ErrInvalidContent) ||
		errors.Is(err, ErrBlockedDestination) ||
		errors.Is(err, ErrBlockedScheme) ||
		errors.Is(err, ErrHTTPSRequired) ||
		errors.Is(err, ErrRedirect) ||
		errors.Is(err, ErrTooManyRedirects) ||
		errors.Is(err, ErrInvalidID) ||
		errors.Is(err, ErrUnknownType) {
		return false
	}
	if status >= 400 && status < 500 && status != http.StatusTooManyRequests {
		return false
	}
	return true
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
