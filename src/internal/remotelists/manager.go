package remotelists

import (
	"context"
	"errors"
	"net/http"
	"os"
	"sync"
	"time"
)

// Manager fetches, validates, and atomically caches remote lists.
type Manager struct {
	Dir      string
	Client   *http.Client
	Timeout  time.Duration
	Attempts int
	Backoff  Backoff
	Sleep    func(context.Context, time.Duration) error
	Now      func() time.Time

	guard *Guard
	mu    sync.Mutex
}

// NewManager stores lists under dir. guard may be nil (default DNS/dial).
func NewManager(dir string, guard *Guard) (*Manager, error) {
	if dir == "" {
		return nil, errors.New("cache dir is empty")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if guard == nil {
		guard = &Guard{}
	}
	return &Manager{
		Dir:      dir,
		Timeout:  defaultFetchTimeout,
		Attempts: defaultMaxAttempts,
		Backoff:  DefaultBackoff(),
		Sleep:    defaultSleep,
		Now:      time.Now,
		guard:    guard,
	}, nil
}

func defaultSleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Load returns last-known-good without touching the network.
func (m *Manager) Load(desc Descriptor) (Result, error) {
	if _, err := safeID(desc.ID); err != nil {
		return Result{}, err
	}
	res, err := loadCache(m.Dir, desc.ID)
	if err != nil {
		return Result{}, err
	}
	res.Descriptor.ID = desc.ID
	if desc.Type != "" {
		res.Descriptor.Type = desc.Type
	}
	res.Descriptor.URL = desc.URL
	res.Descriptor.TrustedOrigin = desc.TrustedOrigin
	res.Descriptor.MaxBytes = desc.MaxBytes
	res.Descriptor.TTL = ClampTTL(desc.TTL)
	parsed, perr := Parse(res.Descriptor.Type, res.Body)
	res.Parsed = parsed
	res.ParseError = perr
	if perr != nil && !errors.Is(perr, ErrProviderFormatNotImplemented) {
		return res, perr
	}
	return res, nil
}

// Update performs a conditional fetch with retries. On network failure it
// returns last-known-good when a cache exists.
func (m *Manager) Update(ctx context.Context, desc Descriptor) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if err := validateDescriptor(desc); err != nil {
		return Result{}, err
	}
	desc.TTL = ClampTTL(desc.TTL)

	m.mu.Lock()
	defer m.mu.Unlock()

	cached, cacheErr := loadCache(m.Dir, desc.ID)
	etag := desc.ETag
	lastMod := desc.LastModified
	if cacheErr == nil {
		if etag == "" {
			etag = cached.ETag
		}
		if lastMod == "" {
			lastMod = cached.LastModified
		}
	}

	attempts := m.Attempts
	if attempts < 1 {
		attempts = 1
	}
	var lastErr error
	for i := 1; i <= attempts; i++ {
		if err := ctx.Err(); err != nil {
			return m.fallback(desc, cached, cacheErr, err)
		}
		out, err := m.fetchOnce(ctx, desc, etag, lastMod)
		if err == nil && out.status == http.StatusNotModified {
			if cacheErr != nil {
				return Result{}, ErrNoCache
			}
			return m.finishNotModified(desc, cached, out)
		}
		if err == nil && out.status >= 200 && out.status <= 299 {
			res, applyErr := m.applyBody(desc, out)
			if applyErr != nil {
				if !retryable(applyErr, out.status) {
					return m.fallback(desc, cached, cacheErr, applyErr)
				}
				lastErr = applyErr
			} else {
				return res, nil
			}
		} else if err != nil {
			lastErr = err
			if !retryable(err, out.status) {
				return m.fallback(desc, cached, cacheErr, err)
			}
		} else {
			lastErr = errors.New("remote list HTTP " + itoa(out.status))
			if !retryable(lastErr, out.status) {
				return m.fallback(desc, cached, cacheErr, lastErr)
			}
		}
		if i == attempts {
			break
		}
		wait := time.Duration(0)
		if m.Backoff != nil {
			wait = m.Backoff.Next(i)
		}
		if m.Sleep != nil {
			if err := m.Sleep(ctx, wait); err != nil {
				return m.fallback(desc, cached, cacheErr, err)
			}
		}
	}
	if lastErr == nil {
		lastErr = errors.New("remote list fetch failed")
	}
	return m.fallback(desc, cached, cacheErr, lastErr)
}

func (m *Manager) applyBody(desc Descriptor, out fetchOutcome) (Result, error) {
	sum := sha256Hex(out.body)
	if !checksumOK(desc.SHA256, sum) {
		return Result{}, ErrChecksumMismatch
	}
	parsed, perr := Parse(desc.Type, out.body)
	if perr != nil && !errors.Is(perr, ErrProviderFormatNotImplemented) {
		return Result{}, perr
	}
	now := m.now()
	if err := saveCache(m.Dir, desc, out.body, out.etag, out.lastModified, sum, now); err != nil {
		return Result{}, err
	}
	return Result{
		Descriptor:   desc,
		Status:       StatusUpdated,
		Body:         out.body,
		SHA256:       sum,
		ETag:         out.etag,
		LastModified: out.lastModified,
		FetchedAt:    now,
		Parsed:       parsed,
		ParseError:   perr,
	}, nil
}

func (m *Manager) finishNotModified(desc Descriptor, cached Result, out fetchOutcome) (Result, error) {
	now := m.now()
	etag := firstNonEmpty(out.etag, cached.ETag)
	lastMod := firstNonEmpty(out.lastModified, cached.LastModified)
	sum := cached.SHA256
	if sum == "" {
		sum = sha256Hex(cached.Body)
	}
	_ = saveCache(m.Dir, desc, cached.Body, etag, lastMod, sum, now)
	parsed, perr := Parse(desc.Type, cached.Body)
	res := Result{
		Descriptor:   desc,
		Status:       StatusNotModified,
		Body:         cached.Body,
		SHA256:       sum,
		ETag:         etag,
		LastModified: lastMod,
		FetchedAt:    now,
		Parsed:       parsed,
		ParseError:   perr,
	}
	if perr != nil && !errors.Is(perr, ErrProviderFormatNotImplemented) {
		return res, perr
	}
	return res, nil
}

func (m *Manager) fallback(desc Descriptor, cached Result, cacheErr, cause error) (Result, error) {
	if cacheErr != nil {
		if cause == nil {
			cause = cacheErr
		}
		return Result{}, cause
	}
	parsed, perr := Parse(desc.Type, cached.Body)
	res := Result{
		Descriptor:   desc,
		Status:       StatusLastKnownGood,
		Body:         cached.Body,
		SHA256:       cached.SHA256,
		ETag:         cached.ETag,
		LastModified: cached.LastModified,
		FetchedAt:    cached.FetchedAt,
		Parsed:       parsed,
		ParseError:   perr,
	}
	if res.SHA256 == "" {
		res.SHA256 = sha256Hex(cached.Body)
	}
	return res, nil
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func validateDescriptor(d Descriptor) error {
	if _, err := safeID(d.ID); err != nil {
		return err
	}
	if !knownType(d.Type) {
		return ErrUnknownType
	}
	if d.URL == "" {
		return ErrBlockedScheme
	}
	return nil
}
