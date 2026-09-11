package profiles

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/igorpooh1978/blacktemple_kn/src/internal/subscription"
	"github.com/igorpooh1978/blacktemple_kn/src/internal/xray"
)

// Source is the persisted BlackKey bootstrap. Values are never printed.
type Source struct {
	Kind string
	raw  string
}

func (s Source) String() string {
	return "Source{Kind:" + s.Kind + " raw:[redacted]}"
}

func (s Source) GoString() string { return s.String() }

// Raw returns the bootstrap material. Callers must not log it.
func (s Source) Raw() string { return s.raw }

func NewSource(kind, raw string) Source {
	return Source{Kind: kind, raw: raw}
}

// BlackKeyResolver turns a BlackKey bootstrap into runnable candidates.
type BlackKeyResolver interface {
	Resolve(ctx context.Context, source Source) ([]subscription.ParsedShare, error)
}

var (
	ErrResolverUnavailable     = errors.New("blackkey resolver unavailable")
	ErrResolverRejected        = errors.New("blackkey resolver rejected")
	ErrResolverInvalidResponse = errors.New("blackkey resolver invalid response")
)

const (
	ClassResolverUnavailable     = "BLACKKEY_RESOLVER_UNAVAILABLE"
	ClassResolverRejected        = "BLACKKEY_RESOLVER_REJECTED"
	ClassResolverInvalidResponse = "BLACKKEY_RESOLVER_INVALID_RESPONSE"
)

func resolverUnavailable(err error) error {
	return &persistClassError{
		class:  ClassResolverUnavailable,
		status: http.StatusBadGateway,
		public: "Не удалось обновить список серверов.",
		cause:  errors.Join(ErrResolverUnavailable, err),
	}
}

func resolverRejected(err error) error {
	return &persistClassError{
		class:  ClassResolverRejected,
		status: http.StatusBadRequest,
		public: "Не удалось обновить список серверов.",
		cause:  errors.Join(ErrResolverRejected, err),
	}
}

func resolverInvalid(err error) error {
	return &persistClassError{
		class:  ClassResolverInvalidResponse,
		status: http.StatusBadGateway,
		public: "Не удалось обновить список серверов.",
		cause:  errors.Join(ErrResolverInvalidResponse, err),
	}
}

func wrapResolverError(err error) error {
	if err == nil {
		return nil
	}
	var pe *persistClassError
	if errors.As(err, &pe) {
		return err
	}
	switch {
	case errors.Is(err, ErrResolverRejected):
		return resolverRejected(err)
	case errors.Is(err, ErrResolverInvalidResponse):
		return resolverInvalid(err)
	default:
		return resolverUnavailable(err)
	}
}

func resolverCandidates(entries []subscription.ParsedShare) []subscription.ParsedShare {
	out := make([]subscription.ParsedShare, 0, len(entries))
	for _, e := range entries {
		if !resolverPublishable(e) {
			continue
		}
		if err := validateResolvedGenerate(e); err != nil {
			continue
		}
		out = append(out, e)
	}
	return out
}

func resolverPublishable(e subscription.ParsedShare) bool {
	if !publishableEntry(e) {
		return false
	}
	if strings.EqualFold(e.Security, "reality") {
		return false
	}
	if strings.EqualFold(e.Protocol, "vless") && !xray.InspectVLESSUserID(e.Material()).CanonicalUUID {
		return false
	}
	tr := strings.ToLower(strings.TrimSpace(e.Transport))
	sec := strings.ToLower(strings.TrimSpace(e.Security))
	if sec != "tls" && sec != "xtls-vision" && sec != "none" {
		return false
	}
	switch tr {
	case "ws":
		return true
	case "xhttp":
		return true
	default:
		return false
	}
}

func (s *Service) replaceResolved(rec *record, published []subscription.ParsedShare) {
	ks, srvs := s.entities(rec.profile.ID, rec.sub.ID, published)
	prev, had := rec.keys.ActiveCandidate()
	rec.keys.SetKeys(ks)
	rec.servers = srvs
	rec.profile.ResolutionState = resolutionOf(len(ks))
	if had {
		if _, err := rec.keys.SelectCandidate(prev.KeyID, prev.ServerID); err != nil && len(ks) > 0 {
			_, _ = rec.keys.SelectCandidate(ks[0].ID, ks[0].ServerID)
		}
	} else if len(ks) > 0 {
		_, _ = rec.keys.SelectCandidate(ks[0].ID, ks[0].ServerID)
	}
}

// Resolve fetches a replacement candidate set. Failure leaves memory and disk unchanged.
func (s *Service) Resolve(ctx context.Context, profileID string) error {
	if s == nil || s.resolver == nil {
		return resolverUnavailable(nil)
	}
	s.mu.Lock()
	rec, ok := s.byID[profileID]
	if !ok {
		s.mu.Unlock()
		return ErrNotFound
	}
	src := NewSource(rec.sub.Kind, rec.sub.SourceURL())
	s.mu.Unlock()
	entries, err := s.resolver.Resolve(ctx, src)
	if err != nil {
		return wrapResolverError(err)
	}
	published := resolverCandidates(entries)
	if len(published) == 0 {
		return resolverInvalid(nil)
	}
	return s.commit(func(m *memory) error {
		rec, ok := m.byID[profileID]
		if !ok {
			return ErrNotFound
		}
		s.replaceResolved(rec, published)
		return nil
	})
}
