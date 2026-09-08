package profiles

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/igorpooh1978/blacktemple_kn/src/internal/countries"
	"github.com/igorpooh1978/blacktemple_kn/src/internal/keys"
	"github.com/igorpooh1978/blacktemple_kn/src/internal/servers"
	"github.com/igorpooh1978/blacktemple_kn/src/internal/subscription"
)

var (
	ErrNotFound     = errors.New("profile not found")
	ErrNoRefreshURL = errors.New("profile has no subscription URL to refresh")
	ErrEmptyImport  = errors.New("black key is empty")
)

// ImportRequest matches contracts ImportKeyRequest. blackKey is never echoed.
type ImportRequest struct {
	BlackKey string
	Name     string
}

func (r ImportRequest) String() string {
	return "ImportRequest{Name:" + r.Name + " BlackKey:[redacted]}"
}

func (r ImportRequest) GoString() string { return r.String() }

type record struct {
	profile Profile
	sub     subscription.Subscription
	keys    *keys.State
	servers []servers.Server
}

// Service is the in-memory profile/subscription/key lifecycle.
type Service struct {
	mu       sync.Mutex
	client   *http.Client
	changer  keys.KeyChanger
	catalog  *countries.Catalog
	byID     map[string]*record
	order    []string
	activeID string
	now      func() time.Time
}

func NewService(client *http.Client, changer keys.KeyChanger) *Service {
	if changer == nil {
		changer = keys.UnconfiguredChanger{}
	}
	return &Service{
		client:  client,
		changer: changer,
		catalog: countries.NewCatalog(),
		byID:    map[string]*record{},
		now:     func() time.Time { return time.Now().UTC() },
	}
}

func (s *Service) Catalog() *countries.Catalog { return s.catalog }

func (s *Service) List() []Profile {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Profile, 0, len(s.order))
	for _, id := range s.order {
		out = append(out, s.byID[id].profile)
	}
	return out
}

func (s *Service) Get(id string) (Profile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.byID[id]
	if !ok {
		return Profile{}, ErrNotFound
	}
	return rec.profile, nil
}

func (s *Service) ActiveID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activeID
}

func (s *Service) SetActive(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byID[id]; !ok {
		return ErrNotFound
	}
	s.activeID = id
	return nil
}

func (s *Service) Keys(profileID string) ([]keys.Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.byID[profileID]
	if !ok {
		return nil, ErrNotFound
	}
	return append([]keys.Key(nil), rec.keys.Keys...), nil
}

func (s *Service) Servers(profileID string) ([]servers.Server, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.byID[profileID]
	if !ok {
		return nil, ErrNotFound
	}
	return append([]servers.Server(nil), rec.servers...), nil
}

func (s *Service) Candidate(profileID string) (keys.ConnectionCandidate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.byID[profileID]
	if !ok {
		return keys.ConnectionCandidate{}, ErrNotFound
	}
	c, ok := rec.keys.ActiveCandidate()
	if !ok {
		return keys.ConnectionCandidate{}, keys.ErrNoCandidate
	}
	return c, nil
}

func (s *Service) LastKnownGood(profileID string) (keys.LastKnownGood, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.byID[profileID]
	if !ok {
		return keys.LastKnownGood{}, ErrNotFound
	}
	lkg, ok := rec.keys.LastKnownGood()
	if !ok {
		return keys.LastKnownGood{}, keys.ErrNoLastKnownGood
	}
	return lkg, nil
}

// Import validates a BlackKey (URL or share / generic JSON) and stores entities.
func (s *Service) Import(ctx context.Context, req ImportRequest) (Profile, error) {
	raw := strings.TrimSpace(req.BlackKey)
	if raw == "" {
		return Profile{}, ErrEmptyImport
	}
	name := strings.TrimSpace(req.Name)
	parsed, subMeta, err := s.load(ctx, raw)
	if err != nil {
		return Profile{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	id := newID()
	if name == "" {
		name = "profile-" + id[:8]
	}
	subID := hashOrRandom(subMeta.kind, subMeta.sanitized)
	sub := subscription.Subscription{
		ID:          subID,
		ProfileID:   id,
		Kind:        subMeta.kind,
		ContentType: subMeta.contentType,
		Encoding:    parsed.Encoding,
		EntryCount:  len(parsed.Entries),
		FetchedAt:   s.now(),
	}
	sub = withSource(sub, subMeta.source)
	ks, srvs := s.entities(id, subID, parsed.Entries)
	st := keys.NewState(id, ks)
	if len(ks) > 0 {
		_, _ = st.SelectCandidate(ks[0].ID, ks[0].ServerID)
	}
	p := Profile{ID: id, Name: name, SubscriptionID: subID, CreatedAt: s.now()}
	s.byID[id] = &record{profile: p, sub: sub, keys: st, servers: srvs}
	s.order = append(s.order, id)
	if s.activeID == "" {
		s.activeID = id
	}
	return p, nil
}

// Refresh re-fetches a URL subscription and replaces keys/servers.
func (s *Service) Refresh(ctx context.Context, profileID string) error {
	s.mu.Lock()
	rec, ok := s.byID[profileID]
	if !ok {
		s.mu.Unlock()
		return ErrNotFound
	}
	src := rec.sub.SourceURL()
	kind := rec.sub.Kind
	s.mu.Unlock()
	if kind != "url" || src == "" {
		return ErrNoRefreshURL
	}
	parsed, subMeta, err := s.load(ctx, src)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok = s.byID[profileID]
	if !ok {
		return ErrNotFound
	}
	ks, srvs := s.entities(profileID, rec.sub.ID, parsed.Entries)
	prev, had := rec.keys.ActiveCandidate()
	rec.keys.SetKeys(ks)
	rec.servers = srvs
	sub := rec.sub
	sub.ContentType = subMeta.contentType
	sub.Encoding = parsed.Encoding
	sub.EntryCount = len(parsed.Entries)
	sub.FetchedAt = s.now()
	rec.sub = withSource(sub, src)
	if had {
		if _, err := rec.keys.SelectCandidate(prev.KeyID, prev.ServerID); err != nil && len(ks) > 0 {
			_, _ = rec.keys.SelectCandidate(ks[0].ID, ks[0].ServerID)
		}
	} else if len(ks) > 0 {
		_, _ = rec.keys.SelectCandidate(ks[0].ID, ks[0].ServerID)
	}
	return nil
}

func (s *Service) SelectCandidate(profileID, keyID, serverID string) (keys.ConnectionCandidate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.byID[profileID]
	if !ok {
		return keys.ConnectionCandidate{}, ErrNotFound
	}
	return rec.keys.SelectCandidate(keyID, serverID)
}

func (s *Service) ChangeServer(profileID, serverID string) (keys.ConnectionCandidate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.byID[profileID]
	if !ok {
		return keys.ConnectionCandidate{}, ErrNotFound
	}
	srv, err := findServer(rec.servers, serverID)
	if err != nil {
		return keys.ConnectionCandidate{}, err
	}
	active, ok := rec.keys.ActiveCandidate()
	keyID := ""
	if ok {
		keyID = active.KeyID
	} else if len(rec.keys.Keys) > 0 {
		keyID = rec.keys.Keys[0].ID
	}
	if keyID == "" {
		return keys.ConnectionCandidate{}, keys.ErrNotFound
	}
	return rec.keys.SelectCandidate(keyID, srv.ID)
}

func (s *Service) SelectServerMode(profileID string, mode servers.Mode, manualID string) (keys.ConnectionCandidate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.byID[profileID]
	if !ok {
		return keys.ConnectionCandidate{}, ErrNotFound
	}
	prev := ""
	if c, ok := rec.keys.ActiveCandidate(); ok {
		prev = c.ServerID
	}
	srv, err := servers.Select(mode, rec.servers, manualID, prev)
	if err != nil {
		return keys.ConnectionCandidate{}, err
	}
	keyID := keyForServer(rec.keys.Keys, srv.ID)
	if keyID == "" && len(rec.keys.Keys) > 0 {
		keyID = rec.keys.Keys[0].ID
	}
	if keyID == "" {
		return keys.ConnectionCandidate{}, keys.ErrNotFound
	}
	return rec.keys.SelectCandidate(keyID, srv.ID)
}

func (s *Service) Rotate(profileID string) (keys.ConnectionCandidate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.byID[profileID]
	if !ok {
		return keys.ConnectionCandidate{}, ErrNotFound
	}
	if len(rec.servers) > 1 {
		prev := ""
		if c, ok := rec.keys.ActiveCandidate(); ok {
			prev = c.ServerID
		}
		srv, err := servers.Select(servers.ModeRotate, rec.servers, "", prev)
		if err != nil {
			return keys.ConnectionCandidate{}, err
		}
		keyID := keyForServer(rec.keys.Keys, srv.ID)
		if keyID == "" {
			return rec.keys.RotateKey()
		}
		return rec.keys.SelectCandidate(keyID, srv.ID)
	}
	return rec.keys.RotateKey()
}

func (s *Service) ChangeKey(ctx context.Context, profileID, keyID string) (keys.ConnectionCandidate, error) {
	s.mu.Lock()
	rec, ok := s.byID[profileID]
	if !ok {
		s.mu.Unlock()
		return keys.ConnectionCandidate{}, ErrNotFound
	}
	if _, ok := rec.keys.Key(keyID); !ok {
		s.mu.Unlock()
		return keys.ConnectionCandidate{}, keys.ErrNotFound
	}
	changer := s.changer
	s.mu.Unlock()

	resp, err := changer.ChangeKey(ctx, keys.ChangeKeyRequest{ProfileID: profileID, KeyID: keyID})
	if err != nil {
		return keys.ConnectionCandidate{}, err
	}
	parsed, err := subscription.Parse([]byte(strings.TrimSpace(resp.ShareURI())))
	if err != nil {
		return keys.ConnectionCandidate{}, err
	}
	if len(parsed.Entries) == 0 {
		return keys.ConnectionCandidate{}, subscription.ErrEmpty
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok = s.byID[profileID]
	if !ok {
		return keys.ConnectionCandidate{}, ErrNotFound
	}
	ks, srvs := s.entities(profileID, rec.sub.ID, parsed.Entries[:1])
	if len(ks) == 0 {
		return keys.ConnectionCandidate{}, subscription.ErrEmpty
	}
	rec.servers = mergeServers(rec.servers, srvs)
	return rec.keys.ReplaceKey(keyID, ks[0])
}

func (s *Service) CommitLastKnownGood(profileID string) (keys.LastKnownGood, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.byID[profileID]
	if !ok {
		return keys.LastKnownGood{}, ErrNotFound
	}
	return rec.keys.CommitGood(s.now())
}

func (s *Service) Rollback(profileID string) (keys.ConnectionCandidate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.byID[profileID]
	if !ok {
		return keys.ConnectionCandidate{}, ErrNotFound
	}
	return rec.keys.Rollback()
}

type loadedMeta struct {
	kind        string
	source      string
	sanitized   string
	contentType string
}

func (s *Service) load(ctx context.Context, raw string) (subscription.Result, loadedMeta, error) {
	low := strings.ToLower(strings.TrimSpace(raw))
	if strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "https://") {
		fetched, err := subscription.Fetch(ctx, s.client, raw)
		if err != nil {
			return subscription.Result{}, loadedMeta{}, err
		}
		parsed, err := subscription.Parse(fetched.Body)
		if err != nil {
			return subscription.Result{}, loadedMeta{}, err
		}
		return parsed, loadedMeta{
			kind:        "url",
			source:      raw,
			sanitized:   sanitizeForID(raw),
			contentType: fetched.ContentType,
		}, nil
	}
	parsed, err := subscription.Parse([]byte(raw))
	if err != nil {
		return subscription.Result{}, loadedMeta{}, err
	}
	kind := "share"
	if parsed.Format == "json-uri-array" || parsed.Format == "json-outbound" || parsed.Format == "json-vmess" {
		kind = "json"
	}
	return parsed, loadedMeta{kind: kind, source: raw, sanitized: parsed.Format}, nil
}

func (s *Service) entities(profileID, subID string, entries []subscription.ParsedShare) ([]keys.Key, []servers.Server) {
	var ks []keys.Key
	var srvs []servers.Server
	seenSrv := map[string]struct{}{}
	for _, e := range entries {
		countryID := ""
		if e.CountryHint != "" {
			c := s.catalog.Register(e.CountryHint, e.CountryHint)
			countryID = c.ID
		}
		srv := servers.Server{
			ID:        e.StableID,
			ProfileID: profileID,
			Host:      e.Host,
			Port:      e.Port,
			Transport: e.Transport,
			Security:  e.Security,
			CountryID: countryID,
			Remark:    e.Remark,
		}
		if _, ok := seenSrv[srv.ID]; !ok {
			seenSrv[srv.ID] = struct{}{}
			srvs = append(srvs, srv)
		}
		ks = append(ks, keys.New(e.StableID, profileID, subID, srv.ID, e.Protocol, e.Remark, e.Material()).WithParams(e.Params))
	}
	return ks, srvs
}

func findServer(list []servers.Server, id string) (servers.Server, error) {
	for _, srv := range list {
		if srv.ID == id {
			return srv, nil
		}
	}
	return servers.Server{}, servers.ErrNotFound
}

func keyForServer(ks []keys.Key, serverID string) string {
	for _, k := range ks {
		if k.ServerID == serverID {
			return k.ID
		}
	}
	return ""
}

func mergeServers(old, next []servers.Server) []servers.Server {
	seen := map[string]struct{}{}
	var out []servers.Server
	for _, s := range old {
		if _, ok := seen[s.ID]; ok {
			continue
		}
		seen[s.ID] = struct{}{}
		out = append(out, s)
	}
	for _, s := range next {
		if _, ok := seen[s.ID]; ok {
			continue
		}
		seen[s.ID] = struct{}{}
		out = append(out, s)
	}
	return out
}

func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return hex.EncodeToString([]byte(itoa(int(time.Now().UnixNano()))))
	}
	return hex.EncodeToString(b[:])
}

func hashOrRandom(kind, sanitized string) string {
	if sanitized == "" {
		return newID()
	}
	sum := sha256.Sum256([]byte(kind + "|" + sanitized))
	return hex.EncodeToString(sum[:16])
}

func sanitizeForID(raw string) string {
	// IDs must not incorporate query tokens from subscription URLs.
	if i := strings.Index(raw, "?"); i >= 0 {
		raw = raw[:i]
	}
	if i := strings.Index(raw, "#"); i >= 0 {
		raw = raw[:i]
	}
	return raw
}

func withSource(sub subscription.Subscription, source string) subscription.Subscription {
	return subscription.WithSource(sub, source)
}
