package profiles

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/igorpooh1978/blacktemple_kn/src/internal/atomicfile"
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

// Config wires a profile service. Empty DataDir keeps an in-memory store.
type Config struct {
	Client  *http.Client
	Changer keys.KeyChanger
	DataDir string
	Writer  *atomicfile.Writer
}

type record struct {
	profile Profile
	sub     subscription.Subscription
	keys    *keys.State
	servers []servers.Server
}

// Service is the profile/subscription/key lifecycle with optional durable store.
type Service struct {
	mu             sync.Mutex
	client         *http.Client
	changer        keys.KeyChanger
	catalog        *countries.Catalog
	byID           map[string]*record
	order          []string
	activeID       string
	now            func() time.Time
	dataDir        string
	storePath      string
	writer         *atomicfile.Writer
	persistBlocked bool
}

func NewService(client *http.Client, changer keys.KeyChanger) *Service {
	return New(Config{Client: client, Changer: changer})
}

func New(cfg Config) *Service {
	if cfg.Changer == nil {
		cfg.Changer = keys.UnconfiguredChanger{}
	}
	s := &Service{
		client:    cfg.Client,
		changer:   cfg.Changer,
		catalog:   countries.NewCatalog(),
		byID:      map[string]*record{},
		now:       func() time.Time { return time.Now().UTC() },
		dataDir:   cfg.DataDir,
		writer:    cfg.Writer,
		storePath: "",
	}
	if cfg.DataDir != "" {
		s.storePath = filepath.Join(cfg.DataDir, storeFileName)
		if err := s.loadFromDisk(); err != nil {
			s.byID = map[string]*record{}
			s.order = nil
			s.activeID = ""
			s.persistBlocked = true
		}
	}
	return s
}

func (s *Service) Catalog() *countries.Catalog { return s.catalog }

func (s *Service) StorePath() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.storePathLocked()
}

func (s *Service) PersistBlocked() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.persistBlocked
}

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
	return s.commit(func(m *memory) error {
		if _, ok := m.byID[id]; !ok {
			return ErrNotFound
		}
		m.activeID = id
		return nil
	})
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
	parsed, subMeta, err := s.load(ctx, raw)
	if err != nil {
		return Profile{}, err
	}
	var p Profile
	err = s.commit(func(m *memory) error {
		id := newID()
		name := strings.TrimSpace(req.Name)
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
		published := filterPublishable(parsed.Entries)
		ks, srvs := s.entities(id, subID, published)
		st := keys.NewState(id, ks)
		if len(ks) > 0 {
			_, _ = st.SelectCandidate(ks[0].ID, ks[0].ServerID)
		}
		p = Profile{
			ID:              id,
			Name:            name,
			SubscriptionID:  subID,
			CreatedAt:       s.now(),
			SourceKind:      sourceKindOf(subMeta.kind, parsed.Entries, published),
			ResolutionState: resolutionOf(len(ks)),
		}
		m.byID[id] = &record{profile: p, sub: sub, keys: st, servers: srvs}
		m.order = append(m.order, id)
		if m.activeID == "" {
			m.activeID = id
		}
		return nil
	})
	if err != nil {
		return Profile{}, err
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
	return s.commit(func(m *memory) error {
		rec, ok := m.byID[profileID]
		if !ok {
			return ErrNotFound
		}
		published := filterPublishable(parsed.Entries)
		sub := rec.sub
		sub.ContentType = subMeta.contentType
		sub.Encoding = parsed.Encoding
		sub.EntryCount = len(parsed.Entries)
		sub.FetchedAt = s.now()
		rec.sub = withSource(sub, src)
		if len(published) == 0 {
			rec.profile.ResolutionState = resolutionOf(len(rec.keys.Keys))
			return nil
		}
		ks, srvs := s.entities(profileID, rec.sub.ID, published)
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
		return nil
	})
}

func (s *Service) SelectCandidate(profileID, keyID, serverID string) (keys.ConnectionCandidate, error) {
	var out keys.ConnectionCandidate
	err := s.commit(func(m *memory) error {
		rec, ok := m.byID[profileID]
		if !ok {
			return ErrNotFound
		}
		c, err := rec.keys.SelectCandidate(keyID, serverID)
		if err != nil {
			return err
		}
		out = c
		return nil
	})
	return out, err
}

func (s *Service) ChangeServer(profileID, serverID string) (keys.ConnectionCandidate, error) {
	var out keys.ConnectionCandidate
	err := s.commit(func(m *memory) error {
		rec, ok := m.byID[profileID]
		if !ok {
			return ErrNotFound
		}
		srv, err := findServer(rec.servers, serverID)
		if err != nil {
			return err
		}
		active, ok := rec.keys.ActiveCandidate()
		keyID := ""
		if ok {
			keyID = active.KeyID
		} else if len(rec.keys.Keys) > 0 {
			keyID = rec.keys.Keys[0].ID
		}
		if keyID == "" {
			return keys.ErrNotFound
		}
		c, err := rec.keys.SelectCandidate(keyID, srv.ID)
		if err != nil {
			return err
		}
		out = c
		return nil
	})
	return out, err
}

func (s *Service) SelectServerMode(profileID string, mode servers.Mode, manualID string) (keys.ConnectionCandidate, error) {
	var out keys.ConnectionCandidate
	err := s.commit(func(m *memory) error {
		rec, ok := m.byID[profileID]
		if !ok {
			return ErrNotFound
		}
		prev := ""
		if c, ok := rec.keys.ActiveCandidate(); ok {
			prev = c.ServerID
		}
		srv, err := servers.Select(mode, rec.servers, manualID, prev)
		if err != nil {
			return err
		}
		keyID := keyForServer(rec.keys.Keys, srv.ID)
		if keyID == "" && len(rec.keys.Keys) > 0 {
			keyID = rec.keys.Keys[0].ID
		}
		if keyID == "" {
			return keys.ErrNotFound
		}
		c, err := rec.keys.SelectCandidate(keyID, srv.ID)
		if err != nil {
			return err
		}
		out = c
		return nil
	})
	return out, err
}

func (s *Service) Rotate(profileID string) (keys.ConnectionCandidate, error) {
	var out keys.ConnectionCandidate
	err := s.commit(func(m *memory) error {
		rec, ok := m.byID[profileID]
		if !ok {
			return ErrNotFound
		}
		var c keys.ConnectionCandidate
		var err error
		if len(rec.servers) > 1 {
			prev := ""
			if active, ok := rec.keys.ActiveCandidate(); ok {
				prev = active.ServerID
			}
			srv, selErr := servers.Select(servers.ModeRotate, rec.servers, "", prev)
			if selErr != nil {
				return selErr
			}
			keyID := keyForServer(rec.keys.Keys, srv.ID)
			if keyID == "" {
				c, err = rec.keys.RotateKey()
			} else {
				c, err = rec.keys.SelectCandidate(keyID, srv.ID)
			}
		} else {
			c, err = rec.keys.RotateKey()
		}
		if err != nil {
			return err
		}
		out = c
		return nil
	})
	return out, err
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
		return keys.ConnectionCandidate{}, subscription.ClassifyParse(err)
	}
	if len(parsed.Entries) == 0 {
		return keys.ConnectionCandidate{}, subscription.ClassifyParse(subscription.ErrEmpty)
	}
	if !strings.EqualFold(parsed.Entries[0].Protocol, "vless") {
		return keys.ConnectionCandidate{}, ErrUnsupportedProtocol
	}

	var out keys.ConnectionCandidate
	err = s.commit(func(m *memory) error {
		rec, ok := m.byID[profileID]
		if !ok {
			return ErrNotFound
		}
		if _, ok := rec.keys.Key(keyID); !ok {
			return keys.ErrNotFound
		}
		ks, srvs := s.entities(profileID, rec.sub.ID, parsed.Entries[:1])
		if len(ks) == 0 {
			return subscription.ClassifyParse(subscription.ErrEmpty)
		}
		rec.servers = mergeServers(rec.servers, srvs)
		c, err := rec.keys.ReplaceKey(keyID, ks[0])
		if err != nil {
			return err
		}
		out = c
		return nil
	})
	return out, err
}

func (s *Service) CommitLastKnownGood(profileID string) (keys.LastKnownGood, error) {
	var out keys.LastKnownGood
	err := s.commit(func(m *memory) error {
		rec, ok := m.byID[profileID]
		if !ok {
			return ErrNotFound
		}
		lkg, err := rec.keys.CommitGood(s.now())
		if err != nil {
			return err
		}
		out = lkg
		return nil
	})
	return out, err
}

func (s *Service) Rollback(profileID string) (keys.ConnectionCandidate, error) {
	var out keys.ConnectionCandidate
	err := s.commit(func(m *memory) error {
		rec, ok := m.byID[profileID]
		if !ok {
			return ErrNotFound
		}
		c, err := rec.keys.Rollback()
		if err != nil {
			return err
		}
		out = c
		return nil
	})
	return out, err
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
			return subscription.Result{}, loadedMeta{}, subscription.ClassifyParse(err)
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
		return subscription.Result{}, loadedMeta{}, subscription.ClassifyParse(err)
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
