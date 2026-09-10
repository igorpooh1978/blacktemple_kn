package profiles

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/igorpooh1978/blacktemple_kn/src/internal/atomicfile"
	"github.com/igorpooh1978/blacktemple_kn/src/internal/keys"
	"github.com/igorpooh1978/blacktemple_kn/src/internal/servers"
	"github.com/igorpooh1978/blacktemple_kn/src/internal/subscription"
)

const (
	storeVersion     = 1
	storeFileName    = "profiles.json"
	storeFileMode    = 0o600
	classPersistFail = "PERSIST_FAILED"
	classStoreVer    = "STORE_VERSION"
	publicPersist    = "Не удалось сохранить профиль."
)

var (
	ErrUnsupportedStoreVersion = errors.New("profiles store version is not supported")
	ErrPersistFailed           = errors.New("profiles persist failed")
	ErrUnsupportedProtocol     = errors.New("unsupported protocol")
	ErrCorruptStore            = errors.New("profiles store is corrupt")
)

type persistClassError struct {
	class  string
	status int
	public string
	cause  error
}

func (e *persistClassError) Error() string {
	if e == nil {
		return "profiles persist error"
	}
	if e.class != "" {
		return "profiles " + e.class
	}
	return "profiles persist error"
}

func (e *persistClassError) Unwrap() error { return e.cause }

func (e *persistClassError) HTTPStatus() int {
	if e == nil {
		return 0
	}
	return e.status
}

func (e *persistClassError) PublicMessage() string {
	if e == nil {
		return ""
	}
	return e.public
}

func (e *persistClassError) GoString() string { return e.Error() }

func persistFailed(err error) error {
	return &persistClassError{class: classPersistFail, status: 500, public: publicPersist, cause: errors.Join(ErrPersistFailed, err)}
}

func storeVersionError(err error) error {
	return &persistClassError{class: classStoreVer, status: 500, public: publicPersist, cause: errors.Join(ErrUnsupportedStoreVersion, err)}
}

// memory is a cloneable durable snapshot of profile records.
type memory struct {
	byID     map[string]*record
	order    []string
	activeID string
}

type storeFile struct {
	Version         int            `json:"version"`
	ActiveProfileID string         `json:"activeProfileId"`
	Profiles        []profileStore `json:"profiles"`
}

type profileStore struct {
	ID             string          `json:"id"`
	Name           string          `json:"name"`
	SubscriptionID string          `json:"subscriptionId"`
	CreatedAt      time.Time       `json:"createdAt"`
	Subscription   subStore        `json:"subscription"`
	Keys           []keyStore      `json:"keys"`
	Servers        []serverStore   `json:"servers"`
	Active         *candidateStore `json:"activeCandidate,omitempty"`
	HasActive      bool            `json:"hasActive"`
	LKG            *lkgStore       `json:"lastKnownGood,omitempty"`
	HasLKG         bool            `json:"hasLastKnownGood"`
	RotateAt       int             `json:"rotateAt,omitempty"`
}

type subStore struct {
	ID          string    `json:"id"`
	ProfileID   string    `json:"profileId"`
	Kind        string    `json:"kind"`
	ContentType string    `json:"contentType,omitempty"`
	Encoding    string    `json:"encoding,omitempty"`
	EntryCount  int       `json:"entryCount"`
	FetchedAt   time.Time `json:"fetchedAt"`
	Source      string    `json:"source,omitempty"`
}

type keyStore struct {
	ID             string                        `json:"id"`
	ProfileID      string                        `json:"profileId"`
	SubscriptionID string                        `json:"subscriptionId"`
	ServerID       string                        `json:"serverId"`
	Protocol       string                        `json:"protocol"`
	Remark         string                        `json:"remark,omitempty"`
	Material       string                        `json:"material"`
	Params         subscription.ConnectionParams `json:"params"`
}

type serverStore struct {
	ID        string `json:"id"`
	ProfileID string `json:"profileId"`
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Transport string `json:"transport,omitempty"`
	Security  string `json:"security,omitempty"`
	CountryID string `json:"countryId,omitempty"`
	Remark    string `json:"remark,omitempty"`
}

type candidateStore struct {
	ID        string `json:"id"`
	ProfileID string `json:"profileId"`
	KeyID     string `json:"keyId"`
	ServerID  string `json:"serverId"`
}

type lkgStore struct {
	ProfileID string    `json:"profileId"`
	KeyID     string    `json:"keyId"`
	ServerID  string    `json:"serverId"`
	SavedAt   time.Time `json:"savedAt"`
}

func (s *Service) storePathLocked() string {
	if s.storePath != "" {
		return s.storePath
	}
	if s.dataDir == "" {
		return ""
	}
	return filepath.Join(s.dataDir, storeFileName)
}

func (s *Service) cloneLocked() *memory {
	next := &memory{
		byID:     make(map[string]*record, len(s.byID)),
		order:    append([]string(nil), s.order...),
		activeID: s.activeID,
	}
	for id, rec := range s.byID {
		next.byID[id] = cloneRecord(rec)
	}
	return next
}

func cloneRecord(rec *record) *record {
	if rec == nil {
		return nil
	}
	out := &record{
		profile: rec.profile,
		sub:     rec.sub,
		servers: append([]servers.Server(nil), rec.servers...),
	}
	if rec.keys != nil {
		out.keys = keys.ImportState(rec.keys.Export())
	} else {
		out.keys = keys.NewState(rec.profile.ID, nil)
	}
	return out
}

func (s *Service) commit(fn func(*memory) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.persistBlocked {
		return storeVersionError(ErrUnsupportedStoreVersion)
	}
	next := s.cloneLocked()
	if err := fn(next); err != nil {
		return err
	}
	if err := s.writeMemoryLocked(next); err != nil {
		return err
	}
	s.byID = next.byID
	s.order = next.order
	s.activeID = next.activeID
	return nil
}

func (s *Service) writeMemoryLocked(m *memory) error {
	path := s.storePathLocked()
	if path == "" {
		return nil
	}
	raw, err := encodeStore(m)
	if err != nil {
		return persistFailed(err)
	}
	if s.writer != nil {
		if err := s.writer.WriteFile(path, raw, storeFileMode); err != nil {
			return persistFailed(err)
		}
		return nil
	}
	if err := atomicfile.WriteFile(path, raw, storeFileMode); err != nil {
		return persistFailed(err)
	}
	return nil
}

func encodeStore(m *memory) ([]byte, error) {
	file := storeFile{
		Version:         storeVersion,
		ActiveProfileID: m.activeID,
		Profiles:        make([]profileStore, 0, len(m.order)),
	}
	for _, id := range m.order {
		rec := m.byID[id]
		if rec == nil {
			continue
		}
		file.Profiles = append(file.Profiles, encodeProfile(rec))
	}
	return json.Marshal(file)
}

func encodeProfile(rec *record) profileStore {
	snap := rec.keys.Export()
	ps := profileStore{
		ID:             rec.profile.ID,
		Name:           rec.profile.Name,
		SubscriptionID: rec.profile.SubscriptionID,
		CreatedAt:      rec.profile.CreatedAt,
		Subscription: subStore{
			ID:          rec.sub.ID,
			ProfileID:   rec.sub.ProfileID,
			Kind:        rec.sub.Kind,
			ContentType: rec.sub.ContentType,
			Encoding:    rec.sub.Encoding,
			EntryCount:  rec.sub.EntryCount,
			FetchedAt:   rec.sub.FetchedAt,
			Source:      rec.sub.SourceURL(),
		},
		HasActive: snap.HasActive,
		HasLKG:    snap.HasLKG,
		RotateAt:  snap.RotateAt,
	}
	for _, k := range snap.Keys {
		ps.Keys = append(ps.Keys, keyStore{
			ID:             k.ID,
			ProfileID:      k.ProfileID,
			SubscriptionID: k.SubscriptionID,
			ServerID:       k.ServerID,
			Protocol:       k.Protocol,
			Remark:         k.Remark,
			Material:       k.Material(),
			Params:         k.Params(),
		})
	}
	for _, srv := range rec.servers {
		ps.Servers = append(ps.Servers, serverStore{
			ID:        srv.ID,
			ProfileID: srv.ProfileID,
			Host:      srv.Host,
			Port:      srv.Port,
			Transport: srv.Transport,
			Security:  srv.Security,
			CountryID: srv.CountryID,
			Remark:    srv.Remark,
		})
	}
	if snap.HasActive {
		c := snap.Active
		ps.Active = &candidateStore{ID: c.ID, ProfileID: c.ProfileID, KeyID: c.KeyID, ServerID: c.ServerID}
	}
	if snap.HasLKG {
		l := snap.LKG
		ps.LKG = &lkgStore{ProfileID: l.ProfileID, KeyID: l.KeyID, ServerID: l.ServerID, SavedAt: l.SavedAt}
	}
	return ps
}

func (s *Service) loadFromDisk() error {
	path := s.storePathLocked()
	if path == "" {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil
	}
	var file storeFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return ErrCorruptStore
	}
	if file.Version != storeVersion {
		return ErrUnsupportedStoreVersion
	}
	m, err := decodeStore(file)
	if err != nil {
		return err
	}
	s.byID = m.byID
	s.order = m.order
	s.activeID = m.activeID
	for _, rec := range s.byID {
		for _, srv := range rec.servers {
			if srv.CountryID != "" {
				s.catalog.Register(srv.CountryID, srv.CountryID)
			}
		}
	}
	return nil
}

func decodeStore(file storeFile) (*memory, error) {
	m := &memory{
		byID:     map[string]*record{},
		order:    make([]string, 0, len(file.Profiles)),
		activeID: file.ActiveProfileID,
	}
	seen := map[string]struct{}{}
	for _, p := range file.Profiles {
		if p.ID == "" {
			return nil, ErrCorruptStore
		}
		if _, ok := seen[p.ID]; ok {
			continue
		}
		seen[p.ID] = struct{}{}
		rec, err := decodeProfile(p)
		if err != nil {
			return nil, err
		}
		m.byID[p.ID] = rec
		m.order = append(m.order, p.ID)
	}
	if m.activeID != "" {
		if _, ok := m.byID[m.activeID]; !ok {
			m.activeID = ""
		}
	}
	return m, nil
}

func decodeProfile(p profileStore) (*record, error) {
	ks := make([]keys.Key, 0, len(p.Keys))
	for _, k := range p.Keys {
		ks = append(ks, keys.New(k.ID, k.ProfileID, k.SubscriptionID, k.ServerID, k.Protocol, k.Remark, k.Material).WithParams(k.Params))
	}
	snap := keys.StateSnapshot{
		ProfileID: p.ID,
		Keys:      ks,
		HasActive: p.HasActive,
		HasLKG:    p.HasLKG,
		RotateAt:  p.RotateAt,
	}
	if p.Active != nil {
		snap.Active = keys.ConnectionCandidate{
			ID:        p.Active.ID,
			ProfileID: p.Active.ProfileID,
			KeyID:     p.Active.KeyID,
			ServerID:  p.Active.ServerID,
		}
		snap.HasActive = true
	}
	if p.LKG != nil {
		snap.LKG = keys.LastKnownGood{
			ProfileID: p.LKG.ProfileID,
			KeyID:     p.LKG.KeyID,
			ServerID:  p.LKG.ServerID,
			SavedAt:   p.LKG.SavedAt,
		}
		snap.HasLKG = true
	}
	srvs := make([]servers.Server, 0, len(p.Servers))
	for _, srv := range p.Servers {
		srvs = append(srvs, servers.Server{
			ID:        srv.ID,
			ProfileID: srv.ProfileID,
			Host:      srv.Host,
			Port:      srv.Port,
			Transport: srv.Transport,
			Security:  srv.Security,
			CountryID: srv.CountryID,
			Remark:    srv.Remark,
		})
	}
	sub := subscription.Subscription{
		ID:          p.Subscription.ID,
		ProfileID:   p.Subscription.ProfileID,
		Kind:        p.Subscription.Kind,
		ContentType: p.Subscription.ContentType,
		Encoding:    p.Subscription.Encoding,
		EntryCount:  p.Subscription.EntryCount,
		FetchedAt:   p.Subscription.FetchedAt,
	}
	sub = subscription.WithSource(sub, p.Subscription.Source)
	return &record{
		profile: Profile{
			ID:             p.ID,
			Name:           p.Name,
			SubscriptionID: p.SubscriptionID,
			CreatedAt:      p.CreatedAt,
		},
		sub:     sub,
		keys:    keys.ImportState(snap),
		servers: srvs,
	}, nil
}
