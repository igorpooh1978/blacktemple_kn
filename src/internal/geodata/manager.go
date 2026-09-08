package geodata

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Options configure a Manager. MaxFileBytes and MaxBackups use defaults when <= 0.
type Options struct {
	MaxFileBytes int64
	MaxBackups   int
	Now          func() time.Time
}

// Manager owns geodata file slots under DataDir/geodata/{active,previous,candidate}.
type Manager struct {
	dataDir  string
	root     string
	validate Validator
	maxBytes int64
	backups  int
	now      func() time.Time
	mu       sync.Mutex
}

func NewManager(dataDir string, v Validator, opts Options) (*Manager, error) {
	if dataDir == "" {
		return nil, ErrEmptyDataDir
	}
	if v == nil {
		return nil, ErrNilValidator
	}
	maxBytes := opts.MaxFileBytes
	if maxBytes <= 0 {
		maxBytes = defaultMaxFileBytes
	}
	backups := opts.MaxBackups
	if backups <= 0 {
		backups = defaultMaxBackups
	}
	if backups > 2 {
		backups = 2
	}
	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	root := filepath.Join(dataDir, "geodata")
	return &Manager{
		dataDir:  dataDir,
		root:     root,
		validate: v,
		maxBytes: maxBytes,
		backups:  backups,
		now:      now,
	}, nil
}

func (m *Manager) slotPath(slot string) string {
	return filepath.Join(m.root, slot)
}

func (m *Manager) Active() Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	snap, err := m.loadSnapshot(slotActive)
	if err != nil {
		return Snapshot{
			GeoIP:   missingMeta(),
			GeoSite: missingMeta(),
			Slot:    slotActive,
		}
	}
	return snap
}

// Install stages a local candidate, verifies size and SHA256, runs Validator,
// then atomically replaces active. On failure the working (active) files stay.
func (m *Manager) Install(ctx context.Context, c Candidate) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	candDir := m.slotPath(slotCandidate)
	_ = os.RemoveAll(candDir)
	if err := os.MkdirAll(candDir, 0o755); err != nil {
		return err
	}

	now := m.now()
	geoIPMeta, err := m.stageFile(c.GeoIPPath, filepath.Join(candDir, fileGeoIP), c.GeoIPSHA256, c.Source, c.Version, now)
	if err != nil {
		m.writeFailed(candDir, Metadata{Source: c.Source, Version: c.Version, Status: StatusFailed}, missingMeta(), now)
		return err
	}
	geoSiteMeta, err := m.stageFile(c.GeoSitePath, filepath.Join(candDir, fileGeoSite), c.GeoSiteSHA256, c.Source, c.Version, now)
	if err != nil {
		m.writeFailed(candDir, geoIPMeta.withStatus(StatusFailed), Metadata{Source: c.Source, Version: c.Version, Status: StatusFailed}, now)
		return err
	}

	geoIPMeta.Status = StatusDownloaded
	geoSiteMeta.Status = StatusDownloaded
	_ = m.writeSnapshot(candDir, Snapshot{GeoIP: geoIPMeta, GeoSite: geoSiteMeta, Slot: slotCandidate, UpdatedAt: now})

	ipPath := filepath.Join(candDir, fileGeoIP)
	sitePath := filepath.Join(candDir, fileGeoSite)
	if err := m.validate.Validate(ctx, ipPath, sitePath); err != nil {
		geoIPMeta.Status = StatusFailed
		geoSiteMeta.Status = StatusFailed
		_ = m.writeSnapshot(candDir, Snapshot{GeoIP: geoIPMeta, GeoSite: geoSiteMeta, Slot: slotCandidate, UpdatedAt: now})
		return fmt.Errorf("%w: %v", ErrValidate, err)
	}

	geoIPMeta.Status = StatusValidated
	geoSiteMeta.Status = StatusValidated
	geoIPMeta.ValidatedAt = now
	geoSiteMeta.ValidatedAt = now

	before, _ := m.loadSnapshot(slotActive)

	if err := m.rotateBackups(); err != nil {
		geoIPMeta.Status = StatusFailed
		geoSiteMeta.Status = StatusFailed
		_ = m.writeSnapshot(candDir, Snapshot{GeoIP: geoIPMeta, GeoSite: geoSiteMeta, Slot: slotCandidate, UpdatedAt: now})
		return err
	}

	geoIPMeta.Status = StatusActive
	geoSiteMeta.Status = StatusActive
	if err := m.writeSnapshot(candDir, Snapshot{GeoIP: geoIPMeta, GeoSite: geoSiteMeta, Slot: slotActive, UpdatedAt: now}); err != nil {
		return err
	}

	activeDir := m.slotPath(slotActive)
	if err := os.Rename(candDir, activeDir); err != nil {
		_ = os.RemoveAll(activeDir)
		if err2 := os.Rename(candDir, activeDir); err2 != nil {
			m.restoreActive(before)
			return err2
		}
	}
	_ = syncDir(m.root)
	return nil
}

func (m Metadata) withStatus(s Status) Metadata {
	m.Status = s
	return m
}

func (m *Manager) writeFailed(dir string, ip, site Metadata, now time.Time) {
	ip.Status = StatusFailed
	site.Status = StatusFailed
	_ = m.writeSnapshot(dir, Snapshot{GeoIP: ip, GeoSite: site, Slot: slotCandidate, UpdatedAt: now})
}

func (m *Manager) stageFile(src, dest, wantSHA, source, version string, now time.Time) (Metadata, error) {
	if src == "" {
		return Metadata{Status: StatusFailed}, ErrMissingCandidate
	}
	st, err := os.Stat(src)
	if err != nil {
		return Metadata{Status: StatusFailed}, fmt.Errorf("%w: %v", ErrMissingCandidate, err)
	}
	if st.Size() > m.maxBytes {
		return Metadata{Source: source, Version: version, Size: st.Size(), Status: StatusFailed}, ErrOversized
	}
	if wantSHA == "" {
		return Metadata{Source: source, Version: version, Size: st.Size(), Status: StatusFailed}, ErrMissingChecksum
	}
	sum, err := fileSHA256(src)
	if err != nil {
		return Metadata{Status: StatusFailed}, err
	}
	if sum != wantSHA {
		return Metadata{Source: source, Version: version, SHA256: sum, Size: st.Size(), Status: StatusFailed}, ErrChecksum
	}
	if err := copyFileSync(src, dest, 0o644); err != nil {
		return Metadata{Status: StatusFailed}, err
	}
	return Metadata{
		Source:       source,
		Version:      version,
		SHA256:       sum,
		Size:         st.Size(),
		DownloadedAt: now,
		Status:       StatusDownloaded,
	}, nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (m *Manager) rotateBackups() error {
	active := m.slotPath(slotActive)
	prev := m.slotPath(slotPrevious)
	prev2 := m.slotPath(slotPrevious2)

	if m.backups >= 2 {
		_ = os.RemoveAll(prev2)
		if _, err := os.Stat(prev); err == nil {
			if err := os.Rename(prev, prev2); err != nil {
				return err
			}
		}
	} else {
		_ = os.RemoveAll(prev)
		_ = os.RemoveAll(prev2)
	}
	if _, err := os.Stat(active); err == nil {
		if err := os.Rename(active, prev); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) restoreActive(before Snapshot) {
	prev := m.slotPath(slotPrevious)
	active := m.slotPath(slotActive)
	if _, err := os.Stat(prev); err != nil {
		return
	}
	_ = os.RemoveAll(active)
	_ = os.Rename(prev, active)
	_ = before
}

// Rollback promotes previous → active. Current active moves to candidate.
func (m *Manager) Rollback() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	prev := m.slotPath(slotPrevious)
	if _, err := os.Stat(prev); err != nil {
		return ErrNoPrevious
	}
	cand := m.slotPath(slotCandidate)
	_ = os.RemoveAll(cand)
	active := m.slotPath(slotActive)
	if _, err := os.Stat(active); err == nil {
		if err := os.Rename(active, cand); err != nil {
			return err
		}
	}
	if err := os.Rename(prev, active); err != nil {
		if _, cErr := os.Stat(cand); cErr == nil {
			_ = os.Rename(cand, active)
		}
		return err
	}
	prev2 := m.slotPath(slotPrevious2)
	if _, err := os.Stat(prev2); err == nil {
		_ = os.Rename(prev2, prev)
	}
	_ = syncDir(m.root)
	return nil
}

func (m *Manager) loadSnapshot(slot string) (Snapshot, error) {
	path := filepath.Join(m.slotPath(slot), fileMeta)
	b, err := os.ReadFile(path)
	if err != nil {
		return Snapshot{}, err
	}
	var s Snapshot
	if err := json.Unmarshal(b, &s); err != nil {
		return Snapshot{}, err
	}
	s.Slot = slot
	return s, nil
}

func (m *Manager) writeSnapshot(dir string, s Snapshot) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return writeFileSync(filepath.Join(dir, fileMeta), b, 0o600)
}

func (m *Manager) backupSlots() []string {
	var out []string
	for _, slot := range []string{slotPrevious, slotPrevious2} {
		if _, err := os.Stat(m.slotPath(slot)); err == nil {
			out = append(out, slot)
		}
	}
	return out
}

func (m *Manager) fileExists(slot, name string) bool {
	_, err := os.Stat(filepath.Join(m.slotPath(slot), name))
	return err == nil
}
