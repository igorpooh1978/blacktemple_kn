package geodata

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/igorpooh1978/blacktemple_kn/src/internal/atomicfile"
)

// Options configure a Manager. MaxFileBytes and MaxSets use defaults when <= 0.
type Options struct {
	MaxFileBytes int64
	MaxSets      int
	Now          func() time.Time
	Pointer      *atomicfile.Writer
}

// Manager owns immutable geodata sets under DataDir/geodata/sets and a
// state.json pointer. Last-known-good is never renamed or deleted to install.
type Manager struct {
	dataDir  string
	root     string
	validate Validator
	maxBytes int64
	maxSets  int
	now      func() time.Time
	pointer  *atomicfile.Writer
	seq      uint64
	mu       sync.Mutex

	writeMeta func(path string, data []byte, perm os.FileMode) error
	copyFile  func(src, dest string) (int64, string, error)
	removeAll func(string) error
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
	maxSets := opts.MaxSets
	if maxSets <= 0 {
		maxSets = defaultMaxSets
	}
	if maxSets < 2 {
		maxSets = 2
	}
	if maxSets > 3 {
		maxSets = 3
	}
	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	root := filepath.Join(dataDir, "geodata")
	m := &Manager{
		dataDir:  dataDir,
		root:     root,
		validate: v,
		maxBytes: maxBytes,
		maxSets:  maxSets,
		now:      now,
		pointer:  opts.Pointer,
	}
	m.writeMeta = writeNewFileSync
	m.copyFile = func(src, dest string) (int64, string, error) {
		return streamCopyFile(src, dest, m.maxBytes)
	}
	m.removeAll = os.RemoveAll
	_ = m.Recover()
	return m, nil
}

func (m *Manager) setsDir() string {
	return filepath.Join(m.root, dirSets)
}

func (m *Manager) setDir(id string) string {
	return filepath.Join(m.setsDir(), id)
}

func (m *Manager) statePath() string {
	return filepath.Join(m.root, fileState)
}

func (m *Manager) writePointer(st pointerState) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	w := m.pointer
	if w == nil {
		return atomicfile.WriteFile(m.statePath(), b, 0o600)
	}
	return w.WriteFile(m.statePath(), b, 0o600)
}

func (m *Manager) loadState() (pointerState, error) {
	b, err := os.ReadFile(m.statePath())
	if err != nil {
		return pointerState{}, err
	}
	var st pointerState
	if err := json.Unmarshal(b, &st); err != nil {
		return pointerState{}, fmt.Errorf("%w: %v", ErrCorruptState, err)
	}
	return st, nil
}

func (m *Manager) setComplete(id string) bool {
	if id == "" {
		return false
	}
	dir := m.setDir(id)
	for _, name := range []string{fileGeoIP, fileGeoSite, fileMeta} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			return false
		}
	}
	return true
}

func (m *Manager) loadSetMeta(id string) (Snapshot, error) {
	path := filepath.Join(m.setDir(id), fileMeta)
	b, err := os.ReadFile(path)
	if err != nil {
		return Snapshot{}, err
	}
	var s Snapshot
	if err := json.Unmarshal(b, &s); err != nil {
		return Snapshot{}, err
	}
	s.SetID = id
	s.Slot = id
	return s, nil
}

func (m *Manager) resolveIDs() (active, previous string, err error) {
	st, err := m.loadState()
	if err != nil {
		if os.IsNotExist(err) {
			return "", "", nil
		}
		return "", "", err
	}
	if m.setComplete(st.Active) {
		prev := st.Previous
		if !m.setComplete(prev) {
			prev = ""
		}
		return st.Active, prev, nil
	}
	if m.setComplete(st.Previous) {
		return st.Previous, "", ErrMissingActiveSet
	}
	if st.Active != "" {
		return "", "", ErrMissingActiveSet
	}
	return "", "", nil
}

// Active returns metadata for the authoritative set (active, or previous if
// the pointer's active directory is gone).
func (m *Manager) Active() Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, _, err := m.resolveIDs()
	if id == "" {
		return Snapshot{GeoIP: missingMeta(), GeoSite: missingMeta()}
	}
	snap, loadErr := m.loadSetMeta(id)
	if loadErr != nil {
		_ = err
		return Snapshot{GeoIP: missingMeta(), GeoSite: missingMeta(), SetID: id, Slot: id}
	}
	return snap
}

// ActivePaths returns on-disk locations for the current set. R5 does not embed
// these paths into Xray config.
func (m *Manager) ActivePaths() (ActivePaths, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, _, err := m.resolveIDs()
	if id == "" {
		if err != nil {
			return ActivePaths{}, err
		}
		return ActivePaths{}, ErrMissingActiveSet
	}
	snap, loadErr := m.loadSetMeta(id)
	if loadErr != nil {
		if err != nil {
			return ActivePaths{}, err
		}
		return ActivePaths{}, loadErr
	}
	p := ActivePaths{
		SetID:         id,
		Version:       snap.GeoIP.Version,
		GeoIPPath:     filepath.Join(m.setDir(id), fileGeoIP),
		GeoSitePath:   filepath.Join(m.setDir(id), fileGeoSite),
		GeoIPSHA256:   snap.GeoIP.SHA256,
		GeoSiteSHA256: snap.GeoSite.SHA256,
	}
	return p, err
}

// Install copies a local candidate into a new immutable set, then atomically
// replaces state.json. The previous active set is not modified until the pointer
// commit.
func (m *Manager) Install(ctx context.Context, c Candidate) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := os.MkdirAll(m.setsDir(), 0o755); err != nil {
		return err
	}

	now := m.now()
	oldActive, oldPrevious, _ := m.resolveIDs()

	setID := m.newSetID()
	setDir := m.setDir(setID)
	if err := os.MkdirAll(setDir, 0o755); err != nil {
		return err
	}

	ipMeta, err := m.stageFile(c.GeoIPPath, filepath.Join(setDir, fileGeoIP), c.GeoIPSHA256, c.Source, c.Version, now)
	if err != nil {
		return err
	}
	siteMeta, err := m.stageFile(c.GeoSitePath, filepath.Join(setDir, fileGeoSite), c.GeoSiteSHA256, c.Source, c.Version, now)
	if err != nil {
		return err
	}

	ipPath := filepath.Join(setDir, fileGeoIP)
	sitePath := filepath.Join(setDir, fileGeoSite)
	if err := m.validate.Validate(ctx, ipPath, sitePath); err != nil {
		return fmt.Errorf("%w: %v", ErrValidate, err)
	}

	ipMeta.Status = StatusActive
	siteMeta.Status = StatusActive
	ipMeta.ValidatedAt = now
	siteMeta.ValidatedAt = now
	snap := Snapshot{
		GeoIP:     ipMeta,
		GeoSite:   siteMeta,
		SetID:     setID,
		Slot:      setID,
		UpdatedAt: now,
	}
	metaBytes, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	if err := m.writeMeta(filepath.Join(setDir, fileMeta), metaBytes, 0o600); err != nil {
		return err
	}
	_ = atomicfile.SyncDir(setDir)

	st := pointerState{Active: setID, Previous: oldActive}
	if err := m.writePointer(st); err != nil {
		return err
	}

	keep := map[string]struct{}{setID: {}, oldActive: {}}
	if oldPrevious != "" && oldPrevious != oldActive && oldPrevious != setID {
		if len(keep) < m.maxSets {
			keep[oldPrevious] = struct{}{}
		}
	}
	_ = m.gcLocked(keep)
	return nil
}

func (m *Manager) newSetID() string {
	m.seq++
	return fmt.Sprintf("set-%d-%d", m.now().UnixNano(), m.seq)
}

func (m *Manager) stageFile(src, dest, wantSHA, source, version string, now time.Time) (Metadata, error) {
	if wantSHA == "" {
		return Metadata{Source: source, Version: version, Status: StatusFailed}, ErrMissingChecksum
	}
	size, sum, err := m.copyFile(src, dest)
	if err != nil {
		return Metadata{Source: source, Version: version, Status: StatusFailed}, err
	}
	if sum != wantSHA {
		return Metadata{Source: source, Version: version, SHA256: sum, Size: size, Status: StatusFailed}, ErrChecksum
	}
	return Metadata{
		Source:       source,
		Version:      version,
		SHA256:       sum,
		Size:         size,
		DownloadedAt: now,
		Status:       StatusDownloaded,
	}, nil
}

// Rollback swaps state.active and state.previous via atomic state.json replace.
func (m *Manager) Rollback() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	st, err := m.loadState()
	if err != nil {
		if os.IsNotExist(err) {
			return ErrNoPrevious
		}
		return err
	}
	if st.Previous == "" || !m.setComplete(st.Previous) {
		return ErrNoPrevious
	}
	next := pointerState{Active: st.Previous, Previous: st.Active}
	return m.writePointer(next)
}

func (m *Manager) gcLocked(keep map[string]struct{}) error {
	entries, err := os.ReadDir(m.setsDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var gcErr error
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, ok := keep[e.Name()]; ok {
			continue
		}
		if err := m.removeAll(m.setDir(e.Name())); err != nil && gcErr == nil {
			gcErr = err
		}
	}
	return gcErr
}

func (m *Manager) retainedSetIDs() []string {
	id, prev, _ := m.resolveIDs()
	var out []string
	if id != "" {
		out = append(out, id)
	}
	if prev != "" && prev != id {
		out = append(out, prev)
	}
	return out
}

func (m *Manager) fileExists(id, name string) bool {
	if id == "" {
		return false
	}
	_, err := os.Stat(filepath.Join(m.setDir(id), name))
	return err == nil
}
