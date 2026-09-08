package supervisor

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ErrNotFound is returned by RuntimeStore.Load when no snapshot exists.
var ErrNotFound = errors.New("supervisor: runtime state not found")

// Snapshot is persisted Xray child runtime state. A pid here is a hint, not proof.
type Snapshot struct {
	State        State      `json:"state"`
	PID          *int       `json:"pid"`
	Executable   string     `json:"executable,omitempty"`
	Version      string     `json:"version,omitempty"`
	StartedAt    *time.Time `json:"startedAt,omitempty"`
	LastExit     *int       `json:"lastExit,omitempty"`
	RestartCount int        `json:"restartCount"`
	LastError    string     `json:"lastError,omitempty"`
}

func (s Snapshot) clone() Snapshot {
	out := s
	if s.PID != nil {
		v := *s.PID
		out.PID = &v
	}
	if s.StartedAt != nil {
		v := *s.StartedAt
		out.StartedAt = &v
	}
	if s.LastExit != nil {
		v := *s.LastExit
		out.LastExit = &v
	}
	return out
}

// RuntimeStore persists supervisor snapshot. Implementations must not
// treat the file as a live process without IdentityChecker.
type RuntimeStore interface {
	Load() (Snapshot, error)
	Save(Snapshot) error
}

// MemoryStore is an in-process store (tests and default).
type MemoryStore struct {
	mu      sync.Mutex
	snap    Snapshot
	present bool
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{}
}

func (m *MemoryStore) Load() (Snapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.present {
		return Snapshot{}, ErrNotFound
	}
	return m.snap.clone(), nil
}

func (m *MemoryStore) Save(s Snapshot) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.snap = s.clone()
	m.present = true
	return nil
}

// FileStore persists JSON under Path. Never trust pid from this file blindly.
type FileStore struct {
	Path string
}

func (f *FileStore) Load() (Snapshot, error) {
	if f == nil || f.Path == "" {
		return Snapshot{}, ErrNotFound
	}
	b, err := os.ReadFile(f.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return Snapshot{}, ErrNotFound
		}
		return Snapshot{}, err
	}
	var s Snapshot
	if err := json.Unmarshal(b, &s); err != nil {
		return Snapshot{}, err
	}
	return s, nil
}

func (f *FileStore) Save(s Snapshot) error {
	if f == nil || f.Path == "" {
		return errors.New("supervisor: empty FileStore path")
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(f.Path, b)
}

func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(path)
		if err2 := os.Rename(tmp, path); err2 != nil {
			_ = os.Remove(tmp)
			return err2
		}
	}
	return nil
}
