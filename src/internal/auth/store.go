package auth

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
)

const authFileName = "auth.json"

var (
	ErrAlreadyInitialized = errors.New("already initialized")
	ErrNotInitialized     = errors.New("not initialized")
	ErrInvalidPassword    = errors.New("invalid password")
	ErrPasswordTooShort   = errors.New("password too short")
	ErrCorruptStore       = errors.New("auth store corrupt")
)

type filePayload struct {
	Hash string `json:"hash"`
}

type passwordStore struct {
	mu       sync.Mutex
	path     string
	iter     int
	cached   string
	haveHash bool
}

func newPasswordStore(dataDir string, iterations int) (*passwordStore, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	s := &passwordStore{
		path: filepath.Join(dataDir, authFileName),
		iter: iterations,
	}
	if err := s.load(); err != nil && !errors.Is(err, ErrNotInitialized) {
		return nil, err
	}
	return s, nil
}

func (s *passwordStore) load() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			s.haveHash = false
			s.cached = ""
			return ErrNotInitialized
		}
		return err
	}
	var payload filePayload
	if err := json.Unmarshal(data, &payload); err != nil || payload.Hash == "" {
		return ErrCorruptStore
	}
	if _, _, _, ok := parseEncoded(payload.Hash); !ok {
		return ErrCorruptStore
	}
	s.cached = payload.Hash
	s.haveHash = true
	return nil
}

func (s *passwordStore) initialized() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.haveHash
}

func (s *passwordStore) setup(password string) error {
	if len(password) < 8 {
		return ErrPasswordTooShort
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.haveHash {
		return ErrAlreadyInitialized
	}
	if _, err := os.Stat(s.path); err == nil {
		return ErrAlreadyInitialized
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	encoded, err := Hash(password, s.iter)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(filePayload{Hash: encoded})
	if err != nil {
		return err
	}
	if err := atomicWriteFile(s.path, payload, 0o600); err != nil {
		return err
	}
	s.cached = encoded
	s.haveHash = true
	return nil
}

func (s *passwordStore) verify(password string) error {
	s.mu.Lock()
	encoded := s.cached
	ok := s.haveHash
	s.mu.Unlock()
	if !ok {
		return ErrNotInitialized
	}
	if !Verify(password, encoded) {
		return ErrInvalidPassword
	}
	return nil
}

func atomicWriteFile(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "auth-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	_ = os.Chmod(tmpName, mode)
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(path)
		if err := os.Rename(tmpName, path); err != nil {
			return err
		}
	}
	_ = os.Chmod(path, mode)
	cleanup = false
	return nil
}
