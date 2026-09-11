package auth

import (
	"errors"
	"time"
)

// Config controls first-run password storage and in-memory sessions.
type Config struct {
	DataDir     string
	SessionTTL  time.Duration
	MaxSessions int
	Iterations  int
	Now         func() time.Time
}

// Service is the first-run password + session runtime.
type Service struct {
	passwords *passwordStore
	sessions  *sessionStore
}

// New opens (or creates) the local auth store under DataDir.
func New(cfg Config) (*Service, error) {
	if cfg.DataDir == "" {
		cfg.DataDir = "data"
	}
	if cfg.Iterations == 0 {
		cfg.Iterations = DefaultIterations
	}
	passwords, err := newPasswordStore(cfg.DataDir, cfg.Iterations)
	if err != nil {
		return nil, err
	}
	sessions := newSessionStore(cfg.SessionTTL, cfg.MaxSessions)
	if cfg.Now != nil {
		sessions.now = cfg.Now
	}
	return &Service{passwords: passwords, sessions: sessions}, nil
}

func (s *Service) Initialized() bool {
	return s.passwords.initialized()
}

func (s *Service) Setup(password string) error {
	return s.passwords.setup(password)
}

func (s *Service) ChangePassword(current, next string) error {
	if s == nil || s.passwords == nil {
		return ErrNotInitialized
	}
	return s.passwords.change(current, next)
}

func (s *Service) Login(password string) (sessionID string, expires time.Time, err error) {
	if err := s.passwords.verify(password); err != nil {
		if errors.Is(err, ErrNotInitialized) {
			return "", time.Time{}, ErrInvalidPassword
		}
		return "", time.Time{}, err
	}
	return s.sessions.create()
}

func (s *Service) Lookup(sessionID string) bool {
	_, ok := s.sessions.lookup(sessionID)
	return ok
}

func (s *Service) Logout(sessionID string) {
	s.sessions.revoke(sessionID)
}

// AuthFilePath is the password hash file (for tests). Never contains plaintext.
func (s *Service) AuthFilePath() string {
	return s.passwords.path
}
