package auth

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

const (
	sessionIDBytes     = 32
	defaultMaxSessions = 32
	defaultSessionTTL  = 12 * time.Hour
)

type session struct {
	id        string
	createdAt time.Time
	expiresAt time.Time
}

type sessionStore struct {
	mu    sync.Mutex
	items map[string]session
	ttl   time.Duration
	max   int
	now   func() time.Time
}

func newSessionStore(ttl time.Duration, max int) *sessionStore {
	if ttl <= 0 {
		ttl = defaultSessionTTL
	}
	if max <= 0 {
		max = defaultMaxSessions
	}
	return &sessionStore{
		items: make(map[string]session, max),
		ttl:   ttl,
		max:   max,
		now:   time.Now,
	}
}

func (s *sessionStore) create() (id string, expires time.Time, err error) {
	raw := make([]byte, sessionIDBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", time.Time{}, err
	}
	id = base64.RawURLEncoding.EncodeToString(raw)
	now := s.now()
	expires = now.Add(s.ttl)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evictExpiredLocked(now)
	for len(s.items) >= s.max {
		s.evictOldestLocked()
	}
	s.items[id] = session{id: id, createdAt: now, expiresAt: expires}
	return id, expires, nil
}

func (s *sessionStore) lookup(id string) (session, bool) {
	if id == "" {
		return session{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	sess, ok := s.items[id]
	if !ok {
		return session{}, false
	}
	if !now.Before(sess.expiresAt) {
		delete(s.items, id)
		return session{}, false
	}
	return sess, true
}

func (s *sessionStore) revoke(id string) {
	if id == "" {
		return
	}
	s.mu.Lock()
	delete(s.items, id)
	s.mu.Unlock()
}

func (s *sessionStore) evictExpiredLocked(now time.Time) {
	for id, sess := range s.items {
		if !now.Before(sess.expiresAt) {
			delete(s.items, id)
		}
	}
}

func (s *sessionStore) evictOldestLocked() {
	var oldestID string
	var oldest time.Time
	first := true
	for id, sess := range s.items {
		if first || sess.createdAt.Before(oldest) {
			oldestID = id
			oldest = sess.createdAt
			first = false
		}
	}
	if oldestID != "" {
		delete(s.items, oldestID)
	}
}
