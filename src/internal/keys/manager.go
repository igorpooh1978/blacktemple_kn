package keys

import (
	"time"
)

// State is the in-memory key lifecycle for one profile.
type State struct {
	ProfileID string
	Keys      []Key
	Active    ConnectionCandidate
	LKG       LastKnownGood
	hasActive bool
	hasLKG    bool
	rotateAt  int
}

func NewState(profileID string, ks []Key) *State {
	return &State{ProfileID: profileID, Keys: append([]Key(nil), ks...)}
}

func (s *State) SetKeys(ks []Key) {
	s.Keys = append([]Key(nil), ks...)
}

func (s *State) Key(id string) (Key, bool) {
	for _, k := range s.Keys {
		if k.ID == id {
			return k, true
		}
	}
	return Key{}, false
}

func (s *State) ActiveCandidate() (ConnectionCandidate, bool) {
	if !s.hasActive {
		return ConnectionCandidate{}, false
	}
	return s.Active, true
}

func (s *State) LastKnownGood() (LastKnownGood, bool) {
	if !s.hasLKG {
		return LastKnownGood{}, false
	}
	return s.LKG, true
}

// SelectCandidate records a candidate without committing last-known-good.
func (s *State) SelectCandidate(keyID, serverID string) (ConnectionCandidate, error) {
	k, ok := s.Key(keyID)
	if !ok {
		return ConnectionCandidate{}, ErrNotFound
	}
	if serverID == "" {
		serverID = k.ServerID
	}
	c := ConnectionCandidate{
		ProfileID: s.ProfileID,
		KeyID:     k.ID,
		ServerID:  serverID,
	}.withID()
	s.Active = c
	s.hasActive = true
	return c, nil
}

// CommitGood stores the active candidate as last-known-good after a successful test.
func (s *State) CommitGood(now time.Time) (LastKnownGood, error) {
	if !s.hasActive {
		return LastKnownGood{}, ErrNoCandidate
	}
	s.LKG = LastKnownGood{
		ProfileID: s.Active.ProfileID,
		KeyID:     s.Active.KeyID,
		ServerID:  s.Active.ServerID,
		SavedAt:   now.UTC(),
	}
	s.hasLKG = true
	return s.LKG, nil
}

// Rollback restores last-known-good as the active candidate.
func (s *State) Rollback() (ConnectionCandidate, error) {
	if !s.hasLKG {
		return ConnectionCandidate{}, ErrNoLastKnownGood
	}
	c := ConnectionCandidate{
		ProfileID: s.LKG.ProfileID,
		KeyID:     s.LKG.KeyID,
		ServerID:  s.LKG.ServerID,
	}.withID()
	s.Active = c
	s.hasActive = true
	return c, nil
}

// ReplaceKey swaps a key (change-key / refresh) and selects it as a candidate.
func (s *State) ReplaceKey(oldID string, next Key) (ConnectionCandidate, error) {
	replaced := false
	for i, k := range s.Keys {
		if k.ID == oldID {
			s.Keys[i] = next
			replaced = true
			break
		}
	}
	if !replaced {
		s.Keys = append(s.Keys, next)
	}
	return s.SelectCandidate(next.ID, next.ServerID)
}

// RotateKey walks keys in order, skipping the current active key.
func (s *State) RotateKey() (ConnectionCandidate, error) {
	if len(s.Keys) == 0 {
		return ConnectionCandidate{}, ErrNotFound
	}
	if len(s.Keys) == 1 {
		return s.SelectCandidate(s.Keys[0].ID, s.Keys[0].ServerID)
	}
	s.rotateAt = (s.rotateAt + 1) % len(s.Keys)
	k := s.Keys[s.rotateAt]
	if s.hasActive && k.ID == s.Active.KeyID && len(s.Keys) > 1 {
		s.rotateAt = (s.rotateAt + 1) % len(s.Keys)
		k = s.Keys[s.rotateAt]
	}
	return s.SelectCandidate(k.ID, k.ServerID)
}
