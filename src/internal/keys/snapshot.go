package keys

// StateSnapshot is a persistence DTO. It does not include mutexes.
type StateSnapshot struct {
	ProfileID string
	Keys      []Key
	Active    ConnectionCandidate
	HasActive bool
	LKG       LastKnownGood
	HasLKG    bool
	RotateAt  int
}

// Export copies lifecycle state for durable storage.
func (s *State) Export() StateSnapshot {
	if s == nil {
		return StateSnapshot{}
	}
	ks := make([]Key, 0, len(s.Keys))
	for _, k := range s.Keys {
		ks = append(ks, New(k.ID, k.ProfileID, k.SubscriptionID, k.ServerID, k.Protocol, k.Remark, k.Material()).WithParams(k.Params()))
	}
	return StateSnapshot{
		ProfileID: s.ProfileID,
		Keys:      ks,
		Active:    s.Active,
		HasActive: s.hasActive,
		LKG:       s.LKG,
		HasLKG:    s.hasLKG,
		RotateAt:  s.rotateAt,
	}
}

// ImportState rebuilds State from a snapshot.
func ImportState(snap StateSnapshot) *State {
	st := NewState(snap.ProfileID, snap.Keys)
	st.Active = snap.Active
	st.hasActive = snap.HasActive
	st.LKG = snap.LKG
	st.hasLKG = snap.HasLKG
	st.rotateAt = snap.RotateAt
	return st
}
