package keys

import (
	"time"

	"github.com/igorpooh1978/blacktemple_kn/src/internal/subscription"
)

const redacted = "[redacted]"

type secret string

func (s secret) String() string   { return redacted }
func (s secret) GoString() string { return redacted }
func (s secret) MarshalJSON() ([]byte, error) {
	return []byte(`"` + redacted + `"`), nil
}

// Key is a protocol credential bound to a profile/subscription, not a server blob.
type Key struct {
	ID             string
	ProfileID      string
	SubscriptionID string
	ServerID       string
	Protocol       string
	Remark         string
	secret         secret
	params         subscription.ConnectionParams
}

func (k Key) String() string {
	return "Key{ID:" + k.ID +
		" Protocol:" + k.Protocol +
		" ServerID:" + k.ServerID +
		" Secret:" + redacted + "}"
}

func (k Key) GoString() string { return k.String() }

// Material returns the protocol secret. Do not log it.
func (k Key) Material() string { return string(k.secret) }

// Params returns copied connection material without UUID/password.
func (k Key) Params() subscription.ConnectionParams {
	out := k.params
	if k.params.ALPN != nil {
		out.ALPN = append([]string(nil), k.params.ALPN...)
	}
	return out
}

// WithParams attaches parser-observed connection material.
func (k Key) WithParams(p subscription.ConnectionParams) Key {
	k.params = p
	if p.ALPN != nil {
		k.params.ALPN = append([]string(nil), p.ALPN...)
	}
	return k
}

// New builds a Key. material is never stored in exported fields.
func New(id, profileID, subscriptionID, serverID, protocol, remark, material string) Key {
	return Key{
		ID:             id,
		ProfileID:      profileID,
		SubscriptionID: subscriptionID,
		ServerID:       serverID,
		Protocol:       protocol,
		Remark:         remark,
		secret:         secret(material),
	}
}

// ConnectionCandidate is a selectable (key, server) pair before activation.
type ConnectionCandidate struct {
	ID        string
	ProfileID string
	KeyID     string
	ServerID  string
}

func (c ConnectionCandidate) String() string {
	return "ConnectionCandidate{ID:" + c.ID +
		" ProfileID:" + c.ProfileID +
		" KeyID:" + c.KeyID +
		" ServerID:" + c.ServerID + "}"
}

func (c ConnectionCandidate) GoString() string { return c.String() }

// LastKnownGood is the last activated working candidate for a profile.
type LastKnownGood struct {
	ProfileID string
	KeyID     string
	ServerID  string
	SavedAt   time.Time
}

func (l LastKnownGood) String() string {
	return "LastKnownGood{ProfileID:" + l.ProfileID +
		" KeyID:" + l.KeyID +
		" ServerID:" + l.ServerID +
		" SavedAt:" + l.SavedAt.UTC().Format(time.RFC3339) + "}"
}

func (l LastKnownGood) GoString() string { return l.String() }

func candidateID(profileID, keyID, serverID string) string {
	return profileID + ":" + keyID + ":" + serverID
}

func (c ConnectionCandidate) withID() ConnectionCandidate {
	c.ID = candidateID(c.ProfileID, c.KeyID, c.ServerID)
	return c
}
