package profiles

import (
	"strconv"
	"time"
)

const (
	SourceKindBlackKey = "blackkey"
	SourceKindShare    = "share"
	SourceKindJSON     = "json"

	ResolutionUnresolved = "unresolved"
	ResolutionResolved   = "resolved"
)

// Profile is a named imported BlackKey container. Keys live in package keys.
type Profile struct {
	ID              string
	Name            string
	SubscriptionID  string
	CreatedAt       time.Time
	SourceKind      string
	ResolutionState string
}

func (p Profile) String() string {
	return "Profile{ID:" + p.ID + " Name:" + p.Name + " SubscriptionID:" + p.SubscriptionID +
		" SourceKind:" + p.SourceKind + " Resolution:" + p.ResolutionState + "}"
}

func (p Profile) GoString() string { return p.String() }

func itoa(n int) string { return strconv.Itoa(n) }
