package profiles

import (
	"strconv"
	"time"
)

// Profile is a named imported BlackKey container. Keys live in package keys.
type Profile struct {
	ID             string
	Name           string
	SubscriptionID string
	CreatedAt      time.Time
}

func (p Profile) String() string {
	return "Profile{ID:" + p.ID + " Name:" + p.Name + " SubscriptionID:" + p.SubscriptionID + "}"
}

func (p Profile) GoString() string { return p.String() }

func itoa(n int) string { return strconv.Itoa(n) }
