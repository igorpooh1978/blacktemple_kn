package remotelists

import (
	"net/netip"
	"time"
)

// ListType is a typed remote list kind. Do not collapse these into one string bag.
type ListType string

const (
	TypeDomains         ListType = "domains"
	TypeCIDRs           ListType = "cidrs"
	TypeCountries       ListType = "countries"
	TypeServers         ListType = "servers"
	TypeTelegramIPs     ListType = "telegram-ips"
	TypeWhatsAppIPs     ListType = "whatsapp-ips"
	TypeProviderRouting ListType = "provider-routing"
	TypeGeositeCatalog  ListType = "geosite-catalog"
)

// Well-known list IDs. Values are identifiers, not IP data.
const (
	ListIDTelegramIPs = "telegram-ips"
	ListIDWhatsAppIPs = "whatsapp-ips"
)

// Descriptor names a remote list source and its fetch constraints.
type Descriptor struct {
	ID            string
	Type          ListType
	URL           string
	Version       string
	ETag          string
	LastModified  string
	SHA256        string
	TTL           time.Duration
	MaxBytes      int64
	TrustedOrigin bool
}

func (d Descriptor) String() string {
	return "Descriptor{ID:" + d.ID + " Type:" + string(d.Type) + " Trusted:" + boolString(d.TrustedOrigin) + "}"
}

func (d Descriptor) GoString() string { return d.String() }

// FetchStatus is the outcome of an Update attempt.
type FetchStatus string

const (
	StatusUpdated       FetchStatus = "updated"
	StatusNotModified   FetchStatus = "not_modified"
	StatusLastKnownGood FetchStatus = "last_known_good"
)

// Issue is a skipped or rejected line. Text is omitted for over-long lines.
type Issue struct {
	Line   int
	Reason string
}

// DomainEntry is one validated domain with source metadata.
type DomainEntry struct {
	Domain string
	Line   int
}

// CIDREntry is one validated prefix with source metadata.
type CIDREntry struct {
	Prefix netip.Prefix
	Line   int
}

// CountryRecord is a catalog row. The remote payload parser is not implemented.
type CountryRecord struct {
	ID   string
	Name string
}

// ServerRecord is a server-catalog row. The remote payload parser is not implemented.
type ServerRecord struct {
	ID        string
	Host      string
	Port      int
	CountryID string
}

// Parsed is a typed view of a list body. Unused slices stay nil.
type Parsed struct {
	Type      ListType
	Domains   []DomainEntry
	CIDRs     []CIDREntry
	Countries []CountryRecord
	Servers   []ServerRecord
	Issues    []Issue
	Lines     int
	Entries   int
	Skipped   int
	Dupes     int
}

func (p Parsed) String() string {
	return "Parsed{Type:" + string(p.Type) +
		" Entries:" + itoa(p.Entries) +
		" Skipped:" + itoa(p.Skipped) +
		" Lines:" + itoa(p.Lines) + "}"
}

func (p Parsed) GoString() string { return p.String() }

// Result is a cache-backed list after Update or Load.
type Result struct {
	Descriptor   Descriptor
	Status       FetchStatus
	Body         []byte
	SHA256       string
	ETag         string
	LastModified string
	FetchedAt    time.Time
	Parsed       Parsed
	ParseError   error
}

func (r Result) String() string {
	return "Result{ID:" + r.Descriptor.ID +
		" Status:" + string(r.Status) +
		" Bytes:" + itoa(len(r.Body)) +
		" SHA256:" + shortHex(r.SHA256) + "}"
}

func (r Result) GoString() string { return r.String() }

func boolString(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func shortHex(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:12]
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
