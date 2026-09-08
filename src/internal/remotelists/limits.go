package remotelists

import "time"

const (
	maxBytesSmall  int64 = 256 * 1024
	maxBytesMedium int64 = 2 * 1024 * 1024
	maxLineSmall         = 512
	maxLineMedium        = 2048
	maxLinesSmall        = 50_000
	maxLinesMedium       = 200_000

	defaultFetchTimeout = 30 * time.Second
	defaultTTL          = 12 * time.Hour
	minOrdinaryTTL      = time.Hour
	defaultMaxAttempts  = 3
	maxRedirects        = 5
)

// Limits are hard caps per list type. Descriptor.MaxBytes cannot raise them.
type Limits struct {
	MaxBytes int64
	MaxLine  int
	MaxLines int
}

// LimitsFor returns the hard size class for a list type.
func LimitsFor(t ListType) Limits {
	switch t {
	case TypeProviderRouting, TypeGeositeCatalog:
		return Limits{MaxBytes: maxBytesMedium, MaxLine: maxLineMedium, MaxLines: maxLinesMedium}
	default:
		return Limits{MaxBytes: maxBytesSmall, MaxLine: maxLineSmall, MaxLines: maxLinesSmall}
	}
}

// EffectiveMaxBytes is min(requested, type hard max). Zero requested uses the type max.
func EffectiveMaxBytes(t ListType, requested int64) int64 {
	lim := LimitsFor(t).MaxBytes
	if requested <= 0 {
		return lim
	}
	if requested < lim {
		return requested
	}
	return lim
}

// DefaultTTL is 12h. Ordinary lists refresh on an hours/days cadence.
func DefaultTTL() time.Duration { return defaultTTL }

// ClampTTL raises sub-hour values to one hour for ordinary lists.
// Non-positive TTL means "use default". Tests that need an immediate
// refresh call Update directly; TTL is a scheduler hint, not a fetch skip.
func ClampTTL(d time.Duration) time.Duration {
	if d <= 0 {
		return defaultTTL
	}
	if d < minOrdinaryTTL {
		return minOrdinaryTTL
	}
	return d
}

func knownType(t ListType) bool {
	switch t {
	case TypeDomains, TypeCIDRs, TypeCountries, TypeServers,
		TypeTelegramIPs, TypeWhatsAppIPs, TypeProviderRouting, TypeGeositeCatalog:
		return true
	default:
		return false
	}
}
