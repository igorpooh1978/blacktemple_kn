package subscription

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

// Subscription is the imported source, not a blob of keys.
type Subscription struct {
	ID          string
	ProfileID   string
	Kind        string // url, share, json
	ContentType string
	Encoding    string
	EntryCount  int
	FetchedAt   time.Time
	source      secret
}

func (s Subscription) String() string {
	return "Subscription{ID:" + s.ID + " Kind:" + s.Kind + " Entries:" + strconv.Itoa(s.EntryCount) + " Source:" + redacted + "}"
}

func (s Subscription) GoString() string { return s.String() }

// SourceURL returns the raw source. Callers must not log it.
func (s Subscription) SourceURL() string { return string(s.source) }

// WithSource attaches a raw URL or share. The value is redacted in String().
func WithSource(s Subscription, raw string) Subscription {
	s.source = secret(raw)
	return s
}

// ConnectionParams is the internal normalized transport/security material
// present on a share. Parser copies only fields that were actually present.
// Defaults belong to the Xray generator, not this layer. UUID/password stay
// in secret, never here.
type ConnectionParams struct {
	Flow             string
	SNI              string
	Host             string
	Path             string
	ServiceName      string
	Mode             string
	ALPN             []string
	Fingerprint      string
	RealityPublicKey string
	ShortID          string
	SpiderX          string
	HeaderType       string
	AllowInsecure    bool
}

func (p ConnectionParams) String() string {
	return "ConnectionParams{Flow:" + p.Flow +
		" SNI:" + p.SNI +
		" Host:" + p.Host +
		" Path:" + p.Path +
		" ServiceName:" + p.ServiceName +
		" Mode:" + p.Mode +
		" Fingerprint:" + p.Fingerprint +
		" ShortID:" + p.ShortID +
		" HeaderType:" + p.HeaderType + "}"
}

func (p ConnectionParams) GoString() string { return p.String() }

// ParsedShare is one classified share entry with the secret unexported.
type ParsedShare struct {
	Protocol    string
	Host        string
	Port        int
	Transport   string
	Security    string
	Remark      string
	CountryHint string
	StableID    string
	FieldNames  []string
	Params      ConnectionParams
	secret      secret
}

func (p ParsedShare) String() string {
	return "ParsedShare{Protocol:" + p.Protocol +
		" Host:" + p.Host +
		" Port:" + strconv.Itoa(p.Port) +
		" Transport:" + p.Transport +
		" Security:" + p.Security +
		" Remark:" + p.Remark +
		" ID:" + p.StableID +
		" Params:" + p.Params.String() +
		" Secret:" + redacted + "}"
}

func (p ParsedShare) GoString() string { return p.String() }

// Material returns the protocol secret (UUID/password). Do not log it.
func (p ParsedShare) Material() string { return string(p.secret) }

// Result is a sanitized parse of a subscription body.
type Result struct {
	Entries        []ParsedShare
	DuplicateCount int
	Skipped        int
	Encoding       string
	Format         string
	FieldNames     []string
}

func (r Result) String() string {
	return "Result{Entries:" + strconv.Itoa(len(r.Entries)) +
		" Dupes:" + strconv.Itoa(r.DuplicateCount) +
		" Skipped:" + strconv.Itoa(r.Skipped) +
		" Encoding:" + r.Encoding +
		" Format:" + r.Format + "}"
}

func (r Result) GoString() string { return r.String() }

func stableID(protocol, host string, port int, transport, security, remark string) string {
	var b strings.Builder
	b.WriteString(strings.ToLower(strings.TrimSpace(protocol)))
	b.WriteByte('|')
	b.WriteString(strings.ToLower(strings.TrimSpace(host)))
	b.WriteByte('|')
	b.WriteString(strconv.Itoa(port))
	b.WriteByte('|')
	b.WriteString(strings.ToLower(strings.TrimSpace(transport)))
	b.WriteByte('|')
	b.WriteString(strings.ToLower(strings.TrimSpace(security)))
	b.WriteByte('|')
	b.WriteString(strings.TrimSpace(remark))
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:16])
}

func hashSource(kind, sanitized string) string {
	sum := sha256.Sum256([]byte(kind + "|" + sanitized))
	return hex.EncodeToString(sum[:16])
}

func normalizeTransport(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" || v == "raw" {
		return "tcp"
	}
	if v == "h2" || v == "http" {
		return "http"
	}
	if v == "kcp" {
		return "mkcp"
	}
	return v
}

func normalizeSecurity(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	switch v {
	case "", "none", "0":
		return "none"
	case "tls", "xtls":
		return "tls"
	case "reality":
		return "reality"
	case "xtls-vision", "vision":
		return "xtls-vision"
	default:
		return v
	}
}
