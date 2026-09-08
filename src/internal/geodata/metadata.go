package geodata

import (
	"context"
	"errors"
	"time"
)

var (
	ErrEmptyDataDir     = errors.New("geodata: empty data dir")
	ErrNilValidator     = errors.New("geodata: nil validator")
	ErrOversized        = errors.New("geodata: candidate exceeds size limit")
	ErrChecksum         = errors.New("geodata: sha256 mismatch")
	ErrMissingChecksum  = errors.New("geodata: missing expected sha256")
	ErrValidate         = errors.New("geodata: validator rejected candidate")
	ErrNoPrevious       = errors.New("geodata: no previous slot to roll back")
	ErrSourceDisabled   = errors.New("geodata: no geodata source is enabled")
	ErrMissingCandidate = errors.New("geodata: candidate file missing")
	ErrMissingActiveSet = errors.New("geodata: active set is missing")
	ErrCorruptState     = errors.New("geodata: state pointer is unusable")
)

// Status is the lifecycle state of a geodata file.
type Status string

const (
	StatusMissing    Status = "MISSING"
	StatusDownloaded Status = "DOWNLOADED"
	StatusValidated  Status = "VALIDATED"
	StatusActive     Status = "ACTIVE"
	StatusFailed     Status = "FAILED"
)

// Metadata is per-file geodata identity. SHA256 is hex-encoded lowercase.
type Metadata struct {
	Source       string    `json:"source"`
	Version      string    `json:"version"`
	SHA256       string    `json:"sha256"`
	Size         int64     `json:"size"`
	DownloadedAt time.Time `json:"downloadedAt"`
	ValidatedAt  time.Time `json:"validatedAt"`
	Status       Status    `json:"status"`
}

// Snapshot is active-set metadata without loading .dat into RAM.
type Snapshot struct {
	GeoIP     Metadata  `json:"geoip"`
	GeoSite   Metadata  `json:"geosite"`
	SetID     string    `json:"setId"`
	Slot      string    `json:"slot,omitempty"`
	UpdatedAt time.Time `json:"updatedAt"`
}

func missingMeta() Metadata {
	return Metadata{Status: StatusMissing}
}

// Validator checks candidate files. Implementations must not require D to spawn
// Xray; production may later inject an Xray-backed validator from another owner.
type Validator interface {
	Validate(ctx context.Context, geoIPPath, geoSitePath string) error
}

// Candidate is a local pair of files to install. This package does not download.
type Candidate struct {
	GeoIPPath     string
	GeoSitePath   string
	Source        string
	Version       string
	GeoIPSHA256   string
	GeoSiteSHA256 string
}

// ActivePaths locates the current geodata set on disk. R5 does not wire these
// into Xray config.
type ActivePaths struct {
	SetID         string
	Version       string
	GeoIPPath     string
	GeoSitePath   string
	GeoIPSHA256   string
	GeoSiteSHA256 string
}

// pointerState is the durable active/previous set pointer.
type pointerState struct {
	Active   string `json:"active"`
	Previous string `json:"previous"`
}

const (
	fileGeoIP   = "geoip.dat"
	fileGeoSite = "geosite.dat"
	fileMeta    = "metadata.json"
	fileState   = "state.json"

	dirSets = "sets"

	defaultMaxFileBytes int64 = 32 << 20 // 32 MiB per file
	defaultMaxSets            = 3
)
