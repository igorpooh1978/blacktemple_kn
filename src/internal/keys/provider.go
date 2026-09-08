package keys

import (
	"context"
	"errors"
)

var (
	ErrProviderNotConfigured = errors.New("key changer provider is not configured")
	ErrNotFound              = errors.New("key not found")
	ErrNoCandidate           = errors.New("no connection candidate")
	ErrNoLastKnownGood       = errors.New("no last-known-good candidate")
)

// ChangeKeyRequest is a provider-port payload. It contains IDs only.
type ChangeKeyRequest struct {
	ProfileID string
	KeyID     string
}

func (r ChangeKeyRequest) String() string {
	return "ChangeKeyRequest{ProfileID:" + r.ProfileID + " KeyID:" + r.KeyID + "}"
}

func (r ChangeKeyRequest) GoString() string { return r.String() }

// ChangeKeyResponse carries a replacement share URI. The URI is secret.
type ChangeKeyResponse struct {
	share secret
}

func NewChangeKeyResponse(shareURI string) ChangeKeyResponse {
	return ChangeKeyResponse{share: secret(shareURI)}
}

func (r ChangeKeyResponse) String() string {
	return "ChangeKeyResponse{ShareURI:" + redacted + "}"
}

func (r ChangeKeyResponse) GoString() string { return r.String() }

// ShareURI returns the replacement share. Do not log it.
func (r ChangeKeyResponse) ShareURI() string { return string(r.share) }

// KeyChanger is the optional provider port for key replacement.
// Implementations must not hardcode proprietary HTTP paths or hosts.
// This package never calls /keys/change.
type KeyChanger interface {
	ChangeKey(ctx context.Context, req ChangeKeyRequest) (ChangeKeyResponse, error)
}

// UnconfiguredChanger always returns ErrProviderNotConfigured.
type UnconfiguredChanger struct{}

func (UnconfiguredChanger) ChangeKey(context.Context, ChangeKeyRequest) (ChangeKeyResponse, error) {
	return ChangeKeyResponse{}, ErrProviderNotConfigured
}
