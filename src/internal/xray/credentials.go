package xray

import (
	"encoding/base64"
	"errors"
	"strings"
	"unicode/utf8"
)

const (
	x25519PublicKeySize  = 32
	maxVLESSUserIDBytes  = 30
	maxRealityShortIDHex = 16

	ClassInvalidVLESSUserID      = "INVALID_VLESS_USER_ID"
	ClassInvalidRealityPublicKey = "INVALID_REALITY_PUBLIC_KEY"
	ClassInvalidRealityShortID   = "INVALID_REALITY_SHORT_ID"
	ClassXrayConfigRejected      = "XRAY_CONFIG_REJECTED"
)

var (
	ErrInvalidVLESSUserID      = errors.New("invalid vless user id")
	ErrInvalidRealityPublicKey = errors.New("invalid reality public key")
	ErrInvalidRealityShortID   = errors.New("invalid reality short id")
)

// RealityKeyInfo is a value-free structural report of a Reality public key.
type RealityKeyInfo struct {
	Present       bool
	EncodedLength int
	DecodedLength int
	Valid         bool
}

// RealityShortIDInfo is a value-free structural report of a Reality shortId.
type RealityShortIDInfo struct {
	Present       bool
	EncodedLength int
	Valid         bool
}

// VLESSUserIDInfo is a value-free structural report of a VLESS user id.
type VLESSUserIDInfo struct {
	ByteLength    int
	CanonicalUUID bool
	ShortIDForm   bool
	Valid         bool
}

// InspectRealityPublicKey reports X25519 structure. Never log the value.
func InspectRealityPublicKey(encoded string) RealityKeyInfo {
	raw := strings.TrimSpace(encoded)
	info := RealityKeyInfo{Present: raw != "", EncodedLength: len(raw)}
	if !info.Present {
		return info
	}
	decoded, ok := decodeRealityPublicKey(raw)
	if !ok {
		return info
	}
	info.DecodedLength = len(decoded)
	info.Valid = len(decoded) == x25519PublicKeySize
	return info
}

// InspectRealityShortID reports shortId structure. Empty is allowed.
func InspectRealityShortID(s string) RealityShortIDInfo {
	raw := strings.TrimSpace(s)
	info := RealityShortIDInfo{Present: raw != "", EncodedLength: len(raw)}
	if !info.Present {
		info.Valid = true
		return info
	}
	if len(raw)%2 != 0 || len(raw) > maxRealityShortIDHex {
		return info
	}
	for _, c := range raw {
		if !isHex(c) {
			return info
		}
	}
	info.Valid = true
	return info
}

// InspectVLESSUserID reports id shape without exposing the value.
func InspectVLESSUserID(id string) VLESSUserIDInfo {
	info := VLESSUserIDInfo{ByteLength: len([]byte(id))}
	info.CanonicalUUID = validUUID(id)
	info.ShortIDForm = !info.CanonicalUUID && validVLESSUserID(id)
	info.Valid = validVLESSUserID(id)
	return info
}

func validVLESSUserID(s string) bool {
	if strings.TrimSpace(s) == "" {
		return false
	}
	if validUUID(s) {
		return true
	}
	if !utf8.ValidString(s) {
		return false
	}
	n := len([]byte(s))
	return n >= 1 && n <= maxVLESSUserIDBytes
}

func decodeRealityPublicKey(s string) ([]byte, bool) {
	encodings := []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.StdEncoding,
	}
	for _, enc := range encodings {
		out, err := enc.DecodeString(s)
		if err == nil && len(out) > 0 {
			return out, true
		}
	}
	return nil, false
}
