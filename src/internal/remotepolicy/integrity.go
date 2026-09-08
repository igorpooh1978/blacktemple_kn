package remotepolicy

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// IntegrityInput describes how a remote body was obtained. TLS true with no
// pin and no signature is TLS_ONLY, not SIGNED.
type IntegrityInput struct {
	TLS       bool
	SHA256Pin string
	Signature []byte
	PublicKey []byte
}

// ClassifyIntegrity authenticates body. HTTPS is not treated as a signature.
func ClassifyIntegrity(body []byte, in IntegrityInput) (IntegrityStatus, error) {
	if len(in.PublicKey) > 0 || len(in.Signature) > 0 {
		if len(in.PublicKey) != ed25519.PublicKeySize || len(in.Signature) != ed25519.SignatureSize {
			return "", ErrSignature
		}
		if !ed25519.Verify(ed25519.PublicKey(in.PublicKey), body, in.Signature) {
			return "", ErrSignature
		}
		return IntegritySignatureVerified, nil
	}
	pin := strings.ToLower(strings.TrimSpace(in.SHA256Pin))
	if pin != "" {
		sum := sha256.Sum256(body)
		if hex.EncodeToString(sum[:]) != pin {
			return "", ErrChecksumMismatch
		}
		return IntegrityChecksumPinned, nil
	}
	if in.TLS {
		return IntegrityTLSOnly, nil
	}
	return "", ErrInsecure
}
