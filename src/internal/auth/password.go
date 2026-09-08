package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

const (
	// DefaultIterations is MIPS-friendly PBKDF2-HMAC-SHA256 cost (RFC 8018).
	DefaultIterations = 40000
	minIterations     = 20000
	maxIterations     = 60000
	maxVerifyIter     = 1000000
	saltLen           = 16
	keyLen            = 32
	hashPrefix        = "pbkdf2-sha256"
)

// Hash encodes password as pbkdf2-sha256$iter$saltB64$hashB64.
func Hash(password string, iterations int) (string, error) {
	if iterations < minIterations || iterations > maxIterations {
		return "", fmt.Errorf("pbkdf2 iterations out of range")
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	dk := pbkdf2HMACSHA256([]byte(password), salt, iterations, keyLen)
	return fmt.Sprintf("%s$%d$%s$%s",
		hashPrefix,
		iterations,
		base64.StdEncoding.EncodeToString(salt),
		base64.StdEncoding.EncodeToString(dk),
	), nil
}

// Verify reports whether password matches an encoded PBKDF2 hash.
// Comparison of the derived key is constant-time.
func Verify(password, encoded string) bool {
	iter, salt, want, ok := parseEncoded(encoded)
	if !ok {
		return false
	}
	got := pbkdf2HMACSHA256([]byte(password), salt, iter, len(want))
	return subtle.ConstantTimeCompare(got, want) == 1
}

func parseEncoded(encoded string) (iter int, salt, dk []byte, ok bool) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != hashPrefix {
		return 0, nil, nil, false
	}
	iter64, err := strconv.ParseInt(parts[1], 10, 32)
	if err != nil || iter64 < 1 || iter64 > maxVerifyIter {
		return 0, nil, nil, false
	}
	salt, err = base64.StdEncoding.DecodeString(parts[2])
	if err != nil || len(salt) == 0 {
		return 0, nil, nil, false
	}
	dk, err = base64.StdEncoding.DecodeString(parts[3])
	if err != nil || len(dk) == 0 {
		return 0, nil, nil, false
	}
	return int(iter64), salt, dk, true
}

// pbkdf2HMACSHA256 implements PBKDF2 (RFC 8018) with HMAC-SHA256.
func pbkdf2HMACSHA256(password, salt []byte, iter, dkLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hLen := prf.Size()
	blocks := (dkLen + hLen - 1) / hLen
	dk := make([]byte, 0, blocks*hLen)
	block := make([]byte, len(salt)+4)
	copy(block, salt)
	u := make([]byte, hLen)
	t := make([]byte, hLen)

	for i := 1; i <= blocks; i++ {
		binary.BigEndian.PutUint32(block[len(salt):], uint32(i))
		prf.Reset()
		prf.Write(block)
		sum := prf.Sum(u[:0])
		copy(u, sum)
		copy(t, u)
		for j := 2; j <= iter; j++ {
			prf.Reset()
			prf.Write(u)
			sum = prf.Sum(u[:0])
			copy(u, sum)
			for k, b := range u {
				t[k] ^= b
			}
		}
		dk = append(dk, t...)
	}
	return dk[:dkLen]
}
