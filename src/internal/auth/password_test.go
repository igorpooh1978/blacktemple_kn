package auth

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestPBKDF2HMACSHA256KnownVectors(t *testing.T) {
	// hashlib.pbkdf2_hmac('sha256', b'passwd', b'salt', 1, 64)
	want1, err := hex.DecodeString("55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783")
	if err != nil {
		t.Fatal(err)
	}
	got1 := pbkdf2HMACSHA256([]byte("passwd"), []byte("salt"), 1, 64)
	if hex.EncodeToString(got1) != hex.EncodeToString(want1) {
		t.Fatalf("c=1 got %x want %x", got1, want1)
	}

	want4096, err := hex.DecodeString("c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a")
	if err != nil {
		t.Fatal(err)
	}
	got4096 := pbkdf2HMACSHA256([]byte("password"), []byte("salt"), 4096, 32)
	if hex.EncodeToString(got4096) != hex.EncodeToString(want4096) {
		t.Fatalf("c=4096 got %x want %x", got4096, want4096)
	}
}

func TestHashRoundTrip(t *testing.T) {
	const pw = "correct-horse"
	encoded, err := Hash(pw, DefaultIterations)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(encoded, "pbkdf2-sha256$") {
		t.Fatalf("format %s", encoded)
	}
	if !Verify(pw, encoded) {
		t.Fatal("expected match")
	}
	if Verify("wrong-password", encoded) {
		t.Fatal("wrong password must not match")
	}
	if strings.Contains(encoded, pw) {
		t.Fatal("encoded hash contains plaintext")
	}
}

func TestHashRejectsOutOfRangeIterations(t *testing.T) {
	if _, err := Hash("password1", 1); err == nil {
		t.Fatal("expected error")
	}
}
