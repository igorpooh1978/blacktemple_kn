package auth

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestSetupLoginLogoutAndPlaintextAbsent(t *testing.T) {
	dir := t.TempDir()
	svc, err := New(Config{DataDir: dir, Iterations: minIterations, SessionTTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	const pw = "secret-passphrase-xyz"
	if err := svc.Setup(pw); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(svc.AuthFilePath())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), pw) {
		t.Fatal("password file contains plaintext")
	}
	if strings.Contains(strings.ToLower(string(raw)), "secret-passphrase") {
		t.Fatal("password file contains plaintext fragment")
	}
	if err := svc.Setup(pw); err != ErrAlreadyInitialized {
		t.Fatalf("second setup: %v", err)
	}
	id, _, err := svc.Login(pw)
	if err != nil {
		t.Fatal(err)
	}
	if !svc.Lookup(id) {
		t.Fatal("session missing")
	}
	if _, _, err := svc.Login("nope-nope"); err != ErrInvalidPassword {
		t.Fatalf("bad login: %v", err)
	}
	svc.Logout(id)
	if svc.Lookup(id) {
		t.Fatal("session still valid after logout")
	}
}

func TestChangePassword(t *testing.T) {
	dir := t.TempDir()
	svc, err := New(Config{DataDir: dir, Iterations: minIterations, SessionTTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Setup("old-pass-1"); err != nil {
		t.Fatal(err)
	}
	if err := svc.ChangePassword("old-pass-1", "new-pass-2"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.Login("old-pass-1"); err != ErrInvalidPassword {
		t.Fatalf("old password: %v", err)
	}
	if _, _, err := svc.Login("new-pass-2"); err != nil {
		t.Fatal(err)
	}
}

func TestSessionExpiry(t *testing.T) {
	dir := t.TempDir()
	svc, err := New(Config{DataDir: dir, Iterations: minIterations, SessionTTL: 40 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Setup("password1"); err != nil {
		t.Fatal(err)
	}
	id, _, err := svc.Login("password1")
	if err != nil {
		t.Fatal(err)
	}
	if !svc.Lookup(id) {
		t.Fatal("session should be valid")
	}
	time.Sleep(80 * time.Millisecond)
	if svc.Lookup(id) {
		t.Fatal("session should have expired")
	}
}
