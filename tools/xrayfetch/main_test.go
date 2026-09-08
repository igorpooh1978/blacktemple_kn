package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFetchDownloadsVerifiesAndExtractsOnlyNamedMember(t *testing.T) {
	want := []byte("softfloat-xray-payload")
	zipBytes := mustZip(t, map[string][]byte{
		"xray_softfloat": want,
		"xray":           []byte("hardfloat-must-not-be-used"),
		"geoip.dat":      []byte("geo"),
		"README.md":      []byte("readme"),
	})
	sum := sha256.Sum256(zipBytes)
	wantSum := hex.EncodeToString(sum[:])

	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.URL.Path != "/Xray-linux-mips32le.zip" {
			http.NotFound(w, r)
			return
		}
		w.Write(zipBytes)
	}))
	defer srv.Close()

	root := t.TempDir()
	lockPath := writeLock(t, root, srv.URL+"/Xray-linux-mips32le.zip", wantSum, "xray_softfloat")
	cache := filepath.Join(root, "cache")
	out := filepath.Join(root, "bin", "xray")

	if err := fetch(lockPath, "linux-mipsle-softfloat", cache, out, false); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("extracted %q want %q", got, want)
	}
	entries, err := os.ReadDir(filepath.Dir(out))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "xray" {
		t.Fatalf("extracted extra files: %v", names(entries))
	}
	if hits != 1 {
		t.Fatalf("download hits=%d want 1", hits)
	}

	if err := fetch(lockPath, "linux-mipsle-softfloat", cache, out, false); err != nil {
		t.Fatal(err)
	}
	if hits != 1 {
		t.Fatalf("cache should skip download, hits=%d", hits)
	}
}

func TestFetchOfflineCacheMissFails(t *testing.T) {
	root := t.TempDir()
	lockPath := writeLock(t, root, "http://127.0.0.1:1/missing.zip", strings.Repeat("ab", 32), "xray_softfloat")
	err := fetch(lockPath, "linux-mipsle-softfloat", filepath.Join(root, "cache"), filepath.Join(root, "xray"), true)
	if err == nil {
		t.Fatal("expected offline cache miss")
	}
	if !strings.Contains(err.Error(), "offline") || !strings.Contains(err.Error(), "cache miss") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFetchOfflineUsesCache(t *testing.T) {
	want := []byte("cached-binary")
	zipBytes := mustZip(t, map[string][]byte{"xray_softfloat": want})
	sum := sha256.Sum256(zipBytes)
	wantSum := hex.EncodeToString(sum[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("download must not run in offline cache-hit")
	}))
	defer srv.Close()

	root := t.TempDir()
	cache := filepath.Join(root, "cache")
	if err := os.MkdirAll(cache, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cache, wantSum+".zip"), zipBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	lockPath := writeLock(t, root, srv.URL+"/never.zip", wantSum, "xray_softfloat")
	out := filepath.Join(root, "xray")
	if err := fetch(lockPath, "linux-mipsle-softfloat", cache, out, true); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %q", got)
	}
}

func TestFetchSHA256Mismatch(t *testing.T) {
	zipBytes := mustZip(t, map[string][]byte{"xray_softfloat": []byte("x")})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(zipBytes)
	}))
	defer srv.Close()
	root := t.TempDir()
	lockPath := writeLock(t, root, srv.URL+"/x.zip", strings.Repeat("cd", 32), "xray_softfloat")
	err := fetch(lockPath, "linux-mipsle-softfloat", filepath.Join(root, "cache"), filepath.Join(root, "xray"), false)
	if err == nil {
		t.Fatal("expected sha256 mismatch")
	}
	if !strings.Contains(err.Error(), "sha256") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFetchUnknownTarget(t *testing.T) {
	root := t.TempDir()
	lockPath := writeLock(t, root, "http://example.invalid/x.zip", strings.Repeat("ef", 32), "xray_softfloat")
	err := fetch(lockPath, "linux-mips-softfloat", filepath.Join(root, "cache"), filepath.Join(root, "xray"), true)
	if err == nil {
		t.Fatal("expected unknown target")
	}
	if !strings.Contains(err.Error(), "unknown lock target") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadLockReadsPinnedVersion(t *testing.T) {
	root := t.TempDir()
	lockPath := writeLock(t, root, "https://example.invalid/Xray-linux-mips32le.zip", strings.Repeat("aa", 32), "xray_softfloat")
	lock, err := loadLock(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	if lock.Version != "v26.3.27" {
		t.Fatalf("version %q", lock.Version)
	}
	if !strings.Contains(lock.Targets["linux-mipsle-softfloat"].ZipURL, "Xray-linux-mips32le.zip") {
		t.Fatalf("url %s", lock.Targets["linux-mipsle-softfloat"].ZipURL)
	}
}

func TestRepoLockParsesWithoutRewrite(t *testing.T) {
	path := filepath.Join("..", "..", "third_party", "xray.lock.json")
	lock, err := loadLock(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"linux-mipsle-softfloat", "linux-mips-softfloat"} {
		tgt, err := lock.lookup(key)
		if err != nil {
			t.Fatal(err)
		}
		if tgt.BinaryInZip != "xray_softfloat" {
			t.Fatalf("%s binaryInZip=%q", key, tgt.BinaryInZip)
		}
	}
}

func writeLock(t *testing.T, root, zipURL, sha, binary string) string {
	t.Helper()
	lock := lockFile{
		SchemaVersion: 1,
		Name:          "xray-core",
		Version:       "v26.3.27",
		Tag:           "v26.3.27",
		Targets: map[string]lockTarget{
			"linux-mipsle-softfloat": {
				ZipURL:      zipURL,
				ZipSha256:   sha,
				BinaryInZip: binary,
				IpkArch:     "mipsel-3.4_kn",
			},
		},
	}
	b, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "xray.lock.json")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func mustZip(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func names(entries []os.DirEntry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}
