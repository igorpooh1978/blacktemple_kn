package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

const userAgent = "blacktemple-kn-xrayfetch/0.1"

var httpClient = &http.Client{Timeout: 2 * time.Minute}

type lockFile struct {
	SchemaVersion int                   `json:"schemaVersion"`
	Name          string                `json:"name"`
	Version       string                `json:"version"`
	Tag           string                `json:"tag"`
	Targets       map[string]lockTarget `json:"targets"`
}

type lockTarget struct {
	ZipURL      string `json:"zipUrl"`
	ZipSha256   string `json:"zipSha256"`
	BinaryInZip string `json:"binaryInZip"`
	IpkArch     string `json:"ipkArch"`
}

func main() {
	lockPath := flag.String("lock", "", "path to third_party/xray.lock.json")
	targetName := flag.String("target", "", "lock target key, e.g. linux-mipsle-softfloat")
	cacheDir := flag.String("cache", "", "cache directory keyed by zip sha256")
	outPath := flag.String("out", "", "destination path for extracted binary")
	offline := flag.Bool("offline", false, "do not download; fail if cache is missing")
	flag.Parse()
	if *lockPath == "" || *targetName == "" || *cacheDir == "" || *outPath == "" {
		fmt.Fprintln(os.Stderr, "usage: xrayfetch -lock <xray.lock.json> -target <key> -cache <dir> -out <file> [-offline]")
		os.Exit(2)
	}
	if err := fetch(*lockPath, *targetName, *cacheDir, *outPath, *offline); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("PASS %s\n", *outPath)
}

func fetch(lockPath, targetName, cacheDir, outPath string, offline bool) error {
	lock, err := loadLock(lockPath)
	if err != nil {
		return err
	}
	target, err := lock.lookup(targetName)
	if err != nil {
		return err
	}
	wantSum, err := normalizeSHA256(target.ZipSha256)
	if err != nil {
		return fmt.Errorf("target %s: %w", targetName, err)
	}
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return err
	}
	zipPath := filepath.Join(cacheDir, wantSum+".zip")
	if err := ensureZip(target.ZipURL, wantSum, zipPath, offline); err != nil {
		return err
	}
	payload, err := extractZipMember(zipPath, target.BinaryInZip)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		if filepath.Dir(outPath) != "." {
			return err
		}
	}
	if err := os.WriteFile(outPath, payload, 0o755); err != nil {
		return err
	}
	fmt.Printf("xray version=%s target=%s binary=%s sha256=%s cache=%s\n",
		lock.Version, targetName, target.BinaryInZip, wantSum, zipPath)
	return nil
}

func loadLock(path string) (*lockFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lock lockFile
	if err := json.Unmarshal(b, &lock); err != nil {
		return nil, fmt.Errorf("parse lock: %w", err)
	}
	if len(lock.Targets) == 0 {
		return nil, fmt.Errorf("lock has no targets")
	}
	return &lock, nil
}

func (l *lockFile) lookup(name string) (lockTarget, error) {
	t, ok := l.Targets[name]
	if !ok {
		keys := make([]string, 0, len(l.Targets))
		for k := range l.Targets {
			keys = append(keys, k)
		}
		return lockTarget{}, fmt.Errorf("unknown lock target %q (have %s)", name, strings.Join(keys, ", "))
	}
	if strings.TrimSpace(t.ZipURL) == "" || strings.TrimSpace(t.ZipSha256) == "" || strings.TrimSpace(t.BinaryInZip) == "" {
		return lockTarget{}, fmt.Errorf("target %s: zipUrl, zipSha256, and binaryInZip are required", name)
	}
	return t, nil
}

func normalizeSHA256(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) != 64 {
		return "", fmt.Errorf("zipSha256 must be 64 hex chars, got %d", len(s))
	}
	if _, err := hex.DecodeString(s); err != nil {
		return "", fmt.Errorf("zipSha256: %w", err)
	}
	return s, nil
}

func ensureZip(url, wantSum, zipPath string, offline bool) error {
	if ok, err := zipMatches(zipPath, wantSum); err != nil {
		return err
	} else if ok {
		return nil
	}
	if offline {
		return fmt.Errorf("xray zip cache miss (offline): expected %s (sha256=%s). Re-run without -Offline to download the pinned zip from the lock URL", zipPath, wantSum)
	}
	_ = os.Remove(zipPath)
	if err := downloadFile(url, zipPath+".partial"); err != nil {
		_ = os.Remove(zipPath + ".partial")
		return err
	}
	ok, err := zipMatches(zipPath+".partial", wantSum)
	if err != nil {
		_ = os.Remove(zipPath + ".partial")
		return err
	}
	if !ok {
		sum, _ := fileSHA256(zipPath + ".partial")
		_ = os.Remove(zipPath + ".partial")
		return fmt.Errorf("sha256 mismatch after download: got %s want %s", sum, wantSum)
	}
	_ = os.Remove(zipPath)
	if err := os.Rename(zipPath+".partial", zipPath); err != nil {
		return err
	}
	return nil
}

func zipMatches(path, wantSum string) (bool, error) {
	st, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if st.IsDir() || st.Size() == 0 {
		return false, nil
	}
	got, err := fileSHA256(path)
	if err != nil {
		return false, err
	}
	return got == wantSum, nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func downloadFile(url, dest string) error {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: HTTP %s", url, resp.Status)
	}
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(f, resp.Body)
	closeErr := f.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func extractZipMember(zipPath, binaryInZip string) ([]byte, error) {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	want := path.Clean(filepath.ToSlash(binaryInZip))
	var found *zip.File
	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}
		name := path.Clean(filepath.ToSlash(f.Name))
		if name == want || path.Base(name) == want {
			found = f
			break
		}
	}
	if found == nil {
		return nil, fmt.Errorf("zip %s: member %q not found", zipPath, binaryInZip)
	}
	rc, err := found.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, rc); err != nil {
		return nil, err
	}
	if buf.Len() == 0 {
		return nil, fmt.Errorf("zip member %q is empty", binaryInZip)
	}
	return buf.Bytes(), nil
}
