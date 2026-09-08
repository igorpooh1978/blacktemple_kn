package lab

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// FileSHA256 returns the lowercase hex digest of path.
func FileSHA256(path string) (string, error) {
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

// VerifySHA256 compares path against want (hex, case-insensitive).
func VerifySHA256(path, want string) error {
	got, err := FileSHA256(path)
	if err != nil {
		return err
	}
	if !strings.EqualFold(got, strings.TrimSpace(want)) {
		return fmt.Errorf("sha256 mismatch %s: got %s want %s", filepath.Base(path), got, strings.ToLower(strings.TrimSpace(want)))
	}
	return nil
}

// EnsureAsset downloads url into cacheDir/filename if needed and verifies SHA256.
func EnsureAsset(cacheDir string, a Asset, client *http.Client) (string, error) {
	if err := validateAsset("asset", a); err != nil {
		return "", err
	}
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return "", err
	}
	dest := filepath.Join(cacheDir, a.Filename)
	if _, err := os.Stat(dest); err == nil {
		if err := VerifySHA256(dest, a.SHA256); err == nil {
			return dest, nil
		}
		if rmErr := os.Remove(dest); rmErr != nil {
			return "", fmt.Errorf("remove corrupt cache: %w", rmErr)
		}
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Minute}
	}
	tmp := dest + ".part"
	if err := downloadFile(client, a.URL, tmp); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	if err := VerifySHA256(tmp, a.SHA256); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	if err := os.Rename(tmp, dest); err != nil {
		return "", err
	}
	return dest, nil
}

func downloadFile(client *http.Client, url, dest string) error {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode)
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
