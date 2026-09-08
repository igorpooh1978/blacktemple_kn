package remotelists

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
)

type cacheMeta struct {
	ID           string `json:"id"`
	Type         string `json:"type"`
	URL          string `json:"url"`
	Version      string `json:"version"`
	ETag         string `json:"etag"`
	LastModified string `json:"lastModified"`
	SHA256       string `json:"sha256"`
	FetchedAt    string `json:"fetchedAt"`
}

func safeID(id string) (string, error) {
	id = strings.TrimSpace(id)
	if id == "" || strings.Contains(id, "..") {
		return "", ErrInvalidID
	}
	for _, r := range id {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' || r == '-' || r == '_' {
			continue
		}
		return "", ErrInvalidID
	}
	return id, nil
}

func listDir(root, id string) (string, error) {
	sid, err := safeID(id)
	if err != nil {
		return "", err
	}
	return filepath.Join(root, sid), nil
}

func bodyPath(dir string) string { return filepath.Join(dir, "body") }
func metaPath(dir string) string { return filepath.Join(dir, "meta.json") }

func loadCache(root, id string) (Result, error) {
	dir, err := listDir(root, id)
	if err != nil {
		return Result{}, err
	}
	raw, err := os.ReadFile(bodyPath(dir))
	if err != nil {
		if os.IsNotExist(err) {
			return Result{}, ErrNoCache
		}
		return Result{}, err
	}
	res := Result{Body: raw, SHA256: sha256Hex(raw), Status: StatusLastKnownGood}
	metaRaw, err := os.ReadFile(metaPath(dir))
	if err != nil {
		if os.IsNotExist(err) {
			return res, nil
		}
		return Result{}, err
	}
	var meta cacheMeta
	if err := json.Unmarshal(metaRaw, &meta); err != nil {
		return res, nil
	}
	res.Descriptor = Descriptor{
		ID:           meta.ID,
		Type:         ListType(meta.Type),
		URL:          meta.URL,
		Version:      meta.Version,
		ETag:         meta.ETag,
		LastModified: meta.LastModified,
		SHA256:       meta.SHA256,
	}
	res.ETag = meta.ETag
	res.LastModified = meta.LastModified
	if meta.SHA256 != "" {
		res.SHA256 = meta.SHA256
	}
	if t, err := time.Parse(time.RFC3339, meta.FetchedAt); err == nil {
		res.FetchedAt = t
	}
	return res, nil
}

func saveCache(root string, desc Descriptor, body []byte, etag, lastModified, sum string, fetchedAt time.Time) error {
	dir, err := listDir(root, desc.ID)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := atomicReplace(bodyPath(dir), body); err != nil {
		return err
	}
	meta := cacheMeta{
		ID:           desc.ID,
		Type:         string(desc.Type),
		URL:          desc.URL,
		Version:      desc.Version,
		ETag:         etag,
		LastModified: lastModified,
		SHA256:       sum,
		FetchedAt:    fetchedAt.UTC().Format(time.RFC3339),
	}
	payload, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	return atomicReplace(metaPath(dir), payload)
}

func atomicReplace(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "list-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	_ = os.Chmod(tmpName, 0o600)
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(path)
		if err := os.Rename(tmpName, path); err != nil {
			return err
		}
	}
	_ = os.Chmod(path, 0o600)
	cleanup = false
	return nil
}

func sha256Hex(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func checksumOK(pin, actual string) bool {
	pin = strings.ToLower(strings.TrimSpace(pin))
	actual = strings.ToLower(strings.TrimSpace(actual))
	if pin == "" {
		return true
	}
	return pin == actual
}
