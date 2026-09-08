package remotelists

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/igorpooh1978/blacktemple_kn/src/internal/atomicfile"
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

type pointerState struct {
	Active   string `json:"active"`
	Previous string `json:"previous"`
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

func revisionsDir(dir string) string {
	return filepath.Join(dir, "revisions")
}

func currentPath(dir string) string {
	return filepath.Join(dir, "current.json")
}

func revisionDir(listRoot, revID string) string {
	return filepath.Join(revisionsDir(listRoot), revID)
}

func bodyPath(revDir string) string { return filepath.Join(revDir, "body") }
func metaPath(revDir string) string { return filepath.Join(revDir, "meta.json") }

func loadPointer(dir string) (pointerState, error) {
	raw, err := os.ReadFile(currentPath(dir))
	if err != nil {
		return pointerState{}, err
	}
	var st pointerState
	if err := json.Unmarshal(raw, &st); err != nil {
		return pointerState{}, err
	}
	return st, nil
}

func revisionComplete(dir, revID string) bool {
	if revID == "" {
		return false
	}
	rev := revisionDir(dir, revID)
	if _, err := os.Stat(bodyPath(rev)); err != nil {
		return false
	}
	if _, err := os.Stat(metaPath(rev)); err != nil {
		return false
	}
	return true
}

func resolveRevision(dir string) (active, previous string, err error) {
	st, err := loadPointer(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return "", "", ErrNoCache
		}
		return "", "", err
	}
	if revisionComplete(dir, st.Active) {
		prev := st.Previous
		if !revisionComplete(dir, prev) {
			prev = ""
		}
		return st.Active, prev, nil
	}
	if revisionComplete(dir, st.Previous) {
		return st.Previous, "", ErrMissingRevision
	}
	return "", "", ErrNoCache
}

func loadCache(root, id string) (Result, error) {
	dir, err := listDir(root, id)
	if err != nil {
		return Result{}, err
	}
	revID, _, resErr := resolveRevision(dir)
	if revID == "" {
		if resErr != nil {
			return Result{}, resErr
		}
		return Result{}, ErrNoCache
	}
	res, err := loadRevision(dir, revID)
	if err != nil {
		return Result{}, err
	}
	return res, resErr
}

func loadRevision(dir, revID string) (Result, error) {
	rev := revisionDir(dir, revID)
	raw, err := os.ReadFile(bodyPath(rev))
	if err != nil {
		if os.IsNotExist(err) {
			return Result{}, ErrNoCache
		}
		return Result{}, err
	}
	res := Result{Body: raw, SHA256: sha256Hex(raw), Status: StatusLastKnownGood}
	metaRaw, err := os.ReadFile(metaPath(rev))
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

func writeNewFileSync(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = f.Close()
			_ = os.Remove(path)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	cleanup = false
	return atomicfile.SyncDir(filepath.Dir(path))
}

func defaultWriteRevision(listRoot string, desc Descriptor, body []byte, etag, lastModified, sum string, fetchedAt time.Time, seq uint64) (string, error) {
	short := sum
	if len(short) > 8 {
		short = short[:8]
	}
	revID := fmt.Sprintf("rev-%d-%d-%s", fetchedAt.UnixNano(), seq, short)
	rev := revisionDir(listRoot, revID)
	if err := os.MkdirAll(rev, 0o700); err != nil {
		return "", err
	}
	if err := writeNewFileSync(bodyPath(rev), body, 0o600); err != nil {
		return "", err
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
		return "", err
	}
	if err := writeNewFileSync(metaPath(rev), payload, 0o600); err != nil {
		return "", err
	}
	_ = atomicfile.SyncDir(rev)
	return revID, nil
}

func commitPointer(listRoot, active, previous string, w *atomicfile.Writer) error {
	st := pointerState{Active: active, Previous: previous}
	payload, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if w == nil {
		return atomicfile.WriteFile(currentPath(listRoot), payload, 0o600)
	}
	return w.WriteFile(currentPath(listRoot), payload, 0o600)
}

func gcRevisions(listRoot string, keep map[string]struct{}, removeAll func(string) error) {
	entries, err := os.ReadDir(revisionsDir(listRoot))
	if err != nil {
		return
	}
	if removeAll == nil {
		removeAll = os.RemoveAll
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, ok := keep[e.Name()]; ok {
			continue
		}
		_ = removeAll(revisionDir(listRoot, e.Name()))
	}
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
