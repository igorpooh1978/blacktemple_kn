package geodata

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/igorpooh1978/blacktemple_kn/src/internal/atomicfile"
)

func streamCopyFile(src, dest string, maxBytes int64) (size int64, sum string, err error) {
	if src == "" {
		return 0, "", ErrMissingCandidate
	}
	in, err := os.Open(src)
	if err != nil {
		return 0, "", fmt.Errorf("%w: %v", ErrMissingCandidate, err)
	}
	defer in.Close()

	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return 0, "", err
	}
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o644)
	if err != nil {
		return 0, "", err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = out.Close()
			_ = os.Remove(dest)
		}
	}()

	h := sha256.New()
	limited := io.LimitReader(in, maxBytes+1)
	n, err := io.Copy(io.MultiWriter(out, h), limited)
	if err != nil {
		return 0, "", err
	}
	if n > maxBytes {
		return 0, "", ErrOversized
	}
	if err := out.Sync(); err != nil {
		return 0, "", err
	}
	if err := out.Close(); err != nil {
		return 0, "", err
	}
	cleanup = false
	return n, hex.EncodeToString(h.Sum(nil)), nil
}

func writeNewFileSync(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
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
