package atomicfile

import (
	"os"
	"path/filepath"
)

// Writer replaces small control/pointer files. Destination is never removed
// before the platform replace; a failed replace leaves the old file intact.
type Writer struct {
	// Replace, if set, replaces tmp with dest. Tests inject failures here.
	// Production nil uses the platform primitive (Unix rename or Windows MoveFileExW).
	Replace func(tmp, dest string) error
}

func (w *Writer) replace(tmp, dest string) error {
	if w != nil && w.Replace != nil {
		return w.Replace(tmp, dest)
	}
	return platformReplace(tmp, dest)
}

// WriteFile writes data to path by creating a same-directory temporary file,
// fsyncing it, then atomically replacing the destination.
func WriteFile(path string, data []byte, perm os.FileMode) error {
	return (*Writer)(nil).WriteFile(path, data, perm)
}

// WriteFile writes data to path using this Writer's replace primitive.
func (w *Writer) WriteFile(path string, data []byte, perm os.FileMode) error {
	if perm == 0 {
		perm = 0o600
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".atomic-*.tmp")
	if err != nil {
		return err
	}
	tmpName := f.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		return err
	}
	if err := w.replace(tmpName, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}
