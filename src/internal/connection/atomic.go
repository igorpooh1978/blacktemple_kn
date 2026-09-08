package connection

import (
	"os"
	"path/filepath"
)

func writeFileSync(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	return f.Close()
}

func replaceFile(tmp, dest string) error {
	bak := dest + ".bak"
	if _, err := os.Stat(dest); err == nil {
		_ = os.Remove(bak)
		if err := os.Rename(dest, bak); err != nil {
			return err
		}
	}
	if err := os.Rename(tmp, dest); err != nil {
		if _, bakErr := os.Stat(bak); bakErr == nil {
			_ = os.Rename(bak, dest)
		}
		return err
	}
	return nil
}

func restoreBackup(dest string) error {
	bak := dest + ".bak"
	if _, err := os.Stat(bak); err != nil {
		return err
	}
	_ = os.Remove(dest)
	return os.Rename(bak, dest)
}
