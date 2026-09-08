//go:build unix

package atomicfile

import (
	"os"
	"path/filepath"
)

func platformReplace(tmp, dest string) error {
	if err := os.Rename(tmp, dest); err != nil {
		return err
	}
	return SyncDir(filepath.Dir(dest))
}
