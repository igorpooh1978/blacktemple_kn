//go:build unix

package atomicfile

import "os"

// SyncDir fsyncs a directory so a prior rename is durable.
func SyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
