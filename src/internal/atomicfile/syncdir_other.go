//go:build !unix

package atomicfile

import "os"

// SyncDir best-effort fsyncs a directory. Windows directory handles often
// reject FlushFileBuffers; a failed Sync is ignored so callers can proceed.
func SyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return nil
	}
	defer d.Close()
	_ = d.Sync()
	return nil
}
