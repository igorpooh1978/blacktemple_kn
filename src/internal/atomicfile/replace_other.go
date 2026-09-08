//go:build !unix && !windows

package atomicfile

import "os"

func platformReplace(tmp, dest string) error {
	return os.Rename(tmp, dest)
}
