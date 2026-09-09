//go:build windows

package platform

// FindOurXrayProcess is not available on Windows manager hosts.
func FindOurXrayProcess(string) (pid int, exe string, ok bool) {
	return 0, "", false
}
