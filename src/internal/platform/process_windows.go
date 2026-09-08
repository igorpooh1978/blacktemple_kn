//go:build windows

package platform

// InspectPID cannot reliably prove executable identity on Windows without extra
// APIs. Supervisor tests must inject a fake IdentityChecker / ProcessRunner.
func InspectPID(pid int) ProcessInfo {
	return ProcessInfo{PID: pid, Alive: false}
}
