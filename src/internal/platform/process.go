package platform

// ProcessInfo is a best-effort view of a pid. Alive=false means "do not trust".
type ProcessInfo struct {
	PID        int
	Alive      bool
	Executable string
}
