package platform

// ManagerRestartHelperArg is the CLI argument stream A should implement on blacktempled.
// Supervisor must not exec this itself from src/cmd (ownership).
const ManagerRestartHelperArg = "restart-helper"

// DetachedManagerRestart is a plan for restarting blacktempled without a
// synchronous kill of the HTTP process (ADR-004 restart manager).
// Execution is owned by src/cmd; this type only names the hook.
type DetachedManagerRestart struct {
	Executable string
	Args       []string
}

// NewDetachedManagerRestart builds the documented helper invocation.
func NewDetachedManagerRestart(executable string) DetachedManagerRestart {
	return DetachedManagerRestart{
		Executable: executable,
		Args:       []string{ManagerRestartHelperArg},
	}
}
