package routing

import (
	"context"
	"os/exec"
)

// CommandExecutor runs name+args via exec.CommandContext. No shell.
type CommandExecutor struct{}

func (CommandExecutor) Run(ctx context.Context, name string, args ...string) (string, error) {
	if name == "" {
		return "", ErrNilExecutor
	}
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}
