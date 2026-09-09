//go:build windows

package xray

import "os/exec"

func setDetached(cmd *exec.Cmd) {}
