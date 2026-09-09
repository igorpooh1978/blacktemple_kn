package xray

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
)

// Runner talks to a pinned xray executable. It does not restart or back off.
type Runner struct {
	Executable string
	Detach     bool

	mu       sync.Mutex
	cmd      *exec.Cmd
	waitCh   chan error
	waitOnce *sync.Once
	waitErr  error
	started  bool
}

// Version runs `xray version` and returns trimmed stdout/stderr.
func (r *Runner) Version(ctx context.Context) (string, error) {
	if err := r.requireExecutable(); err != nil {
		return "", err
	}
	cmd := exec.CommandContext(ctx, r.Executable, "version")
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(RedactBytes(out, ConfigSecrets{}))
	if err != nil {
		return "", fmt.Errorf("xray version: %w: %s", err, text)
	}
	return text, nil
}

// ValidateConfig runs `xray run -test -c <file>` (Xray-core v26.7.28 CLI).
func (r *Runner) ValidateConfig(ctx context.Context, configPath string) error {
	if err := r.requireExecutable(); err != nil {
		return err
	}
	if strings.TrimSpace(configPath) == "" {
		return fmt.Errorf("config path is empty")
	}
	cmd := exec.CommandContext(ctx, r.Executable, "run", "-test", "-c", configPath)
	out, err := cmd.CombinedOutput()
	text := RedactBytes(out, ConfigSecrets{})
	if err != nil {
		return fmt.Errorf("xray run -test: %w: %s", err, strings.TrimSpace(text))
	}
	return nil
}

// Start launches `xray run -c <file>`. Callers own backoff/restart.
func (r *Runner) Start(ctx context.Context, configPath string) error {
	if err := r.requireExecutable(); err != nil {
		return err
	}
	if strings.TrimSpace(configPath) == "" {
		return fmt.Errorf("config path is empty")
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.started {
		return fmt.Errorf("xray already started")
	}

	cmd := exec.Command(r.Executable, "run", "-c", configPath)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if r.Detach {
		setDetached(cmd)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("xray start: %w", err)
	}
	waitCh := make(chan error, 1)
	go func() {
		waitCh <- cmd.Wait()
	}()
	r.cmd = cmd
	r.waitCh = waitCh
	r.waitOnce = &sync.Once{}
	r.waitErr = nil
	r.started = true
	return nil
}

// Stop sends a kill to the child and waits for it to exit.
func (r *Runner) Stop(ctx context.Context) error {
	r.mu.Lock()
	cmd := r.cmd
	started := r.started
	r.mu.Unlock()
	if !started || cmd == nil || cmd.Process == nil {
		return nil
	}
	if err := cmd.Process.Kill(); err != nil && !processAlreadyDone(err) {
		return fmt.Errorf("xray stop: %w", err)
	}
	done := make(chan error, 1)
	go func() { done <- r.reap() }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Wait blocks until the child exits.
func (r *Runner) Wait(ctx context.Context) error {
	done := make(chan error, 1)
	go func() { done <- r.reap() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// PID returns the child PID while running, or 0.
func (r *Runner) PID() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cmd == nil || r.cmd.Process == nil {
		return 0
	}
	return r.cmd.Process.Pid
}

// Path returns the configured executable path.
func (r *Runner) Path() string {
	if r == nil {
		return ""
	}
	return r.Executable
}

func (r *Runner) reap() error {
	r.mu.Lock()
	once := r.waitOnce
	ch := r.waitCh
	started := r.started
	r.mu.Unlock()
	if !started || once == nil || ch == nil {
		return fmt.Errorf("xray not started")
	}
	once.Do(func() {
		err := <-ch
		r.mu.Lock()
		r.waitErr = err
		r.cmd = nil
		r.waitCh = nil
		r.started = false
		r.mu.Unlock()
	})
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.waitErr
}

func (r *Runner) requireExecutable() error {
	if r == nil || strings.TrimSpace(r.Executable) == "" {
		return fmt.Errorf("xray executable path is empty")
	}
	if _, err := os.Stat(r.Executable); err != nil {
		return fmt.Errorf("xray executable: %w", err)
	}
	return nil
}

func processAlreadyDone(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "already finished") || strings.Contains(msg, "process already finished")
}
