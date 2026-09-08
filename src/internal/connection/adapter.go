package connection

import (
	"context"
	"strings"
	"sync"

	"github.com/igorpooh1978/blacktemple_kn/src/internal/supervisor"
)

// XrayProcessAdapter translates xray.Runner (Start(ctx, path)) into
// supervisor.ProcessRunner (Start(ctx)).
type XrayProcessAdapter struct {
	engine Engine

	mu         sync.Mutex
	configPath string
	version    string
}

func NewXrayProcessAdapter(engine Engine) *XrayProcessAdapter {
	return &XrayProcessAdapter{engine: engine}
}

func (a *XrayProcessAdapter) SetConfigPath(path string) {
	a.mu.Lock()
	a.configPath = path
	a.mu.Unlock()
}

func (a *XrayProcessAdapter) ConfigPath() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.configPath
}

func (a *XrayProcessAdapter) Start(ctx context.Context) error {
	a.mu.Lock()
	path := a.configPath
	a.mu.Unlock()
	if err := a.engine.Start(ctx, path); err != nil {
		return err
	}
	a.mu.Lock()
	if a.version == "" {
		if v, err := a.engine.Version(ctx); err == nil {
			a.version = firstVersionLine(v)
		}
	}
	a.mu.Unlock()
	return nil
}

func (a *XrayProcessAdapter) Stop(ctx context.Context) error {
	return a.engine.Stop(ctx)
}

func (a *XrayProcessAdapter) Wait() error {
	return a.engine.Wait(context.Background())
}

func (a *XrayProcessAdapter) Identity() supervisor.Identity {
	a.mu.Lock()
	ver := a.version
	a.mu.Unlock()
	return supervisor.Identity{
		PID:        a.engine.PID(),
		Executable: a.engine.Path(),
		Version:    ver,
	}
}

func firstVersionLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	return s
}
