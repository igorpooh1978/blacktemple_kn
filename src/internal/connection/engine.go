package connection

import (
	"context"

	"github.com/igorpooh1978/blacktemple_kn/src/internal/xray"
)

// Engine is the Xray process seam used by the supervisor adapter.
type Engine interface {
	Start(ctx context.Context, configPath string) error
	Stop(ctx context.Context) error
	Wait(ctx context.Context) error
	ValidateConfig(ctx context.Context, configPath string) error
	Version(ctx context.Context) (string, error)
	PID() int
	Path() string
}

func NewXrayEngine(r *xray.Runner) Engine {
	if r == nil {
		r = &xray.Runner{}
	}
	return xrayEngine{r: r}
}

type xrayEngine struct {
	r *xray.Runner
}

func (e xrayEngine) Start(ctx context.Context, configPath string) error {
	return e.r.Start(ctx, configPath)
}

func (e xrayEngine) Stop(ctx context.Context) error {
	return e.r.Stop(ctx)
}

func (e xrayEngine) Wait(ctx context.Context) error {
	return e.r.Wait(ctx)
}

func (e xrayEngine) ValidateConfig(ctx context.Context, configPath string) error {
	return e.r.ValidateConfig(ctx, configPath)
}

func (e xrayEngine) Version(ctx context.Context) (string, error) {
	return e.r.Version(ctx)
}

func (e xrayEngine) PID() int {
	return e.r.PID()
}

func (e xrayEngine) Path() string {
	return e.r.Path()
}
