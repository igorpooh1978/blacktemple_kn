package connection

import (
	"context"
	"errors"

	"github.com/igorpooh1978/blacktemple_kn/src/internal/api"
	"github.com/igorpooh1978/blacktemple_kn/src/internal/profiles"
)

// ProfileAPI adapts profiles.Service to the frozen HTTP ProfileService.
type ProfileAPI struct {
	svc *profiles.Service
}

func NewProfileAPI(svc *profiles.Service) *ProfileAPI {
	return &ProfileAPI{svc: svc}
}

func (a *ProfileAPI) List(ctx context.Context) ([]api.Profile, error) {
	_ = ctx
	if a == nil || a.svc == nil {
		return nil, errors.New("profiles unavailable")
	}
	active := a.svc.ActiveID()
	raw := a.svc.List()
	out := make([]api.Profile, 0, len(raw))
	for _, p := range raw {
		status := "ready"
		if p.ID == active {
			status = "active"
		}
		out = append(out, api.Profile{ID: p.ID, Name: p.Name, Status: status})
	}
	return out, nil
}

func (a *ProfileAPI) Import(ctx context.Context, blackKey, name string) (api.Profile, error) {
	if a == nil || a.svc == nil {
		return api.Profile{}, errors.New("profiles unavailable")
	}
	p, err := a.svc.Import(ctx, profiles.ImportRequest{BlackKey: blackKey, Name: name})
	if err != nil {
		return api.Profile{}, codeImport(err)
	}
	status := "ready"
	if a.svc.ActiveID() == p.ID {
		status = "active"
	}
	return api.Profile{ID: p.ID, Name: p.Name, Status: status}, nil
}
