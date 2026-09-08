package app

import "github.com/igorpooh1978/blacktemple_kn/src/internal/api"

type stubStatus struct{}

func (stubStatus) Status() api.Status {
	return api.Status{
		Connection: "disconnected",
		Country:    "",
		LatencyMs:  nil,
		Routing:    "smart",
		ServerMode: "auto",
		Key:        "missing",
		Geodata:    "missing",
		Xray: api.XrayProcess{
			State:        "STOPPED",
			PID:          nil,
			Version:      "",
			RestartCount: 0,
		},
	}
}
