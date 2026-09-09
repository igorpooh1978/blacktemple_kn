package app

import (
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/igorpooh1978/blacktemple_kn/src/internal/api"
	"github.com/igorpooh1978/blacktemple_kn/src/internal/auth"
	"github.com/igorpooh1978/blacktemple_kn/src/internal/connection"
	"github.com/igorpooh1978/blacktemple_kn/src/internal/profiles"
	"github.com/igorpooh1978/blacktemple_kn/src/internal/xray"
)

// LANResolver returns a unicast LAN host for auto-lan bind.
// Implementations belong to platform packages (wave F). A never imports them.
// When nil or unsafe, auto-lan fails closed to loopback.
type LANResolver interface {
	LANHost() (string, error)
}

// Config is the daemon composition root.
type Config struct {
	Listen         string
	ListenMode     string
	DataDir        string
	SessionTTL     time.Duration
	Version        string
	UI             fs.FS
	LAN            LANResolver
	XrayExecutable string
	Status         api.StatusProvider
	Connection     api.ConnectionService
	Profiles       api.ProfileService
}

// App is the running daemon.
type App struct {
	addr   string
	server *api.Server
	auth   *auth.Service
}

// New resolves the listen address, opens auth storage, and wires HTTP.
func New(cfg Config) (*App, error) {
	if cfg.Listen == "" {
		cfg.Listen = net.JoinHostPort(defaultListenHost, defaultListenPort)
	}
	if cfg.ListenMode == "" {
		cfg.ListenMode = "loopback"
	}
	if cfg.DataDir == "" {
		cfg.DataDir = "data"
	}
	addr, err := ResolveListen(cfg.ListenMode, cfg.Listen, cfg.LAN)
	if err != nil {
		return nil, err
	}
	svc, err := auth.New(auth.Config{
		DataDir:    cfg.DataDir,
		SessionTTL: cfg.SessionTTL,
	})
	if err != nil {
		return nil, err
	}

	status := cfg.Status
	conn := cfg.Connection
	prof := cfg.Profiles
	if status == nil || conn == nil || prof == nil {
		ps := profiles.New(profiles.Config{
			Client:  &http.Client{Timeout: 20 * time.Second},
			DataDir: cfg.DataDir,
		})
		xrayPath := cfg.XrayExecutable
		if xrayPath == "" {
			xrayPath = lookupXrayExecutable(cfg.DataDir)
		}
		cs := connection.New(connection.Config{
			Profiles: ps,
			Engine:   connection.NewXrayEngine(&xray.Runner{Executable: xrayPath}),
			DataDir:  cfg.DataDir,
		})
		if prof == nil {
			prof = connection.NewProfileAPI(ps)
		}
		if conn == nil {
			conn = cs
		}
		if status == nil {
			status = cs
		}
	}
	server := api.New(api.Config{
		Auth:       svc,
		Status:     status,
		Connection: conn,
		Profiles:   prof,
		Version:    api.VersionInfo{Version: cfg.Version},
		UI:         cfg.UI,
	})
	return &App{addr: addr, server: server, auth: svc}, nil
}

func (a *App) Handler() *api.Server { return a.server }

func (a *App) Addr() string { return a.addr }

func (a *App) Auth() *auth.Service { return a.auth }

func lookupXrayExecutable(dataDir string) string {
	if p := os.Getenv("BTKN_XRAY"); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	if p := os.Getenv("XRAY_EXECUTABLE"); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	names := []string{"xray"}
	if runtime.GOOS == "windows" {
		names = []string{"xray.exe", "xray"}
	}
	var candidates []string
	for _, n := range names {
		candidates = append(candidates,
			filepath.Join(dataDir, "bin", n),
			filepath.Join(filepath.Dir(dataDir), "bin", n),
			filepath.Join("/opt/blacktemple-kn/bin", n),
		)
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}
