package connection

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/igorpooh1978/blacktemple_kn/src/internal/api"
	"github.com/igorpooh1978/blacktemple_kn/src/internal/keys"
	"github.com/igorpooh1978/blacktemple_kn/src/internal/profiles"
	"github.com/igorpooh1978/blacktemple_kn/src/internal/servers"
	"github.com/igorpooh1978/blacktemple_kn/src/internal/supervisor"
	"github.com/igorpooh1978/blacktemple_kn/src/internal/xray"
)

const (
	lkgConfigValidated = "CONFIG_VALIDATED"
	lkgProcessRunning  = "PROCESS_RUNNING"
	lkgNetworkVerified = "NETWORK_VERIFIED"

	defaultSOCKSHost = "127.0.0.1"
	defaultSOCKSPort = 11080
)

// Config wires the connection service.
type Config struct {
	Profiles    *profiles.Service
	Engine      Engine
	DataDir     string
	ListenHost  string
	ListenPort  int
	FastBackoff bool
}

// Service is the single ConnectionService between profiles, Xray, and supervisor.
type Service struct {
	profiles *profiles.Service
	engine   Engine
	adapter  *XrayProcessAdapter
	sup      *supervisor.Supervisor

	dataDir    string
	listenHost string
	listenPort int
	configPath string

	mu       sync.Mutex
	lastErr  string
	lkgStage string
}

func New(cfg Config) *Service {
	if cfg.Profiles == nil {
		cfg.Profiles = profiles.NewService(nil, nil)
	}
	if cfg.Engine == nil {
		cfg.Engine = xrayEngine{r: &xray.Runner{}}
	}
	if cfg.DataDir == "" {
		cfg.DataDir = "data"
	}
	if cfg.ListenHost == "" {
		cfg.ListenHost = defaultSOCKSHost
	}
	if cfg.ListenPort == 0 {
		cfg.ListenPort = defaultSOCKSPort
	}
	runDir := filepath.Join(cfg.DataDir, "run")
	_ = os.MkdirAll(runDir, 0o755)
	adapter := NewXrayProcessAdapter(cfg.Engine)
	path := filepath.Join(runDir, "xray.json")
	adapter.SetConfigPath(path)
	opts := []supervisor.Option{supervisor.WithStore(supervisor.NewMemoryStore())}
	if cfg.FastBackoff {
		opts = append(opts, supervisor.WithPolicy(supervisor.RestartPolicy{
			MaxRestarts:    5,
			Window:         time.Minute,
			InitialBackoff: time.Millisecond,
			MaxBackoff:     20 * time.Millisecond,
			Multiplier:     2,
		}))
	}
	return &Service{
		profiles:   cfg.Profiles,
		engine:     cfg.Engine,
		adapter:    adapter,
		sup:        supervisor.New(adapter, opts...),
		dataDir:    cfg.DataDir,
		listenHost: cfg.ListenHost,
		listenPort: cfg.ListenPort,
		configPath: path,
	}
}

func (s *Service) Profiles() *profiles.Service { return s.profiles }

func (s *Service) Supervisor() *supervisor.Supervisor { return s.sup }

func (s *Service) ConfigPath() string { return s.configPath }

func (s *Service) Control(ctx context.Context, op string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var err error
	switch op {
	case "connect":
		err = s.connectLocked(ctx)
	case "disconnect":
		err = s.disconnectLocked(ctx)
	case "reconnect":
		err = s.reconnectLocked(ctx)
	case "restart-vpn":
		err = s.restartVPNLocked(ctx)
	case "restart-manager", "full-restart":
		err = ErrUnsupportedInEnvironment
	default:
		err = fmt.Errorf("unknown op")
	}
	if err != nil {
		s.lastErr = publicError(err)
		return codeControl(err)
	}
	s.lastErr = ""
	return nil
}

func (s *Service) connectLocked(ctx context.Context) error {
	raw, err := s.generateLocked()
	if err != nil {
		return err
	}
	if err := s.installConfigLocked(ctx, raw); err != nil {
		return err
	}
	s.lkgStage = lkgConfigValidated
	st := s.sup.State()
	if st == supervisor.StateRunning || st == supervisor.StateStarting || st == supervisor.StateReloading {
		if err := s.sup.RestartVPN(ctx); err != nil {
			_ = restoreBackup(s.configPath)
			s.adapter.SetConfigPath(s.configPath)
			return fmt.Errorf("%w: %v", ErrStart, err)
		}
	} else {
		if err := s.sup.Start(ctx); err != nil {
			_ = restoreBackup(s.configPath)
			s.adapter.SetConfigPath(s.configPath)
			return fmt.Errorf("%w: %v", ErrStart, err)
		}
	}
	if s.sup.State() != supervisor.StateRunning {
		return ErrStart
	}
	s.lkgStage = lkgProcessRunning
	profileID := s.profiles.ActiveID()
	if profileID != "" {
		_, _ = s.profiles.CommitLastKnownGood(profileID)
	}
	return nil
}

func (s *Service) disconnectLocked(ctx context.Context) error {
	if err := s.sup.Stop(ctx); err != nil {
		return err
	}
	return nil
}

func (s *Service) reconnectLocked(ctx context.Context) error {
	if s.sup.State() == supervisor.StateRunning {
		if err := s.sup.Stop(ctx); err != nil {
			return err
		}
	}
	raw, err := s.generateLocked()
	if err != nil {
		return err
	}
	if err := s.installConfigLocked(ctx, raw); err != nil {
		return err
	}
	s.lkgStage = lkgConfigValidated
	if err := s.sup.Start(ctx); err != nil {
		_ = restoreBackup(s.configPath)
		s.adapter.SetConfigPath(s.configPath)
		return fmt.Errorf("%w: %v", ErrStart, err)
	}
	s.lkgStage = lkgProcessRunning
	return nil
}

func (s *Service) restartVPNLocked(ctx context.Context) error {
	if s.sup.State() != supervisor.StateRunning {
		return ErrNotConnected
	}
	if err := s.sup.RestartVPN(ctx); err != nil {
		return fmt.Errorf("%w: %v", ErrStart, err)
	}
	return nil
}

func (s *Service) generateLocked() ([]byte, error) {
	profileID := s.profiles.ActiveID()
	if profileID == "" {
		return nil, ErrNoProfile
	}
	key, srv, err := s.resolveVLESS(profileID)
	if err != nil {
		return nil, err
	}
	p, err := s.profiles.Get(profileID)
	if err != nil {
		return nil, err
	}
	params := key.Params()
	xp := xray.Profile{
		ID:        p.ID,
		Name:      p.Name,
		Protocol:  key.Protocol,
		Server:    srv.Host,
		Port:      srv.Port,
		Transport: srv.Transport,
		Security:  srv.Security,
		Country:   srv.CountryID,
	}
	secrets := xray.ConfigSecrets{UUID: key.Material()}
	out := xray.OutboundParams{
		Flow:        params.Flow,
		SNI:         params.SNI,
		PublicKey:   params.RealityPublicKey,
		ShortID:     params.ShortID,
		Fingerprint: params.Fingerprint,
		SpiderX:     params.SpiderX,
		Path:        params.Path,
		Host:        params.Host,
		ServiceName: params.ServiceName,
		ALPN:        append([]string(nil), params.ALPN...),
		Mode:        params.Mode,
	}
	raw, err := xray.Generate(xp, secrets, out, xray.Options{
		ListenHost: s.listenHost,
		ListenPort: s.listenPort,
	})
	if err != nil {
		if strings.Contains(err.Error(), "not generated") || strings.Contains(err.Error(), "unsupported") {
			return nil, fmt.Errorf("%w: %v", ErrUnsupportedProtocol, err)
		}
		return nil, err
	}
	return raw, nil
}

func (s *Service) resolveVLESS(profileID string) (keys.Key, servers.Server, error) {
	ks, err := s.profiles.Keys(profileID)
	if err != nil {
		return keys.Key{}, servers.Server{}, err
	}
	srvs, err := s.profiles.Servers(profileID)
	if err != nil {
		return keys.Key{}, servers.Server{}, err
	}
	cand, candErr := s.profiles.Candidate(profileID)
	if candErr == nil {
		if k, ok := findKey(ks, cand.KeyID); ok && strings.EqualFold(k.Protocol, "vless") {
			srv, err := findServerByID(srvs, cand.ServerID)
			if err == nil {
				return k, srv, nil
			}
		}
	}
	for _, k := range ks {
		if !strings.EqualFold(k.Protocol, "vless") {
			continue
		}
		srv, err := findServerByID(srvs, k.ServerID)
		if err != nil {
			continue
		}
		_, _ = s.profiles.SelectCandidate(profileID, k.ID, srv.ID)
		return k, srv, nil
	}
	if len(ks) == 0 {
		return keys.Key{}, servers.Server{}, ErrNoCandidate
	}
	return keys.Key{}, servers.Server{}, ErrUnsupportedProtocol
}

func (s *Service) installConfigLocked(ctx context.Context, raw []byte) error {
	tmp := strings.TrimSuffix(s.configPath, ".json") + ".new.json"
	if err := writeFileSync(tmp, raw); err != nil {
		return err
	}
	if err := s.engine.ValidateConfig(ctx, tmp); err != nil {
		_ = os.Remove(tmp)
		if missingExecutable(err) {
			return fmt.Errorf("%w: %v", ErrMissingXray, err)
		}
		return fmt.Errorf("%w: %v", ErrValidate, err)
	}
	if err := replaceFile(tmp, s.configPath); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	s.adapter.SetConfigPath(s.configPath)
	return nil
}

func (s *Service) Status() api.Status {
	snap := s.sup.Snapshot()
	s.mu.Lock()
	lastErr := s.lastErr
	s.mu.Unlock()

	st := api.Status{
		Connection: "disconnected",
		Country:    "",
		LatencyMs:  nil,
		Routing:    "smart",
		ServerMode: "auto",
		Key:        "missing",
		Geodata:    "missing",
		Xray: api.XrayProcess{
			State:        string(snap.State),
			PID:          snap.PID,
			Version:      snap.Version,
			RestartCount: snap.RestartCount,
		},
	}
	switch snap.State {
	case supervisor.StateRunning:
		st.Connection = "connected"
	case supervisor.StateStarting, supervisor.StateReloading, supervisor.StateBackoff:
		st.Connection = "connecting"
	case supervisor.StateFailed:
		st.Connection = "failed"
	default:
		if lastErr != "" {
			st.Connection = "failed"
		}
	}

	profileID := s.profiles.ActiveID()
	if profileID != "" {
		if ks, err := s.profiles.Keys(profileID); err == nil && len(ks) > 0 {
			st.Key = "active"
		}
		if cand, err := s.profiles.Candidate(profileID); err == nil {
			if srvs, err := s.profiles.Servers(profileID); err == nil {
				if srv, err := findServerByID(srvs, cand.ServerID); err == nil {
					st.Country = srv.CountryID
				}
			}
		}
	}
	return st
}

func findKey(ks []keys.Key, id string) (keys.Key, bool) {
	for _, k := range ks {
		if k.ID == id {
			return k, true
		}
	}
	return keys.Key{}, false
}

func findServerByID(list []servers.Server, id string) (servers.Server, error) {
	for _, srv := range list {
		if srv.ID == id {
			return srv, nil
		}
	}
	return servers.Server{}, servers.ErrNotFound
}

func missingExecutable(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "executable path is empty") ||
		strings.Contains(msg, "executable:") ||
		errors.Is(err, os.ErrNotExist)
}

func publicError(err error) string {
	switch {
	case errors.Is(err, ErrNoProfile):
		return "no profile"
	case errors.Is(err, ErrNoCandidate):
		return "no candidate"
	case errors.Is(err, ErrUnsupportedProtocol):
		return "unsupported protocol"
	case errors.Is(err, ErrMissingXray):
		return "xray missing"
	case errors.Is(err, ErrValidate):
		return "invalid xray config"
	case errors.Is(err, ErrStart):
		return "xray start failed"
	case errors.Is(err, ErrUnsupportedInEnvironment):
		return "unsupported in current environment"
	case errors.Is(err, ErrNotConnected):
		return "not connected"
	default:
		return "control failed"
	}
}
