package platform

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/igorpooh1978/blacktemple_kn/src/internal/atomicfile"
)

const (
	// CaptureConfigRel is the canonical daemon config under PrefixDir.
	// packaging/control/conffiles preserves this path across opkg upgrades.
	CaptureConfigRel = "config/config.json"
	// CaptureEngineTransparentIptables is the only engine name this wave stores.
	CaptureEngineTransparentIptables = "transparent-iptables"
	// ReasonCaptureDisabled is the Reconcile reason when the master switch is off.
	ReasonCaptureDisabled = "capture-disabled"
)

// DaemonCaptureConfig is the persisted safety switch. Missing/corrupt values
// fail closed to enabled=false. No environment variable can set enabled=true.
type DaemonCaptureConfig struct {
	Capture CaptureSettings `json:"capture"`
}

// CaptureSettings is the routing master switch.
type CaptureSettings struct {
	Enabled bool   `json:"enabled"`
	Engine  string `json:"engine"`
}

type captureFileProbe struct {
	Capture struct {
		Enabled json.RawMessage `json:"enabled"`
		Engine  string          `json:"engine"`
	} `json:"capture"`
}

// CaptureConfigPath returns PrefixDir/config/config.json.
func CaptureConfigPath(prefix string) string {
	if prefix == "" {
		prefix = PrefixDir
	}
	return filepath.Join(prefix, "config", "config.json")
}

func defaultCaptureConfig() DaemonCaptureConfig {
	return DaemonCaptureConfig{
		Capture: CaptureSettings{
			Enabled: false,
			Engine:  CaptureEngineTransparentIptables,
		},
	}
}

func marshalCaptureConfig(cfg DaemonCaptureConfig) ([]byte, error) {
	if cfg.Capture.Engine == "" {
		cfg.Capture.Engine = CaptureEngineTransparentIptables
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// EnsureCaptureConfig writes the default disabled config when the file is missing.
// An existing file is never overwritten (and never auto-enabled).
func EnsureCaptureConfig(path string) error {
	if path == "" {
		path = CaptureConfigPath("")
	}
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	raw, err := marshalCaptureConfig(defaultCaptureConfig())
	if err != nil {
		return err
	}
	return atomicfile.WriteFile(path, raw, 0o600)
}

// LoadCaptureEnabled returns true only when the JSON boolean capture.enabled
// is exactly true. Missing files, missing fields, and corrupt values are false.
// Environment variables are ignored.
func LoadCaptureEnabled(path string) bool {
	return loadCaptureSettings(path).Enabled
}

func loadCaptureSettings(path string) CaptureSettings {
	out := CaptureSettings{Enabled: false, Engine: CaptureEngineTransparentIptables}
	if path == "" {
		return out
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return out
	}
	var probe captureFileProbe
	if err := json.Unmarshal(raw, &probe); err != nil {
		return out
	}
	if probe.Capture.Engine != "" {
		out.Engine = probe.Capture.Engine
	}
	out.Enabled = jsonBoolTrue(probe.Capture.Enabled)
	return out
}

func jsonBoolTrue(raw json.RawMessage) bool {
	s := bytes.TrimSpace(raw)
	if len(s) == 0 {
		return false
	}
	var v bool
	if err := json.Unmarshal(s, &v); err != nil {
		return false
	}
	return v
}

func resolveCaptureEnabled(cmd NFCommand) bool {
	if cmd.CaptureEnabled != nil {
		return *cmd.CaptureEnabled
	}
	path := cmd.CaptureConfigPath
	if path == "" {
		path = CaptureConfigPath(cmd.Prefix)
	}
	return LoadCaptureEnabled(path)
}
