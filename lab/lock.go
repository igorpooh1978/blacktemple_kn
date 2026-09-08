package lab

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

const (
	ExitOK               = 0
	ExitFail             = 1
	ExitSetup            = 2
	ExitQEMUNotInstalled = 3
	ExitSHAMismatch      = 4
	ExitBootTimeout      = 5
	ExitSSHTimeout       = 6
)

const QEMUNotInstalled = "QEMU_NOT_INSTALLED"

// Asset is one pinned OpenWrt file.
type Asset struct {
	Filename string `json:"filename"`
	URL      string `json:"url"`
	SHA256   string `json:"sha256"`
}

// Lock is lab/openwrt.lock.json.
type Lock struct {
	SchemaVersion   int    `json:"schemaVersion"`
	Name            string `json:"name"`
	Version         string `json:"version"`
	Target          string `json:"target"`
	Machine         string `json:"machine"`
	Architecture    string `json:"architecture"`
	Endian          string `json:"endian"`
	CPU             string `json:"cpu"`
	MemoryMiB       int    `json:"memoryMiB"`
	DownloadDate    string `json:"downloadDate"`
	UpstreamIndex   string `json:"upstreamIndex"`
	SHA256SumsURL   string `json:"sha256sumsUrl"`
	NotHardware     string `json:"notHardware"`
	Experimental    bool   `json:"experimental"`
	PinnedNotLatest bool   `json:"pinnedNotLatest"`
	Kernel          Asset  `json:"kernel"`
	OverlayBase     Asset  `json:"overlayBase"`
	Notes           string `json:"notes"`
}

// LoadLock reads and validates a lock file.
func LoadLock(path string) (*Lock, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lock Lock
	if err := json.Unmarshal(raw, &lock); err != nil {
		return nil, fmt.Errorf("lock json: %w", err)
	}
	if err := lock.Validate(); err != nil {
		return nil, err
	}
	return &lock, nil
}

// Validate rejects floating latest, wrong arch, and missing SHA256.
func (l *Lock) Validate() error {
	if l == nil {
		return fmt.Errorf("lock is nil")
	}
	if l.SchemaVersion != 1 {
		return fmt.Errorf("schemaVersion %d want 1", l.SchemaVersion)
	}
	if strings.EqualFold(strings.TrimSpace(l.Version), "latest") {
		return fmt.Errorf("lock version must be pinned, not latest")
	}
	if strings.TrimSpace(l.Version) == "" {
		return incomplete("version")
	}
	if l.Target != "malta/le" {
		return fmt.Errorf("target %q want malta/le (not MT7621)", l.Target)
	}
	if l.Machine != "malta" {
		return fmt.Errorf("machine %q want malta (not MT7621)", l.Machine)
	}
	if l.Architecture != "mipsel" {
		return fmt.Errorf("architecture %q want mipsel", l.Architecture)
	}
	if l.Endian != "little" {
		return fmt.Errorf("endian %q want little", l.Endian)
	}
	if !l.PinnedNotLatest {
		return fmt.Errorf("pinnedNotLatest must be true")
	}
	if err := validateAsset("kernel", l.Kernel); err != nil {
		return err
	}
	if strings.TrimSpace(l.OverlayBase.URL) != "" || strings.TrimSpace(l.OverlayBase.Filename) != "" {
		if err := validateAsset("overlayBase", l.OverlayBase); err != nil {
			return err
		}
	}
	if !strings.Contains(l.Kernel.URL, "downloads.openwrt.org") {
		return fmt.Errorf("kernel url must be official downloads.openwrt.org")
	}
	if strings.Contains(strings.ToLower(l.Kernel.URL), "mt7621") {
		return fmt.Errorf("lock must not pin an MT7621 image")
	}
	return nil
}

func validateAsset(name string, a Asset) error {
	if strings.TrimSpace(a.Filename) == "" {
		return incomplete(name + ".filename")
	}
	if strings.TrimSpace(a.URL) == "" {
		return incomplete(name + ".url")
	}
	sum := strings.ToLower(strings.TrimSpace(a.SHA256))
	if sum == "" {
		return incomplete(name + ".sha256")
	}
	if len(sum) != 64 {
		return fmt.Errorf("%s sha256 length %d want 64", name, len(sum))
	}
	for _, c := range sum {
		if c >= '0' && c <= '9' || c >= 'a' && c <= 'f' {
			continue
		}
		return fmt.Errorf("%s sha256 is not hex", name)
	}
	return nil
}

func incomplete(field string) error {
	return fmt.Errorf("lock incomplete: missing %s", field)
}

// Incomplete reports whether err is an incomplete lock.
func Incomplete(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "lock incomplete")
}
