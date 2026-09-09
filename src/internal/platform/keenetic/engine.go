package keenetic

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/igorpooh1978/blacktemple_kn/src/internal/routing"
)

// EngineKind is the platform selector result. TUN_CANDIDATE is not TUN_READY.
type EngineKind string

const (
	EngineHybridReady           EngineKind = "HYBRID_READY"
	EngineHybridPrepareRequired EngineKind = "HYBRID_PREPARE_REQUIRED"
	EngineTUNCandidate          EngineKind = "TUN_CANDIDATE"
	EngineNoUsable              EngineKind = "NO_USABLE_ENGINE"
)

// PolicyPreservationStatus is a design invariant until NDM policy lookup exists.
const PolicyPreservationStatus = "DESIGN INVARIANT / NOT VERIFIED"

// Runner executes a fixed argv. Never a shell line.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) (stdout string, err error)
}

// Capability is one HybridRequirements item plus provenance.
type Capability struct {
	Name       string
	Present    bool
	Loaded     bool
	ModuleFile string
	Path       string
	Package    string
	Origin     string
}

// PackageRecord is read-only opkg provenance for a userland tool.
type PackageRecord struct {
	Name    string
	Status  string
	Files   string
	Present bool
}

// Report is Detect/Verify output. Prepare never installs capture.
type Report struct {
	XKeenInstalled bool
	TUNChardev     bool
	Engine         EngineKind
	Capabilities   []Capability
	Packages       []PackageRecord
	UserlandOK     bool
	HybridOK       bool
	PrepareNeeded  bool
}

// Detect is read-only. It does not load modules or touch iptables policy.
func Detect(ctx context.Context, r Runner) (Report, error) {
	return inspect(ctx, r)
}

// Verify is a read-only re-check after Prepare.
func Verify(ctx context.Context, r Runner) (Report, error) {
	return inspect(ctx, r)
}

func inspect(ctx context.Context, r Runner) (Report, error) {
	if r == nil {
		return Report{}, errors.New("keenetic: nil runner")
	}
	req := routing.HybridRequirements()
	rep := Report{
		Packages:       probePackages(ctx, r),
		TUNChardev:     fileExists(ctx, r, "/dev/net/tun"),
		XKeenInstalled: detectXKeenInstalled(ctx, r),
	}

	userland := true
	for _, tool := range req.UserlandTools {
		if !toolPresent(ctx, r, tool) {
			userland = false
		}
	}
	rep.UserlandOK = userland

	var caps []Capability
	hybrid := userland
	prepare := false
	for _, name := range req.IptablesTargets {
		c := probeTarget(ctx, r, name)
		caps = append(caps, c)
		if !c.Present {
			hybrid = false
			if c.ModuleFile != "" {
				prepare = true
			}
		} else if !c.Loaded && c.ModuleFile != "" {
			prepare = true
			hybrid = false
		}
	}
	for _, name := range req.IptablesMatches {
		c := probeMatch(ctx, r, name)
		caps = append(caps, c)
		if !c.Present {
			hybrid = false
			if c.ModuleFile != "" {
				prepare = true
			}
		} else if !c.Loaded && c.ModuleFile != "" {
			prepare = true
			hybrid = false
		}
	}
	if req.NeedIPSet {
		c := probeIPSet(ctx, r)
		caps = append(caps, c)
		if !c.Present {
			hybrid = false
		}
	}
	if req.NeedPolicyRouting {
		c := probePolicyRouting(ctx, r)
		caps = append(caps, c)
		if !c.Present {
			hybrid = false
		}
	}
	rep.Capabilities = caps
	rep.HybridOK = hybrid
	rep.PrepareNeeded = prepare && !hybrid
	rep.Engine = SelectEngine(rep)
	return rep, ctx.Err()
}

// SelectEngine maps a Detect/Verify report to the runtime engine kind.
func SelectEngine(rep Report) EngineKind {
	if rep.HybridOK {
		return EngineHybridReady
	}
	if rep.PrepareNeeded {
		return EngineHybridPrepareRequired
	}
	if rep.TUNChardev {
		return EngineTUNCandidate
	}
	return EngineNoUsable
}

func detectXKeenInstalled(ctx context.Context, r Runner) bool {
	for _, p := range []string{"/opt/sbin/xkeen", "/opt/bin/xkeen", "/opt/etc/xkeen"} {
		if fileExists(ctx, r, p) {
			return true
		}
	}
	return false
}

func toolPresent(ctx context.Context, r Runner, name string) bool {
	for _, p := range []string{
		"/opt/sbin/" + name,
		"/opt/bin/" + name,
		"/usr/sbin/" + name,
		"/usr/bin/" + name,
		"/sbin/" + name,
		"/bin/" + name,
	} {
		if fileExists(ctx, r, p) {
			return true
		}
	}
	_, err := r.Run(ctx, name, "--version")
	return err == nil
}

func fileExists(ctx context.Context, r Runner, p string) bool {
	_, err := r.Run(ctx, "test", "-e", p)
	return err == nil
}

func cat(ctx context.Context, r Runner, p string) string {
	out, err := r.Run(ctx, "cat", p)
	if err != nil {
		return ""
	}
	return out
}

func probeTarget(ctx context.Context, r Runner, name string) Capability {
	return probeToken(ctx, r, name, "/proc/net/ip_tables_targets", "xt_"+name)
}

func probeMatch(ctx context.Context, r Runner, name string) Capability {
	return probeToken(ctx, r, name, "/proc/net/ip_tables_matches", "xt_"+name)
}

func probeToken(ctx context.Context, r Runner, name, procFile, modBase string) Capability {
	c := Capability{Name: name, Origin: "KERNEL/UNKNOWN"}
	blob := cat(ctx, r, procFile)
	mods := strings.ToLower(cat(ctx, r, "/proc/modules"))
	if tokenPresent(blob, name) {
		c.Present = true
		c.Loaded = true
	}
	lowBase := strings.ToLower(modBase)
	lowName := strings.ToLower(name)
	if strings.Contains(mods, lowBase) || strings.Contains(mods, "ipt_"+lowName) || strings.Contains(mods, "xt_"+lowName) {
		c.Present = true
		c.Loaded = true
	}
	mod := findModule(ctx, r, allowlistedBasenames(modBase, name))
	if mod.path != "" {
		c.ModuleFile = path.Base(mod.path)
		c.Path = mod.path
		c.Package = mod.owner
		c.Origin = mod.origin
		if !c.Present {
			c.Present = false
		}
	} else if c.Present && c.ModuleFile == "" {
		c.Origin = "KERNEL/UNKNOWN"
	}
	return c
}

func probeIPSet(ctx context.Context, r Runner) Capability {
	c := Capability{Name: "ipset", Origin: "KERNEL/UNKNOWN"}
	if toolPresent(ctx, r, "ipset") {
		c.Present = true
		c.Loaded = true
	}
	mods := cat(ctx, r, "/proc/modules")
	if strings.Contains(mods, "xt_set") || strings.Contains(mods, "ip_set") {
		c.Present = true
		c.Loaded = true
	}
	return c
}

func probePolicyRouting(ctx context.Context, r Runner) Capability {
	c := Capability{Name: "policy-routing", Origin: "KERNEL/UNKNOWN"}
	_, err := r.Run(ctx, "ip", "-4", "rule", "show")
	if err == nil {
		c.Present = true
		c.Loaded = true
	}
	return c
}

func tokenPresent(blob, name string) bool {
	for _, f := range strings.Fields(blob) {
		if strings.EqualFold(f, name) {
			return true
		}
	}
	return false
}

func probePackages(ctx context.Context, r Runner) []PackageRecord {
	var out []PackageRecord
	for _, name := range routing.HybridRequirements().UserlandTools {
		pkg := packageNameForTool(name)
		rec := PackageRecord{Name: pkg}
		st, err := r.Run(ctx, "opkg", "status", pkg)
		if err == nil && strings.TrimSpace(st) != "" {
			rec.Status = st
			rec.Present = strings.Contains(st, "Status:") && !strings.Contains(st, "not-installed")
		}
		files, ferr := r.Run(ctx, "opkg", "files", pkg)
		if ferr == nil {
			rec.Files = files
		}
		out = append(out, rec)
	}
	ca, err := r.Run(ctx, "opkg", "status", "ca-bundle")
	out = append(out, PackageRecord{
		Name:    "ca-bundle",
		Status:  ca,
		Present: err == nil && strings.Contains(ca, "Status:") && !strings.Contains(ca, "not-installed"),
	})
	return out
}

func packageNameForTool(tool string) string {
	switch tool {
	case "ip":
		return "ip-full"
	default:
		return tool
	}
}

func allowlistedBasenames(modBase, name string) []string {
	return []string{
		modBase + ".ko",
		"xt_" + name + ".ko",
		"ipt_" + name + ".ko",
		"nf_tproxy_ipv4.ko",
	}
}

type modHit struct {
	path   string
	origin string
	owner  string
}

func findModule(ctx context.Context, r Runner, names []string) modHit {
	release := strings.TrimSpace(cat(ctx, r, "/proc/sys/kernel/osrelease"))
	if release == "" {
		out, _ := r.Run(ctx, "uname", "-r")
		release = strings.TrimSpace(out)
	}
	roots := []string{
		"/lib/modules/" + release,
		"/lib/system-modules/" + release,
		"/opt/lib/modules",
		"/opt/lib/system-modules/" + release,
	}
	for _, root := range roots {
		for _, base := range names {
			p := strings.TrimSuffix(root, "/") + "/" + base
			if fileExists(ctx, r, p) {
				owner, _ := r.Run(ctx, "opkg", "search", p)
				return modHit{path: p, origin: root, owner: strings.TrimSpace(owner)}
			}
		}
	}
	return modHit{}
}

// Prepare loads allowlisted existing kernel modules. It never applies BTKN
// capture, never installs packages, never writes sysctl, never unloads modules.
func Prepare(ctx context.Context, r Runner) (Report, error) {
	if r == nil {
		return Report{}, errors.New("keenetic: nil runner")
	}
	before, err := Detect(ctx, r)
	if err != nil {
		return before, err
	}
	if before.Engine == EngineHybridReady {
		return Verify(ctx, r)
	}
	for _, c := range before.Capabilities {
		if c.Present && c.Loaded {
			continue
		}
		if c.ModuleFile == "" || c.Path == "" {
			continue
		}
		if err := loadAllowlisted(ctx, r, c.Path); err != nil {
			return before, err
		}
	}
	return Verify(ctx, r)
}

func loadAllowlisted(ctx context.Context, r Runner, modulePath string) error {
	base := path.Base(modulePath)
	if !allowlistedModule(base) {
		return fmt.Errorf("keenetic: module %s is not allowlisted", base)
	}
	if err := validateModulePath(modulePath); err != nil {
		return err
	}
	if _, err := r.Run(ctx, "modprobe", strings.TrimSuffix(base, ".ko")); err == nil {
		return nil
	}
	_, err := r.Run(ctx, "insmod", modulePath)
	return err
}

func allowlistedModule(base string) bool {
	switch base {
	case "xt_TPROXY.ko", "xt_socket.ko", "xt_mark.ko", "xt_CONNMARK.ko", "xt_set.ko",
		"xt_addrtype.ko", "xt_conntrack.ko", "xt_REDIRECT.ko", "ipt_REDIRECT.ko",
		"nf_tproxy_ipv4.ko", "xt_MARK.ko":
		return true
	default:
		return false
	}
}

func validateModulePath(p string) error {
	if p == "" || strings.Contains(p, "\x00") {
		return errors.New("keenetic: empty module path")
	}
	clean := path.Clean(p)
	if clean != p && !strings.HasPrefix(p, "/opt/lib/modules") {
		// Clean may collapse //; still require a known root.
	}
	ok := false
	for _, root := range []string{"/lib/modules/", "/lib/system-modules/", "/opt/lib/modules", "/opt/lib/system-modules/"} {
		if strings.HasPrefix(clean, strings.TrimSuffix(root, "/")) || strings.HasPrefix(clean, root) {
			ok = true
			break
		}
	}
	if !ok {
		return fmt.Errorf("keenetic: module path %s escapes known roots", p)
	}
	if strings.Contains(clean, "/../") {
		return errors.New("keenetic: module path escapes via ..")
	}
	if !allowlistedModule(path.Base(clean)) {
		return errors.New("keenetic: basename not allowlisted")
	}
	return nil
}
