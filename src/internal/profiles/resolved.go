package profiles

import (
	"context"
	"os"
	"strings"

	"github.com/igorpooh1978/blacktemple_kn/src/internal/keys"
	"github.com/igorpooh1978/blacktemple_kn/src/internal/subscription"
	"github.com/igorpooh1978/blacktemple_kn/src/internal/xray"
)

// ResolvedSummary is a value-free import report.
type ResolvedSummary struct {
	CandidateCount int
	WSTLSCount     int
	XHTTPTLSCount  int
	UUIDValidCount int
	RealityCount   int
	InvalidSkipped int
}

func (r ResolvedSummary) String() string {
	return "ResolvedSummary{candidates:" + itoa(r.CandidateCount) +
		" ws_tls:" + itoa(r.WSTLSCount) +
		" xhttp_tls:" + itoa(r.XHTTPTLSCount) +
		" uuid:" + itoa(r.UUIDValidCount) +
		" reality:" + itoa(r.RealityCount) +
		" skipped:" + itoa(r.InvalidSkipped) + "}"
}

func (r ResolvedSummary) GoString() string { return r.String() }

// ImportResolvedJSON imports Android StartLoop JSON into an existing profile.
func (s *Service) ImportResolvedJSON(profileID string, raw []byte) (ResolvedSummary, error) {
	parsed, err := subscription.ParseXrayConfig(raw)
	if err != nil {
		return ResolvedSummary{}, err
	}
	return s.ImportResolved(profileID, parsed)
}

// ImportResolved replaces runnable candidates. Bootstrap source is kept.
func (s *Service) ImportResolved(profileID string, parsed subscription.Result) (ResolvedSummary, error) {
	sum := summarizeResolved(parsed)
	published := make([]subscription.ParsedShare, 0, len(parsed.Entries))
	for _, e := range parsed.Entries {
		if !publishableEntry(e) {
			sum.InvalidSkipped++
			continue
		}
		if err := validateResolvedGenerate(e); err != nil {
			sum.InvalidSkipped++
			continue
		}
		published = append(published, e)
	}
	sum.CandidateCount = len(published)
	sum.WSTLSCount = 0
	sum.XHTTPTLSCount = 0
	sum.UUIDValidCount = 0
	for _, e := range published {
		if strings.EqualFold(e.Transport, "ws") && strings.EqualFold(e.Security, "tls") {
			sum.WSTLSCount++
		}
		if strings.EqualFold(e.Transport, "xhttp") && strings.EqualFold(e.Security, "tls") {
			sum.XHTTPTLSCount++
		}
		if xray.InspectVLESSUserID(e.Material()).CanonicalUUID {
			sum.UUIDValidCount++
		}
	}
	err := s.commit(func(m *memory) error {
		rec, ok := m.byID[profileID]
		if !ok {
			return ErrNotFound
		}
		ks, srvs := s.entities(profileID, rec.sub.ID, published)
		st := keys.NewState(profileID, ks)
		if len(ks) > 0 {
			_, _ = st.SelectCandidate(ks[0].ID, ks[0].ServerID)
		}
		rec.keys = st
		rec.servers = srvs
		p := rec.profile
		if p.SourceKind == "" {
			p.SourceKind = SourceKindBlackKey
		}
		p.ResolutionState = resolutionOf(len(ks))
		rec.profile = p
		return nil
	})
	if err != nil {
		return ResolvedSummary{}, err
	}
	return sum, nil
}

// CreateBlackKeyShell stores an unresolved BlackKey profile with no runnable candidates.
func (s *Service) CreateBlackKeyShell(name string) (Profile, error) {
	var p Profile
	err := s.commit(func(m *memory) error {
		id := newID()
		nm := strings.TrimSpace(name)
		if nm == "" {
			nm = "profile-" + id[:8]
		}
		subID := newID()
		p = Profile{
			ID:              id,
			Name:            nm,
			SubscriptionID:  subID,
			CreatedAt:       s.now(),
			SourceKind:      SourceKindBlackKey,
			ResolutionState: ResolutionUnresolved,
		}
		sub := subscription.Subscription{ID: subID, ProfileID: id, Kind: "url", FetchedAt: s.now()}
		m.byID[id] = &record{profile: p, sub: sub, keys: keys.NewState(id, nil), servers: nil}
		m.order = append(m.order, id)
		if m.activeID == "" {
			m.activeID = id
		}
		return nil
	})
	return p, err
}

func summarizeResolved(parsed subscription.Result) ResolvedSummary {
	return ResolvedSummary{InvalidSkipped: parsed.Skipped, RealityCount: 0}
}

func validateResolvedGenerate(e subscription.ParsedShare) error {
	xp := xray.Profile{
		ID:        "resolved",
		Name:      "resolved",
		Protocol:  "vless",
		Server:    e.Host,
		Port:      e.Port,
		Transport: e.Transport,
		Security:  e.Security,
	}
	secrets := xray.ConfigSecrets{UUID: e.Material()}
	params := xray.OutboundParams{
		Flow:          e.Params.Flow,
		SNI:           e.Params.SNI,
		Fingerprint:   e.Params.Fingerprint,
		Path:          e.Params.Path,
		Host:          e.Params.Host,
		ServiceName:   e.Params.ServiceName,
		ALPN:          append([]string(nil), e.Params.ALPN...),
		Mode:          e.Params.Mode,
		AllowInsecure: e.Params.AllowInsecure,
	}
	raw, err := xray.Generate(xp, secrets, params, xray.Options{
		ListenHost: "127.0.0.1",
		ListenPort: 11080,
	})
	if err != nil {
		return err
	}
	exe := strings.TrimSpace(os.Getenv("XRAY_EXECUTABLE"))
	if exe == "" {
		return nil
	}
	f, err := os.CreateTemp("", "btkn-resolved-*.json")
	if err != nil {
		return err
	}
	path := f.Name()
	_, werr := f.Write(raw)
	cerr := f.Close()
	defer os.Remove(path)
	if werr != nil {
		return werr
	}
	if cerr != nil {
		return cerr
	}
	r := &xray.Runner{Executable: exe}
	return r.ValidateConfig(context.Background(), path)
}
