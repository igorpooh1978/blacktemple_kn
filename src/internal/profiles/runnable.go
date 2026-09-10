package profiles

import (
	"strings"

	"github.com/igorpooh1978/blacktemple_kn/src/internal/subscription"
	"github.com/igorpooh1978/blacktemple_kn/src/internal/xray"
)

func publishableEntry(e subscription.ParsedShare) bool {
	if !strings.EqualFold(e.Protocol, "vless") {
		return true
	}
	if !xray.InspectVLESSUserID(e.Material()).Valid {
		return false
	}
	sec := strings.ToLower(strings.TrimSpace(e.Security))
	switch sec {
	case "reality":
		if !xray.InspectRealityPublicKey(e.Params.RealityPublicKey).Valid {
			return false
		}
		return xray.InspectRealityShortID(e.Params.ShortID).Valid
	case "tls", "xtls-vision", "none":
		return true
	default:
		return false
	}
}

func filterPublishable(entries []subscription.ParsedShare) []subscription.ParsedShare {
	out := make([]subscription.ParsedShare, 0, len(entries))
	for _, e := range entries {
		if publishableEntry(e) {
			out = append(out, e)
		}
	}
	return out
}

func sourceKindOf(kind string, entries, published []subscription.ParsedShare) string {
	if kind == "url" {
		return SourceKindBlackKey
	}
	if kind == "json" {
		return SourceKindJSON
	}
	if len(published) == 0 && hadVLESS(entries) {
		return SourceKindBlackKey
	}
	return SourceKindShare
}

func hadVLESS(entries []subscription.ParsedShare) bool {
	for _, e := range entries {
		if strings.EqualFold(e.Protocol, "vless") {
			return true
		}
	}
	return false
}

func resolutionOf(published int) string {
	if published > 0 {
		return ResolutionResolved
	}
	return ResolutionUnresolved
}
