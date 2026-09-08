package remotepolicy

// BuiltInDefaults are conservative. Remote policy does not enable advanced
// transports or filtering by itself.
func BuiltInDefaults() Settings {
	f := false
	return Settings{
		AutoSwitch:      boolPtr(f),
		BlockQUIC:       boolPtr(f),
		FakeDNS:         boolPtr(f),
		FragmentEnabled: boolPtr(f),
		MemorySaver:     boolPtr(f),
		MuxEnabled:      boolPtr(f),
		Sniffing:        boolPtr(f),
		TCPFastOpen:     boolPtr(f),
		TCPNoDelay:      boolPtr(f),
	}
}

func boolPtr(v bool) *bool { return &v }

func cloneStringSlice(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

func overlay(dst *Settings, src Settings) {
	if src.AutoSwitch != nil {
		v := *src.AutoSwitch
		dst.AutoSwitch = &v
	}
	if src.BlackKeyProtocol != nil {
		v := *src.BlackKeyProtocol
		dst.BlackKeyProtocol = &v
	}
	if src.BlockQUIC != nil {
		v := *src.BlockQUIC
		dst.BlockQUIC = &v
	}
	if src.CustomRouteAction != nil {
		v := *src.CustomRouteAction
		dst.CustomRouteAction = &v
	}
	if src.CustomRouteDomains != nil {
		dst.CustomRouteDomains = cloneStringSlice(src.CustomRouteDomains)
	}
	if src.DNSDirect != nil {
		v := *src.DNSDirect
		dst.DNSDirect = &v
	}
	if src.DomainStrategy != nil {
		v := *src.DomainStrategy
		dst.DomainStrategy = &v
	}
	if src.FakeDNS != nil {
		v := *src.FakeDNS
		dst.FakeDNS = &v
	}
	if src.FragmentEnabled != nil {
		v := *src.FragmentEnabled
		dst.FragmentEnabled = &v
	}
	if src.FragmentInterval != nil {
		v := *src.FragmentInterval
		dst.FragmentInterval = &v
	}
	if src.FragmentLength != nil {
		v := *src.FragmentLength
		dst.FragmentLength = &v
	}
	if src.FragmentPackets != nil {
		v := *src.FragmentPackets
		dst.FragmentPackets = &v
	}
	if src.MemorySaver != nil {
		v := *src.MemorySaver
		dst.MemorySaver = &v
	}
	if src.MTU != nil {
		v := *src.MTU
		dst.MTU = &v
	}
	if src.MuxConcurrency != nil {
		v := *src.MuxConcurrency
		dst.MuxConcurrency = &v
	}
	if src.MuxEnabled != nil {
		v := *src.MuxEnabled
		dst.MuxEnabled = &v
	}
	if src.MuxXUDPConcurrency != nil {
		v := *src.MuxXUDPConcurrency
		dst.MuxXUDPConcurrency = &v
	}
	if src.MuxXUDPQUIC != nil {
		v := *src.MuxXUDPQUIC
		dst.MuxXUDPQUIC = &v
	}
	if src.PolicyBufferSize != nil {
		v := *src.PolicyBufferSize
		dst.PolicyBufferSize = &v
	}
	if src.PolicyConnIdle != nil {
		v := *src.PolicyConnIdle
		dst.PolicyConnIdle = &v
	}
	if src.PolicyHandshake != nil {
		v := *src.PolicyHandshake
		dst.PolicyHandshake = &v
	}
	if src.Sniffing != nil {
		v := *src.Sniffing
		dst.Sniffing = &v
	}
	if src.TCPFastOpen != nil {
		v := *src.TCPFastOpen
		dst.TCPFastOpen = &v
	}
	if src.TCPNoDelay != nil {
		v := *src.TCPNoDelay
		dst.TCPNoDelay = &v
	}
	if src.TelegramIPs != nil {
		v := *src.TelegramIPs
		dst.TelegramIPs = &v
	}
	if src.WhatsAppIPs != nil {
		v := *src.WhatsAppIPs
		dst.WhatsAppIPs = &v
	}
}

// Merge applies layers from lowest to highest precedence:
// built-in, remote, local user override, session override.
func Merge(builtin, remote, local, session Settings) Settings {
	out := Settings{}
	overlay(&out, builtin)
	overlay(&out, remote)
	overlay(&out, local)
	overlay(&out, session)
	return out
}
