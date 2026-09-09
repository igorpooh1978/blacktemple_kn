package protocols

// HybridTransparentInbound is the R6 tunnel inbound pair for iptables
// REDIRECT (TCP) and TPROXY (UDP). Generated JSON only — not SUPPORTED
// until KN-1011 hardware Apply PASS.
func HybridTransparentInbound() Combination {
	return Combination{
		Protocol:  "tunnel",
		Transport: "tcp+udp",
		Security:  "followRedirect",
		Generated: true,
		XrayTest:  StatusNotRun,
		QEMU:      StatusNotRun,
		Hardware:  StatusNotRun,
		Notes:     "Two inbounds on 0.0.0.0:11820 (never 1181): redirect-in TCP without tproxy sockopt; tproxy-in UDP with sockopt.tproxy=tproxy. Direct :11820 is not a forward proxy. Do not treat as SUPPORTED until KN-1011 hardware PASS.",
	}
}
