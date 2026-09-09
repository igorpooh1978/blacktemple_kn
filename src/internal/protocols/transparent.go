package protocols

// HybridTransparentInbound is the R6 dokodemo-door inbound for iptables
// REDIRECT (TCP) and TPROXY (UDP). It is generated JSON only — not SUPPORTED
// until KN-1011 hardware Apply PASS.
func HybridTransparentInbound() Combination {
	return Combination{
		Protocol:  "dokodemo-door",
		Transport: "tcp,udp",
		Security:  "followRedirect",
		Generated: true,
		XrayTest:  StatusNotRun,
		QEMU:      StatusNotRun,
		Hardware:  StatusNotRun,
		Notes:     "Hybrid transparent inbound listen 127.0.0.1:11820 (never 1181). sockopt.tproxy=tproxy. Do not treat as SUPPORTED until KN-1011 hardware PASS.",
	}
}
