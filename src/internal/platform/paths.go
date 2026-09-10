package platform

// Fixed Entware/Keenetic paths. Never interpolate user-provided strings into
// shell or iptables argv from these constants.
const (
	EntwareRoot = "/opt"
	PrefixDir   = "/opt/blacktemple-kn"

	// DefaultDataDir is the packaged runtime store. Auth, profiles.json and
	// run/xray.json live here. Capture config stays under PrefixDir/config.
	DefaultDataDir = "/opt/blacktemple-kn/data"

	// DefaultManagerPath is our daemon, not a foreign binary.
	DefaultManagerPath = "/opt/blacktemple-kn/bin/blacktempled"
	// DefaultXrayPath is our pinned binary. Never /opt/bin/xray (XKeen).
	DefaultXrayPath = "/opt/blacktemple-kn/bin/xray"

	// NetfilterHookInstalled is the Keenetic NDM hook path observed as a
	// directory on KN-1011 (/opt/etc/ndm/netfilter.d exists; XKeen uses
	// proxy.sh there). Ours is a distinct filename.
	NetfilterHookInstalled = "/opt/etc/ndm/netfilter.d/blacktemple-kn.sh"
	NetfilterHookSource    = "packaging/keenetic/netfilter.d/blacktemple-kn.sh"

	// ChainPrefix is the only iptables prefix we may name. D owns Apply/Remove.
	ChainPrefix = "BTKN_"

	// NetfilterReconcileArg is the CLI argument stream A should implement on
	// blacktempled. F does not wire src/cmd.
	NetfilterReconcileArg     = "netfilter-reconcile"
	NetfilterReconcileStopArg = "stop"

	// NDMHookEnv is set by packaging/keenetic/netfilter.d/blacktemple-kn.sh.
	// It only marks origin=ndm. It does not skip XKeen or lock safety checks
	// and must never enable capture.enabled.
	NDMHookEnv = "BTKN_NDM_HOOK"

	// ProductionRouterMutationAck is the only accepted value of
	// BTKN_PRODUCTION_ROUTER_MUTATION_ACK for future mutating hardware smoke.
	ProductionRouterMutationAck    = "I_ACCEPT_NETWORK_LOSS"
	ProductionRouterMutationAckEnv = "BTKN_PRODUCTION_ROUTER_MUTATION_ACK"

	// KeeneticDenyFwmark is the policy drop mark observed on KN-1011
	// (ip rule fwmark 0xffffaaa → table 4096 then blackhole). Capture must
	// not grant internet Keenetic already denied.
	KeeneticDenyFwmark = "0xffffaaa"
)
