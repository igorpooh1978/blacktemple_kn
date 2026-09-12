package routing

import "strconv"

func tproxyMarkSpec() string {
	return "0x42544b4e/0xffffffff"
}

func iptables(args ...string) Argv {
	cp := make([]string, len(args))
	copy(cp, args)
	return Argv{Name: "iptables", Args: cp}
}

func ipset(args ...string) Argv {
	cp := make([]string, len(args))
	copy(cp, args)
	return Argv{Name: "ipset", Args: cp}
}

func ipcmd(bin string, args ...string) Argv {
	if bin == "" {
		bin = "ip"
	}
	cp := make([]string, len(args))
	copy(cp, args)
	return Argv{Name: bin, Args: cp}
}

func addrtypeReturns(table, chain string) []Argv {
	out := make([]Argv, 0, 3)
	for _, kind := range []string{"LOCAL", "BROADCAST", "MULTICAST"} {
		out = append(out, iptables("-t", table, "-A", chain, "-m", "addrtype", "--dst-type", kind, "-j", "RETURN"))
	}
	return out
}

func (e *HybridIptablesEngine) ipBin() string {
	if e.ipPath != "" {
		return e.ipPath
	}
	return "ip"
}

func (e *HybridIptablesEngine) useAddrtype() bool {
	if !e.capsKnown {
		return true
	}
	return e.addrtype
}

func (e *HybridIptablesEngine) usePolicyRouting() bool {
	if !e.capsKnown {
		return true
	}
	return e.policyRouting
}

func (e *HybridIptablesEngine) installCommands() []Argv {
	mark := tproxyMarkSpec()
	port := strconv.Itoa(CapturePort)
	table := strconv.Itoa(RouteTable)
	pref := strconv.Itoa(RulePreference)
	ip := e.ipBin()

	cmds := []Argv{
		ipset("create", SetClientsV4, "hash:ip", "family", "inet", "-exist"),
		ipset("create", SetExcludeV4, "hash:net", "family", "inet", "-exist"),
	}
	for _, p := range IPv4DirectPrefixes() {
		cmds = append(cmds, ipset("add", SetExcludeV4, p.String(), "-exist"))
	}
	cmds = append(cmds, ipset("add", SetClientsV4, e.client.String(), "-exist"))

	// Reserved BTKN_OUT is created empty and never attached to OUTPUT.
	cmds = append(cmds,
		iptables("-t", "nat", "-N", ChainPRE),
		iptables("-t", "nat", "-N", ChainTCP),
		iptables("-t", "nat", "-N", ChainOUT),
		iptables("-t", "mangle", "-N", ChainPRE),
		iptables("-t", "mangle", "-N", ChainUDP),
		iptables("-t", "mangle", "-N", ChainOUT),
	)

	// TCP REDIRECT: selected LAN client → nat PREROUTING → private/local
	// exclusion → REDIRECT → 11820. addrtype is omitted when the match
	// is unavailable; RFC1918/localhost stay DIRECT via btkn_exclude_v4.
	cmds = append(cmds,
		iptables("-t", "nat", "-A", ChainPRE, "-m", "set", "!", "--match-set", SetClientsV4, "src", "-j", "RETURN"),
		iptables("-t", "nat", "-A", ChainPRE, "-j", ChainTCP),
		iptables("-t", "nat", "-A", ChainTCP, "-m", "set", "--match-set", SetExcludeV4, "dst", "-j", "RETURN"),
	)
	if e.useAddrtype() {
		cmds = append(cmds, addrtypeReturns("nat", ChainTCP)...)
	}
	cmds = append(cmds,
		iptables("-t", "nat", "-A", ChainTCP, "-p", "tcp", "-j", "REDIRECT", "--to-ports", port),
	)

	if e.usePolicyRouting() {
		// UDP TPROXY: hardware-proven XKeen order, BTKN mark/port/table only.
		cmds = append(cmds,
			iptables("-t", "mangle", "-A", ChainPRE, "-m", "set", "!", "--match-set", SetClientsV4, "src", "-j", "RETURN"),
			iptables("-t", "mangle", "-A", ChainPRE, "-j", ChainUDP),
			iptables("-t", "mangle", "-A", ChainUDP, "-p", "udp", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "CONNMARK", "--restore-mark", "--nfmask", "0xffffffff", "--ctmask", "0xffffffff"),
			iptables("-t", "mangle", "-A", ChainUDP, "-m", "conntrack", "--ctstate", "DNAT", "-j", "RETURN"),
			iptables("-t", "mangle", "-A", ChainUDP, "-m", "conntrack", "--ctstate", "INVALID", "-j", "RETURN"),
			iptables("-t", "mangle", "-A", ChainUDP, "-m", "set", "--match-set", SetExcludeV4, "dst", "-j", "RETURN"),
		)
		if e.useAddrtype() {
			cmds = append(cmds, addrtypeReturns("mangle", ChainUDP)...)
		}
		cmds = append(cmds,
			iptables("-t", "mangle", "-A", ChainUDP, "-p", "udp", "-m", "socket", "--transparent", "-j", "MARK", "--set-xmark", mark),
			iptables("-t", "mangle", "-A", ChainUDP, "-p", "udp", "-m", "mark", "!", "--mark", "0x0", "-j", "CONNMARK", "--save-mark", "--nfmask", "0xffffffff", "--ctmask", "0xffffffff"),
			iptables("-t", "mangle", "-A", ChainUDP, "-p", "udp", "-j", "TPROXY", "--on-ip", TProxyAddress, "--on-port", port, "--tproxy-mark", mark),
		)
		// TPROXY sets fwmark on the skb. Xray IP_TRANSPARENT replies to the
		// LAN client keep that mark. Without a more-specific rule they hit
		// table 4254 local default lo and never reach br0 (CASE D: access
		// log YES, iPhone srflx NO). SOCKS UDP to 127.0.0.1 is unaffected.
		lanPref := strconv.Itoa(LANReplyRulePreference)
		for _, p := range IPv4DirectPrefixes() {
			cmds = append(cmds, ipcmd(ip, "-4", "rule", "add", "fwmark", mark, "to", p.String(), "lookup", "main", "pref", lanPref))
		}
		cmds = append(cmds,
			ipcmd(ip, "-4", "rule", "add", "fwmark", mark, "lookup", table, "pref", pref),
			ipcmd(ip, "-4", "route", "add", "local", "default", "dev", "lo", "table", table),
			iptables("-t", "mangle", "-I", "PREROUTING", "1", "-j", ChainPRE),
		)
	}

	cmds = append(cmds,
		iptables("-t", "nat", "-I", "PREROUTING", "1", "-j", ChainPRE),
	)
	return cmds
}

func (e *HybridIptablesEngine) removeCommands() []Argv {
	mark := tproxyMarkSpec()
	table := strconv.Itoa(RouteTable)
	ip := e.ipBin()
	lanPref := strconv.Itoa(LANReplyRulePreference)

	// Detach our jumps first. Never flush PREROUTING or foreign chains.
	cmds := []Argv{
		iptables("-t", "nat", "-D", "PREROUTING", "-j", ChainPRE),
		iptables("-t", "mangle", "-D", "PREROUTING", "-j", ChainPRE),
		iptables("-t", "nat", "-F", ChainTCP),
		iptables("-t", "nat", "-F", ChainPRE),
		iptables("-t", "nat", "-F", ChainOUT),
		iptables("-t", "mangle", "-F", ChainUDP),
		iptables("-t", "mangle", "-F", ChainPRE),
		iptables("-t", "mangle", "-F", ChainOUT),
		iptables("-t", "nat", "-X", ChainTCP),
		iptables("-t", "nat", "-X", ChainPRE),
		iptables("-t", "nat", "-X", ChainOUT),
		iptables("-t", "mangle", "-X", ChainUDP),
		iptables("-t", "mangle", "-X", ChainPRE),
		iptables("-t", "mangle", "-X", ChainOUT),
	}
	for _, p := range IPv4DirectPrefixes() {
		cmds = append(cmds, ipcmd(ip, "-4", "rule", "del", "fwmark", mark, "to", p.String(), "lookup", "main", "pref", lanPref))
	}
	cmds = append(cmds,
		ipcmd(ip, "-4", "rule", "del", "fwmark", mark, "lookup", table),
		ipcmd(ip, "-4", "route", "del", "local", "default", "dev", "lo", "table", table),
		ipset("destroy", SetClientsV4),
		ipset("destroy", SetExcludeV4),
	)
	return cmds
}
