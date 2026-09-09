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

func ipcmd(args ...string) Argv {
	cp := make([]string, len(args))
	copy(cp, args)
	return Argv{Name: "ip", Args: cp}
}

func (e *HybridIptablesEngine) installCommands() []Argv {
	mark := tproxyMarkSpec()
	port := strconv.Itoa(CapturePort)
	table := strconv.Itoa(RouteTable)
	pref := strconv.Itoa(RulePreference)

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
	// exclusion → REDIRECT → 11820.
	cmds = append(cmds,
		iptables("-t", "nat", "-A", ChainPRE, "-m", "set", "!", "--match-set", SetClientsV4, "src", "-j", "RETURN"),
		iptables("-t", "nat", "-A", ChainPRE, "-j", ChainTCP),
		iptables("-t", "nat", "-A", ChainTCP, "-m", "set", "--match-set", SetExcludeV4, "dst", "-j", "RETURN"),
		iptables("-t", "nat", "-A", ChainTCP, "-m", "addrtype", "--dst-type", "LOCAL", "-j", "RETURN"),
		iptables("-t", "nat", "-A", ChainTCP, "-m", "addrtype", "--dst-type", "BROADCAST", "-j", "RETURN"),
		iptables("-t", "nat", "-A", ChainTCP, "-m", "addrtype", "--dst-type", "MULTICAST", "-j", "RETURN"),
		iptables("-t", "nat", "-A", ChainTCP, "-p", "tcp", "-j", "REDIRECT", "--to-ports", port),
	)

	// UDP TPROXY: selected LAN client → mangle PREROUTING → private/local
	// exclusion → socket-transparent guard → TPROXY 127.0.0.1:11820
	// mark 0x42544b4e → ip rule → table 4254 → local lo.
	cmds = append(cmds,
		iptables("-t", "mangle", "-A", ChainPRE, "-m", "set", "!", "--match-set", SetClientsV4, "src", "-j", "RETURN"),
		iptables("-t", "mangle", "-A", ChainPRE, "-j", ChainUDP),
		iptables("-t", "mangle", "-A", ChainUDP, "-j", "CONNMARK", "--restore-mark", "--mask", "0xffffffff"),
		iptables("-t", "mangle", "-A", ChainUDP, "-m", "mark", "--mark", mark, "-j", "RETURN"),
		iptables("-t", "mangle", "-A", ChainUDP, "-m", "set", "--match-set", SetExcludeV4, "dst", "-j", "RETURN"),
		iptables("-t", "mangle", "-A", ChainUDP, "-m", "addrtype", "--dst-type", "LOCAL", "-j", "RETURN"),
		iptables("-t", "mangle", "-A", ChainUDP, "-m", "addrtype", "--dst-type", "BROADCAST", "-j", "RETURN"),
		iptables("-t", "mangle", "-A", ChainUDP, "-m", "addrtype", "--dst-type", "MULTICAST", "-j", "RETURN"),
		iptables("-t", "mangle", "-A", ChainUDP, "-p", "udp", "-m", "socket", "--transparent", "-j", "RETURN"),
		iptables("-t", "mangle", "-A", ChainUDP, "-p", "udp", "-j", "TPROXY", "--on-ip", TProxyAddress, "--on-port", port, "--tproxy-mark", mark),
	)

	cmds = append(cmds,
		ipcmd("-4", "rule", "add", "fwmark", mark, "lookup", table, "pref", pref),
		ipcmd("-4", "route", "add", "local", "default", "dev", "lo", "table", table),
	)

	// Attach last so a partial Apply before this point does not capture.
	cmds = append(cmds,
		iptables("-t", "nat", "-A", "PREROUTING", "-j", ChainPRE),
		iptables("-t", "mangle", "-A", "PREROUTING", "-j", ChainPRE),
	)
	return cmds
}

func (e *HybridIptablesEngine) removeCommands() []Argv {
	mark := tproxyMarkSpec()
	table := strconv.Itoa(RouteTable)

	// Detach our jumps first. Never flush PREROUTING or foreign chains.
	return []Argv{
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
		ipcmd("-4", "rule", "del", "fwmark", mark, "lookup", table),
		ipcmd("-4", "route", "del", "local", "default", "dev", "lo", "table", table),
		ipset("destroy", SetClientsV4),
		ipset("destroy", SetExcludeV4),
	}
}
