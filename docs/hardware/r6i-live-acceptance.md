# R6-I live selected-client routing (sanitized)

Filled from real KN-1011 SSH sessions. Unit tests are not hardware PASS.
No IP, MAC, BlackKey, HMAC, or provider host values belong here.
Test client alias: `TEST_CLIENT-A`. Other XKeen device alias: `XKEEN-CLIENT-B`.

## 2026-09-12 live Apply

```text
TEST_CLIENT-A:
  found automatically: YES (Home, active, Default/empty policy, not router, not SSH)
  policy before: Keenetic Policy0 (description xkeen)
  policy during test: Default / empty
  selected set count: 1 (TEST_CLIENT-A only)

XKEEN-CLIENT-B:
  found: YES (Home, active, Policy0 / xkeen)
  still XKeen policy: YES
  in btkn_clients_v4: NO
  conntrack to 11820: 0

RESCUE:
  present: YES (/opt/blacktemple-kn/scripts/btkn-rescue.sh)
  armed: YES (then disarmed after cleanup)
  recover live fire: NOT RUN
  scope: BTKN_* / btkn_* / mark 0x42544b4e / table 4254 / OUR Xray only

OUR XRAY:
  version: 26.7.28
  SOCKS 127.0.0.1:11080: YES
  SOCKS HTTPS generate_204: 204
  transparent 11820 TCP+UDP listen during Apply: YES
  xray run -test: PASS
  path: /opt/blacktemple-kn/bin/xray

APPLY:
  capture.enabled: true (during test only)
  production path: blacktempled netfilter-reconcile
  BTKN PREROUTING position: 1 (nat + mangle), ahead of xkeen
  selected set count: 1
  OUTPUT BTKN: 0
  BusyBox ip table 4254: unsupported (invalid argument) — skipped
  iptables -m addrtype: unavailable (No chain/target/match) — skipped
  RFC1918 still RETURN via btkn_exclude_v4

LIVE TCP:
  BTKN_TCP REDIRECT 11820 counters increased (0 → 28 first pass; 0 → 24 second pass)
  BTKN_PRE selected jump to BTKN_TCP increased
  conntrack involving TEST_CLIENT-A and 11820 increased (20 → 41)
  conntrack involving XKEEN-CLIENT-B and 11820: 0
  SOCKS generate_204 on the same OUR Xray outbound: 204
  result: SELECTED CLIENT TCP ROUTING = VERIFIED
  PROVIDER VPN FROM LAN CLIENT = VERIFIED (11820 REDIRECT + same outbound as SOCKS 204)
  TEST_CLIENT-A Keenetic policy during capture: Default, not Policy0/xkeen
  BTKN jump is PREROUTING position 1, before xkeen REDIRECT 1181

XKEEN:
  PID before/during/after: unchanged
  path: /opt/sbin/xray
  1181 TCP: :::1181 LISTEN unchanged
  1181 UDP: :::1181 unchanged
  mark 0x111: present
  table 111: present

NON-SELECTED:
  BTKN_PRE !match-set src RETURN counters increased (non-selected bypass)
  XKEEN-CLIENT-B not in selected ipset
  XKeen 1181 remained live
  BTKN bypass: PASS
  XKeen still works: PASS (policy unchanged, not captured, 1181 live)

ROUTER LOCAL:
  nat OUTPUT BTKN: 0
  mangle OUTPUT BTKN: 0
  router DNS: success
  router HTTPS generate_204: 204
  result: PASS (not captured via 11820)

UDP:
  BTKN_UDP TPROXY counters increased on second pass (0 → 24)
  mark 0x42544b4e ip rule: absent (BusyBox cannot install table 4254)
  table 4254: unsupported
  OUR Xray UDP access log: absent (loglevel warning, no access file)
  UDP TPROXY = NOT VERIFIED (rule hits observed; local delivery via table 4254 not possible on this BusyBox ip)

FAILURE:
  OUR Xray stop via blacktempled xray-stop: YES
  SSH: alive
  XKeen PID: unchanged
  recovery xray-start: SOCKS 204

CLEANUP:
  capture.enabled final: false
  netfilter-reconcile stop: success
  BTKN chains: 0
  BTKN ipset: ABSENT
  table 4254 / mark 0x42544b4e: absent
  11820: inactive (SOCKS-only running config restored)
  SSH: alive
  XKeen PID / 1181 / mark 0x111 / table 111: unchanged

UI PASSWORD REMOVAL = NOT DONE — SEPARATE FIX REQUIRED
```

## 2026-09-12 earlier STOP (superseded)

Previous live Apply failed until BusyBox table 4254 skip, tcp6 XKeen listen classification, expected PID for 11820, and addrtype skip landed. Capture was never left enabled after those attempts.

## 2026-09-11 session

STOP REASON at that time: TEST_CLIENT_REQUIRED. SOCKS 204 after product xray-start. No netfilter Apply.
