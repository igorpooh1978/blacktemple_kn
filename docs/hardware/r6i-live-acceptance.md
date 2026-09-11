# R6-I live selected-client routing (sanitized)

Filled from a real KN-1011 SSH session. Unit tests are not hardware PASS.
No IP, MAC, BlackKey, HMAC, or provider host values belong here.

```text
STOP REASON: TEST_CLIENT_REQUIRED

configured selected client: ABSENT
Home DHCP leases observed: multiple (not unique)
SSH management identity: not used as selected client
netfilter Apply: NOT RUN
rescue armed: NO (script absent on router; Apply not attempted)

LIVE TCP: NOT VERIFIED
UDP TPROXY LIVE: NOT VERIFIED
NON-SELECTED: NOT VERIFIED (ipset empty; no Apply)
ROUTER LOCAL: NOT VERIFIED as capture-negative (no Apply; OUTPUT BTKN count=0)
XKEEN COEXISTENCE: PARTIAL (PID and 1181 TCP+UDP unchanged during OUR Xray restart; Apply not run)
SSH SAFETY: PASS
CLEANUP: N/A (no Apply)
CAPTURE FINAL: DISABLED

SOCKS 11080 HTTPS generate_204: 204
OUR Xray run -test: PASS
OUR Xray version: 26.7.28
transparent 11820: inactive (disabled lifecycle / SOCKS-only running config)
XKeen path: /opt/sbin/xray
1181 TCP: present
1181 UDP: present
mark 0x111: present
table 111: present
BTKN chains: 0
BTKN ipset: 0
BTKN mark 0x42544b4e: absent
OUTPUT BTKN: 0
```
