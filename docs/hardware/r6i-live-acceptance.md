# R6-I live selected-client routing (sanitized)

Filled from real KN-1011 SSH sessions. Unit tests are not hardware PASS.
No IP, MAC, BlackKey, HMAC, or provider host values belong here.

## 2026-09-12 session

```text
STOP REASON: TEST_CLIENT_REQUIRED

configured selected client: ABSENT
BTKN_TEST_CLIENT_IPV4: ABSENT
Home DHCP leases: multiple named leases (not unique)
SSH management identity: excluded, not used as selected client
netfilter Apply: NOT RUN
rescue armed: NO (script absent on router)

LIVE TCP: NOT VERIFIED
UDP TPROXY LIVE: NOT VERIFIED
NON-SELECTED: NOT VERIFIED (no Apply)
ROUTER LOCAL: OUTPUT BTKN count=0 (no Apply)
XKEEN COEXISTENCE: PARTIAL (PID and 1181 TCP+UDP unchanged during OUR Xray restart; Apply not run)
SSH SAFETY: PASS
CLEANUP: N/A (no Apply)
CAPTURE FINAL: DISABLED

SOCKS 11080 HTTPS generate_204: 204
OUR Xray run -test: PASS
OUR Xray version: 26.7.28
OUR Xray: was down at session start; restored via blacktempled xray-start
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
capture.enabled: false
```

## 2026-09-11 session

Same STOP REASON. SOCKS 204 after product xray-start. No netfilter Apply.
