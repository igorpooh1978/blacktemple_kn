# ADR-009: Traffic capture abstraction; no Android tunnel copy

## Status

Accepted (R2 freeze)

## Context

APK ships `libhev-socks5-tunnel.so`, `libtun2socks.so`, Xray TUN inbound template (`xray_config_with_tun.json`), and Java `XrayVpnService` / `restartWithNewConfig` tun lifecycle.

Keenetic is a router: transparent capture is usually iptables/TPROXY/policy routing, not a userspace TUN per Android VpnService.

## Decision

Abstraction: `TrafficCaptureEngine`.

Candidates: `transparent-iptables`, `xray-tun`.

Первый выбор определяется реальными kernel capabilities KN-1011 (REDIRECT, TPROXY, TUN, fwmark, policy routing, ipset, UDP).

HEV/tun2socks — только если hardware evidence потребует. Не добавлять процесс «для соответствия Android».

До hardware probe статус: **UNKNOWN / not selected**.

## Consequences

R7/R13 решают конкретный engine. Контракт API говорит `captureEngine`, не `hev`.
