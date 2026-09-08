# packaging/

Entware IPK control scripts and rootfs templates.

- No systemd.
- Init: `/opt/etc/init.d/S99blacktemple-kn`.
- Uninstall removes only `BTKN_` rules and `/opt/blacktemple-kn`.
- Do not touch `/opt/bin/xray` (xkeen coexistence).
