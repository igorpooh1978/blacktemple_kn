# packaging/

Entware IPK control scripts and rootfs templates.

- No systemd.
- Init: `/opt/etc/init.d/S99blacktemple-kn`.
- Uninstall removes only `BTKN_` rules and `/opt/blacktemple-kn`.
- Do not touch `/opt/bin/xray` (xkeen coexistence).
- Packed Xray (when `-IncludeXray`) is `/opt/blacktemple-kn/bin/xray`.
- `control/conffiles` lists `/opt/blacktemple-kn/config/config.json` so opkg keeps a user-modified config on upgrade. Hello-service does not ship a default config file yet.
