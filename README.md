# PasarGuard SNI Router & Fallback Manager

By - Meysam | [github.com/logi443/nginx](https://github.com/logi443/nginx)

Interactive Ubuntu/Debian script that sets up nginx as an SNI-based TLS router
(for sharing port 443 between PasarGuard and a legacy panel like 3x-ui) plus a
local fallback backend that proxies unauthenticated TLS traffic to a real decoy
site.

## Requirements

- Ubuntu / Debian, root access
- PasarGuard (and optionally a legacy panel) already installed

## Usage

Run directly (one-liner):

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/logi443/nginx/main/pasarguard-sni-manager.sh)"
```

Or download first, then run:

```bash
curl -O https://raw.githubusercontent.com/logi443/nginx/main/pasarguard-sni-manager.sh
sudo bash pasarguard-sni-manager.sh
```

## Menu

| Option | Action |
|---|---|
| 1 | Install — prompts for the fake SNI domain, PasarGuard's internal port, the legacy backend's internal port (only if port 443 is already occupied), and the fallback port. Does nothing if already installed. |
| 2 | Edit configuration — change any saved value, or toggle SNI routing on/off. |
| 3 | Remove — deletes all generated nginx configs and the saved state. |
| 4 | Service status — nginx status, listening ports, config test. |
| 5 | Switch to PasarGuard-only mode — drops the legacy backend from routing once you no longer need it (e.g. after removing 3x-ui). PasarGuard must then be set to listen directly on port 443 in its own panel. |
| 0 | Exit |

## What it sets up

- `/etc/nginx/stream.conf.d/sni-router.conf` — routes port 443 by SNI between
  PasarGuard and the legacy backend (only when routing is enabled).
- `/etc/nginx/conf.d/pasarguard-fallback.conf` — local nginx backend
  (`127.0.0.1:<fallback_port>`) that reverse-proxies to the fake SNI domain.
  Point PasarGuard's TLS fallback `dest` to this address.
- `/etc/pasarguard-sni-fallback.conf` — saved configuration used by the
  install/edit/remove/status actions.

## Notes

- PasarGuard's inbound must listen on `127.0.0.1:<port>` when routing is
  enabled, and directly on `443` when in PasarGuard-only mode.
- The legacy panel's inbound must listen on `127.0.0.1:<legacy_port>` when
  routing is enabled.
- Set `Encryption`/`Decryption` to `none` on the PasarGuard VLESS inbound —
  Xray does not allow `fallbacks` together with non-`none` decryption.
