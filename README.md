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
| 1 | Install — first asks the mode: **SNI routing** (nginx owns the public port and splits traffic by SNI between PasarGuard and a legacy panel) or **Direct** (PasarGuard owns the public port, only the fallback is set up). Then prompts for the fake SNI domain, PasarGuard's internal port, the public port nginx listens on (routing mode only, default 443), the legacy backend port, and the fallback port. Does nothing if already installed. |
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

- In SNI routing mode, PasarGuard's inbound must listen on `127.0.0.1:<port>`
  and the legacy panel's inbound on `127.0.0.1:<legacy_port>`; nginx owns the
  public port and routes by SNI.
- In Direct / PasarGuard-only mode, PasarGuard's inbound listens directly on the
  public port (e.g. `0.0.0.0:443`) and nginx only hosts the fallback backend.
- Set `Encryption`/`Decryption` to `none` on the PasarGuard VLESS inbound —
  Xray does not allow `fallbacks` together with non-`none` decryption.
