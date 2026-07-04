#!/usr/bin/env bash
# pasarguard-sni-manager.sh
# Interactive menu-driven installer/manager for the nginx SNI-router +
# PasarGuard TLS fallback setup.
# Target: Ubuntu / Debian
set -euo pipefail

CONFIG_FILE="/etc/pasarguard-sni-fallback.conf"
STREAM_CONF="/etc/nginx/stream.conf.d/sni-router.conf"
FALLBACK_CONF="/etc/nginx/conf.d/pasarguard-fallback.conf"
NGINX_MAIN="/etc/nginx/nginx.conf"
MARKER_STREAM="# managed-by-pasarguard-sni-manager"
MARKER_INCLUDE="# stream-include-managed-by-pasarguard-sni-manager"

log()  { echo -e "\033[1;32m[+]\033[0m $*"; }
warn() { echo -e "\033[1;33m[!]\033[0m $*"; }
err()  { echo -e "\033[1;31m[x]\033[0m $*" >&2; }
pause() { read -rp "Press Enter to continue..." _; }

[[ $EUID -eq 0 ]] || { err "Run this script as root (sudo)."; exit 1; }
command -v apt-get >/dev/null 2>&1 || { err "This script only supports Ubuntu/Debian."; exit 1; }

# ---------------------------------------------------------------------------
# Config state helpers
# ---------------------------------------------------------------------------
FAKE_SNI=""
PG_PORT=""
LEGACY_PORT=""
FALLBACK_PORT=""
ROUTING_ENABLED=""

is_installed() { [[ -f "$CONFIG_FILE" ]] || [[ -f "$FALLBACK_CONF" ]]; }

reconstruct_config_from_files() {
    if [[ -f "$FALLBACK_CONF" ]]; then
        FAKE_SNI="$(grep -oP 'proxy_pass https://\K[^;]+' "$FALLBACK_CONF" | head -1)"
        FALLBACK_PORT="$(grep -oP 'listen 127\.0\.0\.1:\K[0-9]+' "$FALLBACK_CONF" | head -1)"
    fi
    if [[ -f "$STREAM_CONF" ]]; then
        ROUTING_ENABLED="true"
        PG_PORT="$(awk '/upstream pasarguard_backend/,/}/' "$STREAM_CONF" | grep -oP '127\.0\.0\.1:\K[0-9]+' | head -1)"
        LEGACY_PORT="$(awk '/upstream legacy_backend/,/}/' "$STREAM_CONF" | grep -oP '127\.0\.0\.1:\K[0-9]+' | head -1)"
    else
        ROUTING_ENABLED="false"
        LEGACY_PORT=""
    fi
}

load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        # shellcheck disable=SC1090
        source "$CONFIG_FILE"
    elif [[ -f "$FALLBACK_CONF" ]]; then
        reconstruct_config_from_files
        save_config
        warn "Detected an existing installation created outside this manager — imported its settings."
    fi
}

save_config() {
    cat > "$CONFIG_FILE" <<EOF
FAKE_SNI="${FAKE_SNI}"
PG_PORT="${PG_PORT}"
LEGACY_PORT="${LEGACY_PORT}"
FALLBACK_PORT="${FALLBACK_PORT}"
ROUTING_ENABLED="${ROUTING_ENABLED}"
EOF
}

port_busy_443() {
    if command -v ss >/dev/null 2>&1; then
        ss -ltnp 2>/dev/null | awk '$4 ~ /:443$/' | grep -q .
    else
        netstat -ltnp 2>/dev/null | awk '$4 ~ /:443$/' | grep -q .
    fi
}

# ---------------------------------------------------------------------------
# nginx module / package install
# ---------------------------------------------------------------------------
ensure_nginx_with_stream() {
    export DEBIAN_FRONTEND=noninteractive
    if ! command -v nginx >/dev/null 2>&1; then
        log "Installing nginx-full..."
        apt-get update -qq
        apt-get install -y nginx-full
    fi
    mkdir -p /etc/nginx/stream.conf.d /etc/nginx/conf.d

    if ! grep -q "load_module modules/ngx_stream_module.so;" "$NGINX_MAIN" 2>/dev/null \
       && ! grep -rq "ngx_stream_module" /etc/nginx/modules-enabled/ 2>/dev/null; then
        log "Loading stream module explicitly..."
        sed -i '1i load_module modules/ngx_stream_module.so;' "$NGINX_MAIN"
    fi

    if ! grep -q "stream.conf.d" "$NGINX_MAIN" 2>/dev/null; then
        log "Adding stream{} include block to nginx.conf..."
        cat >> "$NGINX_MAIN" <<EOF

${MARKER_INCLUDE}
stream {
    include /etc/nginx/stream.conf.d/*.conf;
}
EOF
    fi
}

# ---------------------------------------------------------------------------
# Config file generation (re-run any time values change)
# ---------------------------------------------------------------------------
write_fallback_conf() {
    cat > "$FALLBACK_CONF" <<EOF
${MARKER_STREAM}
server {
    listen 127.0.0.1:${FALLBACK_PORT};
    server_name _;

    location / {
        proxy_pass https://${FAKE_SNI};
        proxy_set_header Host ${FAKE_SNI};
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_ssl_server_name on;
        proxy_ssl_name ${FAKE_SNI};
        proxy_ssl_verify off;
        proxy_redirect https://${FAKE_SNI}/ /;
        proxy_hide_header Set-Cookie;
    }
}
EOF
}

write_stream_conf() {
    if [[ "$ROUTING_ENABLED" == "true" ]]; then
        cat > "$STREAM_CONF" <<EOF
${MARKER_STREAM}
map \$ssl_preread_server_name \$sni_backend_pool {
    ${FAKE_SNI}   pasarguard_backend;
    default       legacy_backend;
}

upstream pasarguard_backend {
    server 127.0.0.1:${PG_PORT};
}

upstream legacy_backend {
    server 127.0.0.1:${LEGACY_PORT};
}

server {
    listen 443;
    listen [::]:443;
    proxy_pass \$sni_backend_pool;
    ssl_preread on;
    proxy_timeout 300s;
}
EOF
    else
        rm -f "$STREAM_CONF"
    fi
}

apply_and_reload() {
    write_fallback_conf
    write_stream_conf
    if nginx -t; then
        systemctl restart nginx
        log "nginx restarted successfully."
    else
        err "nginx config test failed. Not reloading. Fix the issue and try again."
        return 1
    fi
}

# ---------------------------------------------------------------------------
# 1) Install
# ---------------------------------------------------------------------------
do_install() {
    if is_installed; then
        warn "Already installed. Current configuration:"
        load_config
        print_current_config
        pause
        return
    fi

    echo
    read -rp "Fake SNI domain (e.g. soft98.ir): " FAKE_SNI
    [[ -z "$FAKE_SNI" ]] && { err "SNI domain cannot be empty."; return; }

    read -rp "PasarGuard internal local port (e.g. 8444): " PG_PORT
    [[ -z "$PG_PORT" ]] && { err "PasarGuard port cannot be empty."; return; }

    if port_busy_443; then
        ROUTING_ENABLED="true"
        warn "Port 443 is occupied by another service."
        warn "Set PasarGuard's inbound listen address to 127.0.0.1:${PG_PORT} in its panel."
        read -rp "Internal local port of the EXISTING legacy service (e.g. old 3x-ui, e.g. 8443): " LEGACY_PORT
        [[ -z "$LEGACY_PORT" ]] && { err "Legacy port cannot be empty."; return; }
        warn "Make sure the legacy service is set to listen on 127.0.0.1:${LEGACY_PORT}."
    else
        ROUTING_ENABLED="false"
        LEGACY_PORT=""
        log "Port 443 is free — PasarGuard can listen directly on 0.0.0.0:443. No SNI routing needed."
    fi

    read -rp "Fallback local port (default: 8080): " FALLBACK_PORT
    FALLBACK_PORT="${FALLBACK_PORT:-8080}"

    echo
    echo "------------------------------------------------------------"
    print_current_config
    echo "------------------------------------------------------------"
    read -rp "Proceed with installation? [y/N]: " CONFIRM
    [[ "$CONFIRM" =~ ^[Yy]$ ]] || { warn "Installation cancelled."; return; }

    ensure_nginx_with_stream
    apply_and_reload && save_config && log "Installation complete."
    pause
}

print_current_config() {
    echo " Fake SNI domain      : ${FAKE_SNI}"
    echo " PasarGuard local port: 127.0.0.1:${PG_PORT}"
    [[ "$ROUTING_ENABLED" == "true" ]] && echo " Legacy backend port  : 127.0.0.1:${LEGACY_PORT}"
    echo " Fallback local port  : 127.0.0.1:${FALLBACK_PORT}"
    echo " SNI routing on :443  : ${ROUTING_ENABLED}"
}

# ---------------------------------------------------------------------------
# 2) Edit configuration
# ---------------------------------------------------------------------------
edit_menu() {
    if ! is_installed; then
        err "Not installed yet. Use option 1 first."
        pause
        return
    fi
    load_config

    while true; do
        clear
        echo "=== Edit Configuration ==="
        echo " 1) Fake SNI domain        [current: ${FAKE_SNI}]"
        echo " 2) PasarGuard local port   [current: ${PG_PORT}]"
        if [[ "$ROUTING_ENABLED" == "true" ]]; then
            echo " 3) Legacy backend port    [current: ${LEGACY_PORT}]"
        else
            echo " 3) Legacy backend port    [routing disabled]"
        fi
        echo " 4) Fallback local port     [current: ${FALLBACK_PORT}]"
        echo " 5) Toggle SNI routing on :443 [current: ${ROUTING_ENABLED}]"
        echo " 0) Back to main menu"
        echo
        read -rp "Select an option: " choice

        case "$choice" in
            1)
                read -rp "New fake SNI domain: " new_val
                [[ -n "$new_val" ]] && FAKE_SNI="$new_val"
                ;;
            2)
                read -rp "New PasarGuard local port: " new_val
                [[ -n "$new_val" ]] && PG_PORT="$new_val"
                ;;
            3)
                if [[ "$ROUTING_ENABLED" != "true" ]]; then
                    warn "Routing is disabled — enable it first (option 5)."
                    pause
                    continue
                fi
                read -rp "New legacy backend port: " new_val
                [[ -n "$new_val" ]] && LEGACY_PORT="$new_val"
                ;;
            4)
                read -rp "New fallback local port: " new_val
                [[ -n "$new_val" ]] && FALLBACK_PORT="$new_val"
                ;;
            5)
                if [[ "$ROUTING_ENABLED" == "true" ]]; then
                    ROUTING_ENABLED="false"
                    log "SNI routing disabled. PasarGuard should listen directly on 0.0.0.0:443."
                else
                    read -rp "Legacy backend port (needed to enable routing): " LEGACY_PORT
                    [[ -z "$LEGACY_PORT" ]] && { err "Legacy port required."; pause; continue; }
                    ROUTING_ENABLED="true"
                fi
                ;;
            0)
                return
                ;;
            *)
                err "Invalid option."
                pause
                continue
                ;;
        esac

        if apply_and_reload; then
            save_config
            log "Configuration updated and applied."
        else
            err "Failed to apply new configuration. Previous config file on disk was NOT overwritten."
        fi
        pause
    done
}

# ---------------------------------------------------------------------------
# 3) Remove
# ---------------------------------------------------------------------------
do_remove() {
    if ! is_installed; then
        err "Nothing to remove — not installed."
        pause
        return
    fi

    warn "This will remove the SNI router and fallback nginx configs."
    read -rp "Are you sure? [y/N]: " CONFIRM
    [[ "$CONFIRM" =~ ^[Yy]$ ]] || { warn "Cancelled."; return; }

    rm -f "$STREAM_CONF" "$FALLBACK_CONF"

    # Remove the stream{} include block we added, if present
    if grep -q "$MARKER_INCLUDE" "$NGINX_MAIN" 2>/dev/null; then
        sed -i "/${MARKER_INCLUDE}/,/^}/d" "$NGINX_MAIN"
    fi

    if nginx -t; then
        systemctl restart nginx
        log "nginx restarted after removal."
    else
        warn "nginx config test failed after removal — check ${NGINX_MAIN} manually."
    fi

    rm -f "$CONFIG_FILE"
    log "Removal complete."
    pause
}

# ---------------------------------------------------------------------------
# 4) Service status
# ---------------------------------------------------------------------------
do_status() {
    echo "=== nginx service ==="
    systemctl status nginx --no-pager 2>&1 | head -10
    echo
    echo "=== Listening ports ==="
    ss -ltnp 2>/dev/null | grep -E ':443|:8080' || true
    if is_installed; then
        load_config
        ss -ltnp 2>/dev/null | grep -E ":${PG_PORT}|:${LEGACY_PORT}|:${FALLBACK_PORT}" || true
    fi
    echo
    echo "=== nginx config test ==="
    nginx -t 2>&1 || true
    echo
    if is_installed; then
        load_config
        echo "=== Current saved configuration ==="
        print_current_config
    else
        warn "Not installed."
    fi
    pause
}

# ---------------------------------------------------------------------------
# 5) Switch to PasarGuard-only mode (drop legacy/SNI routing entirely)
# ---------------------------------------------------------------------------
do_pasarguard_only() {
    if ! is_installed; then
        err "Not installed yet. Use option 1 first."
        pause
        return
    fi
    load_config

    if [[ "$ROUTING_ENABLED" != "true" ]]; then
        warn "Already in PasarGuard-only mode (no SNI routing active)."
        pause
        return
    fi

    echo
    warn "This will remove the legacy (e.g. sanaei/3x-ui) backend from routing."
    warn "PasarGuard will become the only service on port 443."
    read -rp "Confirm switch to PasarGuard-only mode? [y/N]: " CONFIRM
    [[ "$CONFIRM" =~ ^[Yy]$ ]] || { warn "Cancelled."; return; }

    ROUTING_ENABLED="false"
    LEGACY_PORT=""

    if apply_and_reload; then
        save_config
        log "Switched to PasarGuard-only mode."
        warn "IMPORTANT: go to the PasarGuard panel and change the inbound listen"
        warn "address from 127.0.0.1:${PG_PORT} to 0.0.0.0:443 (or 443 directly),"
        warn "since nginx is no longer routing traffic to it on port 443."
    else
        err "Failed to apply. Configuration on disk was not changed."
    fi
    pause
}

# ---------------------------------------------------------------------------
# Main menu
# ---------------------------------------------------------------------------
AMBER='\033[38;5;214m'
DARK='\033[1;30m'
RESET='\033[0m'
BOLD='\033[1m'

print_banner() {
    echo -e "${AMBER}${BOLD}"
    cat <<'BANNER'
╔══════════════════════════════════════════════════╗
║         PasarGuard SNI Router & Fallback         ║
║                   Manager v1.0                   ║
╠══════════════════════════════════════════════════╣
║ By     : Meysam                                  ║
║ GitHub : github.com/logi443/nginx                ║
╚══════════════════════════════════════════════════╝
BANNER
    echo -e "${RESET}"
}

main_menu() {
    while true; do
        clear
        print_banner
        if is_installed; then
            echo -e "  Status: ${AMBER}INSTALLED${RESET}"
        else
            echo -e "  Status: ${DARK}NOT INSTALLED${RESET}"
        fi
        echo "------------------------------------------------"
        echo " 1) Install"
        echo " 2) Edit configuration"
        echo " 3) Remove"
        echo " 4) Service status"
        echo " 5) Switch to PasarGuard-only mode (drop legacy routing)"
        echo " 0) Exit"
        echo "================================================"
        read -rp "Select an option: " choice

        case "$choice" in
            1) do_install ;;
            2) edit_menu ;;
            3) do_remove ;;
            4) do_status ;;
            5) do_pasarguard_only ;;
            0) echo "Bye."; exit 0 ;;
            *) err "Invalid option."; pause ;;
        esac
    done
}

main_menu
