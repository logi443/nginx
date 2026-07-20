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
PUBLIC_PORT=""

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
        PUBLIC_PORT="$(grep -oP '^\s*listen \K[0-9]+' "$STREAM_CONF" | head -1)"
        [[ -z "$PUBLIC_PORT" ]] && PUBLIC_PORT="443"
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
PUBLIC_PORT="${PUBLIC_PORT}"
EOF
}

port_busy() {
    local p="$1"
    if command -v ss >/dev/null 2>&1; then
        ss -ltnp 2>/dev/null | awk -v p=":$p\$" '$4 ~ p' | grep -q .
    else
        netstat -ltnp 2>/dev/null | awk -v p=":$p\$" '$4 ~ p' | grep -q .
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

    # Disable nginx's default port-80 site so nginx never tries to bind :80
    # (avoids clashing with any other service already on port 80).
    if [[ -e /etc/nginx/sites-enabled/default ]]; then
        log "Disabling nginx default site (port 80) to avoid conflicts..."
        rm -f /etc/nginx/sites-enabled/default
    fi

    # Always remove any explicit load_module line for the stream module first,
    # regardless of leading whitespace, so we start from a clean slate.
    sed -i '/load_module .*ngx_stream_module\.so;/d' "$NGINX_MAIN"

    # Determine whether the stream module is ALREADY auto-loaded. On Debian/Ubuntu,
    # nginx-full ships /etc/nginx/modules-enabled/*.conf files (often symlinks) that
    # each contain a load_module line. `cat` follows symlinks, so concatenating them
    # and grepping is reliable where `grep -r` on the directory can miss symlinks.
    local auto_loaded="false"
    if cat /etc/nginx/modules-enabled/*.conf 2>/dev/null | grep -q 'ngx_stream_module\.so'; then
        auto_loaded="true"
    elif nginx -V 2>&1 | grep -q -- '--with-stream'; then
        auto_loaded="true"
    fi

    if [[ "$auto_loaded" == "true" ]]; then
        log "Stream module already provided by nginx — no explicit load_module needed."
    else
        if [[ -f /usr/lib/nginx/modules/ngx_stream_module.so || -f /usr/share/nginx/modules/ngx_stream_module.so ]]; then
            log "Loading stream module explicitly..."
            sed -i '1i load_module modules/ngx_stream_module.so;' "$NGINX_MAIN"
        else
            err "Stream module not found. Install it (e.g. apt-get install libnginx-mod-stream) and retry."
            return 1
        fi
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

    # Raise connection limits for high-traffic routing (idempotent).
    if ! grep -q "worker_rlimit_nofile" "$NGINX_MAIN" 2>/dev/null; then
        log "Raising worker_rlimit_nofile for high traffic..."
        sed -i '/^worker_processes/a worker_rlimit_nofile 65535;' "$NGINX_MAIN"
    fi
    if grep -qE "worker_connections\s+[0-9]+;" "$NGINX_MAIN" 2>/dev/null; then
        sed -i -E 's/worker_connections\s+[0-9]+;/worker_connections 16384;/' "$NGINX_MAIN"
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
    listen ${PUBLIC_PORT} reuseport;
    listen [::]:${PUBLIC_PORT} reuseport;
    proxy_pass \$sni_backend_pool;
    ssl_preread on;

    # High-traffic tuning
    proxy_timeout 1h;                 # long-lived tunnels shouldn't be cut at 5m
    proxy_connect_timeout 10s;
    proxy_buffer_size 32k;            # larger buffer for high-throughput streams
    proxy_socket_keepalive on;
    tcp_nodelay on;
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
    echo "How should traffic reach PasarGuard?"
    echo " 1) SNI routing  — nginx listens on the public port and splits traffic"
    echo "                   by SNI between PasarGuard and a legacy panel (e.g. 3x-ui)."
    echo "                   Use this when the public port is shared with another panel."
    echo " 2) Direct       — PasarGuard owns the public port directly, no SNI routing."
    echo "                   Only the local fallback backend is set up."
    echo " 0) Cancel"
    read -rp "Select mode: " mode

    case "$mode" in
        1) ROUTING_ENABLED="true" ;;
        2) ROUTING_ENABLED="false" ;;
        0) warn "Cancelled."; return ;;
        *) err "Invalid option."; return ;;
    esac

    echo
    read -rp "Fake SNI domain (e.g. soft98.ir): " FAKE_SNI
    [[ -z "$FAKE_SNI" ]] && { err "SNI domain cannot be empty."; return; }

    read -rp "PasarGuard internal local port (e.g. 8444): " PG_PORT
    [[ -z "$PG_PORT" ]] && { err "PasarGuard port cannot be empty."; return; }

    if [[ "$ROUTING_ENABLED" == "true" ]]; then
        read -rp "Public port nginx should listen on (default: 443): " PUBLIC_PORT
        PUBLIC_PORT="${PUBLIC_PORT:-443}"

        if port_busy "$PUBLIC_PORT"; then
            warn "Port ${PUBLIC_PORT} is currently in use."
            warn "If that's your legacy panel still on ${PUBLIC_PORT}, move it to an"
            warn "internal port (e.g. 127.0.0.1:8443) in its own panel BEFORE nginx can bind."
            read -rp "Continue anyway? [y/N]: " c
            [[ "$c" =~ ^[Yy]$ ]] || { warn "Cancelled."; return; }
        fi

        read -rp "Legacy backend internal port (e.g. old 3x-ui, e.g. 8443): " LEGACY_PORT
        [[ -z "$LEGACY_PORT" ]] && { err "Legacy port cannot be empty."; return; }
        warn "Set PasarGuard's inbound listen to 127.0.0.1:${PG_PORT} in its panel."
        warn "Set the legacy panel's inbound listen to 127.0.0.1:${LEGACY_PORT}."
    else
        PUBLIC_PORT=""
        LEGACY_PORT=""
        warn "Direct mode: set PasarGuard's inbound to listen directly on the public port"
        warn "(e.g. 0.0.0.0:443) in its panel. nginx will only host the fallback backend."
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
    echo " Mode                 : $([[ "$ROUTING_ENABLED" == "true" ]] && echo "SNI routing" || echo "Direct (PasarGuard owns public port)")"
    echo " Fake SNI domain      : ${FAKE_SNI}"
    echo " PasarGuard local port: 127.0.0.1:${PG_PORT}"
    if [[ "$ROUTING_ENABLED" == "true" ]]; then
        echo " Public port (nginx)  : ${PUBLIC_PORT}"
        echo " Legacy backend port  : 127.0.0.1:${LEGACY_PORT}"
    fi
    echo " Fallback local port  : 127.0.0.1:${FALLBACK_PORT}"
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
        if [[ "$ROUTING_ENABLED" == "true" ]]; then
            echo " 5) Toggle SNI routing      [current: ON]"
            echo " 6) Public port (nginx)     [current: ${PUBLIC_PORT}]"
        else
            echo " 5) Toggle SNI routing      [current: OFF]"
            echo " 6) Public port (nginx)     [routing disabled]"
        fi
        echo " 0) Back to main menu"
        echo
        read -rp "Select an option: " choice

        case "$choice" in
            1)
                read -rp "New fake SNI domain (0 = cancel): " new_val
                if [[ "$new_val" == "0" || -z "$new_val" ]]; then
                    warn "Cancelled — value unchanged."
                    pause
                    continue
                fi
                FAKE_SNI="$new_val"
                ;;
            2)
                read -rp "New PasarGuard local port (0 = cancel): " new_val
                if [[ "$new_val" == "0" || -z "$new_val" ]]; then
                    warn "Cancelled — value unchanged."
                    pause
                    continue
                fi
                PG_PORT="$new_val"
                ;;
            3)
                if [[ "$ROUTING_ENABLED" != "true" ]]; then
                    warn "Routing is disabled — enable it first (option 5)."
                    pause
                    continue
                fi
                read -rp "New legacy backend port (0 = cancel): " new_val
                if [[ "$new_val" == "0" || -z "$new_val" ]]; then
                    warn "Cancelled — value unchanged."
                    pause
                    continue
                fi
                LEGACY_PORT="$new_val"
                ;;
            4)
                read -rp "New fallback local port (0 = cancel): " new_val
                if [[ "$new_val" == "0" || -z "$new_val" ]]; then
                    warn "Cancelled — value unchanged."
                    pause
                    continue
                fi
                FALLBACK_PORT="$new_val"
                ;;
            5)
                if [[ "$ROUTING_ENABLED" == "true" ]]; then
                    ROUTING_ENABLED="false"
                    PUBLIC_PORT=""
                    log "SNI routing disabled. PasarGuard should listen directly on the public port."
                else
                    read -rp "Legacy backend port (0 = cancel): " new_val
                    if [[ "$new_val" == "0" || -z "$new_val" ]]; then
                        warn "Cancelled — routing not enabled."
                        pause
                        continue
                    fi
                    LEGACY_PORT="$new_val"
                    read -rp "Public port nginx should listen on (default: 443): " new_pub
                    PUBLIC_PORT="${new_pub:-443}"
                    ROUTING_ENABLED="true"
                fi
                ;;
            6)
                if [[ "$ROUTING_ENABLED" != "true" ]]; then
                    warn "Routing is disabled — enable it first (option 5)."
                    pause
                    continue
                fi
                read -rp "New public port for nginx (0 = cancel): " new_val
                if [[ "$new_val" == "0" || -z "$new_val" ]]; then
                    warn "Cancelled — value unchanged."
                    pause
                    continue
                fi
                PUBLIC_PORT="$new_val"
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
    if is_installed; then
        load_config
        local pat=""
        for p in "${PUBLIC_PORT:-443}" "$PG_PORT" "$LEGACY_PORT" "$FALLBACK_PORT"; do
            [[ -n "$p" ]] && pat+="${pat:+|}:${p}\\b"
        done
        ss -ltnp 2>/dev/null | grep -E "$pat" || true
    else
        ss -ltnp 2>/dev/null | grep -E ':443|:8080' || true
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
    PUBLIC_PORT=""

    if apply_and_reload; then
        save_config
        log "Switched to PasarGuard-only mode."
        warn "IMPORTANT: go to the PasarGuard panel and change the inbound listen"
        warn "address from 127.0.0.1:${PG_PORT} to the public port directly (e.g. 443),"
        warn "since nginx is no longer routing traffic to it."
    else
        err "Failed to apply. Configuration on disk was not changed."
    fi
    pause
}

# ---------------------------------------------------------------------------
# Main menu
# ---------------------------------------------------------------------------
AMBER='\033[38;5;214m'
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
            echo -e "  Status: \033[1;32mINSTALLED\033[0m"
        else
            echo -e "  Status: \033[1;31mNOT INSTALLED\033[0m"
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
