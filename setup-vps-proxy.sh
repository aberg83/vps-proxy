#!/usr/bin/env bash
#
# setup-vps-proxy.sh
#
# Native (no Docker, no custom-built binaries) hardened, re-runnable reverse-proxy VPS:
#   - unattended-upgrades           (official Ubuntu repo) — auto-applies security patches
#   - a swap file                   (created only if none exists)
#   - Hostname, timezone, and a limited sudo user (general VPS-hardening
#     server-hardening guide), with root's password locked once confirmed
#     working alternative access exists
#   - Tailscale (+ Tailscale SSH)   (official apt repo)
#   - ufw                           (official Ubuntu repo) — public: 80/443 only,
#                                    SSH restricted to the tailscale0 interface only
#   - nginx + libnginx-mod-http-geoip2 + geoipupdate + certbot (official Ubuntu repos)
#     with a bounded 50MB body-size cap and correct websocket handling applied
#     to every proxied site, plus optional streaming-specific tuning (disabled
#     buffering, 1-hour timeouts) for any site tagged ":streaming" in the private sites registry
#   - basic nginx hardening: server_tokens off, security headers, per-IP rate limiting
#   - CrowdSec + firewall bouncer   (CrowdSec's official apt repo)
#   - monit                         (official Ubuntu repo)
#   - healthchecks.io heartbeat     (small local script + systemd timer)
#
# RE-RUNNABLE: proxied services live in a private registry outside Git
# (default: /etc/vps-proxy/sites.list). On every run the script validates the
# complete registry before making changes, re-provisions listed sites, and
# removes only sites recorded as previously managed by this project.
#
# Tested target: Ubuntu 22.04 / 24.04. Run as root (or via sudo).
#
# !!! IMPORTANT SAFETY NOTE ON SSH !!!
# This script locks public SSH (port 22) out entirely and restricts it to the
# Tailscale interface only. Before it enables ufw, it will PAUSE and require you
# to confirm — in a SEPARATE terminal — that you can already reach this VPS over
# Tailscale. Skipping that check risks locking yourself out with no fallback.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: run this script as root (for example: sudo ./setup-vps-proxy.sh)."
    exit 1
fi

VALIDATION_LIB="${SCRIPT_DIR}/lib/validation.sh"
if [[ ! -r "$VALIDATION_LIB" ]]; then
    echo "ERROR: missing validation library: ${VALIDATION_LIB}"
    exit 1
fi
# shellcheck source=lib/validation.sh
source "$VALIDATION_LIB"

### ───────────────────── CONFIG — lives OUTSIDE this file ───────────────────── ###
CONFIG_FILE="${SCRIPT_DIR}/vps-proxy.conf"
if [[ ! -f "$CONFIG_FILE" || -L "$CONFIG_FILE" ]]; then
    echo "ERROR: missing regular configuration file: ${CONFIG_FILE}"
    echo "Copy vps-proxy.conf.example to vps-proxy.conf and fill in your values first."
    exit 1
fi

# vps-proxy.conf is executable shell syntax and is sourced as root. Only root
# may own or modify it; never copy an untrusted configuration into this path.
chown root:root "$CONFIG_FILE"
chmod 600 "$CONFIG_FILE"
# shellcheck source=/dev/null
source "$CONFIG_FILE"

SITES_REGISTRY="${SITES_REGISTRY_FILE:-/etc/vps-proxy/sites.list}"
if [[ "$SITES_REGISTRY" != /* ]]; then
    echo "ERROR: SITES_REGISTRY_FILE must be an absolute path."
    exit 1
fi
if [[ ! -f "$SITES_REGISTRY" || -L "$SITES_REGISTRY" ]]; then
    echo "ERROR: missing private sites registry: ${SITES_REGISTRY}"
    echo "Create it from sites.list.example before running this script."
    echo "Existing installations must migrate the old tracked file BEFORE pulling"
    echo "this version; see README.md's migration section."
    exit 1
fi
chown root:root "$SITES_REGISTRY"
chmod 600 "$SITES_REGISTRY"

validate_runtime_config
validate_sites_file "$SITES_REGISTRY"

mapfile -t ALL_SITES < <(sites_records "$SITES_REGISTRY")
declare -A SEEN=()
for entry in "${ALL_SITES[@]}"; do
    IFS=':' read -r domain port tuning <<< "$entry"
    SEEN["$domain"]=1
done

if [[ -n "${HEALTHCHECK_DOMAIN:-}" && -z "${SEEN[${HEALTHCHECK_DOMAIN}]:-}" ]]; then
    echo "ERROR: HEALTHCHECK_DOMAIN must name a domain in ${SITES_REGISTRY}."
    exit 1
fi
if [[ -z "${MAXMIND_ACCOUNT_ID:-}" && ! -s /usr/share/GeoIP/GeoLite2-Country.mmdb ]]; then
    echo "ERROR: MaxMind credentials are required on the first run so the GeoIP"
    echo "database exists before nginx is configured."
    exit 1
fi

### ───────────────────────────────────────────────────────────────────────── ###

# Wraps a noisy/slow command with a spinner and a single done/FAILED line
# instead of raw output flooding the terminal. Two things are deliberately
# NOT hidden: a real failure always dumps the full captured output (this is
# how several real bugs got caught and fixed during this script's own
# development — a bare "done" would have hidden every one of them), and any
# line containing "warning" or "error" is surfaced even when the command
# still exits 0 (apt in particular sometimes warns about a real problem
# while technically succeeding). Set VERBOSE=1 when invoking this script to
# bypass all of this and see full, unfiltered output for every step, same
# as before this existed. Also falls back automatically if stdout isn't a
# real terminal (e.g. output redirected to a file), since the spinner's
# carriage returns only make sense on an actual terminal.
run_step() {
    local description="$1"
    shift

    if [[ "${VERBOSE:-0}" == "1" || ! -t 1 ]]; then
        echo "==> ${description}"
        "$@"
        return $?
    fi

    local logfile
    logfile=$(mktemp)
    printf "==> %s... " "$description"

    "$@" >"$logfile" 2>&1 &
    local pid=$!

    local spin='-\|/'
    local i=0
    while kill -0 "$pid" 2>/dev/null; do
        i=$(( (i + 1) % 4 ))
        printf "\r==> %s... %s" "$description" "${spin:$i:1}"
        sleep 0.15
    done

    local status=0
    wait "$pid" || status=$?

    if [[ $status -eq 0 ]]; then
        if grep -qiE "warning|error" "$logfile"; then
            printf "\r==> %s... done (warnings — see below)   \n" "$description"
            grep -iE "warning|error" "$logfile"
        else
            printf "\r==> %s... done                          \n" "$description"
        fi
    else
        printf "\r==> %s... FAILED                          \n" "$description"
        echo "----- output -----"
        cat "$logfile"
        echo "-------------------"
    fi

    rm -f "$logfile"
    return $status
}

echo "==> Enabling universe repo"
add-apt-repository -y universe

run_step "Updating package lists" apt-get update -y
run_step "Upgrading installed packages" apt-get upgrade -y
run_step "Installing base packages" apt-get install -y curl gnupg2 ca-certificates lsb-release apt-transport-https git

### ---------------------------------------------------------------------------
### 0a. Unattended security upgrades
### ---------------------------------------------------------------------------
run_step "Installing unattended-upgrades (auto-applies security patches)" apt-get install -y unattended-upgrades apt-listchanges
echo 'APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";' > /etc/apt/apt.conf.d/20auto-upgrades
# Auto-reboot is deliberately left OFF — this box runs family-facing services;
# an unattended reboot mid-stream is worse than a delayed manual one. Patches
# still apply automatically; only a kernel-requiring-reboot case needs your input.
systemctl enable --now unattended-upgrades

### ---------------------------------------------------------------------------
### 0b. Swap file (only if none exists)
### ---------------------------------------------------------------------------
if swapon --show | grep -q .; then
    echo "==> Swap already present, skipping"
else
    echo "==> Creating a ${SWAP_SIZE_MB}MB swap file"
    fallocate -l "${SWAP_SIZE_MB}M" /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    if ! grep -q '/swapfile' /etc/fstab; then
        echo '/swapfile none swap sw 0 0' >> /etc/fstab
    fi
fi

### ---------------------------------------------------------------------------
### 0c. Hostname, timezone, and a limited sudo user (general VPS-hardening
### best practices)
### ---------------------------------------------------------------------------
if [[ -n "${VPS_HOSTNAME:-}" ]]; then
    CURRENT_HOSTNAME=$(hostnamectl --static)
    if [[ "$CURRENT_HOSTNAME" != "$VPS_HOSTNAME" ]]; then
        echo "==> Setting hostname to ${VPS_HOSTNAME} (was ${CURRENT_HOSTNAME})"
        hostnamectl set-hostname "$VPS_HOSTNAME"
        if grep -q "^127.0.1.1" /etc/hosts; then
            sed -i "s/^127.0.1.1.*/127.0.1.1\t${VPS_HOSTNAME}/" /etc/hosts
        else
            echo -e "127.0.1.1\t${VPS_HOSTNAME}" >> /etc/hosts
        fi
    else
        echo "==> Hostname already set to ${VPS_HOSTNAME}"
    fi
fi

if [[ -n "${VPS_TIMEZONE:-}" ]]; then
    echo "==> Setting timezone to ${VPS_TIMEZONE}"
    timedatectl set-timezone "$VPS_TIMEZONE"
fi

if [[ -n "${NEW_SUDO_USERNAME:-}" ]]; then
    echo "==> Setting up limited sudo user: ${NEW_SUDO_USERNAME}"

    ALREADY_CONFIGURED=false
    if id "$NEW_SUDO_USERNAME" &>/dev/null && id -nG "$NEW_SUDO_USERNAME" | grep -qw sudo; then
        ALREADY_CONFIGURED=true
        echo "    User already exists and is in the sudo group — nothing to do"
    fi

    if [[ "$ALREADY_CONFIGURED" == "false" ]]; then
        if id "$NEW_SUDO_USERNAME" &>/dev/null; then
            echo "    User already exists, skipping creation"
        else
            adduser --disabled-password --gecos "" "$NEW_SUDO_USERNAME"
            echo "    Created"
        fi
        usermod -aG sudo "$NEW_SUDO_USERNAME"
        echo "    Added to the sudo group"

        # No password is ever stored in vps-proxy.conf — entered here,
        # interactively, once, and only when the user doesn't already have
        # one set. Skipped entirely on a non-interactive run; the account is
        # left key-only until you set one by hand.
        if [[ -t 0 ]]; then
            while true; do
                read -r -s -p "    Set a password for ${NEW_SUDO_USERNAME} (sudo prompts, Lish console, local login): " NEW_SUDO_PW
                echo
                read -r -s -p "    Confirm password: " NEW_SUDO_PW_CONFIRM
                echo
                if [[ -z "$NEW_SUDO_PW" ]]; then
                    echo "    Password cannot be blank. Ctrl+C to skip and set one later with: sudo passwd ${NEW_SUDO_USERNAME}"
                    continue
                fi
                if [[ "$NEW_SUDO_PW" != "$NEW_SUDO_PW_CONFIRM" ]]; then
                    echo "    Passwords didn't match, try again."
                    continue
                fi
                break
            done
            echo "${NEW_SUDO_USERNAME}:${NEW_SUDO_PW}" | chpasswd
            unset NEW_SUDO_PW NEW_SUDO_PW_CONFIRM
            echo "    Password set."
        else
            echo "    Not running interactively — skipping the password prompt."
            echo "    Set one later with: sudo passwd ${NEW_SUDO_USERNAME}"
        fi
    fi

    # Carry over root's existing authorized_keys, if any, so key-based SSH
    # access (e.g. from your bootstrap session) still works for the new user
    # once root access is later locked down.
    if [[ -s /root/.ssh/authorized_keys ]]; then
        user_ssh_dir="/home/${NEW_SUDO_USERNAME}/.ssh"
        user_authorized_keys="${user_ssh_dir}/authorized_keys"
        install -d -m 700 -o "$NEW_SUDO_USERNAME" -g "$NEW_SUDO_USERNAME" "$user_ssh_dir"
        touch "$user_authorized_keys"
        while IFS= read -r public_key; do
            [[ -n "$public_key" ]] || continue
            grep -qxF "$public_key" "$user_authorized_keys" || echo "$public_key" >> "$user_authorized_keys"
        done < /root/.ssh/authorized_keys
        chown "${NEW_SUDO_USERNAME}:${NEW_SUDO_USERNAME}" "$user_authorized_keys"
        chmod 600 "$user_authorized_keys"
        echo "    Merged root's authorized_keys without replacing the user's existing keys"
    fi
fi

### ---------------------------------------------------------------------------
### 1. Tailscale (+ Tailscale SSH)
### ---------------------------------------------------------------------------
if command -v tailscale >/dev/null 2>&1; then
    echo "==> Tailscale already installed"
else
    run_step "Installing Tailscale (official apt repo)" bash -c 'curl -fsSL https://tailscale.com/install.sh | sh'
fi

if tailscale status >/dev/null 2>&1; then
    echo "==> Tailscale already connected, skipping 'tailscale up'"
else
    if [[ -n "${TAILSCALE_AUTHKEY:-}" ]]; then
        echo "==> Bringing up Tailscale with Tailscale SSH enabled"
        tailscale up --ssh --authkey="${TAILSCALE_AUTHKEY:-}" --advertise-tags=tag:vps
        echo "    Enrolled successfully. TAILSCALE_AUTHKEY has done its job — it's not"
        echo "    needed again (future runs skip this step once already connected)."
        echo "    Consider blanking it out in vps-proxy.conf now rather than leaving"
        echo "    a live enrollment key sitting in a file indefinitely, even a"
        echo "    root-only-readable one."
    else
        echo "==> Run this manually to authenticate, with SSH enabled, then re-run this script:"
        echo "      tailscale up --ssh --advertise-tags=tag:vps"
    fi
fi

### ---------------------------------------------------------------------------
### 2. nginx + GeoIP2 module + certbot + hardening
### ---------------------------------------------------------------------------
run_step "Installing nginx, GeoIP2 module, geoipupdate, certbot" apt-get install -y nginx libnginx-mod-http-geoip2 geoipupdate certbot

echo "==> Configuring geoipupdate"
mkdir -p /usr/share/GeoIP
if [[ -n "${MAXMIND_ACCOUNT_ID:-}" && -n "${MAXMIND_LICENSE_KEY:-}" ]]; then
    cat > /etc/GeoIP.conf <<EOF
AccountID ${MAXMIND_ACCOUNT_ID}
LicenseKey ${MAXMIND_LICENSE_KEY}
EditionIDs GeoLite2-Country
DatabaseDirectory /usr/share/GeoIP
EOF
    chmod 600 /etc/GeoIP.conf
    run_step "Downloading GeoIP database" geoipupdate -v
    systemctl enable --now geoipupdate.timer
else
    echo "    Reusing the existing GeoLite2 database; credentials are not stored."
fi

echo "==> Enabling the GeoIP2 nginx module"
# Auto-detect the actual path — Debian/Ubuntu packaging convention varies, and
# hardcoding a guessed path (a real bug this script had) fails silently via a
# broken symlink, which then takes nginx down with a confusing error far away
# from the actual cause. Search rather than assume, and fail loudly if not found.
GEOIP2_MODULE_CONF=$(dpkg -L libnginx-mod-http-geoip2 2>/dev/null | grep -E 'geoip2.*\.conf$' | head -1)
if [[ -z "$GEOIP2_MODULE_CONF" || ! -f "$GEOIP2_MODULE_CONF" ]]; then
    echo "ERROR: could not locate the geoip2 nginx module's .conf file."
    echo "Run 'dpkg -L libnginx-mod-http-geoip2' to find it manually, then:"
    echo "  ln -sf <path> /etc/nginx/modules-enabled/50-nginx-module-geoip2.conf"
    exit 1
fi
# Some Debian/Ubuntu nginx module packages auto-enable themselves via their own
# postinst script. Check whether the module is already loaded from anywhere in
# modules-enabled/ before adding our own symlink — otherwise nginx refuses to
# start with "module is already loaded" from the resulting duplicate.
if grep -Rq "ngx_http_geoip2_module\.so" /etc/nginx/modules-enabled/ 2>/dev/null; then
    echo "    GeoIP2 module is already enabled (package auto-enabled it) — skipping our own symlink."
else
    echo "    Found: ${GEOIP2_MODULE_CONF}"
    ln -sf "$GEOIP2_MODULE_CONF" /etc/nginx/modules-enabled/50-nginx-module-geoip2.conf
fi

echo "==> Writing shared nginx config (GeoIP map, hardening headers, rate limiting, websocket map)"

# ALLOWED_COUNTRY can be a single code ("CA") or a space-separated list
# ("CA US MX") — one map line per allowed country, everything else denied.
ALLOWED_COUNTRY_MAP_LINES=""
for country_code in $ALLOWED_COUNTRY; do
    ALLOWED_COUNTRY_MAP_LINES="${ALLOWED_COUNTRY_MAP_LINES}    ${country_code} yes;
"
done

cat > /etc/nginx/conf.d/00-geoip.conf <<EOF
geoip2 /usr/share/GeoIP/GeoLite2-Country.mmdb {
    \$geoip2_country_code country iso_code;
}

map \$geoip2_country_code \$allowed_country {
    default no;
${ALLOWED_COUNTRY_MAP_LINES}}

# Local HTTPS health probes originate from loopback and therefore have no
# GeoIP country. Permit only literal loopback sources to bypass the country
# gate so the probe reaches the configured backend instead of merely testing
# nginx's 403 response.
map \$remote_addr \$loopback_request {
    default   no;
    127.0.0.1 yes;
    ::1       yes;
}

map "\$allowed_country:\$loopback_request" \$request_allowed {
    default   no;
    "no:yes"  yes;
    "yes:no"  yes;
    "yes:yes" yes;
}

# A dedicated log, separate from nginx's own default access log, with the
# resolved country on every line. A 403 here is unambiguously a geoblock
# denial (nothing else in this config returns 403), and the country is
# already right there instead of needing a separate IP lookup afterward.
log_format geoblock '\$remote_addr - [\$time_local] "\$request" \$status country=\$geoip2_country_code';
access_log /var/log/nginx/geoblock.log geoblock;
EOF

# Ubuntu's nginx package sometimes already sets server_tokens directly in the
# stock nginx.conf — declaring it again in our own conf.d file then causes a
# hard duplicate-directive error. Check first rather than assume, same pattern
# as the geoip2 module fix above.
SERVER_TOKENS_LINE="server_tokens off;"
if grep -q "server_tokens" /etc/nginx/nginx.conf 2>/dev/null; then
    echo "    server_tokens already set in nginx.conf — not duplicating it here"
    SERVER_TOKENS_LINE="# server_tokens already set in nginx.conf, intentionally not repeated here"
fi

cat > /etc/nginx/conf.d/01-hardening.conf <<EOF
${SERVER_TOKENS_LINE}

add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

# Correct websocket Connection-header handling per nginx's own documented
# guidance (a hardcoded "Connection: upgrade" breaks non-websocket requests).
map \$http_upgrade \$connection_upgrade {
    default upgrade;
    ''      close;
}

# Basic per-IP rate limiting as a second layer under CrowdSec — catches a
# sudden flood immediately, including from IPs CrowdSec hasn't classified yet.
limit_req_zone \$binary_remote_addr zone=general_limit:10m rate=60r/s;

# A much stricter zone for Jellyfin's own login endpoint specifically. This is
# friction against automated credential guessing, NOT a substitute for a real
# account lockout policy in Jellyfin itself — at 1r/s an unattended script
# still eventually works through a short PIN's whole keyspace, just slowly.
# A normal login (even a mistyped one, retried) never comes close to this rate.
limit_req_zone \$binary_remote_addr zone=jellyfin_auth_limit:10m rate=1r/s;

# Resolve the backend host's Tailscale hostname via Tailscale's own DNS server, not the
# VPS's system resolver. This sidesteps Linux's notoriously inconsistent
# MagicDNS/systemd-resolved integration entirely — 100.100.100.100 answers
# *.ts.net queries locally inside tailscaled regardless of how (or whether)
# the VPS's /etc/resolv.conf is wired up. valid=30s also means nginx re-checks
# periodically instead of caching the backend's IP forever, so it self-heals if that
# IP ever changes.
resolver 100.100.100.100 valid=30s;
EOF

mkdir -p /var/www/certbot

# Verify nginx can actually load before going any further, now that both of
# our own conf.d files are freshly written — fail fast and clearly here
# rather than limping forward into confusing certbot/provisioning errors far
# downstream of the real problem. (This check must come AFTER we've written
# our own config, not before — testing too early checks stale leftover files
# from a prior run instead of this run's actual output, which is a bug this
# script itself had.)
if ! nginx -t 2>&1; then
    echo "ERROR: nginx config test failed. Fix the error above before re-running"
    echo "this script — nothing downstream will work correctly until"
    echo "'nginx -t' passes cleanly."
    exit 1
fi

# Base proxy settings — safe defaults for ANY reverse-proxied app, not tuned
# for any particular one. Correct websocket Connection-header handling (used
# by plenty of ordinary web apps, not just streaming ones) lives here since
# it's just correct behavior, not an app-specific assumption.
#
# client_max_body_size: a bounded cap, not unlimited. Streaming reads don't
# need large POST bodies, and admin-panel uploads (artwork, subtitles, etc.)
# comfortably fit well under this — unlimited just needlessly lets a client
# shovel arbitrarily large request bodies at the VPS/backend for no real gain.
write_shared_proxy_snippet() {
    cat > /etc/nginx/snippets/proxy-common.conf <<EOF
client_max_body_size 50m;
proxy_http_version 1.1;
proxy_set_header Upgrade \$http_upgrade;
proxy_set_header Connection \$connection_upgrade;
proxy_set_header Host \$host;
proxy_set_header X-Real-IP \$remote_addr;
proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto \$scheme;
EOF
}

# Streaming-specific overrides — disabled buffering and long timeouts, adapted
# from Jellyfin's own reverse-proxy documentation and linuxserver.io's
# reverse-proxy-confs. Only included for sites explicitly marked ":streaming"
# in the private sites registry — NOT applied by default, so a future non-streaming service
# (Sonarr, a dashboard, whatever) doesn't inherit hour-long timeouts it has no
# use for.
write_streaming_proxy_snippet() {
    cat > /etc/nginx/snippets/proxy-streaming.conf <<EOF
proxy_buffering off;
proxy_read_timeout 3600s;
proxy_send_timeout 3600s;
EOF
}
mkdir -p /etc/nginx/snippets
write_shared_proxy_snippet
write_streaming_proxy_snippet

# Phase 1: minimal HTTP-only config — serves ONLY the ACME challenge path.
# Does NOT proxy to the backend at all: there's no reason the application
# needs to be reachable during certificate issuance/renewal, and doing so
# means every re-run briefly exposes the backend with no geoblock in front
# of it (geoblock only applies in the final config below). 404 everything
# else instead — certbot only needs the challenge path to succeed.
write_bootstrap_site() {
    local domain="$1"
    cat > "/etc/nginx/sites-available/${domain}.conf" <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${domain};

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location / {
        return 404;
    }
}
EOF
    ln -sf "/etc/nginx/sites-available/${domain}.conf" "/etc/nginx/sites-enabled/${domain}.conf"
}

# Phase 2: final config — explicit HTTP->HTTPS redirect, geoblock + rate limit
# only on the actual proxied location (never on the ACME challenge path, so
# renewals always keep working).
write_final_site() {
    local domain="$1" port="$2" tuning="${3:-standard}"
    local certdir="/etc/letsencrypt/live/${domain}"
    local streaming_include=""
    [[ "$tuning" == "streaming" ]] && streaming_include="include /etc/nginx/snippets/proxy-streaming.conf;"

    if [[ ! -f "${certdir}/fullchain.pem" ]]; then
        echo "    Skipping final config for ${domain} — no certificate yet."
        return 1
    fi

    cat > "/etc/nginx/sites-available/${domain}.conf" <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${domain};

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name ${domain};

    ssl_certificate ${certdir}/fullchain.pem;
    ssl_certificate_key ${certdir}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers off;

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    # Jellyfin's own login API. Exact-match so this only applies to that one
    # literal path — harmless no-op on any site that doesn't have it (Seerr,
    # anything future). A much stricter rate limit here than the general one,
    # specifically to slow automated credential guessing against short PINs.
    # This is friction, not a substitute for Jellyfin's own account lockout.
    location = /Users/AuthenticateByName {
        if (\$request_allowed = no) {
            return 403;
        }
        limit_req zone=jellyfin_auth_limit burst=5 nodelay;
        include /etc/nginx/snippets/proxy-common.conf;
        ${streaming_include}
        set \$backend "http://${BACKEND_TAILNET_HOST}:${port}";
        proxy_pass \$backend;
    }

    location / {
        if (\$request_allowed = no) {
            return 403;
        }
        limit_req zone=general_limit burst=100 nodelay;
        include /etc/nginx/snippets/proxy-common.conf;
        ${streaming_include}
        set \$backend "http://${BACKEND_TAILNET_HOST}:${port}";
        proxy_pass \$backend;
    }
}
EOF
    ln -sf "/etc/nginx/sites-available/${domain}.conf" "/etc/nginx/sites-enabled/${domain}.conf"
}

# reload if nginx is already running (fast, no dropped connections), or start/
# restart it if it isn't — a bare 'systemctl reload' fails outright if nginx
# was never successfully started yet, which a first run or a recovery from an
# earlier failed config test both hit.
nginx_apply() {
    if systemctl is-active --quiet nginx; then
        systemctl reload nginx
    else
        systemctl restart nginx
    fi
}

provision_site() {
    local domain="$1" port="$2" tuning="${3:-standard}"
    local current_conf="/etc/nginx/sites-available/${domain}.conf"
    local backup_conf
    local had_previous=false
    backup_conf=$(mktemp)

    if [[ -f "$current_conf" ]]; then
        cp -a "$current_conf" "$backup_conf"
        had_previous=true
    fi

    rollback_site() {
        echo "    Rolling back nginx configuration for ${domain}"
        if [[ "$had_previous" == "true" ]]; then
            cp -a "$backup_conf" "$current_conf"
            ln -sf "$current_conf" "/etc/nginx/sites-enabled/${domain}.conf"
        else
            rm -f "$current_conf" "/etc/nginx/sites-enabled/${domain}.conf"
        fi
        if nginx -t >/dev/null 2>&1; then
            nginx_apply || true
        fi
        rm -f "$backup_conf"
    }

    echo "==> Provisioning ${domain} -> ${BACKEND_TAILNET_HOST}:${port} (tuning: ${tuning})"
    write_bootstrap_site "$domain"
    if ! nginx -t; then
        rollback_site
        return 1
    fi
    nginx_apply

    if ! run_step "Requesting certificate for ${domain}" certbot certonly --webroot -w /var/www/certbot \
        -d "$domain" \
        --agree-tos -m "$CERTBOT_EMAIL" --non-interactive --keep-until-expiring; then
        echo "    ERROR: certbot failed for ${domain}; restoring its previous configuration."
        rollback_site
        return 1
    fi

    if ! write_final_site "$domain" "$port" "$tuning" || ! nginx -t; then
        rollback_site
        return 1
    fi
    nginx_apply
    rm -f "$backup_conf"
}

rm -f /etc/nginx/sites-enabled/default

echo "==> (Re-)provisioning all known sites"
PROVISION_FAILED=false
for entry in "${ALL_SITES[@]}"; do
    IFS=':' read -r domain port tuning <<< "$entry"
    tuning="${tuning:-standard}"
    if ! provision_site "$domain" "$port" "$tuning"; then
        PROVISION_FAILED=true
    fi
done
if [[ "$PROVISION_FAILED" == "true" ]]; then
    echo "ERROR: one or more sites failed; no sites or certificates were pruned."
    exit 1
fi

echo "==> Pruning previously managed sites no longer in the private registry"
MANAGED_STATE_DIR="/var/lib/vps-proxy"
MANAGED_SITES_FILE="${MANAGED_STATE_DIR}/managed-sites"
install -d -m 700 -o root -g root "$MANAGED_STATE_DIR"
OLD_MANAGED=()
if [[ -f "$MANAGED_SITES_FILE" ]]; then
    mapfile -t OLD_MANAGED < "$MANAGED_SITES_FILE"
fi

PRUNED_ANY=false
for site_domain in "${OLD_MANAGED[@]}"; do
    [[ -n "$site_domain" ]] || continue
    if [[ -z "${SEEN[$site_domain]:-}" ]]; then
        echo "    Removing previously managed site ${site_domain}"
        rm -f "/etc/nginx/sites-enabled/${site_domain}.conf"
        rm -f "/etc/nginx/sites-available/${site_domain}.conf"
        certbot delete --cert-name "$site_domain" --non-interactive 2>/dev/null \
            || echo "    (no certificate found for ${site_domain}, or already removed)"
        PRUNED_ANY=true
    fi
done
if [[ "$PRUNED_ANY" == "true" ]]; then
    nginx -t && nginx_apply
fi

managed_tmp=$(mktemp)
for site_domain in "${!SEEN[@]}"; do
    echo "$site_domain"
done | sort > "$managed_tmp"
install -m 600 -o root -g root "$managed_tmp" "$MANAGED_SITES_FILE"
rm -f "$managed_tmp"

echo "==> Installing a certbot deploy hook so renewals actually reach nginx"
# Certbot's timer renews the certificate FILES on disk, but nginx keeps using
# whatever it already loaded into memory until it reloads — nothing does that
# automatically otherwise, so a renewal could succeed on disk while nginx
# silently keeps serving the old (soon to expire) certificate indefinitely.
mkdir -p /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh <<'EOF'
#!/bin/sh
nginx -t && systemctl reload nginx
EOF
chmod +x /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh

echo "==> Ensuring certbot's renewal timer is active"
systemctl enable --now certbot.timer

### ---------------------------------------------------------------------------
### 3. CrowdSec + firewall bouncer
### ---------------------------------------------------------------------------
if command -v cscli >/dev/null 2>&1; then
    echo "==> CrowdSec already installed"
else
    run_step "Installing CrowdSec (official apt repo)" bash -c 'curl -fsSL https://install.crowdsec.net | sh'
    run_step "Installing crowdsec package" apt-get install -y crowdsec
fi
run_step "Installing CrowdSec firewall bouncer" apt-get install -y crowdsec-firewall-bouncer-iptables

cat > /etc/crowdsec/acquis.d/nginx.yaml <<EOF
filenames:
  - /var/log/nginx/access.log
  - /var/log/nginx/error.log
labels:
  type: nginx
EOF

run_step "Installing CrowdSec's nginx collection" cscli collections install crowdsecurity/nginx || true

systemctl enable crowdsec crowdsec-firewall-bouncer
systemctl restart crowdsec crowdsec-firewall-bouncer

### ---------------------------------------------------------------------------
### 3b. Weekly full upgrade — covers Tailscale/CrowdSec's third-party repos too
### ---------------------------------------------------------------------------
# unattended-upgrades (section 0a) only covers Ubuntu's own official repos on
# their security pocket. Tailscale, CrowdSec, and the CrowdSec firewall bouncer
# ship from their vendors' own separate apt repos and are NOT covered by that —
# left as-is, they'd never auto-upgrade. This closes that gap with a weekly full
# 'apt upgrade' (every configured repo, not just Ubuntu's security pocket) plus
# a CrowdSec hub content refresh (parsers/scenarios — separate from the package
# itself, and otherwise never updated automatically at all).
#
# Runs via a systemd timer with no TTY attached — without explicitly forcing
# a non-interactive frontend and a deterministic conffile policy, a future
# package upgrade that ships a changed config file (nginx.conf, sshd_config,
# etc.) could hang this unattended run indefinitely waiting for input that
# will never come, silently blocking every upgrade after it. --force-confold
# also means any config file a package owns is left as-is on conflict, never
# silently overwritten — this only affects package-shipped conffiles, not our
# own files in conf.d/sites-available/snippets, which packages don't own and
# can't touch regardless.
echo "==> Setting up weekly full upgrade (all repos) + CrowdSec hub refresh"
cat > /usr/local/bin/weekly-full-upgrade.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get -y \
    -o Dpkg::Options::="--force-confdef" \
    -o Dpkg::Options::="--force-confold" \
    upgrade
apt-get autoremove -y
if command -v cscli >/dev/null 2>&1; then
    cscli hub upgrade || true
fi
EOF
chmod +x /usr/local/bin/weekly-full-upgrade.sh

cat > /etc/systemd/system/weekly-full-upgrade.service <<'EOF'
[Unit]
Description=Weekly full apt upgrade (all repos) + CrowdSec hub refresh

[Service]
Type=oneshot
ExecStart=/usr/local/bin/weekly-full-upgrade.sh
EOF

cat > /etc/systemd/system/weekly-full-upgrade.timer <<'EOF'
[Unit]
Description=Run weekly-full-upgrade weekly

[Timer]
OnCalendar=weekly
RandomizedDelaySec=6h
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now weekly-full-upgrade.timer

### ---------------------------------------------------------------------------
### 4. ufw — public 80/443 only, SSH restricted to the Tailscale interface
### ---------------------------------------------------------------------------
run_step "Installing ufw" apt-get install -y ufw

UFW_WAS_ACTIVE=false
ufw status | grep -q "Status: active" && UFW_WAS_ACTIVE=true

# Reconcile the required rules even when a provider image shipped with UFW
# already active. "UFW active" alone says nothing about whether the policy is
# actually the one this project promises.
ufw default deny incoming
ufw default allow outgoing
ufw allow 80/tcp comment 'vps-proxy HTTP'
ufw allow 443/tcp comment 'vps-proxy HTTPS'
ufw allow in on tailscale0 to any port 22 proto tcp comment 'vps-proxy Tailscale SSH'
ufw allow 41641/udp comment 'vps-proxy Tailscale direct'

# Never silently remove administrator rules. Abort if a conventional public
# SSH rule is present and print exact manual remediation instead.
if ufw show added | grep -Eq '^ufw (allow|limit)( in)? (22(/tcp)?|OpenSSH)([[:space:]]|$)' ||
   ufw status | grep -Eq '^(22(/tcp)?|OpenSSH)[[:space:]]+(ALLOW|LIMIT)[[:space:]]+IN[[:space:]]+Anywhere'; then
    echo "ERROR: UFW contains a public SSH rule. This script will not remove it automatically."
    echo "Review 'ufw status numbered', delete only the public port-22/OpenSSH rule,"
    echo "confirm Tailscale SSH works, then re-run."
    exit 1
fi

ROOT_LOCK_NEEDED=false
if [[ "${LOCK_ROOT_PASSWORD:-false}" == "true" ]] &&
   ! passwd -S root 2>/dev/null | awk '{print $2}' | grep -q '^L'; then
    ROOT_LOCK_NEEDED=true
    if [[ -z "${NEW_SUDO_USERNAME:-}" ]] ||
       ! id "$NEW_SUDO_USERNAME" >/dev/null 2>&1 ||
       ! id -nG "$NEW_SUDO_USERNAME" | grep -qw sudo; then
        echo "ERROR: refusing to lock root: NEW_SUDO_USERNAME is not a verified sudo user."
        exit 1
    fi
fi

NEEDS_SAFETY_CONFIRMATION=false
[[ "$UFW_WAS_ACTIVE" == "false" || "$ROOT_LOCK_NEEDED" == "true" ]] && NEEDS_SAFETY_CONFIRMATION=true

if [[ "$NEEDS_SAFETY_CONFIRMATION" == "true" ]]; then
    echo ""
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo " SAFETY CHECK before enabling the firewall and/or locking root"
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    [[ "$UFW_WAS_ACTIVE" == "false" ]] && echo " - Will enable UFW with public 80/443 and SSH only on tailscale0"
    [[ "$ROOT_LOCK_NEEDED" == "true" ]] && echo " - Will lock root's password"
    echo " In a SEPARATE terminal verify Tailscale SSH, then run 'sudo whoami'."
    echo ""

    if ! command -v tailscale >/dev/null 2>&1 || ! tailscale status >/dev/null 2>&1; then
        echo "ERROR: Tailscale is not connected. Rules were staged, but UFW was not enabled"
        echo "and root was not locked."
        PROCEED=1
    elif [[ -t 0 ]]; then
        read -r -p "Did SSH succeed and did sudo whoami print root? Type 'yes': " CONFIRM
        [[ "$CONFIRM" == "yes" ]] && PROCEED=0 || PROCEED=1
    else
        echo "Not running interactively; refusing the lockout-sensitive changes."
        PROCEED=1
    fi

    if [[ "${PROCEED:-1}" -eq 0 ]]; then
        [[ "$UFW_WAS_ACTIVE" == "false" ]] && ufw --force enable
        if [[ "$ROOT_LOCK_NEEDED" == "true" ]]; then
            passwd -l root
            echo "==> root password locked; administration is via ${NEW_SUDO_USERNAME} + sudo."
        fi
    else
        echo "==> Lockout-sensitive changes skipped. Re-run from an interactive terminal."
    fi
fi
ufw status verbose

### ---------------------------------------------------------------------------
### 5. monit
### ---------------------------------------------------------------------------
run_step "Installing monit" apt-get install -y monit

# Enable monit's control interface, localhost-only. Without this, even local
# CLI commands like `monit status` can't reach the running daemon at all —
# the CLI talks to monit over this same interface, it's not a web-UI-only
# thing. Binding to localhost + allowing only localhost means nothing new is
# exposed externally; ufw never needs to open anything for this.
cat > /etc/monit/conf.d/00-httpd << 'EOF'
set httpd port 2812 and
    use address localhost
    allow localhost
EOF

cat > /etc/monit/conf.d/vps-stack << EOF
check process nginx with pidfile /run/nginx.pid
    start program = "/usr/bin/systemctl start nginx"
    stop program = "/usr/bin/systemctl stop nginx"
    # TLS-handshake-only check, deliberately NOT a full HTTP protocol test:
    # an HTTP-level check here hits localhost with no matching server_name
    # and no real GeoIP country for the loopback source, which our OWN
    # geoblock correctly 403s — monit would then misread that as nginx being
    # down and restart a perfectly healthy process. A TCP+TLS handshake still
    # proves nginx is alive, listening, and serving TLS correctly, without
    # tripping over application-layer logic that was never meant to gate this.
    if failed port 443 type tcpssl then restart

# CrowdSec, its firewall bouncer, and tailscaled don't reliably write PID
# files at predictable paths under systemd's own process tracking (unlike
# nginx, confirmed above) — matching against the running process itself is
# more robust than guessing a pidfile path, same lesson as the nginx GeoIP2
# module path issue earlier: verify, don't assume.
check process crowdsec matching "/usr/bin/crowdsec -c"
    start program = "/usr/bin/systemctl start crowdsec"
    stop program = "/usr/bin/systemctl stop crowdsec"
    if 5 restarts within 5 cycles then timeout

check process crowdsec-firewall-bouncer matching "crowdsec-firewall-bouncer"
    start program = "/usr/bin/systemctl start crowdsec-firewall-bouncer"
    stop program = "/usr/bin/systemctl stop crowdsec-firewall-bouncer"
    if 5 restarts within 5 cycles then timeout

check process tailscaled matching "tailscaled"
    start program = "/usr/bin/systemctl start tailscaled"
    stop program = "/usr/bin/systemctl stop tailscaled"
    if 5 restarts within 5 cycles then timeout
EOF

systemctl enable monit
systemctl restart monit

### ---------------------------------------------------------------------------
### 6. healthchecks.io — external dead-man's-switch
### ---------------------------------------------------------------------------
if [[ -n "${HEALTHCHECKS_PING_URL:-}" ]]; then
    HEALTHCHECK_DOMAIN="${HEALTHCHECK_DOMAIN:-${ALL_SITES[0]%%:*}}"
    HEALTHCHECK_PATH="${HEALTHCHECK_PATH:-/}"
    HEALTHCHECK_EXPECTED_STATUS="${HEALTHCHECK_EXPECTED_STATUS:-200,301,302}"

    install -d -m 700 -o root -g root /etc/vps-proxy
    {
        printf 'PING_URL=%q\n' "$HEALTHCHECKS_PING_URL"
        printf 'CHECK_DOMAIN=%q\n' "$HEALTHCHECK_DOMAIN"
        printf 'CHECK_PATH=%q\n' "$HEALTHCHECK_PATH"
        printf 'EXPECTED_STATUS=%q\n' "$HEALTHCHECK_EXPECTED_STATUS"
    } > /etc/vps-proxy/healthcheck.conf
    chmod 600 /etc/vps-proxy/healthcheck.conf

    cat > /usr/local/bin/healthcheck-ping.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=/dev/null
source /etc/vps-proxy/healthcheck.conf

fail_check() {
    curl -fsS -m 10 --retry 2 "${PING_URL}/fail" --data-raw "$1" >/dev/null 2>&1 || true
    exit 1
}

for svc in nginx crowdsec crowdsec-firewall-bouncer tailscaled; do
    systemctl is-active --quiet "$svc" || fail_check "service down: $svc"
done
nginx -t >/dev/null 2>&1 || fail_check "nginx configuration test failed"

status=$(curl -sS -m 15 -o /dev/null -w '%{http_code}' \
    --resolve "${CHECK_DOMAIN}:443:127.0.0.1" \
    "https://${CHECK_DOMAIN}${CHECK_PATH}") ||
    fail_check "HTTPS request failed for ${CHECK_DOMAIN}${CHECK_PATH}"

case ",${EXPECTED_STATUS}," in
    *",${status},"*) ;;
    *) fail_check "unexpected HTTP status ${status} for ${CHECK_DOMAIN}${CHECK_PATH}" ;;
esac

curl -fsS -m 10 --retry 3 "$PING_URL" >/dev/null
EOF
    chmod 700 /usr/local/bin/healthcheck-ping.sh

    cat > /etc/systemd/system/healthcheck-ping.service <<'EOF'
[Unit]
Description=Ping healthchecks.io if the reverse-proxy stack is healthy
After=network-online.target nginx.service tailscaled.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/healthcheck-ping.sh
EOF

    cat > /etc/systemd/system/healthcheck-ping.timer <<'EOF'
[Unit]
Description=Run healthcheck-ping every 5 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
Persistent=true

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable --now healthcheck-ping.timer
else
    echo "==> SKIPPED healthchecks.io wiring — set HEALTHCHECKS_PING_URL to enable it."
fi

echo "==> Manual git workflow: on this VPS, run 'git -C ${SCRIPT_DIR} pull' then"
echo "    re-run this script whenever you've pushed changes."

echo ""
echo "=========================================================================="
echo " Setup complete. Currently proxied sites:"
sed 's/^/   - /' "$SITES_REGISTRY" 2>/dev/null
echo ""
echo " To add or remove a service later: edit ${SITES_REGISTRY} on the VPS and re-run."
echo ""
echo " Remaining manual steps:"
echo "  1. If Tailscale wasn't brought up yet: tailscale up --ssh --advertise-tags=tag:vps"
echo "  2. In the Tailscale admin console, scope tag:vps's ACL to only the ports"
echo "     listed above on ${BACKEND_TAILNET_HOST}."
echo "  3. If MaxMind credentials weren't set, edit /etc/GeoIP.conf, then run:"
echo "       geoipupdate -v && systemctl enable --now geoipupdate.timer"
echo "  4. Point DNS at this VPS for any site where certbot failed, then re-run."
echo "  5. Confirm ufw: ufw status verbose"
echo "  6. Confirm root's password is locked (if LOCK_ROOT_PASSWORD=true): passwd -S root"
echo "  7. Check CrowdSec: cscli decisions list"
echo "  8. Check monit: monit status"
echo "  9. If HEALTHCHECKS_PING_URL was set, add a matching check in your"
echo "     healthchecks.io dashboard (5-minute period, ~10-minute grace)."
echo "=========================================================================="
