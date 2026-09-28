#!/usr/bin/env bash
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../lib/validation.sh
# shellcheck disable=SC1091
source "${REPO_ROOT}/lib/validation.sh"

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

expect_valid() {
    printf '%s\n' "$1" > "${tmpdir}/sites.list"
    validate_sites_file "${tmpdir}/sites.list"
}

expect_invalid() {
    printf '%s\n' "$1" > "${tmpdir}/sites.list"
    if validate_sites_file "${tmpdir}/sites.list" >/dev/null 2>&1; then
        echo "expected invalid input to fail: $1" >&2
        exit 1
    fi
}

expect_valid 'media.example.com:8096:streaming'
expect_valid $'# comment\nrequests.example.com:5055'
expect_invalid 'UPPER.example.com:443'
expect_invalid 'media.example.com:0'
expect_invalid 'media.example.com:65536'
expect_invalid 'media.example.com:443:unknown'
expect_invalid $'media.example.com:443\nmedia.example.com:8443'
expect_invalid '../escape:443'
expect_invalid 'media.example.com:18446744073709552059'
expect_invalid ''

validate_host_label 'vps-proxy'
validate_host_label 'vps1'
if validate_host_label '-vps-proxy' || validate_host_label 'VPS-PROXY' ||
   validate_host_label 'vps_proxy'; then
    echo "invalid single-label hostname was accepted" >&2
    exit 1
fi

# validate_runtime_config reads the sourced config's globals, so each case
# runs in a subshell starting from a known-good baseline plus overrides.
# shellcheck disable=SC2034
runtime_config() {
    (
        CONFIG_FILE="${tmpdir}/vps-proxy.conf"
        BACKEND_TAILNET_HOST="backend.example.ts.net"
        ALLOWED_COUNTRY="CA US"
        CERTBOT_EMAIL="admin@example.com"
        unset SWAP_SIZE_MB LOCK_ROOT_PASSWORD NEW_SUDO_USERNAME VPS_HOSTNAME \
            MAXMIND_ACCOUNT_ID MAXMIND_LICENSE_KEY HEALTHCHECK_DOMAIN \
            HEALTHCHECK_PATH HEALTHCHECK_EXPECTED_STATUS HSTS_MAX_AGE \
            HEALTHCHECKS_PING_URL UPGRADE_HEALTHCHECKS_PING_URL
        for assignment in "$@"; do
            if [[ "$assignment" == unset:* ]]; then
                unset "${assignment#unset:}"
            else
                declare "$assignment"
            fi
        done
        validate_runtime_config
    )
}

expect_config_valid() {
    if ! runtime_config "$@" >/dev/null 2>&1; then
        echo "expected valid runtime config to pass: $*" >&2
        exit 1
    fi
}

expect_config_invalid() {
    if runtime_config "$@" >/dev/null 2>&1; then
        echo "expected invalid runtime config to fail: $*" >&2
        exit 1
    fi
}

expect_config_valid
expect_config_valid 'SWAP_SIZE_MB=4096' 'LOCK_ROOT_PASSWORD=false'
expect_config_valid 'LOCK_ROOT_PASSWORD=true' 'NEW_SUDO_USERNAME=admin'
expect_config_valid 'VPS_HOSTNAME=vps-proxy' 'VPS_HOSTNAME=vps.example.com'
expect_config_valid 'MAXMIND_ACCOUNT_ID=123' 'MAXMIND_LICENSE_KEY=abc'
expect_config_valid 'HEALTHCHECK_DOMAIN=media.example.com' 'HEALTHCHECK_PATH=/health' \
    'HEALTHCHECK_EXPECTED_STATUS=200,204'
expect_config_valid 'HSTS_MAX_AGE=0' 'HSTS_MAX_AGE=63072000'
expect_config_valid 'HEALTHCHECKS_PING_URL=https://hc-ping.com/abc' \
    'UPGRADE_HEALTHCHECKS_PING_URL=http://hc.example.ts.net/ping/abc'
expect_config_invalid 'unset:BACKEND_TAILNET_HOST'
expect_config_invalid 'unset:ALLOWED_COUNTRY'
expect_config_invalid 'unset:CERTBOT_EMAIL'
expect_config_invalid 'BACKEND_TAILNET_HOST=Backend.example.ts.net'
expect_config_invalid 'ALLOWED_COUNTRY=ca'
expect_config_invalid 'ALLOWED_COUNTRY=CAN'
expect_config_invalid 'CERTBOT_EMAIL=not-an-email'
expect_config_invalid 'SWAP_SIZE_MB=0'
expect_config_invalid 'SWAP_SIZE_MB=2G'
expect_config_invalid 'LOCK_ROOT_PASSWORD=yes'
expect_config_invalid 'LOCK_ROOT_PASSWORD=true'
expect_config_invalid 'NEW_SUDO_USERNAME=Admin'
expect_config_invalid 'VPS_HOSTNAME=VPS'
expect_config_invalid 'MAXMIND_ACCOUNT_ID=123'
expect_config_invalid 'MAXMIND_LICENSE_KEY=abc'
expect_config_invalid 'HEALTHCHECK_DOMAIN=not_a_domain'
expect_config_invalid 'HEALTHCHECK_PATH=health'
expect_config_invalid 'HEALTHCHECK_PATH=/a b'
expect_config_invalid 'HEALTHCHECK_EXPECTED_STATUS=200;301'
expect_config_invalid 'HEALTHCHECK_EXPECTED_STATUS=600'
expect_config_invalid 'HSTS_MAX_AGE=-1'
expect_config_invalid 'HSTS_MAX_AGE=1y'
expect_config_invalid 'HSTS_MAX_AGE=0100'
expect_config_invalid 'HEALTHCHECKS_PING_URL=hc-ping.com/abc'
expect_config_invalid 'UPGRADE_HEALTHCHECKS_PING_URL=https://hc-ping.com/a b'

# Rules as printed by 'ufw show added'.
for rule in 'ufw allow 22' 'ufw allow 22/tcp' 'ufw allow in 22/tcp' 'ufw limit 22/tcp' \
            'ufw allow OpenSSH' 'ufw allow ssh' "ufw allow 22/tcp comment 'old rule'" \
            'ufw allow to any port 22' 'ufw allow proto tcp from any to any port 22' \
            'ufw allow from 0.0.0.0/0 to any port 22' 'ufw allow from any to any port 80,22' \
            'ufw allow from any to any port 20:25 proto tcp' \
            'ufw allow from any to any app OpenSSH' 'ufw allow in on eth0 to any port 22'; do
    if ! ufw_rule_is_public_ssh "$rule"; then
        echo "public SSH rule not detected: $rule" >&2
        exit 1
    fi
done
for rule in "ufw allow in on tailscale0 to any port 22 proto tcp comment 'vps-proxy Tailscale SSH'" \
            'ufw allow from 203.0.113.4 to any port 22' 'ufw allow 80/tcp' 'ufw allow 222/tcp' \
            'ufw allow to any port 2222' 'ufw allow proto udp to any port 22' 'ufw deny 22/tcp' \
            "ufw allow 41641/udp comment 'vps-proxy Tailscale direct'" \
            "Added user rules (see 'ufw status' for running firewall):"; do
    if ufw_rule_is_public_ssh "$rule"; then
        echo "non-public rule flagged as public SSH: $rule" >&2
        exit 1
    fi
done

setup_script="${REPO_ROOT}/setup-vps-proxy.sh"
# shellcheck disable=SC2016
grep -Fq 'map "\$allowed_country:\$loopback_request" \$request_allowed {' "$setup_script"
# shellcheck disable=SC2016
if [[ $(grep -Fc 'if (\$request_allowed = no)' "$setup_script") -ne 2 ]]; then
    echo "expected both proxied locations to use the combined access gate" >&2
    exit 1
fi
# shellcheck disable=SC2016
if grep -Fq 'if (\$allowed_country = no)' "$setup_script"; then
    echo "legacy country-only access gate is still present" >&2
    exit 1
fi
# shellcheck disable=SC2016
if grep -Fq '\$proxy_add_x_forwarded_for' "$setup_script"; then
    echo "edge proxy must overwrite, not append to, client X-Forwarded-For" >&2
    exit 1
fi
if grep -Fq 'location = /Users/AuthenticateByName' "$setup_script"; then
    echo "case-sensitive exact-match login location lets variants skip the limit" >&2
    exit 1
fi

echo "validation tests passed"
