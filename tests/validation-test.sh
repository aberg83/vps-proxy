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
            HEALTHCHECK_PATH HEALTHCHECK_EXPECTED_STATUS
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
