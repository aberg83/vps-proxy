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

echo "validation tests passed"
