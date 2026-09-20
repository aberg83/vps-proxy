#!/usr/bin/env bash
set -euo pipefail

patterns="(-----BEGIN (OPENSSH|RSA|EC|DSA) PRIVATE KEY-----|tskey-[A-Za-z0-9_-]{10,}|github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9_]{20,}|hc-ping\\.com/[0-9a-fA-F-]{20,}|MAXMIND_LICENSE_KEY=[\"'][^\"']{8,})"

if git grep -nEI "$patterns" -- . ':(exclude)scripts/public-safety-check.sh'; then
    echo "possible secret found in the tracked tree" >&2
    exit 1
fi

# A public HTTPS workflow must not recreate the old private-repository
# deploy-key machinery.
if git grep -nEI '(id_ed25519_deploy|Settings.*Deploy keys|git@github\.com)' -- \
    setup-vps-proxy.sh README.md; then
    echo "private GitHub deploy-key workflow found in the public tree" >&2
    exit 1
fi

# Keep deployment-specific inventory out of the reusable public tree.
if git grep -nF 'boxer.sh' -- . ':(exclude)scripts/public-safety-check.sh'; then
    echo "deployment-specific hostname found in the tracked tree" >&2
    exit 1
fi

echo "public-tree safety checks passed"
