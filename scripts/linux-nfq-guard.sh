#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
RULESET="${SCRIPT_DIR}/linux-nfq-guard.nft"
TABLE="inet aegisxii"

usage() {
    cat <<'EOF'
Usage: linux-nfq-guard.sh {install|remove|status}

install  Atomically install IPv4 NFQUEUE and IPv6 drop rules.
remove   Remove only the Aegis XII nftables table (maintenance action).
status   Show the Aegis XII nftables rules, if installed.
EOF
}

if [[ ${EUID} -ne 0 ]]; then
    echo "Run this command as root (for example, with sudo)." >&2
    exit 1
fi

if ! command -v nft >/dev/null 2>&1; then
    echo "nft is required; install the nftables package first." >&2
    exit 1
fi

case "${1:-}" in
    install)
        if [[ ! -r "${RULESET}" ]]; then
            echo "Cannot read ruleset: ${RULESET}" >&2
            exit 1
        fi
        # nft processes a file as one transaction. Check it before applying;
        # the queue rule intentionally has no 'bypass' flag (no listener = drop).
        nft --check --file "${RULESET}"
        nft --file "${RULESET}"
        nft list table ${TABLE}
        ;;
    remove)
        # destroy is idempotent if the owned table does not exist.
        nft destroy table ${TABLE}
        ;;
    status)
        nft list table ${TABLE}
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac
