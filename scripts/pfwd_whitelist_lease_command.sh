#!/usr/bin/env bash
set -euo pipefail

orig="${SSH_ORIGINAL_COMMAND:-}"
[ -n "$orig" ] || {
    echo "command not allowed" >&2
    exit 126
}

case "$orig" in
    "pfwd guard whitelist-lease list"|"pfwd guard whitelist-lease status"|"pfwd guard whitelist-lease clear")
        exec /usr/local/bin/$orig
        ;;
    pfwd\ guard\ whitelist-lease\ add\ *|pfwd\ guard\ whitelist-lease\ delete\ *)
        exec /usr/local/bin/$orig
        ;;
    *)
        echo "command not allowed" >&2
        exit 126
        ;;
esac
