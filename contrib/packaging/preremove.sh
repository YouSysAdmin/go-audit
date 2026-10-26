#!/bin/sh
# Stop the service on removal but not on upgrade.
# deb passes "remove", rpm passes the number of versions left (0 on removal).
case "$1" in
    remove|0)
        if command -v systemctl >/dev/null 2>&1; then
            systemctl disable --now go-audit.service >/dev/null 2>&1 || true
        fi
        ;;
esac
