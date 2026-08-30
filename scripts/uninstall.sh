#!/usr/bin/env bash
# hawk uninstaller — removes the binary and all user-level hawk data
# (clean removal). Per-project `.hawk` data directories under the current
# directory are also removed.
#
#   One-line uninstall:
#     curl -fsSL https://raw.githubusercontent.com/parkjangwon/hawk/main/scripts/uninstall.sh | bash
set -euo pipefail

INSTALL_DIR="${HAWK_INSTALL_DIR:-$HOME/.local/bin}"
removed=0

if [ -f "$INSTALL_DIR/hawk" ]; then
    rm -f "$INSTALL_DIR/hawk"
    echo "hawk: removed $INSTALL_DIR/hawk"
    removed=1
fi

# User-level data locations (cache, config, state) if any exist.
for dir in \
    "$HOME/.cache/hawk" \
    "$HOME/.config/hawk" \
    "$HOME/.local/share/hawk" \
    "$HOME/.local/state/hawk"; do
    if [ -d "$dir" ]; then
        rm -rf "$dir"
        echo "hawk: removed $dir"
        removed=1
    fi
done

# Project-local data (cache, baseline) in the current directory.
if [ -d "./.hawk" ]; then
    rm -rf "./.hawk"
    echo "hawk: removed ./.hawk"
    removed=1
fi

if [ "$removed" = 0 ]; then
    echo "hawk: not installed — nothing to remove."
else
    echo "hawk: uninstalled."
fi
