#!/usr/bin/env bash
# hawk installer — installs or updates the latest release binary.
#
#   One-line install:
#     curl -fsSL https://raw.githubusercontent.com/parkjangwon/hawk/main/scripts/install.sh | bash
#
#   Override the install directory with HAWK_INSTALL_DIR, or pin a version
#   with HAWK_VERSION (e.g. v0.1.0). Re-running the script updates hawk.
set -euo pipefail

REPO="parkjangwon/hawk"
INSTALL_DIR="${HAWK_INSTALL_DIR:-$HOME/.local/bin}"
VERSION="${HAWK_VERSION:-latest}"

# Map the host platform to the release asset name (hawk-<arch>-<os>).
os="$(uname -s)"
arch="$(uname -m)"
case "$os" in
    Linux) os_triple="unknown-linux-gnu" ;;
    Darwin) os_triple="apple-darwin" ;;
    *)
        echo "error: unsupported OS '$os' (Linux and macOS only)" >&2
        exit 1
        ;;
esac
case "$arch" in
    x86_64 | amd64) arch_triple="x86_64" ;;
    aarch64 | arm64) arch_triple="aarch64" ;;
    *)
        echo "error: unsupported architecture '$arch'" >&2
        exit 1
        ;;
esac
TARGET="hawk-${arch_triple}-${os_triple}"

if [ "$VERSION" = "latest" ]; then
    URL="https://github.com/${REPO}/releases/latest/download/${TARGET}"
else
    URL="https://github.com/${REPO}/releases/download/${VERSION}/${TARGET}"
fi

mkdir -p "$INSTALL_DIR"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

echo "hawk: downloading ${TARGET} (${VERSION})..."
if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$URL" -o "$tmp"
else
    wget -qO "$tmp" "$URL"
fi
chmod +x "$tmp"
install -m 0755 "$tmp" "$INSTALL_DIR/hawk"

echo "hawk: installed $( "$INSTALL_DIR/hawk" --version ) to $INSTALL_DIR/hawk"
case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *)
        echo "note: add $INSTALL_DIR to your PATH, e.g. export PATH=\"$INSTALL_DIR:\$PATH\""
        ;;
esac
