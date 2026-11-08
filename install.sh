#!/usr/bin/env bash
#
# HellCat installer / updater for Linux servers.
#
# Installs Go (if needed) and Xray-core, builds hellcat from this checkout and
# installs the binary into a bin directory. Safe to re-run.
#
# Usage:
#   sudo ./install.sh                 # system-wide (/usr/local/bin)
#   ./install.sh --user               # per-user (~/.local/bin)
#   sudo ./install.sh --no-deps       # only build/install hellcat
#   sudo ./install.sh --no-build      # only install Go + Xray
#   sudo ./install.sh --prefix /opt   # install to /opt/bin
#
set -euo pipefail

BIN_NAME="hellcat"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

INSTALL_DEPS=1
BUILD=1
USER_MODE=0
PREFIX="/usr/local"
GO_VERSION="${GO_VERSION:-}"
XRAY_VERSION="${XRAY_VERSION:-latest}"

usage() {
  sed -n '3,14p' "$0" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --user) USER_MODE=1; shift ;;
    --prefix) PREFIX="${2:?--prefix requires a path}"; shift 2 ;;
    --no-deps) INSTALL_DEPS=0; shift ;;
    --no-build) BUILD=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

log()  { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

[[ "$(uname -s)" == "Linux" ]] || die "This installer targets Linux (detected $(uname -s))."

if [[ "$(id -u)" -eq 0 ]]; then
  SUDO=""
elif [[ "$USER_MODE" -eq 1 ]]; then
  SUDO=""
elif command -v sudo >/dev/null 2>&1; then
  SUDO="sudo"
else
  SUDO=""
  die "Root or sudo is required; re-run with --user for a user-local install."
fi

run_root() {
  if [[ -n "$SUDO" ]]; then "$SUDO" "$@"; else "$@"; fi
}

if [[ "$USER_MODE" -eq 1 ]]; then
  BIN_DIR="$HOME/.local/bin"
  GO_PARENT="$HOME/.local"
else
  BIN_DIR="$PREFIX/bin"
  GO_PARENT="$PREFIX"
fi

case "$(uname -m)" in
  x86_64|amd64)  GO_ARCH="amd64"; XRAY_ASSET="Xray-linux-64.zip" ;;
  aarch64|arm64) GO_ARCH="arm64"; XRAY_ASSET="Xray-linux-arm64-v8a.zip" ;;
  armv7l)        GO_ARCH="armv6l"; XRAY_ASSET="Xray-linux-arm32-v7a.zip" ;;
  armv6l)        GO_ARCH="armv6l"; XRAY_ASSET="Xray-linux-arm32-v6.zip" ;;
  i686|i386)     GO_ARCH="386";   XRAY_ASSET="Xray-linux-32.zip" ;;
  *) die "Unsupported architecture: $(uname -m)" ;;
esac

download() {
  local url="$1" out="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --retry 3 --connect-timeout 15 -o "$out" "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -q --tries=3 --timeout=15 -O "$out" "$url"
  else
    die "curl or wget is required"
  fi
}

install_packages() {
  [[ $# -eq 0 ]] && return 0
  if command -v apt-get >/dev/null 2>&1; then
    run_root apt-get update -qq
    run_root env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@"
  elif command -v dnf >/dev/null 2>&1; then
    run_root dnf install -y "$@"
  elif command -v yum >/dev/null 2>&1; then
    run_root yum install -y "$@"
  elif command -v apk >/dev/null 2>&1; then
    run_root apk add --no-cache "$@"
  else
    warn "No supported package manager found; please install manually: $*"
    return 1
  fi
}

if [[ "$INSTALL_DEPS" -eq 1 ]]; then
  NEEDED=()
  for tool in curl unzip tar; do
    command -v "$tool" >/dev/null 2>&1 || NEEDED+=("$tool")
  done
  if [[ ${#NEEDED[@]} -gt 0 ]]; then
    log "Installing required tools: ${NEEDED[*]}"
    install_packages "${NEEDED[@]}" || die "Could not install ${NEEDED[*]}"
  fi

  GO_BIN="$(command -v go 2>/dev/null || true)"
  if [[ -z "$GO_BIN" ]]; then
    [[ -n "$GO_VERSION" ]] || GO_VERSION="$(curl -fsSL --max-time 15 'https://go.dev/VERSION?m=text' | head -n1 || true)"
    [[ -n "$GO_VERSION" ]] || GO_VERSION="go1.22.3"
    [[ "$GO_VERSION" == go* ]] || GO_VERSION="go$GO_VERSION"

    log "Installing $GO_VERSION for linux-$GO_ARCH"
    TMP_GO="$(mktemp)"
    download "https://go.dev/dl/${GO_VERSION}.linux-${GO_ARCH}.tar.gz" "$TMP_GO"
    run_root rm -rf "$GO_PARENT/go"
    run_root tar -C "$GO_PARENT" -xzf "$TMP_GO"
    rm -f "$TMP_GO"
    GO_BIN="$GO_PARENT/go/bin/go"
    [[ -x "$GO_BIN" ]] || die "Go installation failed"
  fi

  export PATH="$(dirname "$GO_BIN"):$PATH"
  GO_VER="$("$GO_BIN" version | awk '{print $3}')"
  log "Using Go $GO_VER"

  if ! command -v xray >/dev/null 2>&1; then
    if [[ "$XRAY_VERSION" == "latest" ]]; then
      XRAY_VERSION="$(curl -fsSL --max-time 20 'https://api.github.com/repos/XTLS/Xray-core/releases/latest' \
        | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n1 || true)"
      [[ -n "$XRAY_VERSION" ]] || XRAY_VERSION="$(curl -fsSLI -o /dev/null -w '%{url_effective}' \
        'https://github.com/XTLS/Xray-core/releases/latest' | sed 's#.*/tag/##')"
    fi
    [[ -n "$XRAY_VERSION" ]] || die "Could not determine the latest Xray version"

    log "Installing Xray-core $XRAY_VERSION ($XRAY_ASSET)"
    TMP_DIR="$(mktemp -d)"
    download "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/${XRAY_ASSET}" "$TMP_DIR/xray.zip"
    unzip -qo "$TMP_DIR/xray.zip" -d "$TMP_DIR"
    run_root install -d -m 0755 "$BIN_DIR"
    run_root install -m 0755 "$TMP_DIR/xray" "$BIN_DIR/xray"
    rm -rf "$TMP_DIR"
  else
    log "Xray already installed: $(xray version | head -n1)"
  fi
fi

if [[ "$BUILD" -eq 1 ]]; then
  [[ -n "${GO_BIN:-}" ]] || GO_BIN="$(command -v go 2>/dev/null || true)"
  [[ -n "$GO_BIN" ]] || die "Go is not installed; run without --no-deps or install Go 1.22+ manually."

  VERSION="$(git -C "$REPO_DIR" describe --tags --always --dirty 2>/dev/null || echo dev)"
  log "Building hellcat $VERSION"
  (
    cd "$REPO_DIR"
    CGO_ENABLED=0 "$GO_BIN" build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "$REPO_DIR/$BIN_NAME" .
  )

  run_root install -d -m 0755 "$BIN_DIR"
  run_root install -m 0755 "$REPO_DIR/$BIN_NAME" "$BIN_DIR/$BIN_NAME"
  rm -f "$REPO_DIR/$BIN_NAME"
  log "Installed $BIN_DIR/$BIN_NAME"
fi

if ! command -v xray >/dev/null 2>&1; then
  warn "xray is not in PATH. Add $BIN_DIR to PATH or install Xray-core before running hellcat."
fi
if ! command -v "$BIN_NAME" >/dev/null 2>&1; then
  warn "$BIN_NAME is not in PATH. Add $BIN_DIR to PATH:"
  printf '    export PATH="%s:$PATH"\n' "$BIN_DIR"
fi

cat <<EOF

Done.

Quick start:
  $BIN_NAME --list /etc/hellcat/links.txt --instances 20 --threads 200

Server deployment (systemd):
  sudo mkdir -p /etc/hellcat /var/lib/hellcat
  sudo cp deploy/hellcat.service /etc/systemd/system/
  sudo systemctl daemon-reload
  sudo systemctl enable --now hellcat

See README.md for flags, tuning and troubleshooting.
EOF
