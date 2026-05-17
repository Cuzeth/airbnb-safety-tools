#!/usr/bin/env bash
#
# SafeStay one-line installer.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/Cuzeth/airbnb-safety-tools/main/install.sh | bash
#
# What it does:
#   1. Detects your OS + CPU
#   2. Downloads the matching prebuilt binary from the latest GitHub release
#   3. Installs it to ~/.local/bin (no sudo required)
#   4. Prints how to run it
#
# This script never asks for sudo, never modifies system paths, and never
# pipes a second curl|bash. If something fails, it tells you exactly what
# to do manually.
#
# LEGAL: SafeStay is provided AS IS, with NO WARRANTY and NO LIABILITY. It is
# NOT legal advice. The author does NOT condone, encourage, or recommend its
# use. Network scanning may be illegal in your jurisdiction — you alone are
# responsible for confirming you have authorization to scan before scanning.
# By running this installer you agree to the full disclaimer at
# https://github.com/Cuzeth/airbnb-safety-tools/blob/main/DISCLAIMER.md

set -euo pipefail

REPO="Cuzeth/airbnb-safety-tools"
BIN_NAME="safestay"
INSTALL_DIR="${SAFESTAY_INSTALL_DIR:-$HOME/.local/bin}"

red()    { printf '\033[31m%s\033[0m\n' "$*"; }
green()  { printf '\033[32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[33m%s\033[0m\n' "$*"; }
bold()   { printf '\033[1m%s\033[0m\n' "$*"; }

detect_platform() {
  local os arch
  os=$(uname -s | tr '[:upper:]' '[:lower:]')
  arch=$(uname -m)

  case "$os" in
    darwin|linux) ;;
    *)
      red "Unsupported OS: $os"
      echo "SafeStay currently provides prebuilt binaries for macOS and Linux."
      echo "On Windows, download from: https://github.com/$REPO/releases/latest"
      exit 1
      ;;
  esac

  case "$arch" in
    x86_64|amd64) arch="amd64" ;;
    arm64|aarch64) arch="arm64" ;;
    *)
      red "Unsupported CPU architecture: $arch"
      exit 1
      ;;
  esac

  PLATFORM="${os}-${arch}"
}

download_binary() {
  local url tmp
  url="https://github.com/$REPO/releases/latest/download/${BIN_NAME}-${PLATFORM}"
  tmp=$(mktemp)

  bold "Downloading SafeStay for $PLATFORM..."
  if ! curl -fL --progress-bar -o "$tmp" "$url"; then
    red "Download failed."
    echo "Tried: $url"
    echo "Check that a release exists at https://github.com/$REPO/releases/latest"
    rm -f "$tmp"
    exit 1
  fi

  chmod +x "$tmp"
  mkdir -p "$INSTALL_DIR"
  mv "$tmp" "$INSTALL_DIR/$BIN_NAME"
  green "Installed to: $INSTALL_DIR/$BIN_NAME"
}

print_next_steps() {
  echo
  bold "Next steps:"
  echo
  if ! echo ":$PATH:" | grep -q ":$INSTALL_DIR:"; then
    yellow "  $INSTALL_DIR is not in your PATH yet."
    echo "  Add this line to your shell config (~/.zshrc or ~/.bashrc):"
    echo
    echo "    export PATH=\"$INSTALL_DIR:\$PATH\""
    echo
    echo "  Or run SafeStay directly with the full path:"
    echo
    bold "    sudo $INSTALL_DIR/$BIN_NAME"
  else
    bold "  sudo safestay"
  fi
  echo
  echo "  Run with sudo for best results — that enables ARP scanning which"
  echo "  finds more devices than the non-privileged fallback."
  echo
  echo "  Inside the TUI, press ? at any time for the physical-check guide"
  echo "  (covers cameras the network scan can't see, plus what to do if"
  echo "  you find one)."
  echo
  yellow "  LEGAL: This tool is provided AS IS, with NO WARRANTY and NO LIABILITY."
  yellow "  It is NOT legal advice. Network scanning may be illegal where you are."
  yellow "  Run 'safestay --disclaimer' for the full legal notice before using."
}

main() {
  detect_platform
  download_binary
  print_next_steps
}

main "$@"
