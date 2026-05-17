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
#   3. Downloads checksums.txt and verifies the binary's SHA-256 against it
#   4. Installs it to ~/.local/bin (no sudo required)
#   5. Prints how to run it
#
# This script never asks for sudo, never modifies system paths, and never
# pipes a second curl|bash. If verification fails, it aborts and prints
# exactly what happened.
#
# Per the project's DISCLAIMER.md: SafeStay is provided AS IS, with NO
# WARRANTY and NO LIABILITY (per the MIT license). It is NOT legal advice.
# Network scanning may be illegal in your jurisdiction — you alone are
# responsible for confirming you have authorization to scan before
# scanning. Full text: https://github.com/Cuzeth/airbnb-safety-tools/blob/main/DISCLAIMER.md

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

# Pick a sha256 tool. macOS ships shasum; most Linux ships sha256sum.
detect_sha256_tool() {
  if command -v sha256sum >/dev/null 2>&1; then
    SHA256_CMD="sha256sum"
  elif command -v shasum >/dev/null 2>&1; then
    SHA256_CMD="shasum -a 256"
  else
    red "Neither sha256sum nor shasum is available."
    echo "Install one of them and re-run, or download manually with checksum verification."
    exit 1
  fi
}

download_binary() {
  local bin_url checksums_url tmpdir
  bin_url="https://github.com/$REPO/releases/latest/download/${BIN_NAME}-${PLATFORM}"
  checksums_url="https://github.com/$REPO/releases/latest/download/checksums.txt"
  tmpdir=$(mktemp -d)
  trap "rm -rf '$tmpdir'" EXIT

  bold "Downloading SafeStay for $PLATFORM..."
  if ! curl -fL --progress-bar -o "$tmpdir/$BIN_NAME" "$bin_url"; then
    red "Download failed."
    echo "Tried: $bin_url"
    echo "Check that a release exists at https://github.com/$REPO/releases/latest"
    exit 1
  fi

  bold "Downloading checksums..."
  if ! curl -fL --silent -o "$tmpdir/checksums.txt" "$checksums_url"; then
    red "Checksum download failed."
    echo "Tried: $checksums_url"
    echo "Aborting: this script will not install an unverified binary."
    exit 1
  fi

  bold "Verifying SHA-256..."
  local expected actual artifact="${BIN_NAME}-${PLATFORM}"
  expected=$(grep -E "[[:space:]]+\*?${artifact}\$" "$tmpdir/checksums.txt" | awk '{print $1}' | head -n 1)
  if [ -z "$expected" ]; then
    red "Could not find a checksum for $artifact in checksums.txt."
    echo "Aborting: this script will not install an unverified binary."
    exit 1
  fi
  actual=$($SHA256_CMD "$tmpdir/$BIN_NAME" | awk '{print $1}')
  if [ "$expected" != "$actual" ]; then
    red "Checksum mismatch!"
    echo "  expected: $expected"
    echo "  actual:   $actual"
    echo "Aborting. Please report this at https://github.com/$REPO/security/advisories/new"
    exit 1
  fi
  green "Checksum OK ($actual)"

  chmod +x "$tmpdir/$BIN_NAME"
  mkdir -p "$INSTALL_DIR"
  mv "$tmpdir/$BIN_NAME" "$INSTALL_DIR/$BIN_NAME"
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
  echo "  Run with sudo for best results — that lets the discovery phase send"
  echo "  raw ICMP probes, which puts more devices in the ARP cache."
  echo
  echo "  Inside the TUI, press ? at any time for the physical-check guide"
  echo "  (covers cameras the network scan can't see, plus what to do if"
  echo "  you find one)."
  echo
  yellow "  Important: this tool is provided AS IS, with no warranty and no"
  yellow "  liability (per the MIT license). It is not legal advice. Network"
  yellow "  scanning may be illegal where you are. Run 'safestay --disclaimer'"
  yellow "  for the full informational notice before using."
}

main() {
  detect_platform
  detect_sha256_tool
  download_binary
  print_next_steps
}

main "$@"
