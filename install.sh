#!/usr/bin/env bash
# BinaryInspector Installer
# Safe, local inspection of ELF binaries
set -euo pipefail

REPO="bisug/BinaryInspector"
GITHUB_URL="https://github.com/${REPO}"
RAW_URL="https://raw.githubusercontent.com/${REPO}/main"

INSTALL_CLI=true
INSTALL_GUI=true
FROM_SOURCE=false
VERSION=""
DEST_DIR="${HOME}/.local/bin"

print_usage() {
    cat <<EOF
BinaryInspector Installer

Usage:
  install.sh [OPTIONS]

Options:
  --cli-only        Install only the command-line interface (binary-inspector)
  --gui-only        Install only the desktop GUI (binary-inspector-gui)
  --to <DIR>        Target binary directory (default: \$HOME/.local/bin)
  --version <TAG>   Install a specific release version (e.g., v0.1.0)
  --from-source     Build from source using local cargo instead of downloading
  -h, --help        Show this help message
EOF
}

# Parse options
while [[ $# -gt 0 ]]; do
    case "$1" in
        --cli-only)
            INSTALL_GUI=false
            shift
            ;;
        --gui-only)
            INSTALL_CLI=false
            shift
            ;;
        --to|--prefix)
            DEST_DIR="$2"
            shift 2
            ;;
        --version)
            VERSION="$2"
            shift 2
            ;;
        --from-source)
            FROM_SOURCE=true
            shift
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        *)
            echo "Error: Unknown argument '$1'" >&2
            print_usage
            exit 1
            ;;
    esac
done

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$OS" in
    linux)  OS_NAME="linux" ;;
    darwin) OS_NAME="macos" ;;
    *)
        echo "Error: Unsupported operating system: $OS" >&2
        exit 1
        ;;
esac

case "$ARCH" in
    x86_64|amd64) ARCH_NAME="x86_64" ;;
    *)
        echo "Error: Pre-built release binaries are currently only available for x86_64." >&2
        echo "Consider building from source with: cargo install --path ." >&2
        exit 1
        ;;
esac

download() {
    local url="$1"
    local output="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url" -o "$output"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$output" "$url"
    else
        echo "Error: Neither curl nor wget is available." >&2
        exit 1
    fi
}

verify_sha256() {
    local file="$1"
    local expected_hash="$2"
    local actual_hash=""

    if command -v sha256sum >/dev/null 2>&1; then
        actual_hash="$(sha256sum "$file" | awk '{print $1}')"
    elif command -v shasum >/dev/null 2>&1; then
        actual_hash="$(shasum -a 256 "$file" | awk '{print $1}')"
    else
        echo "Warning: sha256sum/shasum not found; skipping cryptographic verification." >&2
        return 0
    fi

    if [ "$actual_hash" != "$expected_hash" ]; then
        echo "Error: SHA256 checksum mismatch for $(basename "$file")!" >&2
        echo "Expected: $expected_hash" >&2
        echo "Actual:   $actual_hash" >&2
        return 1
    fi
}

TMP_DIR="$(mktemp -d -t binary-inspector-install.XXXXXX)"
trap 'rm -rf "$TMP_DIR"' EXIT

mkdir -p "$DEST_DIR"

if [ "$FROM_SOURCE" = true ]; then
    if ! command -v cargo >/dev/null 2>&1; then
        if [ -x "${HOME}/.cargo/bin/cargo" ]; then
            export PATH="${HOME}/.cargo/bin:$PATH"
        fi
    fi
    if ! command -v cargo >/dev/null 2>&1; then
        echo "Error: cargo is required to build from source but was not found in PATH." >&2
        exit 1
    fi
    echo "Building BinaryInspector from source..."
    if [ "$INSTALL_CLI" = true ]; then
        cargo build --release --locked --bin binary-inspector
        install -m 755 target/release/binary-inspector "$DEST_DIR/binary-inspector"
        echo "✓ Installed CLI to $DEST_DIR/binary-inspector"
    fi
    if [ "$INSTALL_GUI" = true ]; then
        cargo build --release --locked --bin binary-inspector-gui
        install -m 755 target/release/binary-inspector-gui "$DEST_DIR/binary-inspector-gui"
        echo "✓ Installed GUI to $DEST_DIR/binary-inspector-gui"
    fi
else
    if [ -z "$VERSION" ]; then
        if command -v curl >/dev/null 2>&1; then
            VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' || true)"
        fi
        if [ -z "$VERSION" ]; then
            VERSION="v0.1.0"
        fi
    fi

    RELEASE_BASE="${GITHUB_URL}/releases/download/${VERSION}"
    echo "Installing BinaryInspector ${VERSION} (${OS_NAME}-${ARCH_NAME})..."

    # Download checksums
    CHECKSUMS_FILE="$TMP_DIR/SHA256SUMS.txt"
    download "${RELEASE_BASE}/SHA256SUMS.txt" "$CHECKSUMS_FILE"

    # Install CLI
    if [ "$INSTALL_CLI" = true ]; then
        if [ "$OS_NAME" = "linux" ]; then
            ARCHIVE="binary-inspector-cli-linux-x86_64.tar.gz"
            echo "Downloading ${ARCHIVE}..."
            download "${RELEASE_BASE}/${ARCHIVE}" "$TMP_DIR/${ARCHIVE}"
            EXPECTED_HASH="$(grep "${ARCHIVE}" "$CHECKSUMS_FILE" | awk '{print $1}')"
            verify_sha256 "$TMP_DIR/${ARCHIVE}" "$EXPECTED_HASH"
            tar -xzf "$TMP_DIR/${ARCHIVE}" -C "$TMP_DIR"
            install -m 755 "$TMP_DIR/binary-inspector" "$DEST_DIR/binary-inspector"
            echo "✓ Installed CLI to $DEST_DIR/binary-inspector"
        else
            echo "Note: Pre-built CLI is only available for Linux. To build on macOS, use: cargo build --release"
        fi
    fi

    # Install GUI
    if [ "$INSTALL_GUI" = true ]; then
        if [ "$OS_NAME" = "linux" ]; then
            ARCHIVE="binary-inspector-gui-linux-x86_64.tar.gz"
        else
            ARCHIVE="binary-inspector-gui-macos.tar.gz"
        fi
        echo "Downloading ${ARCHIVE}..."
        download "${RELEASE_BASE}/${ARCHIVE}" "$TMP_DIR/${ARCHIVE}"
        EXPECTED_HASH="$(grep "${ARCHIVE}" "$CHECKSUMS_FILE" | awk '{print $1}')"
        verify_sha256 "$TMP_DIR/${ARCHIVE}" "$EXPECTED_HASH"
        tar -xzf "$TMP_DIR/${ARCHIVE}" -C "$TMP_DIR"
        install -m 755 "$TMP_DIR/binary-inspector-gui" "$DEST_DIR/binary-inspector-gui"
        echo "✓ Installed GUI to $DEST_DIR/binary-inspector-gui"
    fi
fi

# Linux Desktop Integration
if [ "$OS_NAME" = "linux" ] && [ "$INSTALL_GUI" = true ]; then
    ICON_DIR="${HOME}/.local/share/icons/hicolor/scalable/apps"
    APP_DIR="${HOME}/.local/share/applications"
    mkdir -p "$ICON_DIR" "$APP_DIR"

    if [ -f "assets/binary-inspector.svg" ]; then
        cp "assets/binary-inspector.svg" "$ICON_DIR/binary-inspector.svg"
    else
        download "${RAW_URL}/assets/binary-inspector.svg" "$ICON_DIR/binary-inspector.svg" || true
    fi

    cat <<EOF > "$APP_DIR/binary-inspector.desktop"
[Desktop Entry]
Name=BinaryInspector
Comment=Safe, local inspection of ELF binaries
Exec=${DEST_DIR}/binary-inspector-gui %F
Icon=binary-inspector
Terminal=false
Type=Application
Categories=Development;Utility;
MimeType=application/x-executable;application/x-sharedlib;
StartupNotify=true
EOF

    chmod +x "$APP_DIR/binary-inspector.desktop"
    if command -v update-desktop-database >/dev/null 2>&1; then
        update-desktop-database "$APP_DIR" >/dev/null 2>&1 || true
    fi
    echo "✓ Desktop launcher registered at $APP_DIR/binary-inspector.desktop"
fi

echo ""
echo "Installation complete!"
case ":$PATH:" in
    *":$DEST_DIR:"*) ;;
    *)
        echo ""
        echo "Notice: '$DEST_DIR' is not currently in your PATH."
        echo "Add it to your environment by adding this line to ~/.bashrc or ~/.zshrc:"
        echo "  export PATH=\"$DEST_DIR:\$PATH\""
        ;;
esac
