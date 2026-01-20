#!/bin/bash
# Build script for Google Docs Viewer Tunnel
# Builds for Windows, macOS, Linux, and Android

set -e

echo "=================================="
echo "Building Google Docs Viewer Tunnel"
echo "=================================="

# Install cross-compilation targets if not present
install_targets() {
    echo "Installing cross-compilation targets..."
    rustup target add x86_64-pc-windows-gnu 2>/dev/null || true
    rustup target add x86_64-apple-darwin 2>/dev/null || true
    rustup target add aarch64-apple-darwin 2>/dev/null || true
    rustup target add x86_64-unknown-linux-musl 2>/dev/null || true
    rustup target add aarch64-linux-android 2>/dev/null || true
    rustup target add armv7-linux-androideabi 2>/dev/null || true
}

# Build for current platform
build_native() {
    echo ""
    echo "Building for current platform..."
    cargo build --release
    echo "  Output: target/release/gdocs_tunnel"
}

# Build for Windows
build_windows() {
    echo ""
    echo "Building for Windows (x86_64)..."
    if command -v x86_64-w64-mingw32-gcc &> /dev/null; then
        cargo build --release --target x86_64-pc-windows-gnu
        echo "  Output: target/x86_64-pc-windows-gnu/release/gdocs_tunnel.exe"
    else
        echo "  Skipped: mingw-w64 not installed"
        echo "  Install with: brew install mingw-w64 (macOS) or apt install mingw-w64 (Linux)"
    fi
}

# Build for Linux (static)
build_linux() {
    echo ""
    echo "Building for Linux (x86_64, static musl)..."
    if rustup target list --installed | grep -q "x86_64-unknown-linux-musl"; then
        cargo build --release --target x86_64-unknown-linux-musl
        echo "  Output: target/x86_64-unknown-linux-musl/release/gdocs_tunnel"
    else
        echo "  Skipped: musl target not configured"
    fi
}

# Build for Android
build_android() {
    echo ""
    echo "Building for Android..."
    if command -v cargo-ndk &> /dev/null; then
        echo "  Building ARM64..."
        cargo ndk -t arm64-v8a build --release
        echo "  Output: target/aarch64-linux-android/release/libgdocs_tunnel.so"

        echo "  Building ARMv7..."
        cargo ndk -t armeabi-v7a build --release
        echo "  Output: target/armv7-linux-androideabi/release/libgdocs_tunnel.so"
    else
        echo "  Skipped: cargo-ndk not installed"
        echo "  Install with: cargo install cargo-ndk"
        echo "  Also need Android NDK: https://developer.android.com/ndk"
    fi
}

# Package releases
package_releases() {
    echo ""
    echo "Packaging releases..."

    mkdir -p releases

    # Get version
    VERSION=$(grep '^version' Cargo.toml | head -1 | cut -d'"' -f2)

    # Package each target
    if [ -f "target/release/gdocs_tunnel" ]; then
        case "$(uname -s)" in
            Darwin*)
                cp target/release/gdocs_tunnel releases/gdocs_tunnel-${VERSION}-macos
                ;;
            Linux*)
                cp target/release/gdocs_tunnel releases/gdocs_tunnel-${VERSION}-linux
                ;;
        esac
    fi

    if [ -f "target/x86_64-pc-windows-gnu/release/gdocs_tunnel.exe" ]; then
        cp target/x86_64-pc-windows-gnu/release/gdocs_tunnel.exe releases/gdocs_tunnel-${VERSION}-windows.exe
    fi

    if [ -f "target/x86_64-unknown-linux-musl/release/gdocs_tunnel" ]; then
        cp target/x86_64-unknown-linux-musl/release/gdocs_tunnel releases/gdocs_tunnel-${VERSION}-linux-static
    fi

    echo "  Releases in: releases/"
    ls -la releases/ 2>/dev/null || true
}

# Main
case "${1:-all}" in
    native)
        build_native
        ;;
    windows)
        build_windows
        ;;
    linux)
        build_linux
        ;;
    android)
        build_android
        ;;
    all)
        install_targets
        build_native
        build_windows
        build_linux
        build_android
        package_releases
        ;;
    *)
        echo "Usage: $0 [native|windows|linux|android|all]"
        exit 1
        ;;
esac

echo ""
echo "Done!"
