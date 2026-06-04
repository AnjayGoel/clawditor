#!/usr/bin/env bash
# Host-side bootstrap for the dynamic-analysis phase.
# Cross-platform: macOS (brew) + Linux (apt / dnf / pacman / apk / zypper).
# Idempotent — re-running is safe; existing pieces are detected and skipped.
#
# Installs / verifies:
#   - mitmproxy (brew or pipx)
#   - objection + frida-tools (pipx)
#   - Android cmdline-tools + platform-tools + emulator (brew on macOS; auto-download on Linux)
#   - system-images;android-34;google_apis;<host_arch>
#   - AVD 'clawditor-pixel7' (Pixel 7 profile, API 34, google_apis image)
#   - frida-server binary → vendor/frida-server-<arch>
#   - NVISO disable-flutter-tls-verification.js → vendor/scripts/disable-flutter-tls.js
#   - On Linux: KVM packages for hardware-accelerated emulation
#
# After this finishes:
#   1. Run `mitmproxy` once (press q to quit) to generate ~/.mitmproxy/mitmproxy-ca-cert.cer
#   2. uv run clawditor dynamic start

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENDOR="$ROOT/vendor"
SCRIPTS_DIR="$VENDOR/scripts"
mkdir -p "$VENDOR" "$SCRIPTS_DIR"

. "$ROOT/scripts/_lib.sh"
detect_platform

case "$ARCH" in
    arm64)  ANDROID_IMG_ARCH="arm64-v8a" ; FRIDA_ARCH="arm64" ;;
    x86_64) ANDROID_IMG_ARCH="x86_64"    ; FRIDA_ARCH="x86_64" ;;
esac

c_step "host: $OS / $ARCH  →  Android image: $ANDROID_IMG_ARCH"

# ─────────────────── pipx ───────────────────
c_step "pipx"
ensure_pipx

# ─────────────────── mitmproxy ───────────────────
c_step "mitmproxy"
if has mitmweb; then
    c_ok "mitmproxy already installed: $(mitmweb --version 2>&1 | head -1)"
elif [[ "$PKG_MGR" == "brew" ]]; then
    brew install mitmproxy
else
    # On Linux the distro mitmproxy is often stale; pipx is more reliable
    pipx install mitmproxy
fi

# ─────────────────── objection + frida-tools ───────────────────
c_step "objection + frida-tools"
ensure_pipx_pkg objection
ensure_pipx_pkg frida-tools frida

# ─────────────────── Linux KVM (hardware-accelerated emulation) ───────────────────
if [[ "$OS" == "Linux" ]]; then
    c_step "KVM (hardware acceleration for emulator)"
    if [[ -e /dev/kvm ]]; then
        c_ok "/dev/kvm present"
        if ! groups | grep -qE '\bkvm\b'; then
            c_warn "you're not in the 'kvm' group — emulator will fall back to software. Run:"
            c_warn "  $SUDO usermod -aG kvm $USER  &&  newgrp kvm   (or log out + back in)"
        fi
    else
        case "$PKG_MGR" in
            apt)    pkg_install qemu-kvm libvirt-daemon-system bridge-utils ;;
            dnf|yum) pkg_install qemu-kvm ;;
            pacman) pkg_install qemu-base libvirt ;;
            *)      c_warn "install KVM manually for your distro" ;;
        esac
        c_warn "after install: $SUDO usermod -aG kvm $USER  &&  log out + back in"
    fi
fi

# ─────────────────── Android cmdline-tools / platform-tools / emulator ───────────────────
c_step "Android SDK (cmdline-tools, platform-tools, emulator)"

# Prefer locally-installed cmdline-tools (newer + Java-17 compatible) over the
# brew-installed cask. Older sdkmanager (≤ ~6.0) needs Java 8 because of
# javax.xml.bind, which was removed in Java 9 — that's a common failure mode
# on modern systems.
ANDROID_HOME="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
[[ "$OS" == "Linux" ]] && ANDROID_HOME="${ANDROID_HOME:-$HOME/Android/Sdk}"
LOCAL_SDKMGR="$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager"
LOCAL_AVDMGR="$ANDROID_HOME/cmdline-tools/latest/bin/avdmanager"

if [[ -x "$LOCAL_SDKMGR" ]]; then
    SDKMANAGER="$LOCAL_SDKMGR"
    AVDMANAGER="$LOCAL_AVDMGR"
    c_ok "using locally-installed cmdline-tools at $ANDROID_HOME/cmdline-tools/latest"
else
    SDKMANAGER="$(command -v sdkmanager || true)"
    AVDMANAGER="$(command -v avdmanager || true)"

    # Heuristic: if sdkmanager is present but errors on Java 17, download latest manually.
    if [[ -n "$SDKMANAGER" ]] && ! "$SDKMANAGER" --version >/dev/null 2>&1; then
        c_warn "system sdkmanager is broken on this Java (likely needs Java 8). Downloading latest cmdline-tools."
        SDKMANAGER=""
    fi

    if [[ -z "$SDKMANAGER" ]]; then
        c_info "downloading Android cmdline-tools (latest, Java-17-compatible)"
        mkdir -p "$ANDROID_HOME/cmdline-tools"
        CMDLINE_ZIP="$VENDOR/cmdline-tools.zip"
        if [[ "$OS" == "Darwin" ]]; then
            CMDLINE_URL="https://dl.google.com/android/repository/commandlinetools-mac-13114758_latest.zip"
        else
            CMDLINE_URL="https://dl.google.com/android/repository/commandlinetools-linux-13114758_latest.zip"
        fi
        curl -fsSL -o "$CMDLINE_ZIP" "$CMDLINE_URL"
        rm -rf "$ANDROID_HOME/cmdline-tools/latest"
        unzip -oq "$CMDLINE_ZIP" -d "$ANDROID_HOME/cmdline-tools/"
        mv "$ANDROID_HOME/cmdline-tools/cmdline-tools" "$ANDROID_HOME/cmdline-tools/latest"
        rm "$CMDLINE_ZIP"
        SDKMANAGER="$LOCAL_SDKMGR"
        AVDMANAGER="$LOCAL_AVDMGR"
        c_warn "Add to your shell profile so subsequent shells pick these up:"
        c_warn "  export ANDROID_HOME=\"$ANDROID_HOME\""
        c_warn "  export PATH=\"\$ANDROID_HOME/cmdline-tools/latest/bin:\$ANDROID_HOME/platform-tools:\$ANDROID_HOME/emulator:\$PATH\""
    fi
fi

# Linux fallback: download cmdline-tools from Google directly
if [[ -z "$SDKMANAGER" && "$OS" == "Linux" ]]; then
    ANDROID_HOME="${ANDROID_HOME:-$HOME/Android/Sdk}"
    mkdir -p "$ANDROID_HOME/cmdline-tools"
    CMDLINE_ZIP="$VENDOR/cmdline-tools.zip"
    c_info "downloading Android cmdline-tools (Linux)"
    curl -fsSL -o "$CMDLINE_ZIP" \
        "https://dl.google.com/android/repository/commandlinetools-linux-13114758_latest.zip"
    rm -rf "$ANDROID_HOME/cmdline-tools/latest"
    unzip -q "$CMDLINE_ZIP" -d "$ANDROID_HOME/cmdline-tools/"
    mv "$ANDROID_HOME/cmdline-tools/cmdline-tools" "$ANDROID_HOME/cmdline-tools/latest"
    rm "$CMDLINE_ZIP"
    export PATH="$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$PATH"
    SDKMANAGER="$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager"
    AVDMANAGER="$ANDROID_HOME/cmdline-tools/latest/bin/avdmanager"
    c_warn "Add to your shell profile so subsequent shells find these tools:"
    c_warn "  export ANDROID_HOME=\"$ANDROID_HOME\""
    c_warn "  export PATH=\"\$ANDROID_HOME/cmdline-tools/latest/bin:\$ANDROID_HOME/platform-tools:\$ANDROID_HOME/emulator:\$PATH\""
fi

if [[ -z "$SDKMANAGER" ]]; then
    c_err "could not locate sdkmanager. Install Android command-line tools manually."
    exit 1
fi

c_info "accepting SDK licenses + installing SDK packages (takes a few minutes)"
yes | "$SDKMANAGER" --licenses >/dev/null 2>&1 || true
"$SDKMANAGER" --install \
    "emulator" \
    "platform-tools" \
    "platforms;android-34" \
    "system-images;android-34;google_apis;${ANDROID_IMG_ARCH}"

# ─────────────────── AVD ───────────────────
c_step "AVD 'clawditor-pixel7'"
AVD_NAME="clawditor-pixel7"
if "$AVDMANAGER" list avd 2>/dev/null | grep -q "Name: ${AVD_NAME}\b"; then
    c_ok "AVD '${AVD_NAME}' already exists"
else
    c_info "creating AVD '${AVD_NAME}' (Pixel 7, API 34, google_apis ${ANDROID_IMG_ARCH})"
    echo "no" | "$AVDMANAGER" create avd \
        --name "${AVD_NAME}" \
        --package "system-images;android-34;google_apis;${ANDROID_IMG_ARCH}" \
        --device "pixel_7" \
        --force
fi

# ─────────────────── frida-server ───────────────────
c_step "frida-server (matched to Android emulator arch)"
FRIDA_BIN="$VENDOR/frida-server-${FRIDA_ARCH}"
if [[ -f "$FRIDA_BIN" ]]; then
    c_ok "frida-server present at $FRIDA_BIN"
else
    c_info "resolving latest frida release tag"
    FRIDA_TAG="$(curl -fsSL https://api.github.com/repos/frida/frida/releases/latest \
        | grep -E '"tag_name"' | head -1 | sed -E 's/.*"([^"]+)".*/\1/')"
    [[ -n "$FRIDA_TAG" ]] || { c_err "could not resolve latest frida tag (rate-limited?)"; exit 1; }
    XZ="$VENDOR/frida-server-${FRIDA_TAG}-android-${FRIDA_ARCH}.xz"
    URL="https://github.com/frida/frida/releases/download/${FRIDA_TAG}/frida-server-${FRIDA_TAG}-android-${FRIDA_ARCH}.xz"
    c_info "downloading $URL"
    curl -fL --progress-bar -o "$XZ" "$URL"
    xz -d -f "$XZ"
    mv "$VENDOR/frida-server-${FRIDA_TAG}-android-${FRIDA_ARCH}" "$FRIDA_BIN"
    chmod 755 "$FRIDA_BIN"
    c_ok "frida-server ${FRIDA_TAG} ready at $FRIDA_BIN"
fi

# ─────────────────── disable-flutter-tls Frida script ───────────────────
c_step "NVISO disable-flutter-tls Frida script"
FLUTTER_SCRIPT="$SCRIPTS_DIR/disable-flutter-tls.js"
if [[ -f "$FLUTTER_SCRIPT" ]]; then
    c_ok "disable-flutter-tls.js present"
else
    c_info "downloading from NVISOsecurity/disable-flutter-tls-verification"
    # The repo is named ...-verification but the script inside is just
    # disable-flutter-tls.js (the old ...-verification.js URL 404s now).
    FLUTTER_URL="https://raw.githubusercontent.com/NVISOsecurity/disable-flutter-tls-verification/main/disable-flutter-tls.js"
    if ! curl -fsSI "$FLUTTER_URL" >/dev/null 2>&1; then
        c_err "URL not reachable: $FLUTTER_URL"
        c_err "Check upstream repo at https://github.com/NVISOsecurity/disable-flutter-tls-verification"
        exit 1
    fi
    curl -fsSL -o "$FLUTTER_SCRIPT" "$FLUTTER_URL"
    c_ok "disable-flutter-tls.js fetched"
fi

# ─────────────────── WireGuard Android client (for --wireguard transport) ───────────────────
# mitmproxy WireGuard mode needs a WG client on the device to capture apps that
# ignore the Android system proxy (Flutter/Dart). See docs/dynamic-analysis.md.
c_step "WireGuard Android client APK"
if compgen -G "$VENDOR/com.wireguard.android-*.apk" >/dev/null; then
    c_ok "WireGuard APK present"
else
    c_info "downloading latest from download.wireguard.com"
    WG_LATEST="$(curl -fsSL https://download.wireguard.com/android-client/ \
        | grep -oE 'com\.wireguard\.android-[0-9.]+\.apk' | sort -V | tail -1)"
    if [[ -n "$WG_LATEST" ]]; then
        curl -fsSL -o "$VENDOR/$WG_LATEST" "https://download.wireguard.com/android-client/$WG_LATEST"
        c_ok "WireGuard client $WG_LATEST fetched"
    else
        c_err "could not resolve a WireGuard APK from download.wireguard.com (skipping; --wireguard will fail until present)"
    fi
fi

# ─────────────────── httptoolkit unpinning scripts (AGPL — fetched, not vendored) ───────────────────
c_step "httptoolkit unpinning scripts (battle-tested 50+ pin hooks)"
HT_DIR="$SCRIPTS_DIR/httptoolkit"
mkdir -p "$HT_DIR"
HT_FILES=(
    android-certificate-unpinning.js
    android-certificate-unpinning-fallback.js
    android-disable-root-detection.js
    android-proxy-override.js
    android-system-certificate-injection.js
)
HT_BASE="https://raw.githubusercontent.com/httptoolkit/frida-interception-and-unpinning/main/android"
for f in "${HT_FILES[@]}"; do
    if [[ -f "$HT_DIR/$f" ]]; then
        c_ok "  $f already present"
    else
        c_info "  downloading $f"
        curl -fsSL -o "$HT_DIR/$f" "$HT_BASE/$f"
    fi
done

# ─────────────────── mitm CA cert + httptoolkit config.js ───────────────────
c_step "mitmproxy CA cert + httptoolkit config.js"
CA="$HOME/.mitmproxy/mitmproxy-ca-cert.cer"
if [[ -f "$CA" ]]; then
    c_ok "mitmproxy CA present at $CA"
    # Auto-generate httptoolkit config.js with our CA embedded — the unpinning
    # scripts ABOVE require it (they call `Java.use("java.lang.String").$new(CERT_PEM)`
    # to inject the mitmproxy CA into the in-process Java trust store).
    HT_CONFIG="$HT_DIR/config.js"
    cat > "$HT_CONFIG" <<EOF
// Auto-generated by setup-dynamic.sh — DO NOT EDIT (re-run setup to refresh).
// Used by vendor/scripts/httptoolkit/android-certificate-unpinning*.js.
const DEBUG_MODE = false;
const PROXY_HOST = '10.0.2.2';
const PROXY_PORT = 8080;
const CERT_PEM = \`$(cat "$CA")\`;
EOF
    c_ok "  wrote $HT_CONFIG with mitmproxy CA embedded"
else
    c_warn "$CA does not exist yet."
    c_warn "Run \`mitmproxy\` once (then quit with q) to generate it, then re-run this script"
    c_warn "to write vendor/scripts/httptoolkit/config.js (required by the unpinning scripts)."
fi

echo
echo "─────────────────────────────────────────────────────────────"
c_ok "setup-dynamic done."
echo
echo "  1. (one-time) mitmproxy   # then press q to quit — generates the CA"
echo "  2. uv run clawditor dynamic start"
echo "  3. uv run clawditor dynamic capture <package> [--flutter] [--duration 60]"
echo "─────────────────────────────────────────────────────────────"
