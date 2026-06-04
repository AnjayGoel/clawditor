#!/usr/bin/env bash
# Install / verify the external tools that the STATIC clawditor pipeline needs.
# Cross-platform: macOS (brew) + Linux (apt / dnf / pacman / apk / zypper).
# Idempotent — re-running is safe.
#
# For DYNAMIC-analysis prerequisites (emulator, frida-server, mitmproxy):
#   ./scripts/setup-dynamic.sh
#
# Usage:
#   ./scripts/bootstrap.sh              # install missing deps
#   ./scripts/bootstrap.sh --check      # just check, exit 1 if anything missing

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENDOR="$ROOT/vendor"
. "$ROOT/scripts/_lib.sh"
detect_platform

CHECK_ONLY=0
[[ "${1:-}" == "--check" ]] && CHECK_ONLY=1

mkdir -p "$VENDOR"

c_step "platform: $OS / $ARCH ($PKG_MGR)"

# ─────────────────── 1. Python project deps via uv ───────────────────
c_step "Python project deps"
if has uv; then
    c_ok "uv found"
    [[ $CHECK_ONLY -eq 0 ]] && (cd "$ROOT" && uv sync --quiet)
else
    c_err "uv not installed."
    case "$PKG_MGR" in
        brew)              c_info "brew install uv" ;;
        apt|dnf|yum|apk|zypper) c_info "curl -LsSf https://astral.sh/uv/install.sh | sh" ;;
        pacman)            c_info "pacman -S uv" ;;
    esac
    [[ $CHECK_ONLY -eq 0 ]] && {
        if [[ "$PKG_MGR" == "brew" ]]; then brew install uv;
        else curl -LsSf https://astral.sh/uv/install.sh | sh; fi
    }
fi

# ─────────────────── 2. Java (OpenJDK 17+) ───────────────────
c_step "Java (OpenJDK 17+)"
if has java; then
    JAVA_VER=$(java -version 2>&1 | head -1 | sed -E 's/.*"([0-9]+).*/\1/')
    if [[ "${JAVA_VER:-0}" -ge 17 ]]; then
        c_ok "java $JAVA_VER on PATH"
    else
        c_warn "java $JAVA_VER too old (need ≥17)"
        [[ $CHECK_ONLY -eq 0 ]] && pkg_install openjdk-17-jdk \
            brew=openjdk@17 dnf=java-17-openjdk-devel pacman=jdk17-openjdk \
            apk=openjdk17 zypper=java-17-openjdk-devel
    fi
else
    if [[ $CHECK_ONLY -eq 1 ]]; then
        c_err "java not installed"; exit 1
    fi
    if [[ "$PKG_MGR" == "brew" ]]; then
        # On macOS prefer the Temurin cask (handles JAVA_HOME linking)
        brew_cask_install temurin
    else
        pkg_install openjdk-17-jdk \
            dnf=java-17-openjdk-devel pacman=jdk17-openjdk \
            apk=openjdk17 zypper=java-17-openjdk-devel
    fi
fi

# ─────────────────── 3. ADB (android-platform-tools) ───────────────────
c_step "ADB (android-platform-tools)"
if has adb; then
    c_ok "adb found at $(command -v adb)"
else
    if [[ $CHECK_ONLY -eq 1 ]]; then c_err "adb missing"; exit 1; fi
    if [[ "$PKG_MGR" == "brew" ]]; then
        brew install --cask android-platform-tools
    else
        pkg_install android-tools dnf=android-tools apk=android-tools \
            pacman=android-tools zypper=android-tools
    fi
fi

# ─────────────────── 4. jadx (DEX → Java) ───────────────────
c_step "jadx"
if has jadx; then
    c_ok "jadx found"
else
    if [[ $CHECK_ONLY -eq 1 ]]; then c_err "jadx missing"; exit 1; fi
    if [[ "$PKG_MGR" == "brew" ]]; then
        brew install jadx
    elif [[ "$PKG_MGR" == "pacman" ]]; then
        $SUDO pacman -S --noconfirm --needed jadx
    else
        # Download release tarball
        JADX_VER="1.5.5"
        c_info "downloading jadx $JADX_VER release"
        curl -sSL -o "$VENDOR/jadx.zip" \
            "https://github.com/skylot/jadx/releases/download/v${JADX_VER}/jadx-${JADX_VER}.zip"
        rm -rf "$VENDOR/jadx" && mkdir -p "$VENDOR/jadx"
        unzip -q "$VENDOR/jadx.zip" -d "$VENDOR/jadx"
        rm "$VENDOR/jadx.zip"
        $SUDO ln -sf "$VENDOR/jadx/bin/jadx" /usr/local/bin/jadx
        c_ok "jadx installed at /usr/local/bin/jadx → $VENDOR/jadx/bin/jadx"
    fi
fi

# ─────────────────── 5. trufflehog ───────────────────
c_step "trufflehog"
if has trufflehog; then
    c_ok "trufflehog found"
else
    if [[ $CHECK_ONLY -eq 1 ]]; then c_err "trufflehog missing"; exit 1; fi
    if [[ "$PKG_MGR" == "brew" ]]; then
        brew install trufflehog
    else
        c_info "installing trufflehog (curl install script)"
        curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
            | $SUDO sh -s -- -b /usr/local/bin
    fi
fi

# ─────────────────── 6. apkleaks + hermes-dec via pipx ───────────────────
c_step "apkleaks + hermes-dec (pipx)"
[[ $CHECK_ONLY -eq 0 ]] && ensure_pipx
ensure_pipx_pkg apkleaks
ensure_pipx_pkg hermes-dec hbc-decompiler

# ─────────────────── 7. APKEditor.jar ───────────────────
c_step "APKEditor.jar"
if [[ -f "$VENDOR/APKEditor.jar" ]]; then
    c_ok "APKEditor.jar present"
else
    if [[ $CHECK_ONLY -eq 1 ]]; then c_err "APKEditor.jar missing"; exit 1; fi
    APKED_VER="1.4.3"
    c_info "downloading APKEditor $APKED_VER"
    curl -sSL -o "$VENDOR/APKEditor.jar" \
        "https://github.com/REAndroid/APKEditor/releases/download/V${APKED_VER}/APKEditor-${APKED_VER}.jar"
    c_ok "APKEditor.jar saved to $VENDOR/APKEditor.jar"
fi

# ─────────────────── 8. Optional: ripgrep (faster code scans) ───────────────────
c_step "ripgrep (optional, faster code_patterns scan)"
if has rg; then
    c_ok "rg found"
else
    if [[ $CHECK_ONLY -eq 0 ]]; then
        pkg_install ripgrep brew=ripgrep dnf=ripgrep pacman=ripgrep apk=ripgrep zypper=ripgrep || true
    else
        c_warn "rg not installed — falls back to grep, slower but works"
    fi
fi

# ─────────────────── done ───────────────────
echo
if [[ $CHECK_ONLY -eq 1 ]]; then
    c_ok "All static-pipeline deps present."
else
    c_ok "Bootstrap complete. Verify with: uv run clawditor check"
    c_info "For dynamic analysis (emulator + mitmproxy + frida), next run: ./scripts/setup-dynamic.sh"
fi
