#!/usr/bin/env bash
# Shared helpers for setup scripts — cross-platform install abstraction.
# Source from other scripts: `. "$(dirname "$0")/_lib.sh"`

set -euo pipefail

# Bright output helpers
c_ok()   { printf '\033[32m✓\033[0m %s\n' "$*"; }
c_warn() { printf '\033[33m![\033[0m] %s\n' "$*"; }
c_err()  { printf '\033[31m✗\033[0m %s\n' "$*" >&2; }
c_info() { printf '\033[36m·\033[0m %s\n' "$*"; }
c_step() { printf '\n\033[1;34m==>\033[0m %s\n' "$*"; }

# Platform detection.  Exports: OS, ARCH, PKG_MGR, SUDO
detect_platform() {
    OS="$(uname -s)"
    ARCH_RAW="$(uname -m)"
    case "$ARCH_RAW" in
        arm64|aarch64) ARCH="arm64" ;;
        x86_64|amd64)  ARCH="x86_64" ;;
        *) c_err "unsupported arch: $ARCH_RAW"; exit 1 ;;
    esac

    SUDO=""
    if [[ "$OS" == "Linux" ]]; then
        [[ "$EUID" -ne 0 ]] && SUDO="sudo"
        if   command -v apt-get >/dev/null;  then PKG_MGR="apt"
        elif command -v dnf >/dev/null;      then PKG_MGR="dnf"
        elif command -v yum >/dev/null;      then PKG_MGR="yum"
        elif command -v pacman >/dev/null;   then PKG_MGR="pacman"
        elif command -v apk >/dev/null;      then PKG_MGR="apk"
        elif command -v zypper >/dev/null;   then PKG_MGR="zypper"
        else
            c_err "unsupported Linux distro — no apt/dnf/yum/pacman/apk/zypper found"
            c_err "Install dependencies manually; see docs/dynamic-analysis.md"
            exit 1
        fi
    elif [[ "$OS" == "Darwin" ]]; then
        PKG_MGR="brew"
        if ! command -v brew >/dev/null; then
            c_err "Homebrew not installed. Install from https://brew.sh first."
            exit 1
        fi
    else
        c_err "unsupported OS: $OS"
        exit 1
    fi
    export OS ARCH PKG_MGR SUDO
}

# Try to install a system package by name.  Pass per-manager name overrides as
# subsequent args: KEY=val (e.g. apt=android-tools-adb dnf=android-tools)
# Usage: pkg_install <generic-name> [apt=...] [dnf=...] [pacman=...] [apk=...] [zypper=...] [brew=...]
pkg_install() {
    local generic="$1"; shift
    local name="$generic"
    for arg in "$@"; do
        case "$arg" in
            "${PKG_MGR}="*) name="${arg#*=}" ;;
        esac
    done
    c_info "installing system package: $name (via $PKG_MGR)"
    case "$PKG_MGR" in
        brew)   brew install "$name" ;;
        apt)    $SUDO apt-get update -qq && $SUDO apt-get install -y "$name" ;;
        dnf)    $SUDO dnf install -y "$name" ;;
        yum)    $SUDO yum install -y "$name" ;;
        pacman) $SUDO pacman -S --noconfirm --needed "$name" ;;
        apk)    $SUDO apk add --no-cache "$name" ;;
        zypper) $SUDO zypper install -y "$name" ;;
    esac
}

# Try to install a cask (macOS only); on Linux, expects the caller to know
# this is a no-op or use pkg_install with appropriate override.
brew_cask_install() {
    local cask="$1"
    if [[ "$PKG_MGR" != "brew" ]]; then
        c_warn "cask '$cask' is macOS-only; skipping"
        return 0
    fi
    if brew list --cask "$cask" >/dev/null 2>&1; then
        c_ok "$cask already installed (cask)"
        return 0
    fi
    c_info "installing brew cask: $cask"
    brew install --cask "$cask"
}

# Make sure pipx is available (user-scope, no sudo).
ensure_pipx() {
    if command -v pipx >/dev/null; then
        c_ok "pipx already installed"
        return 0
    fi
    c_info "installing pipx"
    case "$PKG_MGR" in
        brew)               brew install pipx ;;
        apt)                $SUDO apt-get install -y pipx || $SUDO apt-get install -y python3-pip && python3 -m pip install --user pipx ;;
        dnf|yum)            $SUDO "$PKG_MGR" install -y pipx || python3 -m pip install --user pipx ;;
        pacman)             $SUDO pacman -S --noconfirm --needed python-pipx ;;
        apk)                $SUDO apk add py3-pipx ;;
        zypper)             $SUDO zypper install -y python3-pipx || python3 -m pip install --user pipx ;;
    esac
    # ensure ~/.local/bin is on PATH (pipx default)
    if ! echo "$PATH" | grep -q "$HOME/.local/bin"; then
        c_warn 'add ~/.local/bin to your PATH (e.g. `export PATH="$HOME/.local/bin:$PATH"`)'
    fi
    pipx ensurepath || true
}

ensure_pipx_pkg() {
    local pkg="$1"
    local bin="${2:-$1}"
    if command -v "$bin" >/dev/null; then
        c_ok "$pkg already installed ($bin on PATH)"
        return 0
    fi
    ensure_pipx
    c_info "pipx install $pkg"
    pipx install "$pkg"
}

# Generic "is this command on PATH?" check.
has() { command -v "$1" >/dev/null 2>&1; }
