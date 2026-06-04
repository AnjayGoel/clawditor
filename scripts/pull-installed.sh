#!/usr/bin/env bash
# Pull all third-party APKs (-3 = non-system) installed on the connected ADB
# device to working/<package>/. Skips packages whose base.apk is already there.
#
# Usage:
#   ./scripts/pull-installed.sh                 # all third-party apps
#   ./scripts/pull-installed.sh --since 7       # apps installed in last 7 days
#   ./scripts/pull-installed.sh --pkg com.x     # only one package

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="$ROOT/working"
mkdir -p "$DEST"

ADB="${ADB:-adb}"
SINCE_DAYS=""
ONE_PKG=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --since) SINCE_DAYS="$2"; shift 2;;
    --pkg)   ONE_PKG="$2"; shift 2;;
    -h|--help)
      sed -n '2,12p' "$0"; exit 0;;
    *) echo "unknown arg: $1" >&2; exit 1;;
  esac
done

if ! command -v "$ADB" >/dev/null; then
  echo "adb not found" >&2; exit 1
fi

DEVICE_COUNT=$("$ADB" devices | tail -n +2 | grep -c "device$" || true)
if [[ "$DEVICE_COUNT" -lt 1 ]]; then
  echo "no ADB devices connected" >&2; exit 1
fi

if [[ -n "$ONE_PKG" ]]; then
  PKGS="$ONE_PKG"
elif [[ -n "$SINCE_DAYS" ]]; then
  # Use dumpsys to get firstInstallTime per package, filter to last N days.
  CUTOFF=$(python3 -c "from datetime import datetime, timedelta; print((datetime.now()-timedelta(days=$SINCE_DAYS)).strftime('%Y-%m-%d'))")
  echo "==> filtering to packages installed since $CUTOFF"
  PKGS=$("$ADB" shell "for pkg in \$(pm list packages -3 | sed 's/package://'); do t=\$(dumpsys package \$pkg | grep firstInstallTime | head -1 | awk -F= '{print \$2}' | cut -d' ' -f1); echo \"\$t \$pkg\"; done" \
        | awk -v c="$CUTOFF" '$1 >= c {print $2}')
else
  PKGS=$("$ADB" shell "pm list packages -3" | sed 's/package://' | tr -d '\r')
fi

if [[ -z "${PKGS// }" ]]; then
  echo "no packages matched"; exit 0
fi

echo "==> will pull:"
echo "$PKGS" | sed 's/^/   /'
echo

for pkg in $PKGS; do
  pkg=$(echo "$pkg" | tr -d '\r')
  [[ -z "$pkg" ]] && continue
  pkg_dir="$DEST/$pkg"
  mkdir -p "$pkg_dir"
  if [[ -f "$pkg_dir/base.apk" ]]; then
    echo "[skip] $pkg (already pulled)"
    continue
  fi
  echo "[pull] $pkg"
  paths=$("$ADB" shell "pm path $pkg" | sed 's/package://' | tr -d '\r')
  i=0
  for p in $paths; do
    p=$(echo "$p" | tr -d '\r')
    [[ -z "$p" ]] && continue
    if [[ "$i" = "0" ]]; then out="$pkg_dir/base.apk"; else out="$pkg_dir/split$i.apk"; fi
    "$ADB" pull "$p" "$out" >/dev/null 2>&1 && echo "         $out" || echo "         FAILED $p"
    i=$((i+1))
  done
done

echo
echo "==> done. Pulled APKs are at $DEST/<package>/"
echo "==> run a pipeline against one:"
echo "    cd $ROOT && uv run clawditor run --apk working/<package>/"
