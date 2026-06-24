#!/usr/bin/env bash
# Reverse scripts/install-mac-provider.sh.
#
#   - Stops + unloads the LaunchAgent
#   - Removes the LaunchAgent plist
#   - Removes the installed binary at $COCORE_PREFIX/bin/cocore
#   - Optionally removes ~/.cocore (session + logs) when COCORE_PURGE=1
#
# Usage:
#   ./scripts/uninstall-mac-provider.sh
#   COCORE_PURGE=1 ./scripts/uninstall-mac-provider.sh    # also delete ~/.cocore

set -euo pipefail

readonly LABEL="dev.cocore.provider"
readonly MENUBAR_LABEL="dev.cocore.menubar"
COCORE_PREFIX="${COCORE_PREFIX:-$HOME/.local}"
COCORE_PURGE="${COCORE_PURGE:-0}"
readonly INSTALL_BIN="$COCORE_PREFIX/bin/cocore"
readonly STATE_DIR="$HOME/.cocore"
readonly LAUNCHAGENT_PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
readonly MENUBAR_PLIST="$HOME/Library/LaunchAgents/$MENUBAR_LABEL.plist"

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "this script targets macOS; detected $(uname -s)" >&2
  exit 1
fi

bold "==> stop LaunchAgent"
domain="gui/$(id -u)"
if launchctl print "$domain/$LABEL" >/dev/null 2>&1; then
  launchctl bootout "$domain/$LABEL" 2>/dev/null || true
  note "stopped $LABEL"
else
  note "not loaded"
fi

bold "==> remove LaunchAgent plist"
if [[ -f "$LAUNCHAGENT_PLIST" ]]; then
  rm -f "$LAUNCHAGENT_PLIST"
  note "removed $LAUNCHAGENT_PLIST"
else
  note "$LAUNCHAGENT_PLIST not found"
fi

# Menu-bar companion (installed by default since the menubar feature
# landed; older installs simply won't have it loaded).
bold "==> stop + remove menu-bar companion"
if launchctl print "$domain/$MENUBAR_LABEL" >/dev/null 2>&1; then
  launchctl bootout "$domain/$MENUBAR_LABEL" 2>/dev/null || true
  note "stopped $MENUBAR_LABEL"
else
  note "not loaded"
fi
if [[ -f "$MENUBAR_PLIST" ]]; then
  rm -f "$MENUBAR_PLIST"
  note "removed $MENUBAR_PLIST"
else
  note "$MENUBAR_PLIST not found"
fi

# Reap anything still running before we delete its files. `bootout`
# above covers the launchd-supervised agent, but not an app-supervised
# or manually-started one — and never the Python inference engines it
# spawns (`cocore_inference_server.py`, one per served model). Those
# reparent to launchd when the agent goes and, unsignalled, survive the
# uninstall holding hundreds of MB of RAM. Newer agents self-reap via a
# parent-death watchdog; this sweep covers older ones and mid-startup
# kills. Engines first (no agent left to respawn them), then the agent.
bold "==> stop running processes"
reap_pattern() {
  local label="$1" pattern="$2" pids
  pids="$(pgrep -f "$pattern" 2>/dev/null || true)"
  if [[ -z "$pids" ]]; then
    note "no $label running"
    return 0
  fi
  note "stopping $label"
  # shellcheck disable=SC2086
  echo $pids | tr ' ' '\n' | while read -r pid; do [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true; done
  sleep 1
  # shellcheck disable=SC2086
  echo $pids | tr ' ' '\n' | while read -r pid; do
    [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null || true
  done
}
reap_pattern "inference engine(s)" "cocore_inference_server.py"
reap_pattern "agent process(es)" "cocore(-provider)? agent serve"

bold "==> remove installed binary"
if [[ -f "$INSTALL_BIN" ]]; then
  rm -f "$INSTALL_BIN"
  note "removed $INSTALL_BIN"
else
  note "$INSTALL_BIN not found"
fi

if [[ "$COCORE_PURGE" == "1" ]]; then
  bold "==> purge ~/.cocore (COCORE_PURGE=1)"
  if [[ -d "$STATE_DIR" ]]; then
    rm -rf "$STATE_DIR"
    note "removed $STATE_DIR"
  else
    note "$STATE_DIR not found"
  fi
else
  note "leaving session + logs at $STATE_DIR (set COCORE_PURGE=1 to delete)"
fi

bold "==> done"
