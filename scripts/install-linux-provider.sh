#!/usr/bin/env bash
# Install the cocore agent on Linux from a prebuilt binary.
#
# The Linux counterpart to scripts/install-from-tarball.sh (macOS). It does the
# install / pair / systemd-service phases. The big difference from macOS: there
# is no Python venv to bootstrap (vllm-mlx is Apple-only). Linux inference runs
# through `llama-server` (llama.cpp), which the agent spawns and supervises — so
# this script just needs to know where your `llama-server` binary is. It does
# NOT build llama.cpp (that's GPU-backend-specific: CUDA / ROCm / Vulkan); build
# or install it yourself and point COCORE_LLAMA_SERVER_BIN at it (or have it on
# PATH and we'll detect it).
#
# Usage (after extracting the tarball, or from a source checkout's target/):
#   COCORE_LLAMA_SERVER_BIN=/usr/local/bin/llama-server ./install-linux-provider.sh
#
# Env knobs:
#   COCORE_CONSOLE          console URL      (default: https://console.cocore.dev)
#   COCORE_ADVISOR          advisor wss URL  (default: wss://advisor.cocore.dev/v1/agent)
#   COCORE_PREFIX           install prefix   (default: $HOME/.local)
#   COCORE_BIN              path to the cocore binary to install (default: autodetect)
#   COCORE_LLAMA_SERVER_BIN path to llama-server (default: autodetect on PATH)
#   COCORE_INFERENCE_MODELS optional bootstrap model set; the PDS desiredModels
#                           set (via `cocore agent models add`) overrides it
#   COCORE_SKIP_PAIR        1 to skip the device-pair step
#   COCORE_SKIP_SERVICE     1 to skip the systemd unit install

set -euo pipefail

readonly STAGE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

COCORE_CONSOLE="${COCORE_CONSOLE:-https://console.cocore.dev}"
COCORE_ADVISOR="${COCORE_ADVISOR:-wss://advisor.cocore.dev/v1/agent}"
COCORE_PREFIX="${COCORE_PREFIX:-$HOME/.local}"
COCORE_LOG="${COCORE_LOG:-info}"
COCORE_SKIP_PAIR="${COCORE_SKIP_PAIR:-0}"
COCORE_SKIP_SERVICE="${COCORE_SKIP_SERVICE:-0}"
COCORE_INFERENCE_MODELS="${COCORE_INFERENCE_MODELS:-${COCORE_INFERENCE_MODEL:-}}"

readonly INSTALL_BIN_DIR="$COCORE_PREFIX/bin"
readonly INSTALL_BIN="$INSTALL_BIN_DIR/cocore"
readonly STATE_DIR="$HOME/.cocore"
readonly LOG_DIR="$STATE_DIR/logs"
readonly ENV_FILE="$STATE_DIR/provider.env"
readonly UNIT_DIR="$HOME/.config/systemd/user"
readonly UNIT_NAME="cocore-provider.service"
readonly UNIT_PATH="$UNIT_DIR/$UNIT_NAME"
readonly UNIT_TEMPLATE="$STAGE/cocore-provider.service.template"

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }
warn() { printf '\033[33m  warn:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31m  error:\033[0m %s\n' "$*" >&2; exit 1; }
phase() { printf '\n'; bold "==> $*"; }

[[ "$(uname -s)" == "Linux" ]] || die "this installer targets Linux; detected $(uname -s)"

# Locate the binary to install: explicit override, else staged tarball layout,
# else a release/debug build in a sibling target/ dir.
COCORE_BIN="${COCORE_BIN:-}"
if [[ -z "$COCORE_BIN" ]]; then
  for cand in "$STAGE/bin/cocore" "$STAGE/cocore" \
              "$STAGE/../provider/target/release/cocore" \
              "$STAGE/../target/release/cocore"; do
    [[ -x "$cand" ]] && { COCORE_BIN="$cand"; break; }
  done
fi
[[ -n "$COCORE_BIN" && -x "$COCORE_BIN" ]] || die "could not find the cocore binary; set COCORE_BIN=/path/to/cocore"
[[ -f "$UNIT_TEMPLATE" ]] || die "systemd unit template not found at $UNIT_TEMPLATE"

# Locate llama-server (the inference backend the agent spawns). Not fatal — the
# agent serves the stub engine until it's set — but warn loudly.
if [[ -z "${COCORE_LLAMA_SERVER_BIN:-}" ]]; then
  COCORE_LLAMA_SERVER_BIN="$(command -v llama-server || true)"
fi

phase "preflight"
note "console: $COCORE_CONSOLE"
note "advisor: $COCORE_ADVISOR"
note "prefix:  $COCORE_PREFIX"
note "binary:  $COCORE_BIN"
note "arch:    $(uname -m)"
if [[ -n "$COCORE_LLAMA_SERVER_BIN" ]]; then
  note "llama-server: $COCORE_LLAMA_SERVER_BIN"
else
  warn "no llama-server found. The agent will serve 'stub' only until you set"
  warn "COCORE_LLAMA_SERVER_BIN in $ENV_FILE and restart. Build llama.cpp with"
  warn "your GPU backend (CUDA/ROCm/Vulkan) — https://github.com/ggml-org/llama.cpp"
fi

phase "install binary"
mkdir -p "$INSTALL_BIN_DIR" "$STATE_DIR" "$LOG_DIR"
chmod 700 "$STATE_DIR"
install -m 755 "$COCORE_BIN" "$INSTALL_BIN"
note "installed: $INSTALL_BIN"
case ":$PATH:" in
  *":$INSTALL_BIN_DIR:"*) ;;
  *) warn "$INSTALL_BIN_DIR is not on PATH. Add: export PATH=\"$INSTALL_BIN_DIR:\$PATH\"" ;;
esac

phase "write environment file"
# Static config only. The DYNAMIC model set flows through PDS desiredModels
# (set via `cocore agent models add`); COCORE_INFERENCE_MODELS below is just a
# bootstrap default the serve loop falls back to when desiredModels is empty.
{
  echo "# cocore agent static config — read by $UNIT_NAME (EnvironmentFile)."
  echo "# The model set is managed via 'cocore agent models …' (PDS desiredModels);"
  echo "# COCORE_INFERENCE_MODELS here is only a pre-pairing bootstrap default."
  echo "COCORE_CONSOLE=$COCORE_CONSOLE"
  echo "COCORE_ADVISOR=$COCORE_ADVISOR"
  echo "COCORE_LOG=$COCORE_LOG"
  [[ -n "$COCORE_LLAMA_SERVER_BIN" ]] && echo "COCORE_LLAMA_SERVER_BIN=$COCORE_LLAMA_SERVER_BIN"
  [[ -n "$COCORE_INFERENCE_MODELS" ]] && echo "COCORE_INFERENCE_MODELS=$COCORE_INFERENCE_MODELS"
} > "$ENV_FILE.tmp"
mv "$ENV_FILE.tmp" "$ENV_FILE"
chmod 600 "$ENV_FILE"
note "wrote $ENV_FILE"

# Pair flow. Under `curl … | sh` stdin isn't a TTY; treat that like
# COCORE_SKIP_PAIR=1 and tell the user to pair manually afterward.
if [[ ! -t 0 && "$COCORE_SKIP_PAIR" != "1" ]]; then
  warn "stdin is not a TTY; setting COCORE_SKIP_PAIR=1 — run 'cocore agent pair' after install."
  COCORE_SKIP_PAIR=1
fi
if [[ "$COCORE_SKIP_PAIR" == "1" ]]; then
  phase "pair (skipped)"
  note "run: $INSTALL_BIN agent pair --console $COCORE_CONSOLE"
elif [[ -f "$STATE_DIR/session.json" ]]; then
  phase "pair (existing session)"
  "$INSTALL_BIN" agent whoami || true
else
  phase "pair with ATProto identity"
  COCORE_CONSOLE="$COCORE_CONSOLE" "$INSTALL_BIN" agent pair --console "$COCORE_CONSOLE"
fi

if [[ "$COCORE_SKIP_SERVICE" == "1" ]]; then
  phase "systemd unit (skipped, COCORE_SKIP_SERVICE=1)"
else
  phase "install systemd user unit"
  command -v systemctl >/dev/null 2>&1 || die "systemctl not found; this host doesn't use systemd. Run '$INSTALL_BIN agent serve' under your own supervisor."
  mkdir -p "$UNIT_DIR"
  sed -e "s|@@BIN@@|$INSTALL_BIN|g" "$UNIT_TEMPLATE" > "$UNIT_PATH.tmp"
  mv "$UNIT_PATH.tmp" "$UNIT_PATH"
  note "wrote $UNIT_PATH"
  systemctl --user daemon-reload
  systemctl --user enable --now "$UNIT_NAME"
  # Linger lets the user unit keep running without an active login session
  # (the parity for the LaunchAgent surviving logout). Best-effort: needs
  # either passwordless sudo or the user's own loginctl permission.
  if ! loginctl enable-linger "$USER" 2>/dev/null; then
    warn "could not enable linger for $USER. The service stops when you log out."
    warn "Run: sudo loginctl enable-linger $USER"
  fi
  note "systemctl status:"
  systemctl --user --no-pager --lines=0 status "$UNIT_NAME" 2>/dev/null | grep -E 'Active:|Loaded:' || true
fi

phase "done"
note "Binary:       $INSTALL_BIN"
note "Env file:     $ENV_FILE"
note "Session:      $STATE_DIR/session.json"
note "Unit:         $UNIT_PATH"
note "Logs:         journalctl --user -u $UNIT_NAME -f   (+ $LOG_DIR/agent.log)"
note "Add a model:  $INSTALL_BIN agent models add <gguf-hf-repo>   e.g. bartowski/Qwen2.5-7B-Instruct-GGUF"
