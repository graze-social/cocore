#!/usr/bin/env bash
# cocore agent installer — the curl-pipe-sh entrypoint.
#
# Hosted at https://cocore.dev/agent. v0.6.0 collapsed the
# previous stub vs. inference variants into a single install path
# (see the doc-comment on `release.yml` for the dyld-crash that
# motivated it). Every install now:
#
#   1. Picks a model interactively from /dev/tty (the picker walks
#      the curated catalog filtered by detected RAM).
#   2. Downloads the cocore tarball.
#   3. Installs the binary at `~/.local/bin/cocore`.
#   4. Bootstraps a uv-managed Python venv at `~/.cocore/python`
#      with vllm-mlx — the runtime the subprocess engine spawns.
#      No system Python required; uv downloads its own
#      python-build-standalone (~30MB) under `~/.local/share/uv/`.
#   5. Writes + bootstraps the LaunchAgent (suspended until pair).
#   6. Pairs with the user's ATProto identity (URL printed to the
#      terminal; user approves in any browser).
#   7. Waits for the new provider record to land on the AppView
#      before exiting, so a successful curl-pipe-sh exit means
#      "your machine is registered and serving."
#
# Usage:
#   curl -fsSL https://cocore.dev/agent | sh
#
#   # skip the picker by pre-setting the env var:
#   curl -fsSL https://cocore.dev/agent | \
#     COCORE_INFERENCE_MODELS=mlx-community/Qwen2.5-3B-Instruct-4bit sh
#
# ## Why the script prompts before downloading
#
# When `COCORE_INFERENCE_MODELS` isn't preset, the script opens
# `/dev/tty` for an interactive picker — detects this machine's RAM,
# filters the catalog (mirrored from `provider/src/pricing.rs` and
# `packages/console/src/components/start/provider-model-catalog.ts`),
# defaults to the largest model that fits, and lets the user accept,
# pick another, or paste a free-form HuggingFace NSID.
#
# `/dev/tty` is the controlling terminal regardless of whether stdin
# is piped — the same trick `brew install`, `rustup`, and other
# curl-pipe-sh installers use. When `/dev/tty` isn't available (CI,
# remote SSH with no allocated PTY), the picker falls back to the
# default for the detected RAM and prints what it chose.
#
# Knobs (all optional):
#   COCORE_PREFIX            install prefix    (default: $HOME/.local)
#   COCORE_RELEASE_TAG       pin a release tag (default: latest)
#   COCORE_INSTALL_BASE      override console-side base URL
#                            (default: https://cocore.dev/agent)
#   COCORE_INFERENCE_MODELS  comma-separated HF model ids
#                            (default: picked interactively from /dev/tty,
#                            or the largest catalog entry that fits if
#                            no TTY is attached)
#   COCORE_PYTHON_VENV       venv root (default: $HOME/.cocore/python)
#   COCORE_SKIP_VENV         1 to skip the venv bootstrap if you've
#                            already got a working one — or if every model
#                            you serve is attached to your own server via
#                            ~/.cocore/engine-map (docs/attached-engine.md)
#   COCORE_SKIP_PICKER       1 to skip the interactive picker and use
#                            the default for the detected RAM.
#   COCORE_SKIP_PAIR         1 to skip pairing (binary + plist installed
#                            but suspended; user runs `cocore agent pair`
#                            later).
#   COCORE_SKIP_SERVICE      1 to skip the LaunchAgent.
#                            (installed by default; headless installs
#                            degrade to a warning automatically).

set -euo pipefail

COCORE_PREFIX="${COCORE_PREFIX:-$HOME/.local}"
COCORE_INSTALL_BASE="${COCORE_INSTALL_BASE:-https://cocore.dev/agent}"
COCORE_RELEASE_TAG="${COCORE_RELEASE_TAG:-}"
COCORE_SKIP_PICKER="${COCORE_SKIP_PICKER:-0}"
# Capture the user's pair intent BEFORE we override
# COCORE_SKIP_PAIR=1 for the bundled installer (below). The bundled
# installer's pair step is buggy under curl-pipe-sh; we run pair
# ourselves from the wrapper after install completes, where we
# control the flow. COCORE_SKIP_PAIR=1 at the curl-call level still
# opts out of pairing entirely (e.g. unattended CI, headless box
# that'll be paired later by an operator).
USER_REQUESTED_SKIP_PAIR="${COCORE_SKIP_PAIR:-0}"

readonly INSTALL_BIN="$COCORE_PREFIX/bin/cocore"
readonly STATE_DIR="$HOME/.cocore"
readonly LOG_DIR="$STATE_DIR/logs"

# Catalog mirror — keep in sync with:
#   * provider/src/pricing.rs              (Rust source of truth)
#   * packages/console/src/components/start/provider-model-catalog.ts
#     (web /start picker)
# Each entry: id | min_ram_gb | one-line description. Order is
# small → large so the menu walks intuitively. Stub is excluded
# because the stub engine is always loaded; adding it to
# COCORE_INFERENCE_MODELS is a no-op.
readonly CATALOG_IDS=(
  "mlx-community/Qwen2.5-0.5B-Instruct-4bit"
  "mlx-community/Qwen2.5-3B-Instruct-4bit"
  "mlx-community/gemma-3-4b-it-qat-4bit"
  "mlx-community/Qwen2.5-7B-Instruct-4bit"
  "mlx-community/Qwen2.5-32B-Instruct-4bit"
  "mlx-community/Llama-3.3-70B-Instruct-4bit"
)
readonly CATALOG_MIN_RAM=(4 8 8 16 32 64)
readonly CATALOG_DESCS=(
  "Qwen 0.5B — fast, low quality; fits any Apple Silicon"
  "Qwen 3B — small but coherent; tight on 8GB"
  "Gemma 3 4B QAT — balanced default for 8GB+ Macs"
  "Qwen 7B — strong general-purpose; 16GB+ recommended"
  "Qwen 32B — frontier-class; 32GB+ Mac Studio class"
  "Llama 3.3 70B — heavyweight; 64GB+ Mac Studio class"
)

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }
warn() { printf '\033[33m  warn:\033[0m %s\n' "$*" >&2; }
err()  { printf '\033[31m  error:\033[0m %s\n' "$*" >&2; }
die()  { err "$*"; exit 1; }
phase(){ printf '\n'; bold "==> $*"; }

# --- preflight ---------------------------------------------------------

phase "preflight"
if [[ "$(uname -s)" != "Darwin" ]]; then
  die "this installer is macOS-only (got $(uname -s))."
fi
arch="$(uname -m)"
if [[ "$arch" != "arm64" ]]; then
  die "the inference build only ships an Apple Silicon (arm64) binary; got $arch."
fi
note "arch: arm64 (Apple Silicon)"
# Detect RAM up front so the picker phase can default to the largest
# model that fits. hw.memsize is bytes; integer-divide to GB. A bare
# `sysctl -n` failure shouldn't kill the install — fall back to a
# small default that fits any Apple Silicon Mac.
ram_bytes="$(sysctl -n hw.memsize 2>/dev/null || echo 0)"
RAM_GB=$(( ram_bytes / 1024 / 1024 / 1024 ))
if (( RAM_GB <= 0 )); then
  warn "could not detect RAM via sysctl hw.memsize; defaulting to 8GB for picker math."
  RAM_GB=8
fi
note "ram:  ${RAM_GB} GB"
if ! xcode-select -p >/dev/null 2>&1; then
  warn "Xcode Command Line Tools missing — install with 'xcode-select --install'. The Python venv bootstrap may need them to compile native wheels."
fi

# --- pick a release ----------------------------------------------------

phase "release"
if [[ -z "$COCORE_RELEASE_TAG" ]]; then
  resp="$(curl -fsSL "$COCORE_INSTALL_BASE/version" 2>/dev/null || true)"
  COCORE_RELEASE_TAG="$(printf '%s' "$resp" | tr -d '[:space:]')"
  [[ -n "$COCORE_RELEASE_TAG" ]] || die "could not read latest tag from $COCORE_INSTALL_BASE/version (response: $resp)"
fi
note "tag: $COCORE_RELEASE_TAG"

# --- pick a model ------------------------------------------------------
#
# Runs BEFORE the ~300MB tarball download so users don't burn bandwidth
# on a default they'd rather override. Three paths:
#
#   1. COCORE_INFERENCE_MODELS already set    → respect it, skip picker.
#   2. /dev/tty available + not COCORE_SKIP_PICKER → interactive prompt.
#   3. otherwise                               → default for detected RAM.
#
# We read from /dev/tty (not stdin) because under `curl … | sh` stdin
# is the pipe — but the controlling terminal is still attached, so
# /dev/tty works. Same pattern brew/rustup use.

phase "pick a model to serve"

# Find the default index: the LARGEST catalog entry whose min_ram <=
# detected RAM. Defaulting to the biggest that fits matches what a
# new provider usually wants ("the most capable model this Mac can
# run"). Stored as an absolute index into CATALOG_IDS; -1 means
# nothing fits (extremely-low-RAM machines).
default_idx=-1
for i in "${!CATALOG_IDS[@]}"; do
  if (( RAM_GB >= CATALOG_MIN_RAM[i] )); then
    default_idx=$i
  fi
done

if [[ -n "${COCORE_INFERENCE_MODELS:-}" ]]; then
  note "COCORE_INFERENCE_MODELS already set; skipping picker."
  note "model: $COCORE_INFERENCE_MODELS"
elif [[ "$COCORE_SKIP_PICKER" == "1" ]] || [[ ! -e /dev/tty ]]; then
  if (( default_idx < 0 )); then
    die "no catalog model fits ${RAM_GB}GB RAM and no COCORE_INFERENCE_MODELS preset. Set the env var explicitly: COCORE_INFERENCE_MODELS=<model-id>."
  fi
  COCORE_INFERENCE_MODELS="${CATALOG_IDS[$default_idx]}"
  if [[ "$COCORE_SKIP_PICKER" == "1" ]]; then
    note "COCORE_SKIP_PICKER=1; using default for ${RAM_GB}GB."
  else
    note "no /dev/tty (non-interactive shell); using default for ${RAM_GB}GB."
  fi
  note "model: $COCORE_INFERENCE_MODELS"
else
  if (( default_idx < 0 )); then
    note "no catalog model fits ${RAM_GB}GB; you'll need to paste a full HuggingFace NSID."
  fi
  note "Detected ${RAM_GB} GB RAM. Catalog (small → large; * = default):"
  echo
  for i in "${!CATALOG_IDS[@]}"; do
    fits=""
    if (( RAM_GB >= CATALOG_MIN_RAM[i] )); then
      fits=" "
    else
      fits="✗"  # doesn't fit RAM
    fi
    marker="  "
    if (( i == default_idx )); then marker="* "; fi
    printf '  %s%d) %s  [needs %dGB %s]\n' \
      "$marker" $((i + 1)) "${CATALOG_IDS[$i]}" "${CATALOG_MIN_RAM[$i]}" "$fits"
    printf '       %s\n' "${CATALOG_DESCS[$i]}"
  done
  echo
  note "Press Enter for the default, type a number 1-${#CATALOG_IDS[@]},"
  note "or paste a full HuggingFace NSID (org/model)."
  echo

  attempts=0
  picked=""
  while true; do
    attempts=$((attempts + 1))
    if (( attempts > 3 )); then
      warn "too many invalid attempts; using default."
      picked="${CATALOG_IDS[$default_idx]}"
      break
    fi
    printf '  > '
    # `|| true` so EOF on /dev/tty (closed terminal mid-install) doesn't
    # trip `set -e`; the empty `choice` falls through to the default.
    choice=""
    IFS= read -r choice < /dev/tty || true
    if [[ -z "$choice" ]]; then
      if (( default_idx < 0 )); then
        warn "no default available for ${RAM_GB}GB; paste a NSID."
        continue
      fi
      picked="${CATALOG_IDS[$default_idx]}"
      break
    fi
    if [[ "$choice" =~ ^[0-9]+$ ]]; then
      idx=$((choice - 1))
      if (( idx >= 0 && idx < ${#CATALOG_IDS[@]} )); then
        if (( RAM_GB < CATALOG_MIN_RAM[idx] )); then
          warn "'${CATALOG_IDS[$idx]}' needs ${CATALOG_MIN_RAM[$idx]}GB but this Mac has ${RAM_GB}GB."
          warn "It'll fail to load and your machine will publish supportedModels=[\"stub\"]."
          printf '  Pick anyway? (y/N) '
          confirm=""
          IFS= read -r confirm < /dev/tty || true
          # bash 3.2 (macOS /bin/sh) lacks ${var,,} lowercase expansion;
          # use a case glob instead.
          case "$confirm" in
            [yY] | [yY][eE][sS]) ;;
            *) continue ;;
          esac
        fi
        picked="${CATALOG_IDS[$idx]}"
        break
      else
        warn "out of range (1-${#CATALOG_IDS[@]}); try again."
        continue
      fi
    fi
    # Free-form NSID: must look like `org/model`. We don't validate
    # against HuggingFace — the engine load attempt is the canonical
    # validator.
    if [[ "$choice" == */* ]]; then
      picked="$choice"
      break
    fi
    warn "doesn't look like a number or an org/model NSID; try again."
  done
  COCORE_INFERENCE_MODELS="$picked"
  echo
  note "model: $COCORE_INFERENCE_MODELS"
fi

# Export so the bundled install.sh + bootstrap-python-venv.sh
# inherit it. The plist template's @@INFERENCE_MODELS@@ substitution
# reads this; the agent's build_engines() reads the resulting env
# var at serve time to know which subprocess engines to spawn.
export COCORE_INFERENCE_MODELS

# --- download + extract -----------------------------------------------

phase "download (cocore tarball — small binary + bundled installer)"
asset="cocore-mac-arm64.tar.gz"
url="$COCORE_INSTALL_BASE/dl?tag=$COCORE_RELEASE_TAG"
note "url:  $url"
tmp="$(mktemp -d -t cocore-install.XXXXXX)"
trap 'rm -rf "$tmp"' EXIT
curl -fsSL "$url" -o "$tmp/$asset" || die "download failed from $url"
tar -xzf "$tmp/$asset" -C "$tmp" || die "extract failed"

stage="$tmp/cocore-mac-arm64"
[[ -x "$stage/install.sh" ]] \
  || die "tarball missing install.sh at $stage/"

# --- delegate to the bundled installer --------------------------------

mkdir -p "$STATE_DIR" "$LOG_DIR"
chmod 700 "$STATE_DIR"

# Tell the bundled installer that the wrapper is in control of pair
# + final-status output. It will install the binary + bootstrap the
# venv + write the LaunchAgent, but skip the noisy "(skipped pair)"
# and "==> done" blocks because the wrapper prints those itself
# below with the registration-wait outcome.
export COCORE_SKIP_PAIR=1
export COCORE_WRAPPER_INVOKED=1

phase "delegating to bundled installer"
note "this will:"
note "  * install the cocore binary at $INSTALL_BIN"
note "  * bootstrap the uv-managed Python venv at $HOME/.cocore/python"
note "    with vllm-mlx (the inference subprocess engine's runtime)"
note "  * write + bootstrap the LaunchAgent (suspended until pair)"
note ""

cd "$stage"
./install.sh "$@"

# --- pair -------------------------------------------------------------
#
# The bundled installer left the LaunchAgent installed but suspended
# (no session.json → cmd_serve sleeps forever in the no-session loop).
# Run pair from here so a single `curl … | sh` paste goes all the way
# from zero to a registered, serving machine.
#
# `cocore agent pair`:
#   * POSTs to the console's devicePair.start endpoint, prints the
#     verification URL + user code (no stdin read; safe under
#     curl-pipe-sh).
#   * Polls devicePair.poll every 2s for up to 10 minutes.
#   * On approval: stores session.json, calls
#     kickstart_launchagent_if_installed() so the now-paired daemon
#     reloads with the session.
# After kickstart, the daemon runs cmd_serve → loads engines →
# publishes the provider record. The wait phase below blocks until
# that record shows up on the console's listProviders, so a successful
# wrapper exit means "your machine is on /machines, serving."

if [[ "$USER_REQUESTED_SKIP_PAIR" == "1" ]]; then
  phase "pair (skipped — COCORE_SKIP_PAIR=1)"
  note "your machine is installed but not yet registered. To finish:"
  note "  $INSTALL_BIN agent pair"
  exit 0
fi

phase "pair this machine"
note "Open the URL below in any browser signed into the cocore console."
note "Once you approve there, this script will block until your machine"
note "appears on cocore.dev/machines, then print 'done'."
note ""

# Run pair. The binary prints the URL + polls. We don't capture stdout
# (the URL needs to reach the user's terminal). If it fails (denied,
# expired, network blip), drop to a clear "pair manually" fallback —
# the binary + plist are already in place; pair is the last mile.
if ! "$INSTALL_BIN" agent pair; then
  warn "pair did not complete. The binary + LaunchAgent are installed, but"
  warn "no session was stored. Retry with:"
  warn "  $INSTALL_BIN agent pair"
  exit 1
fi

# --- wait for registration --------------------------------------------
#
# `cocore agent pair` returns the moment the session is stored + the
# LaunchAgent is kickstarted. The daemon then needs ~10-60 seconds to
# load the (just-picked) inference engine and publish a provider
# record. Poll the console's listProviders endpoint for our DID until
# we see a record — that's the canonical "machine is registered and
# the AppView knows about it" signal. Time out at 3 minutes so a
# stuck install doesn't hang the user's terminal forever.

phase "wait for registration"
# session.json was just written by cmd_pair; pull the DID out so we
# can target the listProviders check.
session_did=""
if [[ -f "$HOME/.cocore/session.json" ]]; then
  # No `jq` dependency — grep+sed is enough for a 1-key extract from
  # the well-formed session JSON the binary writes.
  session_did="$(sed -n 's/.*"did":"\([^"]*\)".*/\1/p' "$HOME/.cocore/session.json" | head -n1)"
fi
if [[ -z "$session_did" ]]; then
  warn "could not read DID from $HOME/.cocore/session.json; skipping registration wait."
  note "Open cocore.dev/machines in a few seconds to check status."
  exit 0
fi
note "your DID: $session_did"
# Note: $COCORE_INSTALL_BASE is `<console>/agent` (the installer-script
# namespace). The model registry lives at `<console>/api/v1/models` —
# a different namespace. Derive it from the install base so an
# operator-overridden console URL stays consistent across both.
api_base="${COCORE_INSTALL_BASE%/agent}/api"
note "polling $api_base/v1/models for your machine (up to 3 min)..."

deadline=$(( $(date +%s) + 180 ))
registered=0
chosen_model="$COCORE_INFERENCE_MODELS"
while (( $(date +%s) < deadline )); do
  resp="$(curl -fsSL "$api_base/v1/models" 2>/dev/null || true)"
  # Look for our DID anywhere in the response. The /api/v1/models
  # payload is a list of models, each with a `machines` array carrying
  # the provider DIDs that serve it. If our DID appears even once,
  # the AppView has indexed our provider record and we're on
  # /machines — registration is complete.
  if [[ "$resp" == *"\"$session_did\""* ]]; then
    registered=1
    break
  fi
  sleep 5
done

if (( registered == 1 )); then
  phase "done"
  note "Your machine is registered and serving."
  note "Model: $chosen_model"
  note "DID:   $session_did"
  note ""
  note "  cocore.dev/machines  — your machines"
  note "  cocore.dev/models    — the model directory"
  note ""
  note "Day-to-day: use the cocore icon in your menu bar (updates,"
  note "model toggles, re-pair, restart). No more terminal needed."
  note ""
  note "Diagnostics:"
  note "  $INSTALL_BIN agent whoami     # paired identity"
  note "  $INSTALL_BIN agent doctor     # end-to-end check"
  note "  tail -f $LOG_DIR/stderr.log   # live engine + advisor log"
else
  warn "your machine paired successfully but the provider record hasn't"
  warn "landed on the AppView within 3 minutes. The engine load can take"
  warn "longer on first boot if the model is still downloading from HF."
  note "Watch the log to see what's happening:"
  note "  tail -f $LOG_DIR/stderr.log"
  note "Then refresh cocore.dev/machines."
fi
