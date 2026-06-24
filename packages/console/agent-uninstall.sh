#!/usr/bin/env bash
# cocore agent uninstaller — the curl | sh entrypoint.
#
# Hosted at https://cocore.dev/agent/uninstall. Removes
# every artifact a cocore install leaves on disk:
#
#   1. Bounces the LaunchAgent and removes it from launchd's
#      per-user domain (with `bootout`, then `disable` to drop
#      the label from the disabled list so a future fresh
#      install doesn't hit "Bootstrap failed: 5: I/O error").
#   2. Deletes ~/Library/LaunchAgents/dev.cocore.provider.plist
#      (and the *.bak backup the in-place installer leaves).
#   3. Deletes ~/.local/bin/cocore (and ~/.local/bin/cocore-provider
#      if a legacy install left one).
#   4. Removes the state directory ~/.cocore in full — session.json,
#      identity.pem, logs, the Python venv with vllm-mlx.
#   5. Drops the HuggingFace cache for any mlx-community model the
#      agent might have pulled. The cache is shared with anything
#      else using HuggingFace on this machine, so we only delete
#      the `models--mlx-community--*` prefixes — anything else
#      under ~/.cache/huggingface/ is left alone.
#
# With --unpair (or COCORE_UNPAIR=1), the script also deletes
# THIS machine's provider record from the user's PDS before wiping
# local state, so the row disappears from /machines without a
# second manual click. Identity-side state (API keys, console
# prefs, attestations published in the past) is still preserved —
# use /account → "Wipe my data" for that.
#
# What this does NOT do:
#   * Without --unpair: touch any record on the user's PDS.
#     Provider records, attestations, session histories live on
#     the PDS and persist across uninstalls. To remove the
#     provider record for this machine, pass --unpair (below) or
#     visit /machines and click Unpair. To remove EVERYTHING
#     across all machines on this identity, use "Wipe my data" on
#     /account, OR re-pair the affected machines with a different
#     identity.
#   * Touch any console-side state. API keys, OAuth sessions,
#     console_user_prefs stay until you explicitly clear them
#     via /account or an operator-side wipe.
#
# Usage:
#   curl -fsSL https://cocore.dev/agent/uninstall | sh
#   curl -fsSL https://cocore.dev/agent/uninstall | sh -s -- --unpair
#   curl -fsSL https://cocore.dev/agent/uninstall | COCORE_UNPAIR=1 sh
#
# Env knobs (all optional):
#   COCORE_PREFIX     install prefix to clean (default: $HOME/.local)
#   COCORE_KEEP_VENV  1 to keep ~/.cocore/python intact (saves a re-
#                     download on the next install, but leaves
#                     ~2GB of Python wheels on disk).
#   COCORE_KEEP_HF_CACHE 1 to keep the mlx-community model cache
#                        (saves ~1-10GB of model downloads on the
#                        next install; default removes them).
#   COCORE_DRY_RUN    1 to print what would be deleted without doing
#                     anything. Useful for verifying behavior before
#                     committing.
#   COCORE_UNPAIR     1 to also delete this machine's provider record
#                     from the user's PDS (equivalent to clicking
#                     Unpair on /machines). Same as passing --unpair.
#                     Requires `openssl` and `python3` (both present
#                     on stock macOS with Xcode CLT). On failure the
#                     local wipe still proceeds; the user is told to
#                     finish in /machines.

set -euo pipefail

COCORE_PREFIX="${COCORE_PREFIX:-$HOME/.local}"
COCORE_KEEP_VENV="${COCORE_KEEP_VENV:-0}"
COCORE_KEEP_HF_CACHE="${COCORE_KEEP_HF_CACHE:-0}"
COCORE_DRY_RUN="${COCORE_DRY_RUN:-0}"
COCORE_UNPAIR="${COCORE_UNPAIR:-0}"

# Long flags. We don't use getopts because curl-pipe-sh users pass
# args via `sh -s -- --unpair`, which lands them in "$@" verbatim.
for arg in "$@"; do
  case "$arg" in
    --unpair) COCORE_UNPAIR=1 ;;
    --dry-run) COCORE_DRY_RUN=1 ;;
    --help|-h)
      printf 'usage: agent-uninstall.sh [--unpair] [--dry-run]\n\n'
      printf '  --unpair   also delete this machine'\''s provider record from PDS\n'
      printf '             (equivalent to clicking Unpair on /machines)\n'
      printf '  --dry-run  print what would happen; change nothing on disk\n\n'
      printf 'env knobs: COCORE_PREFIX, COCORE_KEEP_VENV, COCORE_KEEP_HF_CACHE,\n'
      printf '           COCORE_DRY_RUN, COCORE_UNPAIR\n'
      exit 0
      ;;
    *)
      printf 'unknown flag: %s\n' "$arg" >&2
      printf 'try --unpair, --dry-run, or --help\n' >&2
      exit 2
      ;;
  esac
done

readonly LABEL="dev.cocore.provider"
readonly INSTALL_BIN="$COCORE_PREFIX/bin/cocore"
readonly LEGACY_BIN="$COCORE_PREFIX/bin/cocore-provider"
readonly STATE_DIR="$HOME/.cocore"
readonly PYTHON_VENV="$STATE_DIR/python"
readonly LAUNCHAGENT_DIR="$HOME/Library/LaunchAgents"
readonly LAUNCHAGENT_PLIST="$LAUNCHAGENT_DIR/$LABEL.plist"
readonly LAUNCHAGENT_BAK="$LAUNCHAGENT_DIR/$LABEL.plist.bak"
readonly HF_CACHE="$HOME/.cache/huggingface/hub"

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }
warn() { printf '\033[33m  warn:\033[0m %s\n' "$*" >&2; }
phase(){ printf '\n'; bold "==> $*"; }

# Run a destructive command, or just print it under DRY_RUN.
do_rm() {
  if [[ "$COCORE_DRY_RUN" == "1" ]]; then
    note "  [dry-run] rm -rf $*"
  else
    rm -rf "$@"
  fi
}

# --- preflight ---------------------------------------------------------

phase "preflight"
if [[ "$(uname -s)" != "Darwin" ]]; then
  warn "non-macOS detected ($(uname -s)); skipping launchctl steps."
fi
if [[ "$COCORE_DRY_RUN" == "1" ]]; then
  bold "(dry run — nothing will actually be deleted)"
fi

# --- LaunchAgent -------------------------------------------------------

if [[ "$(uname -s)" == "Darwin" ]]; then
  phase "LaunchAgent"
  domain="gui/$(id -u)"
  if launchctl print "$domain/$LABEL" >/dev/null 2>&1; then
    if [[ "$COCORE_DRY_RUN" == "1" ]]; then
      note "  [dry-run] launchctl bootout $domain/$LABEL"
    else
      launchctl bootout "$domain/$LABEL" 2>/dev/null || true
      note "bootout'd $domain/$LABEL"
    fi
  else
    note "no LaunchAgent currently loaded for $LABEL"
  fi
  # `disable` is the per-user denylist toggle. We deliberately do NOT
  # call it here — leaving the label off the denylist means a future
  # fresh install's `bootstrap` succeeds without the operator having
  # to manually `enable` first.
  if [[ -e "$LAUNCHAGENT_PLIST" ]]; then
    do_rm "$LAUNCHAGENT_PLIST"
    note "removed $LAUNCHAGENT_PLIST"
  fi
  if [[ -e "$LAUNCHAGENT_BAK" ]]; then
    do_rm "$LAUNCHAGENT_BAK"
    note "removed $LAUNCHAGENT_BAK"
  fi

  # Menu-bar companion (dev.cocore.menubar) — installed by default
  # alongside the provider since the menubar feature landed. Older
  # installs simply won't have it; both steps are no-ops then.
  menubar_label="dev.cocore.menubar"
  menubar_plist="$LAUNCHAGENT_DIR/$menubar_label.plist"
  if launchctl print "$domain/$menubar_label" >/dev/null 2>&1; then
    if [[ "$COCORE_DRY_RUN" == "1" ]]; then
      note "  [dry-run] launchctl bootout $domain/$menubar_label"
    else
      launchctl bootout "$domain/$menubar_label" 2>/dev/null || true
      note "bootout'd $domain/$menubar_label"
    fi
  else
    note "no LaunchAgent currently loaded for $menubar_label"
  fi
  if [[ -e "$menubar_plist" ]]; then
    do_rm "$menubar_plist"
    note "removed $menubar_plist"
  fi
fi

# --- running processes -------------------------------------------------
#
# Reap anything still running BEFORE we delete the binary, venv, and
# state dir out from under it. Two kinds of process:
#
#   1. The agent itself (`cocore agent serve` / the confidential
#      `cocore-provider agent serve`). The LaunchAgent bootout above
#      handles the launchd-supervised case, but an app-supervised or
#      manually-started agent isn't covered by that.
#   2. The Python inference engines (`cocore_inference_server.py`, one
#      per served model). These are spawned by the agent and, if the
#      agent is gone, have reparented to launchd (PID 1). Nothing else
#      signals them, so without this they survive the uninstall holding
#      hundreds of MB of RAM (the bug this phase fixes). Newer agents
#      ship a parent-death watchdog that self-reaps these, but we still
#      sweep here so an uninstall of an older agent — or one killed
#      mid-startup before its watchdog armed — leaves nothing behind.

phase "running processes"
reap_pattern() {
  # SIGTERM matching PIDs, wait briefly, then SIGKILL survivors. Uses
  # pgrep/kill (not pkill) so dry-run can just report. `|| true` keeps
  # set -e happy when nothing matches.
  local label="$1" pattern="$2" pids
  pids="$(pgrep -f "$pattern" 2>/dev/null || true)"
  if [[ -z "$pids" ]]; then
    note "no $label running"
    return 0
  fi
  # shellcheck disable=SC2086
  if [[ "$COCORE_DRY_RUN" == "1" ]]; then
    note "  [dry-run] kill $label: $(echo $pids | tr '\n' ' ')"
    return 0
  fi
  note "stopping $label ($(echo $pids | tr '\n' ' '))"
  echo "$pids" | while read -r pid; do [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true; done
  sleep 1
  echo "$pids" | while read -r pid; do
    [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null || true
  done
}
# Engines first — once the agent is gone there's no one to respawn them,
# and reaping them before the agent avoids the agent's health watchdog
# trying to restart a child mid-uninstall.
reap_pattern "inference engine(s)" "cocore_inference_server.py"
reap_pattern "agent process(es)" "cocore(-provider)? agent serve"

# --- binary ------------------------------------------------------------

phase "binary"
for bin in "$INSTALL_BIN" "$LEGACY_BIN"; do
  if [[ -e "$bin" ]]; then
    do_rm "$bin"
    note "removed $bin"
  fi
done

# --- PDS unpair (opt-in) ----------------------------------------------
#
# Reads session.json + identity.pem (both still present at this point —
# state-directory removal happens in the next phase) to figure out:
#   * which DID + bearer key to authenticate the proxy call with
#   * which rkey under dev.cocore.compute.provider on the user's PDS
#     describes THIS physical machine (matched by attestationPubKey,
#     the P-256 fingerprint pinned to identity.pem)
#
# Then calls /api/xrpc/dev.cocore.proxy.deleteRecord on the console,
# which forwards to com.atproto.repo.deleteRecord on the user's PDS.
# Same code path as the Unpair button on /machines.
#
# Every step is failure-tolerant: if jq/python3/openssl are missing,
# session.json is malformed, the network is down, or the record was
# already gone, we print a single-line warn and let the local wipe
# below proceed. The shell return code stays 0 — partial cleanup is
# the user's normal expectation when they pipe a tarball into sh.

unpair_pds() {
  if [[ ! -f "$STATE_DIR/session.json" ]]; then
    warn "no $STATE_DIR/session.json — not paired, nothing to delete on PDS."
    return 0
  fi
  if [[ ! -f "$STATE_DIR/identity.pem" ]]; then
    warn "no $STATE_DIR/identity.pem — this looks like a Secure-Enclave build (the private key isn't on disk). Skipping PDS-side unpair; finish at https://cocore.dev/machines."
    return 0
  fi
  if ! command -v openssl >/dev/null 2>&1; then
    warn "openssl not found in PATH — cannot derive attestationPubKey. Finish at https://cocore.dev/machines."
    return 0
  fi
  if ! command -v python3 >/dev/null 2>&1; then
    warn "python3 not found in PATH — cannot parse PDS listRecords response. Finish at https://cocore.dev/machines."
    return 0
  fi

  # session.json is a flat JSON object written by oauth::store_session:
  #   { "did":"...", "handle":"...", "apiKey":"cocore-...", "apiBase":"https://..." }
  # Pull the three fields we need with python's json module rather than
  # sed — the values are user-supplied and could contain quoting that
  # breaks a regex.
  #
  # The earlier shape of this read used `read -r did api_key api_base
  # < <(python3 -c '...')` — bash process substitution. That's
  # disabled when bash runs in POSIX mode (which is what `/bin/sh` is
  # on macOS), so `curl … | sh` died with "syntax error near
  # unexpected token `<'" right at this line. The shebang on this
  # file says `bash`, but `curl … | sh` ignores it. To stay sh-safe
  # we emit one value per line from python and read each with sed.
  local session_blob did api_key api_base
  session_blob="$(python3 -c '
import json, sys
with open(sys.argv[1]) as f:
    s = json.load(f)
print(s.get("did", ""))
print(s.get("apiKey", ""))
print(s.get("apiBase", ""))
' "$STATE_DIR/session.json" 2>/dev/null || true)"
  if [[ -z "$session_blob" ]]; then
    warn "could not parse $STATE_DIR/session.json. Finish at https://cocore.dev/machines."
    return 0
  fi
  did="$(printf '%s\n' "$session_blob" | sed -n '1p')"
  api_key="$(printf '%s\n' "$session_blob" | sed -n '2p')"
  api_base="$(printf '%s\n' "$session_blob" | sed -n '3p')"
  if [[ -z "$did" || -z "$api_key" || -z "$api_base" ]]; then
    warn "$STATE_DIR/session.json missing did/apiKey/apiBase. Finish at https://cocore.dev/machines."
    return 0
  fi

  # Derive the attestationPubKey from identity.pem. The PEM is a
  # PKCS#8-encoded P-256 private key; -pubout writes the matching
  # SubjectPublicKeyInfo (DER, 91 bytes total). The last 64 bytes are
  # X || Y of the uncompressed point — exactly what the Rust agent
  # base64s into the `attestationPubKey` field of every provider
  # record it publishes (see provider/src/secure_enclave.rs
  # SoftwareIdentity::from_signing_key and provider/src/pds.rs
  # ProviderRecord.attestationPubKey).
  # `|| true` because we run under `set -euo pipefail`: an openssl
  # failure inside a pipeline-in-command-substitution would otherwise
  # exit the script mid-uninstall and skip the local wipe. We'd
  # rather degrade to "skip PDS unpair, finish cleanup".
  local pubkey
  pubkey="$(openssl pkey -in "$STATE_DIR/identity.pem" -pubout -outform DER 2>/dev/null \
            | tail -c 64 | base64 | tr -d '\n ' || true)"
  if [[ -z "$pubkey" ]]; then
    warn "could not extract pubkey from $STATE_DIR/identity.pem. Finish at https://cocore.dev/machines."
    return 0
  fi

  # Resolve the user's PDS host so we can listRecords directly (no
  # auth needed for read). did:plc goes through plc.directory;
  # did:web encodes the host in the DID itself.
  local pds=""
  case "$did" in
    did:plc:*)
      local plc_doc
      if ! plc_doc="$(curl -fsSL "https://plc.directory/$did" 2>/dev/null)"; then
        warn "could not resolve $did via plc.directory. Finish at https://cocore.dev/machines."
        return 0
      fi
      pds="$(printf '%s' "$plc_doc" | python3 -c '
import json, sys
d = json.load(sys.stdin)
for s in d.get("service", []) or []:
    if s.get("id") == "#atproto_pds":
        print(s.get("serviceEndpoint", ""))
        break
' 2>/dev/null || true)"
      ;;
    did:web:*)
      pds="https://${did#did:web:}"
      ;;
    *)
      warn "unsupported DID method on session ($did). Finish at https://cocore.dev/machines."
      return 0
      ;;
  esac
  if [[ -z "$pds" ]]; then
    warn "could not find atproto_pds service for $did. Finish at https://cocore.dev/machines."
    return 0
  fi

  # List this DID's provider records and find the rkey whose
  # value.attestationPubKey matches ours. listRecords paginates at
  # 100; we cap at 500 here — any single identity with >500 active
  # provider records is itself a bug and the user should hit the
  # /machines dedup affordance.
  local rkey="" cursor=""
  for _ in 1 2 3 4 5; do
    local url="$pds/xrpc/com.atproto.repo.listRecords?repo=$did&collection=dev.cocore.compute.provider&limit=100"
    if [[ -n "$cursor" ]]; then
      url="$url&cursor=$cursor"
    fi
    local body
    if ! body="$(curl -fsSL "$url" 2>/dev/null)"; then
      warn "PDS listRecords failed. Finish at https://cocore.dev/machines."
      return 0
    fi
    local found
    found="$(printf '%s' "$body" | python3 -c '
import json, sys
needle = sys.argv[1]
data = json.load(sys.stdin)
for r in data.get("records", []) or []:
    if (r.get("value") or {}).get("attestationPubKey") == needle:
        uri = r.get("uri", "")
        print("rkey", uri.rsplit("/", 1)[-1])
        sys.exit(0)
print("cursor", data.get("cursor") or "")
' "$pubkey" 2>/dev/null || true)"
    case "$found" in
      rkey\ *)
        rkey="${found#rkey }"
        break
        ;;
      cursor\ *)
        cursor="${found#cursor }"
        if [[ -z "$cursor" ]]; then break; fi
        ;;
      *)
        # python3 failed to parse — give up cleanly.
        break
        ;;
    esac
  done

  if [[ -z "$rkey" ]]; then
    note "no provider record on PDS for this machine's attestationPubKey — already unpaired or never published."
    return 0
  fi

  if [[ "$COCORE_DRY_RUN" == "1" ]]; then
    note "  [dry-run] POST $api_base/api/xrpc/dev.cocore.proxy.deleteRecord rkey=$rkey"
    return 0
  fi

  # Send the proxy.deleteRecord. swapRecord is omitted; the proxy
  # accepts that and PDS deletes the current head. Any non-2xx is a
  # warn, not a failure — the user can finish on /machines.
  local del_resp
  del_resp="$(curl -fsS -X POST \
      -H "Authorization: Bearer $api_key" \
      -H "Content-Type: application/json" \
      -d "{\"collection\":\"dev.cocore.compute.provider\",\"rkey\":\"$rkey\"}" \
      "$api_base/api/xrpc/dev.cocore.proxy.deleteRecord" 2>&1)" || {
    warn "deleteRecord rejected: ${del_resp:0:240}"
    warn "finish manually at https://cocore.dev/machines."
    return 0
  }
  note "deleted provider record $rkey from PDS for $did."
}

if [[ "$COCORE_UNPAIR" == "1" ]]; then
  phase "PDS unpair"
  unpair_pds
fi

# --- state directory ---------------------------------------------------

phase "state directory"
if [[ -d "$STATE_DIR" ]]; then
  if [[ "$COCORE_KEEP_VENV" == "1" && -d "$PYTHON_VENV" ]]; then
    # Remove everything EXCEPT the python venv.
    for child in "$STATE_DIR"/*; do
      [[ "$child" == "$PYTHON_VENV" ]] && continue
      do_rm "$child"
      note "removed $child"
    done
    note "kept $PYTHON_VENV (COCORE_KEEP_VENV=1)"
  else
    do_rm "$STATE_DIR"
    note "removed $STATE_DIR"
  fi
else
  note "no state directory at $STATE_DIR"
fi

# --- HuggingFace cache (mlx-community only) ---------------------------

phase "HuggingFace cache (mlx-community models only)"
if [[ "$COCORE_KEEP_HF_CACHE" == "1" ]]; then
  note "skipped (COCORE_KEEP_HF_CACHE=1)"
elif [[ -d "$HF_CACHE" ]]; then
  shopt -s nullglob
  removed=0
  for dir in "$HF_CACHE"/models--mlx-community--*; do
    do_rm "$dir"
    note "removed $dir"
    removed=$((removed + 1))
  done
  shopt -u nullglob
  if [[ "$removed" == "0" ]]; then
    note "no mlx-community models to remove"
  fi
else
  note "no HuggingFace cache at $HF_CACHE"
fi

# --- summary -----------------------------------------------------------

phase "done"
if [[ "$COCORE_DRY_RUN" == "1" ]]; then
  bold "(dry run — re-run without COCORE_DRY_RUN=1 to actually uninstall)"
else
  note "cocore has been removed from this machine."
  note ""
  if [[ "$COCORE_UNPAIR" == "1" ]]; then
    note "this machine's provider record was deleted from your PDS (or"
    note "was already gone). other identity-level records — receipts,"
    note "attestations published in the past — are untouched."
  else
    note "your PDS records (provider record, receipts, etc.) are untouched."
    note "the machine row on /machines will linger until you click Unpair"
    note "there, or re-run this script with --unpair (or COCORE_UNPAIR=1)."
  fi
  note "to remove ALL identity-level state, use 'Wipe my data' at"
  note "https://cocore.dev/account."
  note ""
  note "to reinstall: curl -fsSL https://cocore.dev/agent | sh"
fi
