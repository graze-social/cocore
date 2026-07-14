#!/usr/bin/env bash
# WS-A: register a secure-release cdHash into the advisor's known-good set.
#
# THE HARD RULE: the cdHash changes on EVERY release (it commits to the exact
# signed bytes). The advisor only advertises a provider as confidential-capable
# when its measured cdHash is in COCORE_KNOWN_GOOD_CDHASHES
# (infra/advisor/src/known-good.ts). If you ship a secure/native release and do
# NOT append its new cdHash here, every confidential request silently downgrades
# to best-effort — no error, just a quiet loss of the confidential guarantee.
# Run this WITH every secure release.
#
# By default this is a DRY RUN: it reads the CURRENT advisor value (from
# Railway if the CLI is linked, else from $COCORE_CURRENT_KNOWN_GOOD), computes
# the deduped APPENDED value, and prints the exact command — it does NOT mutate
# Railway. Pass --apply to actually set it (a bad/replacing value would
# de-bless the whole fleet, so the apply path ONLY ever appends, never shrinks).
#
# Usage:
#   ./scripts/register-known-good.sh <cdhash-hex>            # dry run (print)
#   ./scripts/register-known-good.sh path/to/cdhash.json     # dry run (print)
#   ./scripts/register-known-good.sh < cdhash.json           # JSON on stdin
#   ./scripts/register-known-good.sh --apply cdhash.json     # set it on Railway
#
# Flags:
#   --apply              set COCORE_KNOWN_GOOD_CDHASHES on Railway (redeploys).
#   --service <name>     advisor service name (default "Advisor"; see note).
#   --max <n>            retain at most the n most-recent cdHashes (default 20;
#                        0 = unbounded). Oldest are evicted first so users still
#                        on a recent prior release keep being recognized.
#
# Optional env:
#   COCORE_CURRENT_KNOWN_GOOD  the CURRENT value, if you'd rather not (or can't)
#                              read it from Railway. Takes precedence over the
#                              Railway read.
#   COCORE_ADVISOR_SERVICE     same as --service.
#   COCORE_KNOWN_GOOD_MAX      same as --max.

set -euo pipefail

die() { printf 'register-known-good: error: %s\n' "$*" >&2; exit 1; }
bold() { printf '\033[1m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }

# The Railway service that runs the advisor. NOTE: capital "A" — the service is
# named "Advisor"; lowercase "advisor" 404s on the Railway CLI.
SERVICE="${COCORE_ADVISOR_SERVICE:-Advisor}"
# Retain at most the most-recent N cdHashes so the set stays bounded as we cut
# releases, while still recognizing recent prior versions so users mid-update
# aren't dropped (the bug this whole flow exists to prevent). Oldest are evicted
# first. 0 = unbounded. Override with --max or COCORE_KNOWN_GOOD_MAX.
# Bumped 5→20 (2026-07-06): the confidential fleet updates slowly and a wider
# window keeps mid-update machines recognized across more releases.
MAX="${COCORE_KNOWN_GOOD_MAX:-20}"
apply="no"
positional=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply)     apply="yes"; shift ;;
    --service)   SERVICE="${2:?--service needs a name}"; shift 2 ;;
    --service=*) SERVICE="${1#*=}"; shift ;;
    --max)       MAX="${2:?--max needs a count}"; shift 2 ;;
    --max=*)     MAX="${1#*=}"; shift ;;
    -h|--help)   sed -n '2,35p' "$0"; exit 0 ;;
    --)          shift; break ;;
    -*)          die "unknown flag: $1 (see --help)" ;;
    *)           positional+=("$1"); shift ;;
  esac
done
case "$MAX" in *[!0-9]*) die "--max must be a non-negative integer, got: $MAX" ;; esac
set -- ${positional[@]+"${positional[@]}"}
arg="${1:-}"

# --- resolve the cdHash from: a hex arg, a cdhash.json path, or stdin -------
raw=""
if [[ -n "$arg" && -f "$arg" ]]; then
  raw="$(cat "$arg")"
elif [[ -n "$arg" ]]; then
  raw="$arg"
elif [[ ! -t 0 ]]; then
  raw="$(cat)"            # JSON piped on stdin
else
  die "usage: register-known-good.sh [--apply] <cdhash-hex | cdhash.json>"
fi

# If it looks like JSON, pull .cdHash out of it (no jq dependency — grep/sed).
if printf '%s' "$raw" | grep -q '"cdHash"'; then
  cd_hash="$(printf '%s' "$raw" | sed -n 's/.*"cdHash"[[:space:]]*:[[:space:]]*"\([0-9a-fA-F]*\)".*/\1/p' | head -1)"
else
  # Treat the whole input as the hex hash (strip whitespace).
  cd_hash="$(printf '%s' "$raw" | tr -d '[:space:]')"
fi

cd_hash="$(printf '%s' "$cd_hash" | tr '[:upper:]' '[:lower:]')"
[[ -n "$cd_hash" ]] || die "could not find a cdHash in the input"
# A cdHash is the 20-byte CodeDirectory hash → 40 lowercase hex chars.
case "$cd_hash" in
  *[!0-9a-f]*) die "cdHash has non-hex characters: $cd_hash" ;;
esac
[[ "${#cd_hash}" -eq 40 ]] \
  || die "cdHash is ${#cd_hash} hex chars; expected 40 (20-byte CodeDirectory hash). Got: $cd_hash"

# --- read the CURRENT advisor value ----------------------------------------
# Precedence: explicit env override > Railway read. We track read_ok separately
# from emptiness so an APPLY against a legitimately-empty var (the first secure
# release) is allowed, while a FAILED read blocks apply (never replace blind).
read_railway_current() {
  command -v railway >/dev/null 2>&1 || return 1
  local out
  out="$(railway variables --service "$SERVICE" --json 2>/dev/null)" || return 1
  printf '%s' "$out" \
    | sed -n 's/.*"COCORE_KNOWN_GOOD_CDHASHES"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
    | head -1
  return 0
}

current=""
have_current="no"
if [[ -n "${COCORE_CURRENT_KNOWN_GOOD:-}" ]]; then
  current="$COCORE_CURRENT_KNOWN_GOOD"
  have_current="yes"
elif current="$(read_railway_current)"; then
  have_current="yes"   # read succeeded (current may be empty = var unset)
fi

# --- compute the new env value (current set + new hash, deduped, capped) ----
# Build the ordered set oldest→newest: existing hashes in their current order,
# then the new one appended at the end. Then cap to the most-recent MAX by
# evicting from the FRONT (oldest), so a bounded set still recognizes recent
# prior releases. known-good.ts splits the value on /[\s,]+/.
already="no"
declare -a seen=()
add() {
  h="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  [[ -z "$h" ]] && return 0
  for e in ${seen[@]+"${seen[@]}"}; do [[ "$e" == "$h" ]] && return 0; done
  seen+=("$h")
}
if [[ "$have_current" == "yes" && -n "$current" ]]; then
  # shellcheck disable=SC2086
  for tok in $(printf '%s' "$current" | tr ',' ' '); do add "$tok"; done
fi
for e in ${seen[@]+"${seen[@]}"}; do [[ "$e" == "$cd_hash" ]] && already="yes"; done
add "$cd_hash"

# Cap to the most-recent MAX (0 = unbounded). Positive-offset array slicing
# keeps this working on macOS's stock bash 3.2 (no negative-index slicing).
declare -a dropped=()
if [[ "$MAX" -gt 0 && "${#seen[@]}" -gt "$MAX" ]]; then
  drop_n=$(( ${#seen[@]} - MAX ))
  dropped=( "${seen[@]:0:drop_n}" )
  seen=( "${seen[@]:drop_n}" )
fi
new_value="${seen[*]}"

bold "==> known-good registration for secure release"
note "new cdHash:        $cd_hash"
note "advisor service:   $SERVICE"
note "set size:          ${#seen[@]}$( [[ "$MAX" -gt 0 ]] && printf ' (max %s)' "$MAX" )"
if [[ "$already" == "yes" ]]; then
  note "status:            ALREADY present (no-op)"
fi
if [[ "${#dropped[@]}" -gt 0 ]]; then
  # Never silently truncate — name what aged out so an operator can tell
  # "intended eviction" from "I lost a version still in the field".
  note "evicted (oldest):  ${dropped[*]}"
fi
printf '\n'

# --- apply path: actually set it on Railway --------------------------------
if [[ "$apply" == "yes" ]]; then
  command -v railway >/dev/null 2>&1 || die "railway CLI not found (needed for --apply)"
  [[ "$have_current" == "yes" ]] \
    || die "could not read the current COCORE_KNOWN_GOOD_CDHASHES from Railway service '$SERVICE'. Refusing to apply blind — a replace would de-bless the fleet. Link the project (railway link) or pass COCORE_CURRENT_KNOWN_GOOD."
  # No-op only when the hash is already present AND nothing aged out — i.e. the
  # computed set is identical to what's live. A trim (dropped non-empty) still
  # needs to be written even if the new hash was already there.
  if [[ "$already" == "yes" && "${#dropped[@]}" -eq 0 ]]; then
    note "Nothing to do — already in the set, nothing evicted. No Railway change, no redeploy."
    exit 0
  fi
  bold "==> applying to Railway service '$SERVICE' (this triggers a redeploy)"
  note "value: $new_value"
  railway variables --service "$SERVICE" --set "COCORE_KNOWN_GOOD_CDHASHES=$new_value" \
    || die "railway variables --set failed"
  # Verify the readback contains the new hash (best effort; the redeploy may
  # still be in flight, but the var write itself is synchronous).
  got="$(read_railway_current || true)"
  case " ${got//,/ } " in
    *" $cd_hash "*) note "verified: advisor known-good set now includes $cd_hash" ;;
    *)              note "NOTE: post-set readback didn't show $cd_hash yet (redeploy in flight?). Re-check with:";
                    note "  railway variables --service $SERVICE | grep COCORE_KNOWN_GOOD_CDHASHES" ;;
  esac
  printf '\n'
  note "Reminder: the advisor is an ACCELERATOR, not the authority. A confidential"
  note "requester re-verifies the provider's signed attestation against its OWN"
  note "known-good set at seal time — publish this cdHash to requesters too"
  note "(cdhash.json release asset). See docs/secure-release.md."
  exit 0
fi

# --- dry run: print the exact command --------------------------------------
if [[ "$have_current" != "yes" ]]; then
  bold "1) Read the CURRENT advisor value first (so you APPEND, never replace):"
  cat <<EOS
   railway variables --service $SERVICE | grep COCORE_KNOWN_GOOD_CDHASHES
   # then re-run with that value so it appends + dedupes:
   COCORE_CURRENT_KNOWN_GOOD="<that value>" ./scripts/register-known-good.sh ${arg:-<cdhash-or-json>}
   # …or just let this script read + apply it for you:
   ./scripts/register-known-good.sh --apply ${arg:-<cdhash-or-json>}
EOS
  printf '\n'
  bold "2) Set the appended value (advisor reads COCORE_KNOWN_GOOD_CDHASHES):"
  note "If the var is currently EMPTY, the full value is just the new hash:"
  printf '\n'
  printf '   railway variables --service %s --set "COCORE_KNOWN_GOOD_CDHASHES=%s"\n\n' "$SERVICE" "$cd_hash"
else
  bold "1) Apply the appended value (current set + this release, deduped):"
  printf '\n'
  printf '   ./scripts/register-known-good.sh --apply %s\n' "${arg:-<cdhash-or-json>}"
  note "or set it directly:"
  printf '   railway variables --service %s --set "COCORE_KNOWN_GOOD_CDHASHES=%s"\n\n' "$SERVICE" "$new_value"
fi

bold "2) Confirm the advisor picked it up after redeploy:"
cat <<EOS
   railway variables --service $SERVICE | grep COCORE_KNOWN_GOOD_CDHASHES
   # The advisor logs its known-good set size on boot (KnownGoodSet.fromEnv).
   # size 0 == NOTHING is confidential-eligible (fail-closed).
EOS
printf '\n'
note "Reminder: the advisor is an ACCELERATOR, not the authority. A confidential"
note "requester re-verifies the provider's signed attestation against its OWN"
note "known-good set at seal time — so publish this cdHash to requesters too"
note "(cdhash.json release asset). See docs/secure-release.md."
