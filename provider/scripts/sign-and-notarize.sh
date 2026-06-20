#!/usr/bin/env bash
# WS-AGENT-SIGNING: sign + notarize the `cocore` worker agent so its cdhash is a
# real, OS-enforced, measurable identity (today the worker was spawned ad-hoc
# and unsigned, making its cdhash meaningless and the confidential tier
# impossible).
#
# This is what produces a binary whose live `csops` read (codesign::read_self)
# reports hardenedRuntime + libraryValidation + getTaskAllow=false — the posture
# the confidential verifier requires. The resulting cdhash is what a release
# adds to the advisor's / requesters' known-good set.
#
# Usage:
#   COCORE_SIGN_IDENTITY="Developer ID Application: NAME (TEAMID)" \
#   [COCORE_NOTARY_PROFILE=cocore-notary] \
#   provider/scripts/sign-and-notarize.sh path/to/cocore [path/to/mlx.metallib]
#
# Notarization is skipped unless COCORE_NOTARY_PROFILE names a stored
# `notarytool` keychain profile (set up once with
# `xcrun notarytool store-credentials`). Signing always runs.
set -euo pipefail

BIN="${1:?usage: sign-and-notarize.sh <cocore-binary> [metallib]}"
METALLIB="${2:-}"
IDENT="${COCORE_SIGN_IDENTITY:?set COCORE_SIGN_IDENTITY to a Developer ID Application identity}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
ENTITLEMENTS="$HERE/cocore-provider.entitlements"

[ -f "$ENTITLEMENTS" ] || { echo "missing $ENTITLEMENTS" >&2; exit 1; }

# Sign the metallib first (it's a dependency loaded at runtime; library
# validation requires it to be signed by the same team).
if [ -n "$METALLIB" ]; then
  echo "==> signing metallib $METALLIB"
  codesign --force --options runtime --timestamp --sign "$IDENT" "$METALLIB"
  echo "    metallib SHA-256: $(shasum -a 256 "$METALLIB" | cut -d' ' -f1)"
fi

# CRITICAL: runtime,library. `runtime` alone does NOT set CS_REQUIRE_LV, so the
# attestation's libraryValidation would read false and the confidential tier
# would never qualify (provider/spikes/SPIKE_RESULTS.md, S3).
echo "==> signing $BIN (hardened runtime + library validation)"
codesign --force --options runtime,library --timestamp \
  --entitlements "$ENTITLEMENTS" --sign "$IDENT" "$BIN"

echo "==> verifying signature + posture"
codesign --verify --strict --verbose=2 "$BIN"
codesign -dvvv "$BIN" 2>&1 | grep -iE "CDHash=|TeamIdentifier=|flags=" || true
# Sanity: the code-directory flags MUST advertise BOTH library-validation
# (CS_REQUIRE_LV) and runtime (CS_RUNTIME); codesign prints them by name.
CS_FLAGS="$(codesign -dvvv "$BIN" 2>&1 | grep -iE '^CodeDirectory ' | head -1)"
if ! echo "$CS_FLAGS" | grep -qi "library-validation" || ! echo "$CS_FLAGS" | grep -qi "runtime"; then
  echo "ERROR: missing library-validation/runtime in '$CS_FLAGS' — re-sign with codesign options runtime,library" >&2
  exit 1
fi

if [ -n "${COCORE_NOTARY_PROFILE:-}" ]; then
  echo "==> notarizing via profile '$COCORE_NOTARY_PROFILE'"
  ZIP="$(mktemp -d)/cocore.zip"
  /usr/bin/ditto -c -k --keepParent "$BIN" "$ZIP"
  xcrun notarytool submit "$ZIP" --keychain-profile "$COCORE_NOTARY_PROFILE" --wait
  # Stapling a bare CLI binary isn't supported (no bundle); the notarization
  # ticket is served online and Gatekeeper checks it on first launch. For a
  # .app bundle, `xcrun stapler staple "$BUNDLE"` here.
  echo "==> notarization complete"
else
  echo "==> COCORE_NOTARY_PROFILE unset; skipped notarization (signing done)"
fi

echo "==> measured cdHash (what to add to the known-good release set):"
# Mirror codesign::read_self()'s value — the 20-byte CDHash codesign prints.
codesign -dvvv "$BIN" 2>&1 | grep -i "^CDHash=" | head -1 | cut -d= -f2
