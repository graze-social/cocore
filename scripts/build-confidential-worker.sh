#!/usr/bin/env bash
# Build the CONFIDENTIAL worker bundle — `CoCoreProvider.app` — for the
# attested-confidential canary.
#
# This is the measured push-receiver bundle the runbook (Phase 5.2 / 6.1)
# describes: the `--features apns` agent binary packaged as its OWN app bundle
# with CFBundleIdentifier = dev.cocore.provider + an embedded Developer ID
# provisioning profile carrying aps-environment=production, so AMFI grants the
# binary the right to register for APNs and receive the advisor's code-identity
# challenge. A re-signed fork (no profile / Developer ID) is rejected by AMFI —
# the un-forgeable property the confidential tier's code-identity leg depends on.
#
# Output: provider-shell/build/CoCoreProvider.app  (Developer-ID signed; NOT
# notarized — fine for a local canary, the binary launches on the build machine
# without Gatekeeper quarantine. Notarize for distribution.)
#
# Usage:
#   COCORE_PROVISION_PROFILE=~/Downloads/cocore_provisioning_profile.provisionprofile \
#     ./scripts/build-confidential-worker.sh

set -euo pipefail

readonly REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly PROVIDER="$REPO_ROOT/provider"
readonly OUT_DIR="$REPO_ROOT/provider-shell/build"
readonly APP="$OUT_DIR/CoCoreProvider.app"
readonly TEAM_ID="4L45P7CP9M"
readonly BUNDLE_ID="dev.cocore.provider"
readonly PROFILE="${COCORE_PROVISION_PROFILE:-$HOME/Downloads/cocore_provisioning_profile.provisionprofile}"

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }
die()  { printf '\033[31m  error:\033[0m %s\n' "$*" >&2; exit 1; }

[[ "$(uname -s)" == "Darwin" ]] || die "macOS only"
[[ -f "$PROFILE" ]] || die "provisioning profile not found at $PROFILE (set COCORE_PROVISION_PROFILE)"
xcodebuild -version >/dev/null 2>&1 || die "needs full Xcode (Metal toolchain) for the native engine + metallib"

# Version comes from provider/Cargo.toml so the worker bundle never drifts from
# the agent it wraps (one version source, not a 4th place to bump). CFBundleVersion
# mirrors the outer app's scheme: 0.MINOR.PATCH → MINOR*100+PATCH (0.9.20 → 920).
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "$PROVIDER/Cargo.toml" | head -1)"
[[ -n "$VERSION" ]] || die "could not read version from $PROVIDER/Cargo.toml"
BUNDLE_VERSION="$(printf '%s' "$VERSION" | awk -F. '{printf "%d", $2*100 + $3}')"

# Signing identity. The outer build (build-mac-app.sh) passes COCORE_SIGN_ID so
# the worker is signed by the SAME Developer ID as the app that nests it;
# standalone, we auto-detect. A real Developer ID is REQUIRED — the confidential
# tier's code-identity leg depends on it (an ad-hoc/forked sign is AMFI-rejected).
SIGN_ID="${COCORE_SIGN_ID:-}"
if [[ -z "$SIGN_ID" || "$SIGN_ID" == "-" ]]; then
  SIGN_ID="$(security find-identity -p codesigning -v 2>/dev/null \
    | sed -n 's/.*"\(Developer ID Application: .*\)"/\1/p' | head -1)"
fi
[[ -n "$SIGN_ID" && "$SIGN_ID" != "-" ]] || die "no Developer ID Application identity (set COCORE_SIGN_ID or install one)"
note "signing identity: $SIGN_ID"
note "version: $VERSION (CFBundleVersion $BUNDLE_VERSION)"

bold "==> build the apns (native + push host) agent binary"
( cd "$PROVIDER" && cargo build --release --locked --features apns )
WORKER_BIN="$PROVIDER/target/release/cocore"
[[ -x "$WORKER_BIN" ]] || die "apns binary not found at $WORKER_BIN"
note "built $("$WORKER_BIN" --version)"

bold "==> compile the MLX metallib (xcodebuild PrepareMetalShaders — swift build skips it)"
MLX_ENGINE_DIR="$PROVIDER/mlx-engine"
XCBUILD_DIR="$MLX_ENGINE_DIR/.xcbuild-metallib"
( cd "$MLX_ENGINE_DIR" && xcodebuild -scheme CoCoreMLX \
    -destination 'platform=macOS,arch=arm64' -configuration Release \
    -derivedDataPath "$XCBUILD_DIR" build >/dev/null 2>&1 ) \
  || die "metallib compile failed (xcodebuild -scheme CoCoreMLX)"
METALLIB="$(find "$XCBUILD_DIR" -path '*Cmlx*' -name 'default.metallib' -print -quit 2>/dev/null || true)"
[[ -n "$METALLIB" && -f "$METALLIB" ]] || die "no default.metallib produced under $XCBUILD_DIR"
DYLIB="$MLX_ENGINE_DIR/.build/release/libCoCoreMLX.dylib"
[[ -f "$DYLIB" ]] || die "libCoCoreMLX.dylib not found (cargo build.rs should have produced it)"

bold "==> assemble CoCoreProvider.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
install -m 755 "$WORKER_BIN" "$APP/Contents/MacOS/cocore-provider"
install -m 755 "$DYLIB"      "$APP/Contents/MacOS/libCoCoreMLX.dylib"
install -m 644 "$METALLIB"   "$APP/Contents/MacOS/mlx.metallib"
cp "$PROFILE" "$APP/Contents/embedded.provisionprofile"
note "metallib: $(du -h "$METALLIB" | cut -f1); profile embedded"

# Info.plist: a background (LSUIElement) app whose bundle id matches the App ID
# the provisioning profile authorizes, so Bundle.main resolves to this bundle
# and AMFI maps the embedded profile + aps-environment to the running binary.
cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key><string>${BUNDLE_ID}</string>
    <key>CFBundleName</key><string>co/core provider</string>
    <key>CFBundleExecutable</key><string>cocore-provider</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>${VERSION}</string>
    <key>CFBundleVersion</key><string>${BUNDLE_VERSION}</string>
    <key>LSMinimumSystemVersion</key><string>13.0</string>
    <key>LSUIElement</key><true/>
</dict>
</plist>
PLIST

# Resolved entitlements: ONLY what the provisioning profile authorizes (an
# ungranted restricted entitlement → amfid kills the worker at spawn). The
# profile grants application-identifier, team-identifier, aps-environment, and
# keychain-access-groups; it does NOT grant `com.apple.security.hypervisor`, so
# that defense-in-depth flag is dropped (the native engine runs fine without
# it). The hardened-runtime cs.* flags + get-task-allow=false are plain
# code-signing flags (always permitted) and are what the attestation reports as
# hardenedRuntime / libraryValidation / getTaskAllow=false.
ENTITLEMENTS="$OUT_DIR/cocore-provider.entitlements.resolved"
cat > "$ENTITLEMENTS" <<ENT
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.application-identifier</key><string>${TEAM_ID}.${BUNDLE_ID}</string>
    <key>com.apple.developer.team-identifier</key><string>${TEAM_ID}</string>
    <key>com.apple.developer.aps-environment</key><string>production</string>
    <key>keychain-access-groups</key>
    <array><string>${TEAM_ID}.${BUNDLE_ID}</string></array>
    <key>com.apple.security.cs.allow-jit</key><false/>
    <key>com.apple.security.cs.allow-unsigned-executable-memory</key><false/>
    <key>com.apple.security.cs.allow-dyld-environment-variables</key><false/>
    <key>com.apple.security.cs.disable-library-validation</key><false/>
    <key>com.apple.security.cs.disable-executable-page-protection</key><false/>
    <key>com.apple.security.get-task-allow</key><false/>
</dict>
</plist>
ENT

bold "==> codesign inside-out (Developer ID + hardened runtime)"
# Nested code first: the engine dylib (library validation, so the worker's
# enforced CS_REQUIRE_LV accepts it — same team), then the metallib (nested
# Mach-O code object), then the worker executable WITH entitlements + the
# embedded profile context, then the bundle.
codesign --force --options runtime,library --timestamp \
  --sign "$SIGN_ID" "$APP/Contents/MacOS/libCoCoreMLX.dylib"
codesign --force --options runtime --timestamp \
  --sign "$SIGN_ID" "$APP/Contents/MacOS/mlx.metallib"
# Sign the worker binary directly with entitlements (it is the bundle main
# executable; codesign applies the entitlements to it). runtime,library →
# CS_REQUIRE_LV set, which the attestation reports as libraryValidation=true.
codesign --force --options runtime,library --timestamp \
  --entitlements "$ENTITLEMENTS" \
  --sign "$SIGN_ID" "$APP/Contents/MacOS/cocore-provider"
# Sign the bundle (picks up the embedded profile + nested code). MUST keep
# `library` here too: a bundle sign re-signs the main executable, so signing it
# with plain `runtime` would STRIP the CS_REQUIRE_LV flag set above and the
# attestation would report libraryValidation=false → tier caps at best-effort.
codesign --force --options runtime,library --timestamp \
  --entitlements "$ENTITLEMENTS" \
  --sign "$SIGN_ID" "$APP"

bold "==> verify signature + entitlements"
codesign --verify --strict --verbose=2 "$APP" || die "signature verify failed"
echo "--- worker entitlements (must show aps-environment=production) ---"
codesign -d --entitlements - --xml "$APP/Contents/MacOS/cocore-provider" 2>/dev/null | plutil -p - | grep -E "aps-environment|get-task-allow|application-identifier" || true
echo "--- cdHash / flags ---"
codesign -dvvv "$APP/Contents/MacOS/cocore-provider" 2>&1 | grep -iE "CDHash|TeamIdentifier|flags|Identifier=" || true

bold "==> done"
note "bundle: $APP"
note "cdHash above is the value to add to COCORE_KNOWN_GOOD_CDHASHES on the advisor."
