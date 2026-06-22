#!/usr/bin/env bash
# Build + Developer-ID-sign the cocore-appattest helper .app.
#
#   ./build.sh [path-to.provisionprofile]
#
# The profile MUST authorize com.apple.developer.devicecheck.appattest-environment
# (regenerate the dev.cocore.provider profile in the Apple Developer portal with
# the App Attest capability — see README.md). The same profile that carries the
# APNs aps-environment can carry App Attest; you just re-add the capability and
# regenerate.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
PROFILE="${1:-$HOME/Downloads/cocore_provisioning_profile.provisionprofile}"
IDENTITY="${COCORE_SIGN_IDENTITY:-Developer ID Application: DEVIN FRANCIS GAFFNEY (4L45P7CP9M)}"
APP="$HERE/build/cocore-appattest.app"

[ -f "$PROFILE" ] || { echo "provisioning profile not found: $PROFILE" >&2; exit 1; }

rm -rf "$HERE/build"
mkdir -p "$APP/Contents/MacOS"

echo "==> compiling helper"
swiftc -O "$HERE/helper/main.swift" -o "$APP/Contents/MacOS/cocore-appattest" \
    -framework DeviceCheck -framework CryptoKit

echo "==> assembling bundle"
cp "$HERE/helper/Info.plist" "$APP/Contents/Info.plist"
cp "$PROFILE"                "$APP/Contents/embedded.provisionprofile"

echo "==> signing (Developer ID + hardened runtime + entitlements)"
# runtime alone is fine here — this helper doesn't load third-party dylibs, and
# App Attest only needs the entitlement to be authorized by the profile.
codesign --force --options runtime --timestamp \
    --entitlements "$HERE/helper/entitlements.plist" \
    --sign "$IDENTITY" "$APP"

echo "==> verifying signature + entitlements"
codesign -dvvv "$APP" 2>&1 | grep -iE 'Identifier|TeamIdentifier|Authority=Developer' || true
echo "--- entitlements ---"
codesign -d --entitlements - --xml "$APP" 2>/dev/null | plutil -p - 2>/dev/null \
    | grep -iE 'appattest|application-identifier|team-identifier' || true

echo "built: $APP/Contents/MacOS/cocore-appattest"
