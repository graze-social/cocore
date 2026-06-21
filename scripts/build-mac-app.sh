#!/usr/bin/env bash
# Build the cocore menu-bar app (provider-shell) into a real .app
# bundle WITHOUT Xcode.
#
# The provider-shell README's release path assumes Xcode (archive +
# notarize + Developer ID). That's right for distribution, but it
# makes day-to-day "does the tray icon actually show up" verification
# painful, and it's overkill for local installs. This script assembles
# a double-clickable, ad-hoc-signed bundle straight from `swift build`,
# so `swift`-only machines (Command Line Tools, no full Xcode) can run
# the app.
#
# Output: provider-shell/build/cocore.app
#
# Usage:
#   ./scripts/build-mac-app.sh              # release build
#   CONFIG=debug ./scripts/build-mac-app.sh # faster debug build
#   OPEN=1 ./scripts/build-mac-app.sh       # build then launch it
#
# SECURE / NATIVE build (WS-A, opt-in):
#   COCORE_BUILD_NATIVE=1 ./scripts/build-mac-app.sh
#
#   The DEFAULT build ships the subprocess inference engine (Python venv
#   over a UDS). That path cannot serve the confidential tier: the
#   plaintext leaves the measured, signed `cocore` binary. Setting
#   COCORE_BUILD_NATIVE=1 instead builds with `--features native_mlx`, so
#   the binary contains the in-process MLX engine (libCoCoreMLX.dylib +
#   precompiled mlx.metallib) and `inProcessBackend` can become true. This
#   path REQUIRES the Metal toolchain (full Xcode, not just Command Line
#   Tools) because provider/build.rs runs `swift build` of the MLX engine.
#   It is hardened-signed + notarized exactly like the default path.
#
#   After a native build you MUST extract its cdHash and register it as
#   known-good, or the confidential tier silently downgrades to
#   best-effort. See scripts/extract-cdhash.sh, scripts/register-known-good.sh,
#   and docs/secure-release.md.

set -euo pipefail

readonly REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly SHELL_DIR="$REPO_ROOT/provider-shell"
readonly SRC_RES="$SHELL_DIR/Sources/CoCoreShell/Resources"
CONFIG="${CONFIG:-release}"
OPEN="${OPEN:-0}"
# Opt-in secure/native build (WS-A). When 1, the bundled cocore CLI is built
# with the in-process MLX engine so it can serve the confidential tier.
COCORE_BUILD_NATIVE="${COCORE_BUILD_NATIVE:-0}"
# Fleet confidential build. When 1, the outer cocore.app stays the DEFAULT
# (best-effort, subprocess engine) build — so best-effort machines are
# byte-identical to a normal release and never depend on the (expiring)
# provisioning profile — and we ADD a nested, measured push-receiver bundle
# `Contents/CoCoreProvider.app` (the `--features apns` worker, built by
# scripts/build-confidential-worker.sh). The tray's AgentSupervisor spawns the
# nested worker only on machines the owner opted into attested-confidential
# (desiredTier), via `cocore agent tier`. One notarytool submit of the outer
# app covers the nested bundle. Requires a Developer ID identity + the
# provisioning profile (COCORE_PROVISION_PROFILE).
COCORE_BUILD_APNS="${COCORE_BUILD_APNS:-0}"
# DEV=1 builds a side-by-side dev identity: a distinct bundle id, app name,
# and display name so the local build never collides with a prod cocore.app
# already installed in /Applications (same bundle id = they fight over the one
# status item and the SMAppService login-item registration). Defaults on for
# debug builds, since those are always local dev. Output: cocore-dev.app.
DEV="${DEV:-$([[ "$CONFIG" == "debug" ]] && echo 1 || echo 0)}"
readonly EXEC_NAME="CoCoreShell"
readonly OUT_DIR="$SHELL_DIR/build"
if [[ "$DEV" == "1" ]]; then
  readonly APP_NAME="cocore-dev"
  readonly BUNDLE_ID="dev.cocore.shell.dev"
  readonly DISPLAY_NAME="co/core (dev)"
else
  readonly APP_NAME="cocore"
  readonly BUNDLE_ID="dev.cocore.menubar"
  readonly DISPLAY_NAME="co/core"
fi
readonly APP="$OUT_DIR/$APP_NAME.app"

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }
die()  { printf '\033[31m  error:\033[0m %s\n' "$*" >&2; exit 1; }

[[ "$(uname -s)" == "Darwin" ]] || die "this builds a macOS .app; detected $(uname -s)"

bold "==> swift build ($CONFIG)"
( cd "$SHELL_DIR" && swift build -c "$CONFIG" )
BIN="$(cd "$SHELL_DIR" && swift build -c "$CONFIG" --show-bin-path)/$EXEC_NAME"
[[ -x "$BIN" ]] || die "built binary not found at $BIN"
note "binary: $BIN"

bold "==> assemble $APP_NAME.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

install -m 755 "$BIN" "$APP/Contents/MacOS/$EXEC_NAME"

# Info.plist: start from the source plist, then guarantee the two keys
# a runnable bundle must have (CFBundleExecutable, CFBundlePackageType)
# which the Xcode-oriented source plist omits. PlistBuddy edits in place.
cp "$SRC_RES/Info.plist" "$APP/Contents/Info.plist"
pb() { /usr/libexec/PlistBuddy -c "$1" "$APP/Contents/Info.plist" >/dev/null 2>&1; }
pb "Add :CFBundleExecutable string $EXEC_NAME" || pb "Set :CFBundleExecutable $EXEC_NAME"
pb "Add :CFBundlePackageType string APPL"      || pb "Set :CFBundlePackageType APPL"
pb "Add :CFBundleIconFile string AppIcon"      || pb "Set :CFBundleIconFile AppIcon"
# Override the identity for a DEV build so it lives alongside (not on top of) a
# prod install: distinct bundle id (separate LaunchServices registration +
# login item) and a "(dev)" display name to tell the two apart.
pb "Set :CFBundleIdentifier $BUNDLE_ID"   || pb "Add :CFBundleIdentifier string $BUNDLE_ID"
pb "Set :CFBundleName $DISPLAY_NAME"      || pb "Add :CFBundleName string $DISPLAY_NAME"
pb "Set :CFBundleDisplayName $DISPLAY_NAME" || pb "Add :CFBundleDisplayName string $DISPLAY_NAME"
note "identity: $BUNDLE_ID ($DISPLAY_NAME)"

# Build-time endpoint targeting. When COCORE_CONSOLE_URL / COCORE_ADVISOR_URL
# are set (a PR build wired to its stack, or a dev build), bake them into the
# bundle so the app defaults to that environment's console + advisor. Absent →
# the app falls back to prod at runtime (see Endpoints.swift). Settings →
# Network still overrides either way.
if [[ -n "${COCORE_CONSOLE_URL:-}" ]]; then
  pb "Add :CocoreConsoleURL string $COCORE_CONSOLE_URL" || pb "Set :CocoreConsoleURL $COCORE_CONSOLE_URL"
  note "baked CocoreConsoleURL=$COCORE_CONSOLE_URL"
fi
if [[ -n "${COCORE_ADVISOR_URL:-}" ]]; then
  pb "Add :CocoreAdvisorURL string $COCORE_ADVISOR_URL" || pb "Set :CocoreAdvisorURL $COCORE_ADVISOR_URL"
  note "baked CocoreAdvisorURL=$COCORE_ADVISOR_URL"
fi

bold "==> render app icon (Finder/Spotlight/dock)"
# Master 1024 PNG from brand geometry, then sips → iconset → iconutil.
MASTER="$OUT_DIR/icon_master.png"
ICONSET="$OUT_DIR/AppIcon.iconset"
rm -rf "$ICONSET"; mkdir -p "$ICONSET"
swift "$REPO_ROOT/scripts/make-app-icon.swift" "$MASTER" >/dev/null
for s in 16 32 128 256 512; do
  sips -z "$s" "$s"       "$MASTER" --out "$ICONSET/icon_${s}x${s}.png"    >/dev/null
  sips -z $((s*2)) $((s*2)) "$MASTER" --out "$ICONSET/icon_${s}x${s}@2x.png" >/dev/null
done
iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/AppIcon.icns"
note "icon: $APP/Contents/Resources/AppIcon.icns"

# Copy any SPM-generated resource bundle (none today — the tray icon is
# drawn programmatically — but keep this so adding assets later Just
# Works without editing this script).
shopt -s nullglob
for b in "$(dirname "$BIN")"/*.bundle; do
  cp -R "$b" "$APP/Contents/Resources/"
  note "bundled resource: $(basename "$b")"
done
shopt -u nullglob

# Bundle the cocore CLI so the .app is a SELF-CONTAINED provider: the
# download alone pairs, manages models, and runs the agent — no separate
# `curl … | sh`. AgentSupervisor.locateBinary() finds it at
# Contents/MacOS/cocore. It's signed alongside the app below.
COCORE_CLI="$REPO_ROOT/provider/target/release/cocore"
# Always (re)build so the bundled CLI matches the current source version —
# a stale target/ binary from an earlier version must not get shipped.
# cargo is incremental, so this is a no-op when already up to date.
#
# Default path: subprocess engine (no native_mlx feature) — keeps normal
# releases building on any host. Secure path (COCORE_BUILD_NATIVE=1): add
# `--features native_mlx`, which makes provider/build.rs `swift build` the
# CoCoreMLX engine + link libCoCoreMLX.dylib (the in-process confidential
# engine). That step needs the Metal toolchain (full Xcode), so we fail
# fast with a clear message rather than a deep cargo/swift error.
CARGO_FEATURE_ARGS=()
if [[ "$COCORE_BUILD_NATIVE" == "1" ]]; then
  bold "==> SECURE build requested (COCORE_BUILD_NATIVE=1): --features native_mlx"
  # build.rs runs `swift build --product CoCoreMLX`, which compiles Metal
  # shaders. `xcodebuild -version` only succeeds with a full Xcode + a
  # selected developer dir (Command Line Tools alone can't compile .metal).
  if ! xcodebuild -version >/dev/null 2>&1; then
    die "COCORE_BUILD_NATIVE=1 needs the Metal toolchain (full Xcode). \
'xcodebuild -version' failed — install Xcode and run \
'sudo xcode-select -s /Applications/Xcode.app/Contents/Developer', then retry."
  fi
  note "Metal toolchain: $(xcodebuild -version 2>/dev/null | tr '\n' ' ')"
  CARGO_FEATURE_ARGS+=(--features native_mlx)
else
  note "default (non-native) build: subprocess engine; confidential tier NOT served."
  note "set COCORE_BUILD_NATIVE=1 for the secure/native confidential build."
fi
bold "==> build cocore release binary (to bundle in the app)"
# Expand the (possibly empty) feature args safely under bash 3.2 + `set -u`:
# ${arr[@]:+"${arr[@]}"} yields nothing when the array is empty.
( cd "$REPO_ROOT/provider" && cargo build --release --locked ${CARGO_FEATURE_ARGS[@]:+"${CARGO_FEATURE_ARGS[@]}"} )
[[ -x "$COCORE_CLI" ]] || die "cocore release binary not found at $COCORE_CLI"
install -m 755 "$COCORE_CLI" "$APP/Contents/MacOS/cocore"
note "bundled cocore CLI ($("$COCORE_CLI" --version 2>/dev/null))"

# Secure/native build: colocate the in-process MLX engine next to the CLI so
# its @executable_path rpath resolves at runtime. build.rs links the dylib
# from provider/mlx-engine/.build/release; MLX loads mlx.metallib from the
# same directory as the dylib (see MLXEngine.locateMetallib). Both are signed
# inside-out below and their SHA-256 hashes are pinned into the attestation
# (engineLibHash / metallibHash) — see scripts/extract-cdhash.sh.
if [[ "$COCORE_BUILD_NATIVE" == "1" ]]; then
  bold "==> bundle native MLX engine (libCoCoreMLX.dylib + mlx.metallib)"
  MLX_BUILD_DIR="$REPO_ROOT/provider/mlx-engine/.build/release"
  DYLIB="$MLX_BUILD_DIR/libCoCoreMLX.dylib"
  [[ -f "$DYLIB" ]] || die "native build: $DYLIB not found (did 'swift build --product CoCoreMLX' run?)"
  install -m 755 "$DYLIB" "$APP/Contents/MacOS/libCoCoreMLX.dylib"
  note "bundled libCoCoreMLX.dylib"

  # The precompiled metallib (the GPU kernels that touch plaintext). CRUCIAL:
  # plain `swift build` (what build.rs runs to make the dylib) does NOT compile
  # MLX's Metal shaders — mlx-swift's Package.swift excludes the kernels dir
  # (the `PrepareMetalShaders` exclusion), so no metallib is emitted under
  # .build. Only `xcodebuild` runs that phase, compiling them into
  # `mlx-swift_Cmlx.bundle/Contents/Resources/default.metallib`. We therefore
  # build the engine a second way (xcodebuild) purely to obtain the metallib,
  # then colocate it next to the agent as `mlx.metallib` — MLX's device.cpp
  # first-choice load path (see MLXEngine.locateMetallib) — so inference runs
  # from a PRECOMPILED, signed metallib with no runtime shader JIT
  # (allow-jit=false holds). Its SHA-256 is pinned into the attestation
  # (metallibHash) by extract-cdhash.sh.
  bold "==> compile MLX metallib (xcodebuild PrepareMetalShaders — swift build skips it)"
  MLX_ENGINE_DIR="$REPO_ROOT/provider/mlx-engine"
  XCBUILD_DIR="$MLX_ENGINE_DIR/.xcbuild-metallib"
  ( cd "$MLX_ENGINE_DIR" && xcodebuild -scheme CoCoreMLX \
      -destination 'platform=macOS,arch=arm64' -configuration Release \
      -derivedDataPath "$XCBUILD_DIR" build >/dev/null 2>&1 ) \
    || die "metallib compile failed (xcodebuild -scheme CoCoreMLX). The confidential tier can't load GPU kernels without it."
  # PrepareMetalShaders emits default.metallib inside the Cmlx resource bundle.
  METALLIB="$(find "$XCBUILD_DIR" -path '*Cmlx*' -name 'default.metallib' -print -quit 2>/dev/null || true)"
  [[ -n "$METALLIB" && -f "$METALLIB" ]] \
    || METALLIB="$(find "$XCBUILD_DIR" -name 'default.metallib' -print -quit 2>/dev/null || true)"
  [[ -n "$METALLIB" && -f "$METALLIB" ]] \
    || die "native build: xcodebuild produced no default.metallib under $XCBUILD_DIR — cannot bundle the confidential GPU kernels."
  install -m 644 "$METALLIB" "$APP/Contents/MacOS/mlx.metallib"
  note "bundled mlx.metallib ($(du -h "$METALLIB" | cut -f1), from $(basename "$(dirname "$METALLIB")"))"
fi

# Bundle the Python-venv bootstrap script so a download-only install can
# set up the real-model runtime on demand (VenvBootstrapper runs it).
mkdir -p "$APP/Contents/Resources/scripts"
install -m 755 "$REPO_ROOT/scripts/bootstrap-python-venv.sh" \
  "$APP/Contents/Resources/scripts/bootstrap-python-venv.sh"
note "bundled venv bootstrap script"

# Signing identity. Default: auto-detect a "Developer ID Application"
# identity in the keychain so release builds are distributable. Override
# with COCORE_SIGN_ID="Developer ID Application: …" or COCORE_SIGN_ID="-"
# to force ad-hoc (local dev).
COCORE_SIGN_ID="${COCORE_SIGN_ID:-}"
if [[ -z "$COCORE_SIGN_ID" ]]; then
  COCORE_SIGN_ID="$(security find-identity -p codesigning -v 2>/dev/null \
    | sed -n 's/.*"\(Developer ID Application: .*\)"/\1/p' | head -1)"
  [[ -z "$COCORE_SIGN_ID" ]] && COCORE_SIGN_ID="-"
fi

if [[ "$COCORE_SIGN_ID" == "-" ]]; then
  [[ "$COCORE_BUILD_APNS" == "1" ]] && die "COCORE_BUILD_APNS=1 needs a Developer ID identity (the confidential worker can't be ad-hoc signed). Install a Developer ID cert or unset COCORE_BUILD_APNS."
  bold "==> ad-hoc codesign (no Developer ID identity)"
  note "Gatekeeper will warn on other Macs; install a Developer ID cert for distribution."
  codesign --force --deep --sign - "$APP" 2>&1 | sed 's/^/  /' || die "codesign failed"
  note "signed (ad-hoc)"
else
  bold "==> Developer ID codesign + hardened runtime"
  note "identity: $COCORE_SIGN_ID"
  # Resolve the Xcode-only $(AppIdentifierPrefix) in the entitlements to
  # this identity's Team ID (the 10-char code in the identity name).
  TEAM_ID="$(printf '%s' "$COCORE_SIGN_ID" | sed -n 's/.*(\([A-Z0-9]\{10\}\)).*/\1/p')"
  note "team id: ${TEAM_ID:-unknown}"
  ENTITLEMENTS="$OUT_DIR/cocore.entitlements.resolved"
  cp "$SRC_RES/cocore.entitlements" "$ENTITLEMENTS"
  # Drop keychain-access-groups for the Developer ID build: the Swift
  # shell stores its session in a file (SessionStore), not the keychain,
  # so it doesn't need the group — and a keychain-access-group is a
  # RESTRICTED entitlement that requires a provisioning profile. Signed
  # without one under hardened runtime, amfid silently kills the process
  # at spawn ("Launchd job spawn failed", no crash log). Removing the
  # unused entitlement is the fix.
  /usr/libexec/PlistBuddy -c "Delete :keychain-access-groups" "$ENTITLEMENTS" >/dev/null 2>&1 || true
  # Sign inside-out: deepest nested code first, then the cocore CLI, then the
  # app bundle. Everything needs Hardened Runtime (--options runtime) + a
  # secure --timestamp for notarization. We sign each explicitly rather than
  # using fragile --deep.
  #
  # Secure/native build: the MLX engine dylib + metallib are nested inside the
  # CLI's dylib graph, so they sign FIRST. The dylib is signed with the SAME
  # Developer ID as the CLI so the CLI's enforced library validation
  # (--options runtime,library) accepts it; if the team differs, the loader
  # refuses it and the confidential tier won't come up.
  #
  # The .metallib is NOT a passive resource: `file` reports it as a
  # "MetalLib executable (MacOS)" (Mach-O-based), and sitting in Contents/MacOS/
  # codesign treats it as a nested code object — an UNSIGNED one breaks the
  # app-level sign ("code object is not signed at all / In subcomponent
  # mlx.metallib"). So we sign it explicitly too (runtime + timestamp; no
  # library-validation flag — it isn't a linked dylib). Its SHA-256 is still
  # hashed separately for the attestation (metallibHash); signing doesn't change
  # the file bytes the hash covers.
  if [[ "$COCORE_BUILD_NATIVE" == "1" ]]; then
    codesign --force --options runtime,library --timestamp \
      --sign "$COCORE_SIGN_ID" "$APP/Contents/MacOS/libCoCoreMLX.dylib" 2>&1 | sed 's/^/  /' \
      || die "codesign (libCoCoreMLX.dylib) failed"
    note "signed native MLX engine dylib (library validation)"
    codesign --force --options runtime --timestamp \
      --sign "$COCORE_SIGN_ID" "$APP/Contents/MacOS/mlx.metallib" 2>&1 | sed 's/^/  /' \
      || die "codesign (mlx.metallib) failed"
    note "signed mlx.metallib"
  fi
  # The agent (cocore) must carry CS_REQUIRE_LV for the confidential tier: its
  # runtime attestation reports `libraryValidation` from this flag, and the
  # verifier's confidential gate REQUIRES it true. `--options runtime` alone
  # leaves it unset → libraryValidation reads false → the tier never qualifies
  # (S3 spike finding). Add `library` for the native build. Default
  # (subprocess) builds keep plain `runtime` so their signing is unchanged —
  # they make no confidential claim and the agent dlopens no third-party code.
  COCORE_CLI_OPTS="runtime"
  [[ "$COCORE_BUILD_NATIVE" == "1" ]] && COCORE_CLI_OPTS="runtime,library"
  codesign --force --options "$COCORE_CLI_OPTS" --timestamp \
    --sign "$COCORE_SIGN_ID" "$APP/Contents/MacOS/cocore" 2>&1 | sed 's/^/  /' \
    || die "codesign (bundled cocore CLI) failed"

  # Fleet confidential build: nest the measured push-receiver worker bundle.
  # build-confidential-worker.sh builds `--features apns` and produces a fully
  # signed CoCoreProvider.app (inside-out: dylib + metallib + worker exe with
  # the embedded provisioning profile + aps-environment entitlement, worker +
  # bundle both signed runtime,library so CS_REQUIRE_LV survives → the
  # attestation reports libraryValidation=true). We build it AFTER the outer
  # cocore CLI is already installed into the bundle (its `cargo build --features
  # apns` overwrites target/release/cocore, which we no longer read), then nest
  # it under Contents/. The final outer `codesign "$APP"` below runs WITHOUT
  # --deep, so it seals this already-signed nested bundle by reference — it does
  # NOT re-sign the worker exe, so the worker keeps its runtime,library flags.
  if [[ "$COCORE_BUILD_APNS" == "1" ]]; then
    bold "==> build + nest the confidential worker (CoCoreProvider.app)"
    COCORE_SIGN_ID="$COCORE_SIGN_ID" \
      "$REPO_ROOT/scripts/build-confidential-worker.sh" 2>&1 | sed 's/^/  /' \
      || die "confidential worker build failed"
    WORKER_SRC="$SHELL_DIR/build/CoCoreProvider.app"
    [[ -d "$WORKER_SRC" ]] || die "confidential worker bundle not found at $WORKER_SRC"
    rm -rf "$APP/Contents/CoCoreProvider.app"
    cp -R "$WORKER_SRC" "$APP/Contents/CoCoreProvider.app"
    note "nested $APP/Contents/CoCoreProvider.app"
  fi

  codesign --force --options runtime --timestamp \
    --entitlements "$ENTITLEMENTS" \
    --sign "$COCORE_SIGN_ID" "$APP" 2>&1 | sed 's/^/  /' || die "codesign failed"
  note "verifying signature"
  codesign --verify --strict --verbose=2 "$APP" 2>&1 | sed 's/^/  /' || die "signature verify failed"
  note "signed (Developer ID; notarize separately via scripts/notarize-mac-app.sh)"
fi

bold "==> done"
note "app: $APP"
note "run: open \"$APP\"   (tray icon; Dock hidden once tray lands on Tahoe)"

if [[ "$OPEN" == "1" ]]; then
  bold "==> launch"
  open "$APP"
fi
