#!/usr/bin/env bash
# Build + run the App Attest helper against this machine's REAL receipt-signing
# key, and write a cross-language test fixture to target/appattest-device-fixture.json.
#
#   ./run.sh [path-to.provisionprofile]
#
# Prereqs:
#   * Apple silicon Mac with a Secure Enclave (App Attest is unsupported in VMs
#     and on Intel).
#   * The dev.cocore.provider provisioning profile regenerated WITH the App
#     Attest capability (see README.md). Without it the build still signs, but
#     attestKey fails at runtime.
#   * A built `cocore` agent on PATH (or set COCORE_BIN) so we can read the live
#     signing pubkey via `cocore agent pubkey`. Falls back to a throwaway random
#     key (smoke-test only — the resulting object won't bind to a real signer).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
PROFILE="${1:-$HOME/Downloads/cocore_provisioning_profile.provisionprofile}"
COCORE_BIN="${COCORE_BIN:-cocore}"
OUT="$REPO/target/appattest-device-fixture.json"

"$HERE/build.sh" "$PROFILE"
HELPER="$HERE/build/cocore-appattest.app/Contents/MacOS/cocore-appattest"

# Resolve the signing pubkey: prefer the live agent identity.
if PUBKEY="$("$COCORE_BIN" agent pubkey 2>/dev/null)" && [ -n "$PUBKEY" ]; then
    echo "==> using live signing pubkey from \`$COCORE_BIN agent pubkey\`"
else
    echo "==> WARNING: could not read live pubkey; generating a throwaway key (smoke test only)" >&2
    PUBKEY="$(openssl ecparam -name prime256v1 -genkey -noout 2>/dev/null \
        | openssl ec -pubout -outform DER 2>/dev/null \
        | tail -c 65 | tail -c +2 | base64)"   # last 64 bytes = raw X‖Y
fi

echo "==> running App Attest helper"
HELPER_JSON="$("$HELPER" "$PUBKEY")"
echo "$HELPER_JSON" | python3 -m json.tool >/dev/null || { echo "helper did not emit valid JSON" >&2; exit 1; }

mkdir -p "$REPO/target"
# Bundle the helper output + the pubkey it bound to, so the verifier fixture is
# self-contained.
python3 - "$PUBKEY" <<PY > "$OUT"
import json, sys
helper = json.loads('''$HELPER_JSON''')
helper["publicKey"] = sys.argv[1]
print(json.dumps(helper, indent=2, sort_keys=True))
PY

echo "wrote $OUT"
echo "--- fixture ---"
python3 -m json.tool "$OUT"
echo
echo "Next: this fixture feeds the cross-language App Attest verifier tests."
echo "  Rust: provider/src/appattest.rs honours COCORE_APPATTEST_FIXTURE=$OUT"
