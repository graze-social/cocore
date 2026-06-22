#!/usr/bin/env bash
# Inspect a captured Apple MDA attestation leaf and check whether its freshness
# OID (1.2.840.113635.100.8.11.1) commits to a given P-256 signing pubkey —
# i.e. confirm the option-B binding `freshness == sha256(publicKey)`.
#
#   ./inspect-mda-freshness.sh <leaf.pem|leaf.der> <publicKey-base64>
#
# `publicKey-base64` is the agent's raw 64-byte P-256 X‖Y key (what
# `cocore agent pubkey` prints / what the attestation publishes as publicKey).
#
# Use this on the FIRST real DeviceInformation-attestation capture to confirm
# the exact byte format Apple stores for DeviceAttestationNonce. If it prints
# MATCH, the shipped verifiers (mda freshness_binds == sha256(publicKey)) accept
# it as-is. If NO MATCH, compare the printed freshness bytes to sha256(pubkey)
# and adjust the single freshness normalizer (provider/src/mda.rs
# `freshness_binds`, mirrored in TS/py) accordingly — see infra/mdm/RUNBOOK.md
# "Option-B".
set -euo pipefail

LEAF="${1:?usage: inspect-mda-freshness.sh <leaf.pem|leaf.der> <publicKey-base64>}"
PUBKEY_B64="${2:?missing publicKey-base64}"

PY="${COCORE_PY:-python3}"
if ! "$PY" -c "import cryptography" 2>/dev/null; then
  echo "error: needs Python 'cryptography' (pip install cryptography), or set COCORE_PY" >&2
  exit 1
fi

"$PY" - "$LEAF" "$PUBKEY_B64" <<'PY'
import base64, hashlib, sys
from cryptography import x509

leaf_path, pubkey_b64 = sys.argv[1], sys.argv[2]
raw = open(leaf_path, "rb").read()
leaf = (
    x509.load_pem_x509_certificate(raw)
    if raw.lstrip().startswith(b"-----BEGIN")
    else x509.load_der_x509_certificate(raw)
)

OID = x509.ObjectIdentifier("1.2.840.113635.100.8.11.1")
try:
    ext = leaf.extensions.get_extension_for_oid(OID)
except x509.ExtensionNotFound:
    print("freshness OID 1.2.840.113635.100.8.11.1 NOT PRESENT in leaf"); sys.exit(2)

val = getattr(ext.value, "value", None)
if val is None:
    print("freshness extension has no raw value"); sys.exit(2)

# Tolerate the DER OCTET STRING wrapper (04 20 || 32) the verifiers also strip.
inner = val[2:] if len(val) == 34 and val[0] == 0x04 and val[1] == 0x20 else val
want = hashlib.sha256(base64.b64decode(pubkey_b64)).digest()

print("freshness (raw)     :", val.hex())
print("freshness (unwrapped):", inner.hex())
print("sha256(publicKey)    :", want.hex())
print("MATCH" if inner == want else "NO MATCH (adjust the freshness normalizer to fit these bytes)")
PY
