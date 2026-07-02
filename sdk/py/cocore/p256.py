"""P-256 ECDSA verification (mirror of packages/sdk/src/p256.ts).

Signatures are DER-encoded (Apple CryptoKit / the `p256` Rust crate wire format)
and verified with a SHA-256 prehash, over canonical bytes. Public keys are the
raw 64-byte X||Y point, base64 — the encoding the attestation publishes.
"""

from __future__ import annotations

import base64
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature

from .canonical import canonical_bytes

# Order n of the P-256 (secp256r1) curve, and n/2 (the low-S ceiling).
_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_P256_HALF_N = _P256_N >> 1


def signature_is_high_s(signature_der_b64: str) -> bool:
    """True iff a DER P-256 signature is in the malleable high-S form (s > n/2).

    Parity with the TS ``signatureIsHighS``. Exposed so producers/tests can assert
    their signers normalise to low-S before the ``require_low_s`` guard is enabled
    by default. Returns False for a signature that fails to parse."""
    try:
        _r, s = decode_dss_signature(base64.b64decode(signature_der_b64))
    except (ValueError, TypeError):
        return False
    return s > _P256_HALF_N


def verify_p256(
    public_key_b64: str,
    signature_der_b64: str,
    message: bytes,
    *,
    require_low_s: bool = False,
) -> bool:
    """Verify a DER ECDSA-P256 signature over ``message`` (SHA-256 prehash).

    ``require_low_s`` (L6, parity with the TS ``verifyP256`` option) rejects the
    malleable high-S signature form. OFF by default: the Rust provider and Apple
    CryptoKit do NOT normalise to low-S today (~50% of real signatures are
    high-S), so enforcing it would fail genuine signatures. Enabling it by
    default is a follow-up gated on the producers normalising first."""
    pub_raw = base64.b64decode(public_key_b64)
    if len(pub_raw) != 64:
        return False
    try:
        sig = base64.b64decode(signature_der_b64)
        if require_low_s:
            _r, s = decode_dss_signature(sig)
            if s > _P256_HALF_N:
                return False
        pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + pub_raw)
        pub.verify(sig, message, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


def verify_attestation_signature(attestation: Mapping[str, Any], public_key_b64: str) -> bool:
    """Verify an attestation's ``selfSignature`` against its own ``publicKey``.

    Authenticates every posture field (cdHash, getTaskAllow, encryptionPubKey,
    …). Strips ``selfSignature`` and ``$type``, canonicalizes the rest.
    """
    sig = attestation.get("selfSignature")
    if not sig:
        return False
    body = {k: v for k, v in attestation.items() if k not in ("selfSignature", "$type")}
    return verify_p256(public_key_b64, sig, canonical_bytes(body))


def verify_receipt_signature(receipt: Mapping[str, Any], attestation_public_key_b64: str) -> bool:
    """Verify a receipt's ``enclaveSignature`` against an attestation publicKey."""
    sig = receipt.get("enclaveSignature")
    if not sig:
        return False
    body = {k: v for k, v in receipt.items() if k not in ("enclaveSignature", "$type")}
    return verify_p256(attestation_public_key_b64, sig, canonical_bytes(body))
