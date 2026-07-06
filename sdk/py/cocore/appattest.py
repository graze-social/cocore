"""Apple App Attest attestation verification.

Mirror of provider/src/appattest.rs and packages/sdk/src/appattest.ts. Verifies
an Apple App Attest *attestation object* (CBOR/WebAuthn-shaped) and confirms it
is BOUND to the provider's receipt-signing key via the credential certificate's
nonce extension — the MDM-free path to trustLevel "hardware-attested".

Binding (by construction in the helper): clientDataHash = sha256(signingPubKey),
so here: nonce == sha256(authData || sha256(signingPubKey)) == credCert ext
1.2.840.113635.100.8.2.

CBOR is decoded by a tiny built-in reader (no cbor2 dependency); x509 uses the
`cryptography` lib already required by the SDK.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# Apple App Attest Root CA, P-384, valid 2020 -> 2045. Identical bytes to the
# Rust embed in provider/src/appattest.rs and the TS embed in appattest.ts.
APPLE_APP_ATTEST_ROOT_CA_PEM = (
    "-----BEGIN CERTIFICATE-----\n"
    "MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw\n"
    "JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK\n"
    "QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa\n"
    "Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv\n"
    "biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y\n"
    "bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh\n"
    "NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au\n"
    "Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/\n"
    "MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw\n"
    "CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn\n"
    "53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV\n"
    "oyFraWVIyd/dganmrduC1bmTBGwD\n"
    "-----END CERTIFICATE-----\n"
)

OID_APP_ATTEST_NONCE = "1.2.840.113635.100.8.2"

# AAGUID for genuine production App Attest: ASCII "appattest" + 7 zero bytes.
AAGUID_PRODUCTION = b"appattest" + b"\x00" * 7
AAGUID_DEVELOPMENT = b"appattestdevelop"

# The cocore provider App ID ("TEAMID.bundleID"). rpIdHash = sha256 of this.
APP_ATTEST_APP_ID = "4L45P7CP9M.dev.cocore.provider"

_FLAG_AT = 0x40


class AppAttestError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code


@dataclass
class AppAttestResult:
    valid: bool
    attested_pubkey_uncompressed: bytes
    key_id: bytes
    aaguid: bytes
    rp_id_hash: bytes
    binds_signing_key: bool


def verify_app_attest(
    object_der: bytes,
    key_id: bytes,
    signing_pubkey_raw: bytes,
    app_id: str,
    *,
    trust_anchor_der: Optional[bytes] = None,
    now: Optional[datetime] = None,
    allow_development: bool = False,
) -> AppAttestResult:
    """Verify an App Attest object. Raises AppAttestError on any failure."""
    now = now or datetime.now(timezone.utc)
    root = (
        x509.load_der_x509_certificate(trust_anchor_der)
        if trust_anchor_der is not None
        else x509.load_pem_x509_certificate(APPLE_APP_ATTEST_ROOT_CA_PEM.encode("ascii"))
    )

    # 1. CBOR-decode.
    obj = _decode_object(object_der)
    if obj.fmt != "apple-appattest":
        raise AppAttestError("bad-fmt", f"unexpected fmt {obj.fmt!r}")
    if not obj.x5c:
        raise AppAttestError("shape", "attStmt.x5c is empty")

    # 2. Verify the x5c chain to the App Attest root.
    certs = [x509.load_der_x509_certificate(d) for d in obj.x5c]

    def in_window(c: x509.Certificate) -> bool:
        return c.not_valid_before_utc <= now <= c.not_valid_after_utc

    for i, c in enumerate(certs):
        if not in_window(c):
            raise AppAttestError("not-valid", f"cert {i} not valid at {now.isoformat()}")
    if not in_window(root):
        raise AppAttestError("not-valid", "trust anchor not valid")

    for i in range(len(certs) - 1):
        _verify_sig(certs[i], certs[i + 1], i)
    _verify_sig(certs[-1], root, len(certs) - 1)

    for i, c in enumerate(certs):
        is_ca = _is_ca(c)
        if i == 0 and is_ca:
            raise AppAttestError("leaf-is-ca", "leaf (credCert) must be an end-entity, not a CA")
        if i > 0 and not is_ca:
            raise AppAttestError("non-ca-issuer", f"chain cert {i} is not a CA but signs cert {i - 1}")

    cred_cert = certs[0]

    # 3. Recompute nonce; check the credCert nonce extension.
    client_data_hash = hashlib.sha256(signing_pubkey_raw).digest()
    expected_nonce = hashlib.sha256(obj.auth_data + client_data_hash).digest()
    got_nonce = _parse_nonce_extension(cred_cert)
    if got_nonce is None:
        raise AppAttestError("no-nonce-extension", "credCert has no usable nonce extension")
    if not hmac.compare_digest(got_nonce, expected_nonce):
        raise AppAttestError(
            "nonce-mismatch", "attestation is not bound to the signing key (nonce mismatch)"
        )

    # 4. credCert pubkey -> credentialId, cross-check authData + keyId.
    pub = cred_cert.public_key()
    if not (isinstance(pub, ec.EllipticCurvePublicKey) and isinstance(pub.curve, ec.SECP256R1)):
        raise AppAttestError("shape", "credCert public key is not P-256")
    attested_pubkey = pub.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)  # 0x04||X||Y
    pubkey_hash = hashlib.sha256(attested_pubkey).digest()

    # 5. Parse authData; validate rpIdHash / AAGUID / credentialId.
    ad = _parse_auth_data(obj.auth_data)
    if not hmac.compare_digest(ad.rp_id_hash, hashlib.sha256(app_id.encode("utf-8")).digest()):
        raise AppAttestError("shape", "rpIdHash != sha256(appId)")
    aaguid_ok = ad.aaguid == AAGUID_PRODUCTION or (
        allow_development and ad.aaguid == AAGUID_DEVELOPMENT
    )
    if not aaguid_ok:
        raise AppAttestError("bad-aaguid", f"unrecognized AAGUID {ad.aaguid.hex()}")
    if not hmac.compare_digest(ad.credential_id, pubkey_hash):
        raise AppAttestError("cred-id-mismatch", "credentialId != sha256(attested pubkey)")
    if not hmac.compare_digest(key_id, pubkey_hash):
        raise AppAttestError("key-id-mismatch", "keyId != credentialId")

    return AppAttestResult(
        valid=True,
        attested_pubkey_uncompressed=attested_pubkey,
        key_id=pubkey_hash,
        aaguid=ad.aaguid,
        rp_id_hash=ad.rp_id_hash,
        binds_signing_key=True,
    )


def verify_app_attest_b64(
    object_b64: str,
    key_id_b64: str,
    public_key_b64: str,
    app_id: str,
    *,
    trust_anchor_der: Optional[bytes] = None,
    now: Optional[datetime] = None,
    allow_development: bool = False,
) -> bool:
    """Decode base64 and verify; returns True iff valid AND bound. Never raises
    AppAttestError (returns False instead)."""
    try:
        res = verify_app_attest(
            base64.b64decode(object_b64),
            base64.b64decode(key_id_b64),
            base64.b64decode(public_key_b64),
            app_id,
            trust_anchor_der=trust_anchor_der,
            now=now,
            allow_development=allow_development,
        )
        return res.valid and res.binds_signing_key
    except AppAttestError:
        return False


def verify_app_attest_assertion(
    public_key_b64: str,
    assertion_b64: str,
    message: bytes,
    app_id: str,
) -> bool:
    """Verify an App Attest ASSERTION (ADR-0003) over ``message``, against the SE
    key that IS the signing identity (``public_key_b64`` = the attestation's raw
    64-byte X||Y publicKey). Checks the ES256 signature over
    ``authenticatorData || sha256(message)`` and rpIdHash == sha256(app_id).
    Returns False (never raises) on any shape/verify failure. Mirror of
    ``verifyAppAttestAssertion`` in appattest.ts."""
    try:
        top, _ = _cbor_read(base64.b64decode(assertion_b64), 0)
    except (AppAttestError, ValueError):
        return False
    if not isinstance(top, dict):
        return False
    signature = top.get("signature")
    auth_data = top.get("authenticatorData")
    if not isinstance(signature, (bytes, bytearray)) or not isinstance(auth_data, (bytes, bytearray)):
        return False
    signature = bytes(signature)
    auth_data = bytes(auth_data)
    # authenticatorData = rpIdHash(32) | flags(1) | signCount(4); assertions omit
    # attested-credential-data, so 37 bytes is the minimum.
    if len(auth_data) < 37:
        return False
    if not hmac.compare_digest(auth_data[:32], hashlib.sha256(app_id.encode()).digest()):
        return False
    signed = auth_data + hashlib.sha256(message).digest()
    try:
        raw = base64.b64decode(public_key_b64)
        if len(raw) != 64:
            return False
        pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + raw)
        pub.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


def attested_key_matches_signing_key(
    attested_uncompressed: bytes, signing_pubkey_b64: str
) -> bool:
    """Residency predicate (ADR-0003): does the App-Attest-attested key EQUAL the
    signing key? ``attested_uncompressed`` is the 65-byte 0x04||X||Y; the signing
    key is the attestation's raw 64-byte X||Y. Mirror of
    ``attestedKeyMatchesSigningKey`` in appattest.ts."""
    try:
        sig = base64.b64decode(signing_pubkey_b64)
    except (ValueError, TypeError):
        return False
    return (
        len(attested_uncompressed) == 65
        and len(sig) == 64
        and attested_uncompressed[0] == 0x04
        and hmac.compare_digest(attested_uncompressed[1:], sig)
    )


# ---- internals -------------------------------------------------------


def _verify_sig(cert: x509.Certificate, issuer: x509.Certificate, idx: int) -> None:
    issuer_pub = issuer.public_key()
    if not isinstance(issuer_pub, ec.EllipticCurvePublicKey):
        raise AppAttestError("bad-signature", f"unsupported issuer key for cert {idx}")
    try:
        issuer_pub.verify(
            cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm)
        )
    except InvalidSignature as exc:
        raise AppAttestError("bad-signature", f"signature on cert {idx} doesn't verify") from exc


def _is_ca(cert: x509.Certificate) -> bool:
    try:
        return bool(cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
    except x509.ExtensionNotFound:
        return False


def _parse_nonce_extension(cert: x509.Certificate) -> Optional[bytes]:
    """extnValue is DER: SEQUENCE { [1] EXPLICIT OCTET STRING <nonce> }."""
    try:
        ext = cert.extensions.get_extension_for_oid(x509.ObjectIdentifier(OID_APP_ATTEST_NONCE))
    except x509.ExtensionNotFound:
        return None
    raw = getattr(ext.value, "value", None)
    if raw is None:
        return None
    seq = _read_tlv(raw)
    if seq is None or seq[0] != 0x30:
        return None
    ctx = _read_tlv(seq[1])
    if ctx is None or ctx[0] != 0xA1:
        return None
    octets = _read_tlv(ctx[1])
    if octets is None or octets[0] != 0x04 or len(octets[1]) != 32:
        return None
    return octets[1]


def _read_tlv(data: bytes) -> Optional[tuple[int, bytes, bytes]]:
    """Minimal strict DER TLV reader. Returns (tag, value, rest)."""
    if len(data) < 2:
        return None
    tag = data[0]
    first = data[1]
    if first & 0x80 == 0:
        length = first
        header = 2
    else:
        n = first & 0x7F
        if n == 0 or n > 4 or len(data) < 2 + n:
            return None
        length = int.from_bytes(data[2 : 2 + n], "big")
        header = 2 + n
    end = header + length
    if end > len(data):
        return None
    return tag, data[header:end], data[end:]


@dataclass
class _AuthData:
    rp_id_hash: bytes
    aaguid: bytes
    credential_id: bytes


def _parse_auth_data(ad: bytes) -> _AuthData:
    # rpIdHash(32)|flags(1)|signCount(4)|aaguid(16)|credIdLen(2)|credId(L)|cose...
    if len(ad) < 37:
        raise AppAttestError("short-auth-data", f"authData too short ({len(ad)} bytes)")
    rp_id_hash = ad[0:32]
    if ad[32] & _FLAG_AT == 0:
        raise AppAttestError("no-attested-credential-data", "AT flag not set in authData")
    if len(ad) < 55:
        raise AppAttestError("short-auth-data", f"authData too short ({len(ad)} bytes)")
    aaguid = ad[37:53]
    cred_id_len = int.from_bytes(ad[53:55], "big")
    end = 55 + cred_id_len
    if end > len(ad):
        raise AppAttestError("short-auth-data", f"authData too short for credId ({len(ad)} bytes)")
    return _AuthData(rp_id_hash=rp_id_hash, aaguid=aaguid, credential_id=ad[55:end])


@dataclass
class _Object:
    fmt: str
    x5c: list
    auth_data: bytes


def _decode_object(object_der: bytes) -> _Object:
    top, _ = _cbor_read(object_der, 0)
    if not isinstance(top, dict):
        raise AppAttestError("cbor", "top-level is not a CBOR map")
    fmt = top.get("fmt")
    if not isinstance(fmt, str):
        raise AppAttestError("cbor", "missing fmt")
    att_stmt = top.get("attStmt")
    if not isinstance(att_stmt, dict):
        raise AppAttestError("cbor", "missing attStmt")
    x5c = att_stmt.get("x5c")
    if not isinstance(x5c, list) or not all(isinstance(c, (bytes, bytearray)) for c in x5c):
        raise AppAttestError("cbor", "missing/invalid attStmt.x5c")
    auth_data = top.get("authData")
    if not isinstance(auth_data, (bytes, bytearray)):
        raise AppAttestError("cbor", "missing authData")
    return _Object(fmt=fmt, x5c=[bytes(c) for c in x5c], auth_data=bytes(auth_data))


def _cbor_read(buf: bytes, pos: int):
    """Minimal CBOR decoder: major types 0/1 (int), 2 (bytes), 3 (text),
    4 (array), 5 (map with text keys). Definite lengths only. Returns
    (value, new_pos)."""
    if pos >= len(buf):
        raise AppAttestError("cbor", "unexpected end of CBOR")
    b = buf[pos]
    pos += 1
    major = b >> 5
    info = b & 0x1F
    arg, pos = _cbor_arg(buf, pos, info)
    if major == 0:
        return arg, pos
    if major == 1:
        return -1 - arg, pos
    if major == 2:
        if pos + arg > len(buf):
            raise AppAttestError("cbor", "truncated byte string")
        return buf[pos : pos + arg], pos + arg
    if major == 3:
        if pos + arg > len(buf):
            raise AppAttestError("cbor", "truncated text string")
        return buf[pos : pos + arg].decode("utf-8"), pos + arg
    if major == 4:
        out = []
        for _ in range(arg):
            v, pos = _cbor_read(buf, pos)
            out.append(v)
        return out, pos
    if major == 5:
        out = {}
        for _ in range(arg):
            k, pos = _cbor_read(buf, pos)
            v, pos = _cbor_read(buf, pos)
            if not isinstance(k, str):
                raise AppAttestError("cbor", "non-text CBOR map key")
            out[k] = v
        return out, pos
    raise AppAttestError("cbor", f"unsupported CBOR major type {major}")


def _cbor_arg(buf: bytes, pos: int, info: int):
    if info < 24:
        return info, pos
    if info == 24:
        if pos + 1 > len(buf):
            raise AppAttestError("cbor", "truncated CBOR arg")
        return buf[pos], pos + 1
    if info == 25:
        if pos + 2 > len(buf):
            raise AppAttestError("cbor", "truncated CBOR arg")
        return int.from_bytes(buf[pos : pos + 2], "big"), pos + 2
    if info == 26:
        if pos + 4 > len(buf):
            raise AppAttestError("cbor", "truncated CBOR arg")
        return int.from_bytes(buf[pos : pos + 4], "big"), pos + 4
    if info == 27:
        raise AppAttestError("cbor", "CBOR 64-bit lengths not supported")
    raise AppAttestError("cbor", f"unsupported CBOR additional-info {info}")
