"""Cross-language parity tests for the Python App Attest verifier.

Loads the SAME Rust-generated fixtures the TS suite uses
(target/appattest-cross-lang-fixture.json + confidential-appattest-fixture.json,
written by the provider's cross_lang_fixture test) and asserts the Python
verifier agrees — proving Rust producer ↔ Python verifier parity on the
MDM-free hardware-attested path.
"""

from __future__ import annotations

import base64
import json
import os
from datetime import datetime, timezone

import pytest

import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from cocore import verify_provider_for_seal
from cocore.appattest import (
    APPLE_APP_ATTEST_ROOT_CA_PEM,
    AppAttestError,
    attested_key_matches_signing_key,
    verify_app_attest,
    verify_app_attest_assertion,
    verify_app_attest_b64,
)

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
AA_FIXTURE = os.path.join(REPO, "target", "appattest-cross-lang-fixture.json")
CONF_AA_FIXTURE = os.path.join(REPO, "target", "confidential-appattest-fixture.json")


def _pem_to_der(pem: str) -> bytes:
    body = "".join(
        line for line in pem.splitlines() if line and not line.startswith("-----")
    )
    return base64.b64decode(body)


@pytest.mark.skipif(not os.path.exists(AA_FIXTURE), reason="Rust fixture not generated")
def test_cross_language_app_attest_pass():
    with open(AA_FIXTURE) as fh:
        f = json.load(fh)
    root_der = base64.b64decode(f["rootDerB64"])

    res = verify_app_attest(
        base64.b64decode(f["objectB64"]),
        base64.b64decode(f["keyIdB64"]),
        base64.b64decode(f["publicKeyB64"]),
        f["appId"],
        trust_anchor_der=root_der,
    )
    assert res.valid and res.binds_signing_key
    assert len(res.key_id) == 32
    assert base64.b64encode(res.key_id).decode() == f["keyIdB64"]


@pytest.mark.skipif(not os.path.exists(AA_FIXTURE), reason="Rust fixture not generated")
def test_app_attest_unbound_key_rejected():
    with open(AA_FIXTURE) as fh:
        f = json.load(fh)
    root_der = base64.b64decode(f["rootDerB64"])
    other = b"\x09" * 64
    with pytest.raises(AppAttestError) as ei:
        verify_app_attest(
            base64.b64decode(f["objectB64"]),
            base64.b64decode(f["keyIdB64"]),
            other,
            f["appId"],
            trust_anchor_der=root_der,
        )
    assert ei.value.code == "nonce-mismatch"


@pytest.mark.skipif(not os.path.exists(AA_FIXTURE), reason="Rust fixture not generated")
def test_app_attest_real_apple_root_rejects_synthetic():
    with open(AA_FIXTURE) as fh:
        f = json.load(fh)
    with pytest.raises(AppAttestError) as ei:
        verify_app_attest(
            base64.b64decode(f["objectB64"]),
            base64.b64decode(f["keyIdB64"]),
            base64.b64decode(f["publicKeyB64"]),
            f["appId"],
            trust_anchor_der=_pem_to_der(f["appleRootPem"]),
        )
    assert ei.value.code == "bad-signature"


@pytest.mark.skipif(not os.path.exists(AA_FIXTURE), reason="Rust fixture not generated")
def test_app_attest_wrong_app_id_rejected():
    with open(AA_FIXTURE) as fh:
        f = json.load(fh)
    root_der = base64.b64decode(f["rootDerB64"])
    with pytest.raises(AppAttestError) as ei:
        verify_app_attest(
            base64.b64decode(f["objectB64"]),
            base64.b64decode(f["keyIdB64"]),
            base64.b64decode(f["publicKeyB64"]),
            "4L45P7CP9M.com.evil.fork",
            trust_anchor_der=root_der,
        )
    assert ei.value.code == "shape"


def test_embedded_apple_app_attest_root_matches_rust():
    # The fixture's appleRootPem is the Rust constant; a mismatch means drift.
    if not os.path.exists(AA_FIXTURE):
        pytest.skip("Rust fixture not generated")
    with open(AA_FIXTURE) as fh:
        f = json.load(fh)
    assert APPLE_APP_ATTEST_ROOT_CA_PEM == f["appleRootPem"]


@pytest.mark.skipif(not os.path.exists(AA_FIXTURE), reason="Rust fixture not generated")
def test_verify_b64_true_then_false_on_garbage():
    with open(AA_FIXTURE) as fh:
        f = json.load(fh)
    root_der = base64.b64decode(f["rootDerB64"])
    assert verify_app_attest_b64(
        f["objectB64"], f["keyIdB64"], f["publicKeyB64"], f["appId"], trust_anchor_der=root_der
    )
    assert not verify_app_attest_b64(
        base64.b64encode(b"not-cbor").decode(),
        f["keyIdB64"],
        f["publicKeyB64"],
        f["appId"],
        trust_anchor_der=root_der,
    )


@pytest.mark.skipif(not os.path.exists(CONF_AA_FIXTURE), reason="Rust fixture not generated")
def test_cross_language_confidential_via_app_attest():
    with open(CONF_AA_FIXTURE) as fh:
        f = json.load(fh)
    att = f["attestation"]
    aa_root = base64.b64decode(f["appAttestRootDerB64"])
    now = datetime.now(timezone.utc)

    # No MDA chain — hardware attestation is solely App Attest.
    res = verify_provider_for_seal(
        att,
        None,
        require_confidential=True,
        require_code_attested=False,
        # This fixture's App Attest object binds via clientData to a SEPARATE
        # signing key (keyId != sha256(publicKey)) — the pointer form that
        # ADR-0003's residency gate rejects for confidential. The test exercises
        # object verification, not the residency identity, so opt out.
        require_hardware_bound_key=False,
        known_good_cdhashes=[f["knownGoodCdHash"]],
        known_good_metallib_hashes=[f["knownGoodMetallibHash"]],
        known_good_engine_lib_hashes=[f["knownGoodEngineLibHash"]],
        os_floor=f["osFloor"],
        app_attest_trust_anchor_der=aa_root,
        now=now,
    )
    assert res.tier == "attested-confidential", res.findings
    assert res.ok
    assert res.seal_to_key == att["encryptionPubKey"]

    # App Attest is load-bearing: against the real Apple root it doesn't verify,
    # and with no MDA fallback the result drops to best-effort.
    downgraded = verify_provider_for_seal(
        att,
        None,
        require_confidential=False,
        require_code_attested=False,
        known_good_cdhashes=[f["knownGoodCdHash"]],
        now=now,
    )
    assert downgraded.tier == "best-effort"
    assert "no-mda-chain" in downgraded.codes()
    assert "attestation-signature-invalid" not in downgraded.codes()


# ---- App Attest ASSERTION verification (ADR-0003) --------------------
# Self-contained: synthesize an assertion the way DCAppAttestService would (a
# P-256 SE key signs `authenticatorData || sha256(clientData)`), no device or
# Rust fixture needed. Mirror of the TS appattest.test.ts assertion tests.

_ASSERT_APP_ID = "4L45P7CP9M.dev.cocore.provider"


def _sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def _cbor_bstr(b: bytes) -> bytes:
    if len(b) < 24:
        return bytes([0x40 | len(b)]) + b
    if len(b) < 256:
        return bytes([0x58, len(b)]) + b
    return bytes([0x59, len(b) >> 8, len(b) & 0xFF]) + b


def _cbor_tstr(s: str) -> bytes:
    b = s.encode()
    return bytes([0x60 | len(b)]) + b  # len < 24


def _encode_assertion(signature: bytes, auth_data: bytes) -> bytes:
    return (
        b"\xa2"
        + _cbor_tstr("signature")
        + _cbor_bstr(signature)
        + _cbor_tstr("authenticatorData")
        + _cbor_bstr(auth_data)
    )


def _make_identity():
    priv = ec.generate_private_key(ec.SECP256R1())
    uncompressed = priv.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    pub_b64 = base64.b64encode(uncompressed[1:]).decode()  # raw 64-byte X||Y
    return priv, uncompressed, pub_b64


def _sign_assertion(priv, message: bytes, app_id: str = _ASSERT_APP_ID) -> str:
    auth_data = _sha256(app_id.encode()) + bytes([0x00, 0, 0, 0, 1])
    signed = auth_data + _sha256(message)
    signature = priv.sign(signed, ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(_encode_assertion(signature, auth_data)).decode()


def test_verify_app_attest_assertion_roundtrip():
    priv, _, pub_b64 = _make_identity()
    msg = b"canonical record bytes"
    a = _sign_assertion(priv, msg)
    assert verify_app_attest_assertion(pub_b64, a, msg, _ASSERT_APP_ID) is True
    # Tampered message.
    assert verify_app_attest_assertion(pub_b64, a, b"tampered", _ASSERT_APP_ID) is False
    # Wrong verifying key.
    _, _, other = _make_identity()
    assert verify_app_attest_assertion(other, a, msg, _ASSERT_APP_ID) is False
    # Wrong appId (rpIdHash mismatch).
    assert verify_app_attest_assertion(pub_b64, a, msg, "9Z9Z9Z9Z9Z.dev.cocore.provider") is False


def test_attested_key_matches_signing_key():
    _, uncompressed, pub_b64 = _make_identity()
    assert attested_key_matches_signing_key(uncompressed, pub_b64) is True
    _, other_unc, _ = _make_identity()
    assert attested_key_matches_signing_key(other_unc, pub_b64) is False
    # Raw 64 (no 0x04 prefix) doesn't match.
    assert attested_key_matches_signing_key(base64.b64decode(pub_b64), pub_b64) is False


def test_sig_scheme_appattest_assertion_selfsignature():
    """A record with sigScheme 'appattest-assertion' whose selfSignature is an
    App Attest assertion over the canonical body verifies at gate #0; a tamper is
    still caught. Mirror of the TS verify-provider assertion-dispatch test."""
    from cocore import verify_provider_for_seal
    from cocore.canonical import canonical_bytes

    priv, uncompressed, pub_b64 = _make_identity()

    def _assertion_over(message: bytes) -> str:
        auth_data = _sha256(_ASSERT_APP_ID.encode()) + bytes([0x00, 0, 0, 0, 1])
        signature = priv.sign(auth_data + _sha256(message), ec.ECDSA(hashes.SHA256()))
        return base64.b64encode(_encode_assertion(signature, auth_data)).decode()

    base = {
        "publicKey": pub_b64,
        "encryptionPubKey": "ZW5jcnlwdGlvbktleQ==",
        "chipName": "Apple M3",
        "hardwareModel": "Mac15,8",
        "serialNumberHash": "0" * 64,
        "osVersion": "macOS 14.6.1",
        "binaryHash": "1" * 64,
        "cdHash": "a" * 40,
        "teamId": "TEAM123456",
        "hardenedRuntime": True,
        "libraryValidation": True,
        "getTaskAllow": False,
        "inProcessBackend": True,
        "antiDebug": True,
        "coreDumpsDisabled": True,
        "envScrubbed": True,
        "sipEnabled": True,
        "secureBootEnabled": True,
        "secureEnclaveAvailable": True,
        "authenticatedRootEnabled": True,
        "sigScheme": "appattest-assertion",
        "attestedAt": "2026-06-19T00:00:00Z",
        "expiresAt": "2026-06-20T00:00:00Z",
    }
    att = dict(base)
    att["selfSignature"] = _assertion_over(canonical_bytes(base))
    now = datetime(2026, 6, 19, 12, 0, 0, tzinfo=timezone.utc)

    ok = verify_provider_for_seal(att, None, require_confidential=False, now=now)
    assert "attestation-signature-invalid" not in ok.codes(), ok.findings

    tampered = dict(att)
    tampered["getTaskAllow"] = True
    bad = verify_provider_for_seal(tampered, None, require_confidential=False, now=now)
    assert "attestation-signature-invalid" in bad.codes()
