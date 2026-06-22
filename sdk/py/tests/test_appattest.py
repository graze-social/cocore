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

from cocore import verify_provider_for_seal
from cocore.appattest import (
    APPLE_APP_ATTEST_ROOT_CA_PEM,
    AppAttestError,
    verify_app_attest,
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
