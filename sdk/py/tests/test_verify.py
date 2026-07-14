"""Cross-language parity tests for the Python verifier.

The DEFINITIVE test loads the SAME Rust-generated fixtures the TS suite uses
(target/confidential-attestation-fixture.json, written by the provider's
cross_lang_fixture test) and asserts the Python verifier reaches
attested-confidential end-to-end — proving Rust producer ↔ Python verifier
parity on canonical bytes, P-256, and the MDA chain.
"""

from __future__ import annotations

import base64
import json
import os
from datetime import datetime, timezone

import pytest

from cocore import canonicalize, verify_provider_for_seal
from cocore.canonical import canonical_bytes

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
CONF_FIXTURE = os.path.join(REPO, "target", "confidential-attestation-fixture.json")


def test_canonical_matches_spec():
    # Sorted keys, no whitespace, integers only.
    assert canonicalize({"b": 1, "a": 2}) == '{"a":2,"b":1}'
    assert canonicalize({"x": [1, 2], "y": True, "z": None}) == '{"x":[1,2],"y":true,"z":null}'
    assert canonical_bytes({"k": "v"}) == b'{"k":"v"}'


def test_floats_rejected():
    import pytest as _pytest

    with _pytest.raises(Exception):
        canonicalize({"x": 1.5})


def test_non_ascii_key_rejected():
    # L6: non-ASCII object keys are rejected for cross-language byte parity
    # (JS Array.sort orders by UTF-16 code unit, diverging from code-point order).
    from cocore.canonical import CanonicalError

    with pytest.raises(CanonicalError):
        canonicalize({"café": 1})
    # ASCII keys still fine.
    assert canonicalize({"cafe": 1}) == '{"cafe":1}'


def test_integer_range_capped():
    # L6: integer magnitude is bounded to Rust's i64/u64 range.
    from cocore.canonical import CanonicalError

    assert canonicalize({"n": 2**64 - 1}) == '{"n":18446744073709551615}'
    assert canonicalize({"n": -(2**63)}) == '{"n":-9223372036854775808}'
    with pytest.raises(CanonicalError):
        canonicalize({"n": 2**64})
    with pytest.raises(CanonicalError):
        canonicalize({"n": -(2**63) - 1})


@pytest.mark.skipif(not os.path.exists(CONF_FIXTURE), reason="Rust fixture not generated")
def test_cross_language_confidential_pass():
    with open(CONF_FIXTURE) as fh:
        f = json.load(fh)
    att = f["attestation"]
    root_der = base64.b64decode(f["rootDerB64"])
    now = datetime.now(timezone.utc)

    # (a) advisor-trustless mode: full chain + session key.
    with_key = verify_provider_for_seal(
        att,
        att["mdaCertChain"],
        require_confidential=True,
        require_session_key=True,
        # Offline fixture: the live APNs code-identity leg is asserted separately
        # (see the 0.9.23 secure default), so opt out of it here.
        require_code_attested=False,
        # MDA-freshness fixture predates the App Attest residency gate (ADR-0003),
        # which now caps MDA-only at hardware-attested. This test is cross-language
        # signing parity, not residency policy, so opt out of the residency gate.
        require_hardware_bound_key=False,
        known_good_cdhashes=[f["knownGoodCdHash"]],
        known_good_metallib_hashes=[f["knownGoodMetallibHash"]],
        known_good_engine_lib_hashes=[f["knownGoodEngineLibHash"]],
        os_floor=f["osFloor"],
        trust_anchor_der=root_der,
        attestation_cid=f["attestationCid"],
        nonce=f["nonce"],
        session_key=f["sessionKey"],
        now=now,
    )
    assert with_key.tier == "attested-confidential", with_key.findings
    assert with_key.ok
    assert with_key.seal_to_key == f["sessionKey"]["ephemeralPubKey"]

    # (b) advisor-vouched mode: no session key → seal to encryptionPubKey.
    no_key = verify_provider_for_seal(
        att,
        att["mdaCertChain"],
        require_confidential=True,
        require_code_attested=False,
        # MDA-freshness fixture — opt out of the ADR-0003 residency gate (see above).
        require_hardware_bound_key=False,
        known_good_cdhashes=[f["knownGoodCdHash"]],
        known_good_metallib_hashes=[f["knownGoodMetallibHash"]],
        os_floor=f["osFloor"],
        trust_anchor_der=root_der,
        now=now,
    )
    assert no_key.tier == "attested-confidential", no_key.findings
    assert no_key.seal_to_key == att["encryptionPubKey"]

    # (c) tampered posture → selfSignature gate catches it, fail-closed.
    tampered = dict(att)
    tampered["getTaskAllow"] = True
    bad = verify_provider_for_seal(
        tampered,
        att["mdaCertChain"],
        require_confidential=True,
        known_good_cdhashes=[f["knownGoodCdHash"]],
        trust_anchor_der=root_der,
        now=now,
    )
    assert "attestation-signature-invalid" in bad.codes()
    assert not bad.ok


@pytest.mark.skipif(not os.path.exists(CONF_FIXTURE), reason="Rust fixture not generated")
def test_posture_gates_fail_closed():
    with open(CONF_FIXTURE) as fh:
        f = json.load(fh)
    att = f["attestation"]
    root_der = base64.b64decode(f["rootDerB64"])
    now = datetime.now(timezone.utc)

    # A self-attested provider (no chain) is best-effort, not confidential.
    r = verify_provider_for_seal(
        att, None, known_good_cdhashes=[f["knownGoodCdHash"]], trust_anchor_der=root_der, now=now
    )
    assert r.tier == "best-effort"
    assert "no-mda-chain" in r.codes()

    # require_confidential without a known-good set fails closed.
    r2 = verify_provider_for_seal(
        att,
        att["mdaCertChain"],
        require_confidential=True,
        known_good_cdhashes=[],
        trust_anchor_der=root_der,
        now=now,
    )
    assert not r2.ok
    assert "no-known-good-set" in r2.codes()


def test_require_code_attested_gate():
    """The APNs code-identity gate (parity with verify-provider.ts). A minimal
    attestation fails other gates, but we assert only on the code-not-attested
    finding's presence/absence."""
    att = {"publicKey": "AA=="}

    def codes(r):
        return [fd["code"] for fd in r.findings]

    missing = verify_provider_for_seal(att, None, require_code_attested=True)
    assert "code-not-attested" in codes(missing)
    ok = verify_provider_for_seal(att, None, require_code_attested=True, code_attested=True)
    assert "code-not-attested" not in codes(ok)
    # SECURE DEFAULT (0.9.23): code-attestation is REQUIRED by default → blocks.
    default_required = verify_provider_for_seal(att, None)
    assert "code-not-attested" in codes(default_required)
    # Explicit opt-out (non-APNs advisor) no longer blocks.
    off = verify_provider_for_seal(att, None, require_code_attested=False)
    assert "code-not-attested" not in codes(off)


def test_require_hardware_bound_key_gate():
    """Key-residency gate (ADR-0003, parity with verify-provider.ts). Without a
    bound App Attest object the signing key isn't proven Secure-Enclave-resident,
    so `key-not-hardware-bound` is emitted by default and suppressed on opt-out."""
    att = {"publicKey": "AA=="}

    def codes(r):
        return [fd["code"] for fd in r.findings]

    # Opt-in (a future confidential-compute backend) → blocks.
    required = verify_provider_for_seal(att, None, require_hardware_bound_key=True)
    assert "key-not-hardware-bound" in codes(required)
    # ADR-0004 default: App Attest is retired for the Mac tier, so the gate is off.
    default_off = verify_provider_for_seal(att, None)
    assert "key-not-hardware-bound" not in codes(default_off)


def test_require_secure_enclave_key_gate():
    """ADR-0005 Secure-Enclave-resident-key gate (parity with verify-provider.ts).
    Default OFF (soft cutover); when on, a machine without
    secureEnclaveAvailable=True fails closed with `se-key-not-available`."""

    def codes(r):
        return [fd["code"] for fd in r.findings]

    sw = {"publicKey": "AA==", "secureEnclaveAvailable": False}
    se = {"publicKey": "AA==", "secureEnclaveAvailable": True}

    # Default OFF: not blocked on the SE code.
    assert "se-key-not-available" not in codes(verify_provider_for_seal(sw, None))
    # Enforced + software key → blocks.
    assert "se-key-not-available" in codes(
        verify_provider_for_seal(sw, None, require_secure_enclave_key=True)
    )
    # Enforced + SE key → no SE blocker.
    assert "se-key-not-available" not in codes(
        verify_provider_for_seal(se, None, require_secure_enclave_key=True)
    )


def test_freshness_binds_key_option_b():
    """Option-B binding parity with mda.rs::freshness_binds + verify-provider.ts.
    Uses the SAME vector as the Rust/TS tests (64 bytes of 0x07)."""
    import base64
    import hashlib

    from cocore.verify import _freshness_binds_key

    pub_raw = bytes([7]) * 64
    pub_b64 = base64.b64encode(pub_raw).decode()
    good = hashlib.sha256(pub_raw).digest()

    # raw 32-byte freshness == sha256(pubkey) → binds
    assert _freshness_binds_key(good, pub_b64) is True
    # DER OCTET STRING-wrapped (04 20 ‖ 32) → binds
    assert _freshness_binds_key(b"\x04\x20" + good, pub_b64) is True
    # freshness for a different key → does not bind
    assert _freshness_binds_key(hashlib.sha256(bytes([9]) * 64).digest(), pub_b64) is False
    # missing/empty → False, never raises
    assert _freshness_binds_key(None, pub_b64) is False
    assert _freshness_binds_key(b"", pub_b64) is False
