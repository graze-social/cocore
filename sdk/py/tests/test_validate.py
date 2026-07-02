"""Tests for the Python receipt validators (mirror of validate.test.ts).

These prove the Python verifier reaches the same accept/reject decisions as the
canonical TS SDK: commitment shape + equality, ceiling, expiry, pro-bono
invariant, the strict ES256 receipt-signature check, the H3 attestation
self-signature + owner-DID binding, and the settlement chain.
"""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from cocore import (
    PreChargeContext,
    PreChargeInputs,
    verify_for_charge,
    verify_for_charge_strict,
    verify_receipt,
    verify_receipt_strict,
    verify_settlement_chain,
)
from cocore.canonical import canonical_bytes


# ---- fixtures (mirror validate.test.ts) ------------------------------


def fixture_job(**overrides):
    job = {
        "model": "llama-3.1-70b",
        "inputCommitment": "a" * 64,
        "maxTokensOut": 1000,
        "priceCeiling": {"amount": 100, "currency": "USD"},
        "acceptedTrustLevel": "self-attested",
        "paymentAuthorization": {"uri": "at://did:plc:r/auth/1", "cid": "bafycid"},
        "expiresAt": "2026-05-07T13:00:00Z",
        "createdAt": "2026-05-07T12:00:00Z",
    }
    job.update(overrides)
    return job


def fixture_attestation(**overrides):
    att = {
        "publicKey": "AAAA",
        "encryptionPubKey": "BBBB",
        "chipName": "Apple M3 Max",
        "hardwareModel": "Mac15,8",
        "serialNumberHash": "d" * 64,
        "osVersion": "15.0",
        "binaryHash": "e" * 64,
        "sipEnabled": True,
        "secureBootEnabled": True,
        "secureEnclaveAvailable": True,
        "authenticatedRootEnabled": True,
        "rdmaDisabled": True,
        "selfSignature": "sigsig",
        "attestedAt": "2026-05-07T11:00:00Z",
        "expiresAt": "2026-05-08T11:00:00Z",
    }
    att.update(overrides)
    return att


def fixture_receipt(**overrides):
    r = {
        "job": {"uri": "at://did:plc:r/job/1", "cid": "bafycid"},
        "requester": "did:plc:r",
        "model": "llama-3.1-70b",
        "inputCommitment": "a" * 64,
        "outputCommitment": "b" * 64,
        "tokens": {"in": 32, "out": 128},
        "startedAt": "2026-05-07T12:00:00Z",
        "completedAt": "2026-05-07T12:00:03Z",
        "price": {"amount": 50, "currency": "USD"},
        "attestation": {"uri": "at://did:plc:p/attest/1", "cid": "bafyatt"},
        "enclaveSignature": "sigsig",
    }
    r.update(overrides)
    return r


def fixture_auth(**overrides):
    a = {
        "exchange": "did:web:exchange.example",
        "ceiling": {"amount": 100, "currency": "USD"},
        "scope": "singleJob",
        "nonce": "a" * 32,
        "expiresAt": "2026-05-07T13:00:00Z",
        "createdAt": "2026-05-07T12:00:00Z",
    }
    a.update(overrides)
    return a


def fixture_settlement(**overrides):
    s = {
        "receipt": {"uri": "at://did:plc:p/receipt/1", "cid": "bafyrcpt"},
        "requesterAuthorization": {"uri": "at://did:plc:r/auth/1", "cid": "bafyauth"},
        "amountCharged": {"amount": 50, "currency": "USD"},
        "providerPayout": {"amount": 45, "currency": "USD"},
        "exchangeFee": {"amount": 5, "currency": "USD"},
        "processorReference": "cmVm",
        "status": "settled",
        "settledAt": "2026-05-07T12:00:10Z",
    }
    s.update(overrides)
    return s


# ---- signing helpers (real P-256, DER) -------------------------------


class KeyPair:
    def __init__(self):
        self._priv = ec.generate_private_key(ec.SECP256R1())
        nums = self._priv.public_key().public_numbers()
        raw = nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")
        self.public_key_b64 = base64.b64encode(raw).decode()

    def sign(self, message: bytes) -> str:
        der = self._priv.sign(message, ec.ECDSA(hashes.SHA256()))
        return base64.b64encode(der).decode()


def signed_receipt(kp: KeyPair, **overrides):
    draft = fixture_receipt(**overrides)
    draft["enclaveSignature"] = ""
    signable = {k: v for k, v in draft.items() if k != "enclaveSignature"}
    draft["enclaveSignature"] = kp.sign(canonical_bytes(signable))
    return draft


def signed_attestation(kp: KeyPair, **overrides):
    overrides.setdefault("publicKey", kp.public_key_b64)
    draft = fixture_attestation(**overrides)
    draft["selfSignature"] = ""
    signable = {k: v for k, v in draft.items() if k not in ("selfSignature", "$type")}
    draft["selfSignature"] = kp.sign(canonical_bytes(signable))
    return draft


# ---- structural verify_receipt ---------------------------------------


def test_happy_path_receipt_verifies():
    r = verify_receipt(fixture_receipt(), fixture_job(), fixture_attestation())
    assert r.ok, r.codes()


def test_price_over_ceiling_fails():
    r = verify_receipt(
        fixture_receipt(price={"amount": 500, "currency": "USD"}),
        fixture_job(),
        fixture_attestation(),
    )
    assert not r.ok
    assert "price-over-ceiling" in r.codes()


def test_commitment_mismatch_fails():
    r = verify_receipt(
        fixture_receipt(inputCommitment="z" * 64), fixture_job(), fixture_attestation()
    )
    assert not r.ok
    assert "commitment-mismatch" in r.codes()


def test_bad_commitment_shape_fails():
    # L7: an out-of-shape commitment is rejected on shape even when it matches.
    r = verify_receipt(
        fixture_receipt(inputCommitment="not-hex", outputCommitment="ABC"),
        fixture_job(inputCommitment="not-hex"),
        fixture_attestation(),
    )
    assert not r.ok
    assert "input-commitment-shape" in r.codes()
    assert "output-commitment-shape" in r.codes()


def test_expired_attestation_fails():
    r = verify_receipt(
        fixture_receipt(),
        fixture_job(),
        fixture_attestation(attestedAt="2026-04-01T00:00:00Z", expiresAt="2026-04-02T00:00:00Z"),
    )
    assert not r.ok
    assert "attestation-stale" in r.codes()


def test_missing_signature_fails():
    r = verify_receipt(
        fixture_receipt(enclaveSignature=""), fixture_job(), fixture_attestation()
    )
    assert not r.ok
    assert "no-signature" in r.codes()


def test_pro_bono_zero_verifies():
    r = verify_receipt(
        fixture_receipt(
            proBono=True, price={"amount": 0, "currency": "USD"}, tokens={"in": 0, "out": 0}
        ),
        fixture_job(),
        fixture_attestation(),
    )
    assert r.ok, r.codes()


def test_pro_bono_still_charges_rejected():
    r = verify_receipt(
        fixture_receipt(
            proBono=True, price={"amount": 50, "currency": "USD"}, tokens={"in": 0, "out": 0}
        ),
        fixture_job(),
        fixture_attestation(),
    )
    assert not r.ok
    assert "pro-bono-nonzero-price" in r.codes()


def test_pro_bono_still_meters_rejected():
    r = verify_receipt(
        fixture_receipt(
            proBono=True, price={"amount": 0, "currency": "USD"}, tokens={"in": 32, "out": 128}
        ),
        fixture_job(),
        fixture_attestation(),
    )
    assert not r.ok
    assert "pro-bono-nonzero-tokens" in r.codes()


# ---- settlement ------------------------------------------------------


def test_happy_settlement_verifies():
    r = verify_settlement_chain(
        fixture_settlement(), fixture_receipt(), fixture_auth(), "did:web:exchange.example"
    )
    assert r.ok, r.codes()


def test_settlement_wrong_exchange_fails():
    r = verify_settlement_chain(
        fixture_settlement(), fixture_receipt(), fixture_auth(), "did:web:other.example"
    )
    assert not r.ok
    assert "wrong-exchange" in r.codes()


def test_settlement_split_mismatch_fails():
    r = verify_settlement_chain(
        fixture_settlement(exchangeFee={"amount": 10, "currency": "USD"}),
        fixture_receipt(),
        fixture_auth(),
        "did:web:exchange.example",
    )
    assert not r.ok
    assert "split-mismatch" in r.codes()


# ---- strict receipt verification (real crypto) -----------------------


def test_verify_receipt_strict_valid_passes():
    kp = KeyPair()
    att = signed_attestation(kp)
    receipt = signed_receipt(kp)
    r = verify_receipt_strict(receipt, fixture_job(), att, expected_provider="did:plc:p")
    assert r.ok, r.codes()


def test_verify_receipt_strict_tampered_fails():
    kp = KeyPair()
    att = signed_attestation(kp)
    receipt = signed_receipt(kp)
    receipt["outputCommitment"] = "f" * 64  # tamper after signing
    r = verify_receipt_strict(receipt, fixture_job(), att, expected_provider="did:plc:p")
    assert not r.ok
    assert "signature-invalid" in r.codes()


def test_verify_receipt_strict_h3_forged_attestation_rejected():
    # H3: attestation carries kp's publicKey but is self-signed by an unrelated
    # key — its selfSignature must fail, so the forged attestation is rejected.
    kp = KeyPair()
    other = KeyPair()
    forged = signed_attestation(other, publicKey=kp.public_key_b64)
    receipt = signed_receipt(kp)
    r = verify_receipt_strict(receipt, fixture_job(), forged, expected_provider="did:plc:p")
    assert not r.ok
    assert "attestation-selfsig-invalid" in r.codes()


def test_verify_receipt_strict_fails_closed_without_expected_provider():
    kp = KeyPair()
    att = signed_attestation(kp)
    receipt = signed_receipt(kp)
    r = verify_receipt_strict(receipt, fixture_job(), att)
    assert not r.ok
    assert "attestation-owner-unverified" in r.codes()


def test_verify_receipt_strict_allow_unbound_opts_out():
    kp = KeyPair()
    att = signed_attestation(kp)
    receipt = signed_receipt(kp)
    r = verify_receipt_strict(receipt, fixture_job(), att, allow_unbound_attestation=True)
    assert r.ok, r.codes()


def test_verify_receipt_strict_expected_provider_mismatch_rejected():
    kp = KeyPair()
    att = signed_attestation(kp)
    receipt = signed_receipt(kp, provider="did:plc:p")
    r = verify_receipt_strict(
        receipt, fixture_job(), att, expected_provider="did:plc:someone-else"
    )
    assert not r.ok
    assert "attestation-owner-mismatch" in r.codes()


# ---- verify_for_charge ----------------------------------------------


def _charge_ctx():
    from datetime import datetime, timezone

    return PreChargeContext(
        exchange_did="did:web:exchange.example",
        settled_receipts=frozenset(),
        now=datetime(2026, 5, 7, 12, 0, 1, tzinfo=timezone.utc),
    )


def _charge_inputs(receipt, job):
    return PreChargeInputs(
        receipt=receipt,
        receipt_uri="at://did:plc:p/receipt/1",
        job=job,
        job_owner_did="did:plc:r",
        authorization=fixture_auth(),
        authorization_uri={"uri": "at://did:plc:r/auth/1", "cid": "bafycid"},
    )


def test_verify_for_charge_tokens_over_ceiling_rejected():
    r = verify_for_charge(
        _charge_ctx(),
        _charge_inputs(
            fixture_receipt(tokens={"in": 32, "out": 5000}), fixture_job(maxTokensOut=256)
        ),
    )
    assert not r.ok
    assert "tokens-over-job-ceiling" in r.codes()


def test_verify_for_charge_within_ceiling_passes():
    r = verify_for_charge(
        _charge_ctx(),
        _charge_inputs(
            fixture_receipt(tokens={"in": 32, "out": 128}), fixture_job(maxTokensOut=256)
        ),
    )
    assert r.ok, r.codes()


def test_verify_for_charge_strict_valid_passes():
    kp = KeyPair()
    att = signed_attestation(kp)
    receipt = signed_receipt(kp)
    r = verify_for_charge_strict(_charge_ctx(), _charge_inputs(receipt, fixture_job()), att)
    assert r.ok, r.codes()


def test_verify_for_charge_strict_bad_sig_fails():
    kp = KeyPair()
    att = signed_attestation(kp)
    receipt = signed_receipt(kp)
    receipt["price"] = {"amount": 99, "currency": "USD"}  # tamper after signing
    r = verify_for_charge_strict(_charge_ctx(), _charge_inputs(receipt, fixture_job()), att)
    assert not r.ok
    assert "signature-invalid" in r.codes()
