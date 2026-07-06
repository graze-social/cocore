"""Brokerage countersignature verification (ADR-0004), Python side.

Self-contained: sign a witness with a P-256 key the way the advisor authority
does, then verify — parity with brokerage.ts / the advisor signer via the shared
canonical message.
"""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from cocore.brokerage import brokerage_witness_message, verify_brokerage_countersignature

DID = "did:web:advisor.cocore.dev"
FIELDS = dict(
    authority=DID,
    attestation="at://did:plc:prov/dev.cocore.compute.attestation/a1",
    job_cid="bafyjob",
    job_uri="at://did:plc:req/dev.cocore.compute.job/j1",
    machine_id="3mplnovbfjc2a",
    nonce="0011223344556677",
    requester="did:plc:req",
)


def _identity():
    priv = ec.generate_private_key(ec.SECP256R1())
    uncompressed = priv.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    return priv, base64.b64encode(uncompressed[1:]).decode()


def _receipt(sig_b64: str):
    return {
        "requester": FIELDS["requester"],
        "job": {"uri": FIELDS["job_uri"], "cid": FIELDS["job_cid"]},
        "attestation": {"uri": FIELDS["attestation"]},
        "brokerageCountersignature": {
            "authority": DID,
            "machineId": FIELDS["machine_id"],
            "nonce": FIELDS["nonce"],
            "sig": sig_b64,
        },
    }


def _sign(priv) -> str:
    der = priv.sign(brokerage_witness_message(**FIELDS), ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(der).decode()


def test_verify_valid_witness_in_trust_set():
    priv, pub = _identity()
    ok, authority, reason = verify_brokerage_countersignature(
        _receipt(_sign(priv)),
        trusted_authorities=[DID],
        resolve_authority_key_b64=lambda _did: pub,
    )
    assert ok, reason
    assert authority == DID


def test_reject_untrusted_authority():
    priv, pub = _identity()
    ok, _authority, reason = verify_brokerage_countersignature(
        _receipt(_sign(priv)),
        trusted_authorities=["did:web:other.example"],
        resolve_authority_key_b64=lambda _did: pub,
    )
    assert not ok
    assert "not in the trust set" in reason


def test_reject_altered_bound_field():
    priv, pub = _identity()
    receipt = _receipt(_sign(priv))
    receipt["job"]["uri"] = "at://did:plc:req/dev.cocore.compute.job/EVIL"
    ok, _authority, reason = verify_brokerage_countersignature(
        receipt,
        trusted_authorities=[DID],
        resolve_authority_key_b64=lambda _did: pub,
    )
    assert not ok
    assert "did not verify" in reason


def test_reject_when_key_unresolvable():
    priv, _pub = _identity()
    ok, _authority, reason = verify_brokerage_countersignature(
        _receipt(_sign(priv)),
        trusted_authorities=[DID],
        resolve_authority_key_b64=lambda _did: None,
    )
    assert not ok
    assert "could not resolve" in reason
