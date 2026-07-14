"""Brokerage countersignature — the forkable-authority confidential gate (ADR-0004).

Mirror of packages/sdk/src/brokerage.ts. A receipt is ``attested-confidential``
only when a BROKERAGE the requester trusts has countersigned it, session-bound:
the brokerage live-challenges the machine it dispatches to, so its signature
proves "authority X routed THIS job to the machine it attested." Validity is
relative to a named authority the verifier chooses to trust (CA-style roots).
"""

from __future__ import annotations

from typing import Any, Callable, Iterable, Mapping, Optional

from .canonical import canonical_bytes
from .p256 import verify_p256


def brokerage_witness_message(
    *,
    authority: str,
    attestation: str,
    job_cid: str,
    job_uri: str,
    machine_id: str,
    nonce: str,
    requester: str,
) -> bytes:
    """The EXACT canonical bytes a brokerage signs (ADR-0004) — the
    cross-language contract; MUST be byte-identical to brokerageWitnessMessage in
    brokerage.ts and the advisor signer."""
    return canonical_bytes(
        {
            "authority": authority,
            "attestation": attestation,
            "jobCid": job_cid,
            "jobUri": job_uri,
            "machineId": machine_id,
            "nonce": nonce,
            "requester": requester,
        }
    )


def verify_brokerage_countersignature(
    receipt: Mapping[str, Any],
    *,
    trusted_authorities: Iterable[str],
    resolve_authority_key_b64: Callable[[str], Optional[str]],
) -> tuple[bool, Optional[str], Optional[str]]:
    """Verify a receipt's brokerage countersignature (ADR-0004). Returns
    ``(ok, authority, reason)``. Never raises. ``resolve_authority_key_b64`` maps
    a brokerage DID to its raw 64-byte P-256 signing key (base64), or None."""
    cs = receipt.get("brokerageCountersignature")
    if not isinstance(cs, Mapping):
        return (False, None, "no brokerage countersignature on the receipt")
    authority = cs.get("authority")
    if authority not in set(trusted_authorities):
        return (False, authority, f"authority {authority} is not in the trust set")

    job = receipt.get("job") or {}
    attestation = receipt.get("attestation") or {}
    job_uri = job.get("uri")
    job_cid = job.get("cid")
    att_uri = attestation.get("uri")
    requester = receipt.get("requester")
    machine_id = cs.get("machineId")
    nonce = cs.get("nonce")
    sig = cs.get("sig")
    if not all([job_uri, job_cid, att_uri, requester, machine_id, nonce, sig]):
        return (False, authority, "receipt or countersignature is missing a bound field")

    key = resolve_authority_key_b64(authority)
    if not key:
        return (False, authority, f"could not resolve a signing key for authority {authority}")

    message = brokerage_witness_message(
        authority=authority,
        attestation=att_uri,
        job_cid=job_cid,
        job_uri=job_uri,
        machine_id=machine_id,
        nonce=nonce,
        requester=requester,
    )
    if verify_p256(key, sig, message):
        return (True, authority, None)
    return (False, authority, "countersignature did not verify")
