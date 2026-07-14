"""Cross-record validators for dev.cocore.compute.* records.

Python mirror of packages/sdk/src/validate.ts. The two verifiers MUST agree: a
receipt the TS SDK rejects must also be rejected here, so a Python consumer
cannot be tricked into trusting a receipt the canonical TS verifier would refuse.

Two tiers, mirroring the TS module:
  * ``verify_receipt`` / ``verify_for_charge`` — synchronous structural checks
    (commitment shape + equality, ceiling, expiry, linkage, pro-bono invariant)
    that assert ``enclaveSignature`` is present but do not run the crypto.
  * ``verify_receipt_strict`` / ``verify_for_charge_strict`` — add a real ES256
    verification of ``enclaveSignature`` against ``attestation.publicKey`` AND
    authenticate the attestation itself (its ``selfSignature``) plus the
    owner-DID binding. Fail closed.

Records are plain mappings (already-decoded JSON), matching how the confidential
verifier in ``verify.py`` takes ``attestation`` as a ``Mapping``. Findings are
returned as a structured report rather than raised, mirroring the TS API.

Ported checks (parity with validate.ts):
  verify_receipt, verify_receipt_strict, verify_settlement_chain,
  verify_for_charge, verify_for_charge_strict, plus checkProBonoInvariant and the
  SHA-256 commitment-shape guard.
Not ported: nothing from validate.ts's receipt-validation surface is stubbed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping, Optional

from .canonical import CanonicalError, canonicalize
from .p256 import verify_attestation_signature, verify_receipt_signature

# A SHA-256 commitment on the wire is 64 lowercase hex chars, no prefix
# (CLAUDE.md "Hashes" convention). Anything else is malformed.
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")


@dataclass
class Finding:
    severity: str  # "error" | "warn"
    code: str
    message: str


@dataclass
class ValidationReport:
    ok: bool
    findings: list[Finding] = field(default_factory=list)

    def codes(self) -> list[str]:
        return [f.code for f in self.findings]


def _err(out: list[Finding], code: str, message: str) -> None:
    out.append(Finding("error", code, message))


def _ok(findings: list[Finding]) -> bool:
    return all(f.severity != "error" for f in findings)


def _check_commitment_hex(value: Any, field_name: str, code: str, findings: list[Finding]) -> None:
    """Shape-check a commitment field as a bare lowercase-hex SHA-256 digest.
    Parity with checkCommitmentHex in validate.ts."""
    if not isinstance(value, str) or not _SHA256_HEX.match(value):
        _err(
            findings,
            code,
            f"{field_name} is not a lowercase-hex SHA-256 digest (64 hex chars): {value!r}",
        )


def _check_pro_bono_invariant(receipt: Mapping[str, Any], findings: list[Finding]) -> None:
    """A proBono:true receipt MUST carry price.amount 0 and tokens {0,0}.
    Parity with checkProBonoInvariant in validate.ts."""
    if receipt.get("proBono") is not True:
        return
    price = receipt.get("price") or {}
    tokens = receipt.get("tokens") or {}
    if price.get("amount") != 0:
        _err(
            findings,
            "pro-bono-nonzero-price",
            f"receipt.proBono is true but price.amount is {price.get('amount')}, not 0",
        )
    if tokens.get("in") != 0 or tokens.get("out") != 0:
        _err(
            findings,
            "pro-bono-nonzero-tokens",
            "receipt.proBono is true but tokens are "
            f"{{ in: {tokens.get('in')}, out: {tokens.get('out')} }}, not zero",
        )


def _parse_ms(s: Optional[str]) -> Optional[float]:
    """Parse an RFC3339 timestamp to epoch milliseconds; None if unparseable
    (mirrors JS Date.parse returning NaN, which every comparison then fails)."""
    if not isinstance(s, str):
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp() * 1000
    except ValueError:
        return None


def verify_receipt(
    receipt: Mapping[str, Any],
    job: Mapping[str, Any],
    attestation: Mapping[str, Any],
) -> ValidationReport:
    """Verify a receipt is internally consistent against its job and attestation.
    Parity with verifyReceipt in validate.ts."""
    findings: list[Finding] = []

    _check_commitment_hex(
        receipt.get("inputCommitment"), "receipt.inputCommitment", "input-commitment-shape", findings
    )
    _check_commitment_hex(
        receipt.get("outputCommitment"),
        "receipt.outputCommitment",
        "output-commitment-shape",
        findings,
    )

    if receipt.get("inputCommitment") != job.get("inputCommitment"):
        _err(findings, "commitment-mismatch", "receipt.inputCommitment does not equal job.inputCommitment")
    if receipt.get("model") != job.get("model"):
        _err(
            findings,
            "model-mismatch",
            f'receipt.model "{receipt.get("model")}" does not match job.model "{job.get("model")}"',
        )
    price = receipt.get("price") or {}
    ceiling = job.get("priceCeiling") or {}
    if price.get("currency") != ceiling.get("currency"):
        _err(findings, "currency-mismatch", "receipt.price.currency does not match job.priceCeiling.currency")
    elif _num(price.get("amount")) > _num(ceiling.get("amount")):
        _err(
            findings,
            "price-over-ceiling",
            f"receipt.price.amount {price.get('amount')} exceeds priceCeiling {ceiling.get('amount')}",
        )
    _check_pro_bono_invariant(receipt, findings)

    completed = _parse_ms(receipt.get("completedAt"))
    job_expires = _parse_ms(job.get("expiresAt"))
    if completed is None or job_expires is None or completed > job_expires:
        _err(findings, "job-expired", "receipt.completedAt is past job.expiresAt")

    attested = _parse_ms(attestation.get("attestedAt"))
    att_expires = _parse_ms(attestation.get("expiresAt"))
    if (
        completed is None
        or attested is None
        or att_expires is None
        or completed < attested
        or completed > att_expires
    ):
        _err(
            findings,
            "attestation-stale",
            "receipt.completedAt is outside the attestation validity window",
        )

    # Reconstruct the canonical bytes the provider signed; ensure the body
    # round-trips (mirrors verifyReceipt's canonical-fail guard).
    try:
        signed = {k: v for k, v in receipt.items() if k != "enclaveSignature"}
        canonicalize(signed)
    except CanonicalError as e:
        _err(findings, "canonical-fail", f"receipt body could not be canonicalised: {e}")

    if not receipt.get("enclaveSignature"):
        _err(findings, "no-signature", "receipt is missing enclaveSignature")

    return ValidationReport(ok=_ok(findings), findings=findings)


def verify_receipt_strict(
    receipt: Mapping[str, Any],
    job: Mapping[str, Any],
    attestation: Mapping[str, Any],
    *,
    expected_provider: Optional[str] = None,
    allow_unbound_attestation: bool = False,
) -> ValidationReport:
    """Strict superset of verify_receipt (parity with verifyReceiptStrict):
    real ES256 verification of enclaveSignature against attestation.publicKey,
    authentication of the attestation's own selfSignature, and the owner-DID
    binding.

    H3: verifying the receipt against attestation.publicKey is meaningless if the
    attestation is forged — an attacker can mint a key, publish an attestation
    carrying it, and sign the receipt with it. So this also verifies
    attestation.selfSignature and binds the attestation to the receipt's
    provider. ``expected_provider`` is the DID the caller independently expects
    to own both records; omitting it (without ``allow_unbound_attestation``)
    FAILS CLOSED."""
    baseline = verify_receipt(receipt, job, attestation)
    findings = list(baseline.findings)

    pub = attestation.get("publicKey", "")

    sig = receipt.get("enclaveSignature")
    if sig:
        if not verify_receipt_signature(receipt, pub, attestation.get("sigScheme")):
            _err(
                findings,
                "signature-invalid",
                "enclaveSignature did not verify against attestation.publicKey",
            )

    # Authenticate the attestation itself (mirrors verifyForChargeStrict/H1).
    self_sig = attestation.get("selfSignature")
    if self_sig:
        if not verify_attestation_signature(attestation, pub):
            _err(
                findings,
                "attestation-selfsig-invalid",
                "attestation.selfSignature did not verify against attestation.publicKey",
            )
    else:
        _err(findings, "attestation-unsigned", "attestation is missing selfSignature")

    # Owner-DID binding. The receipt's provider (denormalised, may be absent) and
    # the caller's expected_provider must agree. Fail closed when neither the
    # expected provider nor an explicit opt-out is supplied.
    receipt_provider = receipt.get("provider")
    if expected_provider:
        if receipt_provider and receipt_provider != expected_provider:
            _err(
                findings,
                "attestation-owner-mismatch",
                f"receipt.provider {receipt_provider} does not match expected provider {expected_provider}",
            )
    elif not allow_unbound_attestation:
        _err(
            findings,
            "attestation-owner-unverified",
            "no expected_provider supplied and allow_unbound_attestation is not set; "
            "cannot bind the attestation to the receipt's provider (fail closed)",
        )

    return ValidationReport(ok=_ok(findings), findings=findings)


def verify_settlement_chain(
    settlement: Mapping[str, Any],
    receipt: Mapping[str, Any],
    authorization: Mapping[str, Any],
    exchange_did: str,
) -> ValidationReport:
    """Verify a settlement record correctly chains receipt + authorization.
    Parity with verifySettlementChain in validate.ts."""
    findings: list[Finding] = []

    if authorization.get("exchange") != exchange_did:
        _err(
            findings,
            "wrong-exchange",
            f"authorization names exchange {authorization.get('exchange')}, "
            f"but settlement was published by {exchange_did}",
        )
    ceiling = authorization.get("ceiling") or {}
    charged = settlement.get("amountCharged") or {}
    if ceiling.get("currency") != charged.get("currency"):
        _err(
            findings,
            "currency-mismatch",
            "authorization.ceiling.currency does not match settlement.amountCharged.currency",
        )
    elif _num(charged.get("amount")) > _num(ceiling.get("amount")):
        _err(
            findings,
            "over-ceiling",
            f"settlement.amountCharged {charged.get('amount')} exceeds authorization ceiling {ceiling.get('amount')}",
        )
    payout = settlement.get("providerPayout") or {}
    fee = settlement.get("exchangeFee") or {}
    if _num(charged.get("amount")) != _num(payout.get("amount")) + _num(fee.get("amount")):
        _err(findings, "split-mismatch", "amountCharged != providerPayout + exchangeFee")
    price = receipt.get("price") or {}
    if settlement.get("status") == "settled" and _num(charged.get("amount")) != _num(price.get("amount")):
        _err(findings, "amount-vs-price", "for status=settled, amountCharged must equal receipt.price")

    return ValidationReport(ok=_ok(findings), findings=findings)


@dataclass
class PreChargeContext:
    exchange_did: str
    settled_receipts: frozenset[str] = frozenset()
    now: Optional[datetime] = None


@dataclass
class PreChargeInputs:
    receipt: Mapping[str, Any]
    receipt_uri: str
    job: Mapping[str, Any]
    job_owner_did: str
    authorization: Mapping[str, Any]
    authorization_uri: Mapping[str, Any]


def verify_for_charge(ctx: PreChargeContext, inputs: PreChargeInputs) -> ValidationReport:
    """Pre-charge verification for an exchange. Parity with verifyForCharge."""
    receipt, job, authorization = inputs.receipt, inputs.job, inputs.authorization
    findings: list[Finding] = []
    now = (ctx.now or datetime.now(timezone.utc)).timestamp() * 1000

    if inputs.receipt_uri in ctx.settled_receipts:
        _err(findings, "already-settled", f"receipt {inputs.receipt_uri} has a prior settlement")
    if receipt.get("requester") != inputs.job_owner_did:
        _err(
            findings,
            "job-owner-mismatch",
            f"receipt.requester {receipt.get('requester')} does not match job-owning repo {inputs.job_owner_did}",
        )
    if authorization.get("exchange") != ctx.exchange_did:
        _err(
            findings,
            "wrong-exchange",
            f"authorization names {authorization.get('exchange')}; this exchange is {ctx.exchange_did}",
        )
    job_auth = job.get("paymentAuthorization") or {}
    if job_auth.get("uri") != (inputs.authorization_uri or {}).get("uri"):
        _err(findings, "auth-job-link", "job.paymentAuthorization.uri does not equal supplied authorization uri")
    auth_expires = _parse_ms(authorization.get("expiresAt"))
    if auth_expires is None or auth_expires <= now:
        _err(findings, "auth-expired", f"authorization expired at {authorization.get('expiresAt')}")

    _check_commitment_hex(
        receipt.get("inputCommitment"), "receipt.inputCommitment", "input-commitment-shape", findings
    )
    _check_commitment_hex(
        receipt.get("outputCommitment"),
        "receipt.outputCommitment",
        "output-commitment-shape",
        findings,
    )
    if receipt.get("inputCommitment") != job.get("inputCommitment"):
        _err(findings, "commitment-mismatch", "receipt.inputCommitment != job.inputCommitment")

    price = receipt.get("price") or {}
    ceiling = job.get("priceCeiling") or {}
    if price.get("currency") != ceiling.get("currency"):
        _err(findings, "currency-mismatch", "receipt.price.currency != job.priceCeiling.currency")
    elif _num(price.get("amount")) > _num(ceiling.get("amount")):
        _err(
            findings,
            "price-over-job-ceiling",
            f"receipt.price.amount {price.get('amount')} > job.priceCeiling {ceiling.get('amount')}",
        )
    auth_ceiling = authorization.get("ceiling") or {}
    if price.get("currency") != auth_ceiling.get("currency"):
        _err(findings, "currency-mismatch-auth", "receipt.price.currency != authorization.ceiling.currency")
    elif _num(price.get("amount")) > _num(auth_ceiling.get("amount")):
        _err(
            findings,
            "price-over-auth-ceiling",
            f"receipt.price.amount {price.get('amount')} > authorization.ceiling {auth_ceiling.get('amount')}",
        )
    tokens = receipt.get("tokens") or {}
    if _num(tokens.get("out")) > _num(job.get("maxTokensOut")):
        _err(
            findings,
            "tokens-over-job-ceiling",
            f"receipt.tokens.out {tokens.get('out')} > job.maxTokensOut {job.get('maxTokensOut')}",
        )
    _check_pro_bono_invariant(receipt, findings)
    accepted = job.get("acceptedExchanges")
    if accepted and ctx.exchange_did not in accepted:
        _err(findings, "exchange-not-allowed", f"job.acceptedExchanges does not include {ctx.exchange_did}")
    completed = _parse_ms(receipt.get("completedAt"))
    job_expires = _parse_ms(job.get("expiresAt"))
    if completed is None or job_expires is None or completed > job_expires:
        _err(findings, "job-completed-after-expiry", "receipt.completedAt is past job.expiresAt")
    if not receipt.get("enclaveSignature"):
        _err(findings, "no-signature", "receipt is missing enclaveSignature")

    return ValidationReport(ok=_ok(findings), findings=findings)


def verify_for_charge_strict(
    ctx: PreChargeContext,
    inputs: PreChargeInputs,
    attestation: Mapping[str, Any],
) -> ValidationReport:
    """Strict superset of verify_for_charge (parity with verifyForChargeStrict):
    ES256 over the receipt against attestation.publicKey PLUS the attestation's
    own selfSignature (H1). Fail closed. The owner-DID binding (attestation owned
    by the paid provider) is enforced by the exchange, which holds both repos."""
    baseline = verify_for_charge(ctx, inputs)
    findings = list(baseline.findings)
    pub = attestation.get("publicKey", "")

    if inputs.receipt.get("enclaveSignature"):
        if not verify_receipt_signature(inputs.receipt, pub, attestation.get("sigScheme")):
            _err(
                findings,
                "signature-invalid",
                "enclaveSignature did not verify against attestation.publicKey",
            )

    self_sig = attestation.get("selfSignature")
    if self_sig:
        if not verify_attestation_signature(attestation, pub):
            _err(
                findings,
                "attestation-selfsig-invalid",
                "attestation.selfSignature did not verify against attestation.publicKey",
            )
    else:
        _err(findings, "attestation-unsigned", "attestation is missing selfSignature")

    return ValidationReport(ok=_ok(findings), findings=findings)


def _num(v: Any) -> float:
    """Coerce a numeric field to a comparable number; missing/non-numeric → -inf
    so a missing amount never silently passes a > ceiling check."""
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return float("-inf")
    return v


def finding_by_code(report: ValidationReport, code: str) -> Optional[Finding]:
    for f in report.findings:
        if f.code == code:
            return f
    return None
