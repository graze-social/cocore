"""cocore Python SDK.

Mirrors the TypeScript SDK's verification surface so ML practitioners can verify
a provider's confidential-tier attestation (fail-closed) before sealing a prompt.
"""

from .appattest import (
    APP_ATTEST_APP_ID,
    AppAttestError,
    AppAttestResult,
    verify_app_attest,
    verify_app_attest_b64,
)
from .canonical import CanonicalError, canonical_bytes, canonicalize
from .mda import MdaError, MdaResult, verify_chain, verify_chain_against
from .p256 import (
    signature_is_high_s,
    verify_attestation_signature,
    verify_p256,
    verify_receipt_signature,
)
from .seal import open_from_provider, seal_to_provider
from .validate import (
    Finding,
    PreChargeContext,
    PreChargeInputs,
    ValidationReport,
    finding_by_code,
    verify_for_charge,
    verify_for_charge_strict,
    verify_receipt,
    verify_receipt_strict,
    verify_settlement_chain,
)
from .verify import VerifyResult, session_key_message, verify_provider_for_seal

__all__ = [
    "CanonicalError",
    "canonicalize",
    "canonical_bytes",
    "MdaError",
    "MdaResult",
    "verify_chain",
    "verify_chain_against",
    "AppAttestError",
    "AppAttestResult",
    "verify_app_attest",
    "verify_app_attest_b64",
    "APP_ATTEST_APP_ID",
    "verify_p256",
    "signature_is_high_s",
    "verify_attestation_signature",
    "verify_receipt_signature",
    "seal_to_provider",
    "open_from_provider",
    "VerifyResult",
    "verify_provider_for_seal",
    "session_key_message",
    "Finding",
    "ValidationReport",
    "PreChargeContext",
    "PreChargeInputs",
    "verify_receipt",
    "verify_receipt_strict",
    "verify_settlement_chain",
    "verify_for_charge",
    "verify_for_charge_strict",
    "finding_by_code",
]
