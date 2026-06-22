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
from .p256 import verify_attestation_signature, verify_p256, verify_receipt_signature
from .seal import open_from_provider, seal_to_provider
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
    "verify_attestation_signature",
    "verify_receipt_signature",
    "seal_to_provider",
    "open_from_provider",
    "VerifyResult",
    "verify_provider_for_seal",
    "session_key_message",
]
