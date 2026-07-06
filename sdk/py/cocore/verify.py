"""Requester-side, fail-closed provider verification (mirror of
packages/sdk/src/verify-provider.ts).

Run BEFORE sealing a prompt. Returns ``attested-confidential`` only when ALL of:
the attestation's selfSignature verifies; a bound MDA chain (leaf key ==
publicKey) to the Apple root; cdHash (and optionally metallibHash) in the
known-good set; the hardened posture (sip, secureBoot, hardenedRuntime,
libraryValidation, not getTaskAllow, inProcessBackend, antiDebug,
coreDumpsDisabled, envScrubbed); osVersion >= floor; unexpired; and — when a
SessionKey is supplied — a valid enclave signature over {attestationCid,
ephemeralPubKey, nonce}. Anything weaker is best-effort, and when the caller
demanded confidential it FAILS CLOSED (ok=False).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Optional

from .appattest import (
    APP_ATTEST_APP_ID,
    AppAttestError,
    attested_key_matches_signing_key,
    verify_app_attest,
    verify_app_attest_assertion,
)
from .canonical import canonical_bytes
from .mda import MdaError, verify_chain, verify_chain_against
from .p256 import verify_attestation_signature, verify_p256


def session_key_message(sk: Mapping[str, str]) -> bytes:
    """Canonical bytes an enclave signs for a SessionKey — byte-identical to the
    Rust producer and the TS sessionKeyMessage."""
    return canonical_bytes(
        {
            "attestationCid": sk["attestationCid"],
            "ephemeralPubKey": sk["ephemeralPubKey"],
            "nonce": sk["nonce"],
        }
    )


@dataclass
class VerifyResult:
    tier: str
    ok: bool
    findings: list[dict] = field(default_factory=list)
    seal_to_key: Optional[str] = None

    def codes(self) -> list[str]:
        return [f["code"] for f in self.findings]


def verify_provider_for_seal(
    attestation: Mapping[str, Any],
    mda_chain: Optional[list[str]],
    *,
    require_confidential: bool = False,
    known_good_cdhashes: Iterable[str] = (),
    known_good_metallib_hashes: Iterable[str] = (),
    known_good_engine_lib_hashes: Iterable[str] = (),
    os_floor: Optional[str] = None,
    attestation_cid: Optional[str] = None,
    nonce: Optional[str] = None,
    session_key: Optional[Mapping[str, str]] = None,
    require_session_key: bool = False,
    code_attested: bool = False,
    # SECURE DEFAULT (0.9.23): confidential requires the live APNs code-identity
    # proof unless explicitly opted out (the cdHash is self-reported; the
    # AMFI-gated push is the one leg an operator can't forge). Mirrors the TS SDK.
    require_code_attested: bool = True,
    # Key residency. ADR-0004 RETIRES this gate for the Mac tier: App Attest does
    # not function on macOS (ADR-0003 update), so no Mac provider can satisfy it.
    # Confidential residency now rests on the BROKERAGE COUNTERSIGNATURE checked at
    # receipt-validation time (cocore.brokerage). Default False; kept opt-in for a
    # future confidential-compute backend. Mirrors the TS SDK.
    require_hardware_bound_key: bool = False,
    trust_anchor_der: Optional[bytes] = None,
    app_attest_trust_anchor_der: Optional[bytes] = None,
    allow_development_app_attest: bool = False,
    now: Optional[datetime] = None,
) -> VerifyResult:
    now = now or datetime.now(timezone.utc)
    known_good = {h.strip().lower() for h in known_good_cdhashes if h}
    known_good_metallibs = {h.strip().lower() for h in known_good_metallib_hashes if h}
    known_good_engine_libs = {h.strip().lower() for h in known_good_engine_lib_hashes if h}
    blockers: list[tuple[str, str]] = []

    def block(code: str, message: str) -> None:
        blockers.append((code, message))

    # A signature "by the attestation identity" (selfSignature, session key)
    # dispatches on sigScheme (ADR-0003): raw ECDSA-P256 by default, or an App
    # Attest assertion over `message` when the identity is the SE App Attest key
    # — the form that proves the private key is non-exportable. Mirror of
    # verifyIdentitySig in verify-provider.ts.
    sig_scheme = attestation.get("sigScheme")

    def _verify_identity_sig(sig_b64: str, message: bytes) -> bool:
        pub = attestation.get("publicKey", "")
        if sig_scheme == "appattest-assertion":
            return verify_app_attest_assertion(pub, sig_b64, message, APP_ATTEST_APP_ID)
        return verify_p256(pub, sig_b64, message)

    # 0. The attestation must be self-signed by its own publicKey — this
    #    authenticates every posture field below.
    if sig_scheme == "appattest-assertion":
        self_sig = attestation.get("selfSignature", "")
        body = {k: v for k, v in attestation.items() if k not in ("selfSignature", "$type")}
        self_ok = bool(self_sig) and _verify_identity_sig(self_sig, canonical_bytes(body))
    else:
        self_ok = verify_attestation_signature(attestation, attestation.get("publicKey", ""))
    if not self_ok:
        block(
            "attestation-signature-invalid",
            "attestation.selfSignature did not verify against attestation.publicKey",
        )

    # 1+2. Hardware attestation: a bound App Attest object OR a bound MDA chain.
    # App Attest (attestation["appAttest"]) is the MDM-free path: a verifying
    # object is bound to the signing key by construction (clientDataHash =
    # sha256(publicKey)). If present and bound it SATISFIES the requirement and
    # the MDA gate is skipped; otherwise we fall back to the MDA chain as before.
    mda = None
    pub_b64 = attestation.get("publicKey", "")
    aa = attestation.get("appAttest")
    # Verify the App Attest object once and keep the rich result: we need both
    # whether it BINDS (→ hardware-attested) and whether the attested SE key IS
    # the signing key (→ the residency predicate for confidential; see below).
    aa_result = None
    if aa and aa.get("object") and aa.get("keyId"):
        try:
            aa_result = verify_app_attest(
                base64.b64decode(aa["object"]),
                base64.b64decode(aa["keyId"]),
                base64.b64decode(pub_b64),
                APP_ATTEST_APP_ID,
                trust_anchor_der=app_attest_trust_anchor_der,
                allow_development=allow_development_app_attest,
                now=now,
            )
        except AppAttestError:
            aa_result = None
    app_attest_binds = bool(aa_result and aa_result.valid and aa_result.binds_signing_key)
    # Residency: the attested key must EQUAL the signing key, not merely commit to
    # it via clientData (a genuine SE key can attest a pointer to a separate
    # software signing key — still portable). Only equality proves the signing
    # private key itself is non-exportable.
    key_is_hardware_resident = bool(
        app_attest_binds
        and attested_key_matches_signing_key(aa_result.attested_pubkey_uncompressed, pub_b64)
    )

    if app_attest_binds:
        pass  # hardware-attested via App Attest; no MDA chain required
    elif not mda_chain:
        block(
            "no-mda-chain",
            "attestation carries no MDA certificate chain and no valid bound App Attest object",
        )
    else:
        chain_der = [base64.b64decode(c) for c in mda_chain]
        try:
            mda = (
                verify_chain_against(chain_der, trust_anchor_der, now)
                if trust_anchor_der is not None
                else verify_chain(chain_der)
            )
        except MdaError as exc:
            block("mda-invalid", f"MDA chain did not verify: {exc}")
        if mda is not None:
            if not mda.valid:
                block("mda-invalid", "MDA chain did not verify")
            # BINDING (parity with verify-provider.ts): bind to the signing key
            # via (A) leaf == publicKey, OR (B) freshness-code commits to it
            # (freshness == sha256(publicKey)). Fail-closed if neither holds.
            leaf_binds = bool(mda.leaf_public_key) and mda.leaf_public_key == pub_b64
            fresh_binds = _freshness_binds_key(mda.freshness_code, pub_b64)
            if not leaf_binds and not fresh_binds:
                if not mda.leaf_public_key and not mda.freshness_code:
                    block(
                        "mda-no-binding-material",
                        "MDA leaf has neither an extractable P-256 key nor a freshness code to bind",
                    )
                else:
                    block(
                        "mda-unbound",
                        "MDA chain is not bound to attestation.publicKey (neither leaf-key nor freshness-code binding holds)",
                    )

    # 2b. Key residency: the signing key must be provably non-exportable.
    # `key_is_hardware_resident` requires a bound App Attest object WHOSE ATTESTED
    # KEY IS the signing key (keyId == sha256(publicKey)). A mere binding (object
    # present, or an MDA freshness code) only proves a genuine Apple device
    # vouched for the PUBLIC key — a software private key with such a proof is
    # portable to a non-Apple host (the 2026-07-05 spoof). Confidential-only: NOT
    # a hardware blocker, so an MDA-only / pointer-bound machine caps at
    # hardware-attested rather than dropping to best-effort.
    if require_hardware_bound_key and not key_is_hardware_resident:
        block(
            "key-not-hardware-bound",
            "App Attest object is present but its attested Secure-Enclave key is NOT the signing "
            "key (keyId != sha256(publicKey)) — it only points at the signing key via clientData, "
            "so the signing private key is still exportable/portable"
            if app_attest_binds
            else "signing key is not proven Secure-Enclave-resident: no bound App Attest object "
            "whose attested key is the signing key (an MDA-freshness binding attests the device "
            "that vouched for the public key, not that the private key is non-exportable)",
        )

    # 3. cdHash in the known-good set.
    cd = attestation.get("cdHash")
    if not cd:
        block("no-cdhash", "attestation has no measured cdHash")
    elif not known_good:
        block("no-known-good-set", "no known-good cdHash set supplied; cannot trust any build")
    elif cd.lower() not in known_good:
        block("cdhash-unknown", f"cdHash {cd} is not in the known-good set")

    # Metallib pin (when supplied).
    if known_good_metallibs:
        mh = attestation.get("metallibHash")
        if not mh:
            block("no-metallib-hash", "attestation has no measured metallibHash")
        elif mh.lower() not in known_good_metallibs:
            block("metallib-unknown", f"metallibHash {mh} is not in the known-good set")

    # Engine-dylib pin (when supplied).
    if known_good_engine_libs:
        eh = attestation.get("engineLibHash")
        if not eh:
            block("no-engine-lib-hash", "attestation has no measured engineLibHash")
        elif eh.lower() not in known_good_engine_libs:
            block("engine-lib-unknown", f"engineLibHash {eh} is not in the known-good set")

    # 4. Hardened-runtime posture (absent booleans treated as the unsafe value).
    if attestation.get("sipEnabled") is not True:
        block("sip-off", "SIP is not enabled")
    if attestation.get("secureBootEnabled") is not True:
        block("secure-boot-off", "Secure Boot is not enabled")
    if attestation.get("hardenedRuntime") is not True:
        block("no-hardened-runtime", "binary is not running under the hardened runtime")
    if attestation.get("libraryValidation") is not True:
        block("no-library-validation", "library validation is not enforced")
    if attestation.get("getTaskAllow") is not False:
        block("get-task-allow", "get-task-allow is not provably false")
    if attestation.get("inProcessBackend") is not True:
        block("not-in-process", "inference does not run in-process in the measured binary")
    if attestation.get("antiDebug") is not True:
        block("no-anti-debug", "PT_DENY_ATTACH not applied")
    if attestation.get("coreDumpsDisabled") is not True:
        block("core-dumps-enabled", "core dumps not disabled")
    if attestation.get("envScrubbed") is not True:
        block("env-not-scrubbed", "DYLD_* env not scrubbed")
    if mda is not None and mda.sip_enabled is False:
        block("mda-sip-off", "MDA chain reports SIP disabled")
    if mda is not None and mda.secure_boot_enabled is False:
        block("mda-secure-boot-off", "MDA chain reports Secure Boot disabled")

    # 5. OS floor.
    if os_floor and _cmp_os(attestation.get("osVersion", ""), os_floor) < 0:
        block("os-below-floor", f"osVersion {attestation.get('osVersion')} below floor {os_floor}")

    # 6. Freshness window.
    attested_at = _parse_dt(attestation.get("attestedAt"))
    expires_at = _parse_dt(attestation.get("expiresAt"))
    if attested_at is None or expires_at is None or not (attested_at <= now <= expires_at):
        block("attestation-expired", "attestation is outside its [attestedAt, expiresAt] window")

    # 7. Optional enclave-signed session key (advisor-trustless freshness).
    if session_key:
        if not nonce or session_key.get("nonce") != nonce:
            block("session-nonce-mismatch", "session key nonce does not match the request nonce")
        if not attestation_cid or session_key.get("attestationCid") != attestation_cid:
            block("session-attestation-mismatch", "session key not bound to the attestation CID")
        if not _verify_identity_sig(
            session_key.get("signature", ""),
            session_key_message(session_key),
        ):
            block("session-signature-invalid", "session key signature did not verify")
    elif require_session_key:
        block("no-session-key", "advisor-trustless freshness required but no session key supplied")
    elif not attestation.get("encryptionPubKey"):
        block("no-encryption-key", "attestation has no encryptionPubKey to seal to")

    # APNs code identity (advisor-asserted; the one signal not offline-verifiable
    # from the receipt — the deliberate coordinator-trust carve-out). Only
    # enforced when the caller opts in (the advisor runs APNs).
    if require_code_attested and code_attested is not True:
        block(
            "code-not-attested",
            "provider has not passed a live APNs code-identity challenge",
        )

    confidential = not blockers
    tier = "attested-confidential" if confidential else "best-effort"
    severity = "error" if require_confidential else "warn"
    findings = [{"severity": severity, "code": c, "message": m} for c, m in blockers]
    result = VerifyResult(
        tier=tier, ok=confidential or not require_confidential, findings=findings
    )
    if confidential:
        result.seal_to_key = (
            session_key["ephemeralPubKey"] if session_key else attestation.get("encryptionPubKey")
        )
    return result


def _freshness_binds_key(freshness_code: Optional[bytes], public_key_b64: Optional[str]) -> bool:
    """Option-B binding: the MDA leaf's Apple freshness code commits to the
    signing key iff freshness == sha256(publicKey raw bytes). Tolerates the DER
    OCTET STRING wrapper (04 20 ‖ 32) so it matches the TS/Rust verifiers
    byte-for-byte. Constant-time compare; never raises."""
    if not freshness_code or not public_key_b64:
        return False
    try:
        pub = base64.b64decode(public_key_b64)
    except (ValueError, TypeError):
        return False
    if not pub:
        return False
    fc = freshness_code
    if len(fc) == 34 and fc[0] == 0x04 and fc[1] == 0x20:
        fc = fc[2:]
    return hmac.compare_digest(hashlib.sha256(pub).digest(), fc)


def _parse_dt(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def _cmp_os(a: str, b: str) -> int:
    pa, pb = _ver(a), _ver(b)
    for i in range(max(len(pa), len(pb))):
        x = pa[i] if i < len(pa) else 0
        y = pb[i] if i < len(pb) else 0
        if x != y:
            return -1 if x < y else 1
    return 0


def _ver(s: str) -> list[int]:
    m = re.search(r"\d+(?:\.\d+)*", s)
    if not m:
        return [-1]
    return [int(p) for p in m.group(0).split(".")]
