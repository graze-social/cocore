# ADR-0005: Secure-Enclave-resident signing/encryption keys + observe-then-enforce soft cutover

Status: proposed (accepted in principle — Devin, 2026-07-05)
Date: 2026-07-05

## Context

The 2026-07-05 spoof (astra) defeated the `attested-confidential` tier by
copying the provider's **software** P-256 signing key (`~/.cocore/identity.pem`)
plus a genuine Apple MDA chain onto a non-Apple "Strix" box, and replaying the
APNs code-attestation challenge off-box. The chain of prior fixes narrowed but
did not close the root cause:

- ADR-0003 chased App Attest as the key-residency proof → **dead on macOS**
  (`DCAppAttestService.isSupported` is always false on any Mac).
- ADR-0004 made a trusted **brokerage countersignature** the live confidential
  gate — a session-bound witness that a live challenge passed on the serving
  socket. That closed the self-published-record and unattested-sibling seams,
  but it raised the bar rather than closing the copy-the-key root cause: the
  signing key and the prompt-encryption key were both **software-resident**, so
  they could be lifted off the machine and the challenge replayed elsewhere.

d-inference (darkbloom) does not have this hole because its keys are
**Secure-Enclave-resident**. On Apple Silicon, App Attest is dead but
`SecureEnclave.P256.Signing.PrivateKey` and `SecureEnclave.P256.KeyAgreement.PrivateKey`
work: the private scalar never leaves the SEP, so a copied key is impossible.
The shipped confidential worker, however, built with `--features apns` →
`native_mlx` but **not** `secure_enclave`, so it fell back to the software key.

## Decision

1. **Both keys move into the Secure Enclave.** The signing key
   (`is_hardware_bound() == true`) and a new P-256 KeyAgreement encryption key
   drive a `p256-ecies-se` sealed-box construction (ephemeral-static ECDH →
   HKDF-SHA256 → AES-256-GCM, byte-identical across Rust/TS/Python). The enclave
   performs the ECDH scalar-mult and returns only the raw shared secret; the
   private key never leaves the SEP. This seals the APNs code-challenge nonce
   **and** the confidential prompt to a non-extractable key. `--features apns`
   now implies `secure_enclave`, so the confidential worker can never ship with
   a software key again.

2. **`secureEnclaveAvailable` is the confidential-tier evidence.** The provider
   reports it truthfully from `is_hardware_bound()`; it is authenticated by the
   selfSignature gate, so a copied software key (which reports `false`) can't
   clear it. This is **additive to**, not a replacement for, the ADR-0004
   brokerage countersignature — both must hold for confidential.

3. **Enforcement is a per-machine downgrade behind a default-OFF lever**
   (`COCORE_CONFIDENTIAL_REQUIRE_SE_KEY`), across all four enforcement points
   (advisor `recomputeConfidential`, console `resolveVerifiedTier`, SDK +
   Python `requireSecureEnclaveKey`). No machine is disconnected; a machine
   without the SE flag caps at hardware-attested / best-effort and keeps serving.

4. **Additive scheme negotiation.** The APNs nonce and prompt are sealed with
   the codec the provider advertises (`encScheme`): `p256-ecies-se` for SE
   builds, X25519 fallback for older agents. Nothing forces an old agent onto
   the new codec.

5. **Observe-then-enforce.** Ship the code dormant, watch `secureEnclaveAvailable`
   adoption on the advisor's `/providers`, and flip the lever only once the
   confidential fleet has adopted. Mirrors the C1 and (retired) App-Attest soft
   cutovers.

## Accepted residual (matches d-inference / ADR-0003 / ADR-0004)

SE-residency stops the copy-the-key spoof; it does **not** add memory isolation.
Apple Silicon has an enclave for **keys**, not for general **compute** — the
prompt plaintext still lives in RAM and on the GPU during inference. A kernel
0-day, a physical-RAM attack, or a maliciously substituted signed build could
still expose plaintext. Trust rests on: Apple's platform security, co/core's
measured signed build, and a trusted brokerage's session-bound countersignature.
The GPU-cache scrub (`MLX.GPU.clearCache()` after each generation) and the
output-buffer `mlock` are best-effort hygiene, not a zeroization guarantee. Copy
stays "aims to / experimental / raised bar, not a guarantee."

## Consequences

- Confidential capacity temporarily shrinks to SE-capable machines after the
  flip (fail-closed > fake-confidential; requesters already 503 rather than
  downgrade). Seed ≥1 first-party SE machine before enforcing so the tier isn't
  empty at flip time.
- Old agents keep working best-effort; the console shows a calm upgrade nudge.
- A bad flip is instantly reversible (set the lever back to OFF; the next
  recompute restores standing).
- No new coordinator: `secureEnclaveAvailable` is offline-checkable from the
  attestation; the APNs code-identity leg remains the one documented
  advisor-asserted carve-out.

## Rollout order

1. Release the native+SE agent (`--features apns`, advertising
   `secureEnclaveAvailable=true` + `encScheme="p256-ecies-se"`).
2. Deploy advisor + console + SDK changes DORMANT (all levers OFF). The advisor
   records + exposes `secureEnclaveAvailable`; the APNs seal negotiation +
   prompt ECIES ship additive.
3. Let the fleet self-update.
4. Observe SE adoption on `/providers` (zero downgrade risk in this phase).
5. Flip `COCORE_CONFIDENTIAL_REQUIRE_SE_KEY=1` on advisor + console and the
   SDK/Py verifier defaults once adoption is high.
