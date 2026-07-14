# Implementation plan: maximal Mac-side confidential hardening

Execution plan for **ADR-0003**. Scope: push confidential from "any operator
walks through it" (astra, 2026-07-05) to the ceiling achievable on commodity
Apple silicon — non-forgeable/non-portable identity, a decryption key that can't
leave the box, un-spoofable posture, plaintext hygiene, and public
detectability. Living checklist; tick items as PRs land.

## Goal / non-goal

- **Goal:** close the two holes an operator can walk through *today* (portable
  identity, extractable decryption key) permanently, and harden the rest as far
  as the platform allows.
- **Non-goal (this plan):** a cryptographic guarantee against a determined owner
  with a kernel 0-day or physical RAM attack. That ceiling is irreducible on
  Apple silicon (no general-compute TEE) and needs confidential-compute hardware
  — tracked separately, not here. The Mac tier's honest label stays "hardened
  against a remote/casual operator, not guaranteed against a determined owner."

## The five workstreams (the maximal stack)

| WS | What | Closes | Where it runs |
|----|------|--------|---------------|
| WS1 | Assertion-based App Attest identity (`keyId == sha256(publicKey)`) + App-ID pinning + cdHash-known-good | Portable identity (astra), forgery, modified/forwarding binary | verifier buildable now; producer needs device |
| WS2 | SE P-256 ECIES seal + mandatory per-request ephemeral session key | Decryption key lifted off disk → decrypt off-box | verifier/seal buildable now; SE key needs device |
| WS3 | Full hardened posture, made un-spoofable by WS1 | Debugger/injection/subprocess memory reads | mostly existing gates; enforcement wiring |
| WS4 | Plaintext hygiene: mlock, zeroize, GPU-buffer scrub, metallib pin | Swap/disk/GPU plaintext residue | provider engine; device to validate |
| WS5 | Reproducible builds + public known-good cdHash transparency log | A silently-shipped leaky cocore build | CI + a feed; buildable now |

WS1 is load-bearing: once only a genuine cocore-signed binary can produce a
valid identity, the posture booleans (WS3) and the enc-key residency (WS2)
become trustworthy by riding that same chain.

## Already landed (this session — the soft-cutover framework)

- [x] SDK verifier (TS+Py): `requireHardwareBoundKey` → `key-not-hardware-bound`
      (confidential-only blocker; MDA-only caps at hardware-attested).
- [x] Console `resolveVerifiedTier`: per-machine downgrade gated on
      `COCORE_CONFIDENTIAL_REQUIRE_APP_ATTEST` + C1 `registrationAuthenticated`,
      with `verifiedTierReason` surfaced in MachineDetail.
- [x] Advisor: `registrationAuthenticated` on entry + `/providers`;
      admit-but-downgrade on missing register JWT; folded into
      `confidentialEligible`.
- [x] Lexicon `#tier`/`#trustLevel` codify the residency requirement.
- [x] ADR-0003.

These are the interim "require a bound App Attest object" rung + the rollout
machinery. The plan below replaces the interim rung with the sufficient one
(`keyId == sha256(publicKey)` + assertions) and adds WS2/WS4/WS5.

## Sequencing

Lexicon-first per CLAUDE.md. Each phase is one or more PRs. "Buildable now" =
no Apple device needed (synthetic fixtures); "device" = needs this Mac.

### Phase A — verifier + lexicon (buildable now, no device)

> **Progress (2026-07-05):** A1 done (sigScheme/encScheme added to attestation.json;
> defs.json tier already tightened). A2/A4 **done in TS + Py** (verifier side):
> the App Attest **assertion** verifier (`verifyAppAttestAssertion`), the real
> residency predicate (`attestedKeyMatchesSigningKey`, i.e. `keyId ==
> sha256(publicKey)`), the strengthened `key-not-hardware-bound` gate (attested
> key IS the signing key, not just "an object is present"), AND the `sigScheme`
> dispatch so `selfSignature` + the session key verify as assertions when
> `sigScheme == "appattest-assertion"` — all unit-tested with synthetic
> assertions (no device). **A2/A4 now COMPLETE (verifier side, TS + Py):** the
> receipt `enclaveSignature` assertion path is done too — `verifyReceiptSignature`
> / `verify_receipt_signature` take a `sigScheme` and dispatch to the assertion
> verifier, wired into every consumer (validate.ts x2, appview read-router,
> validate.py x2) + tested. Backward-compatible: absent `sigScheme` = raw p256,
> unchanged for every existing provider/receipt. A3 (ECIES seal), A5 (Rust
> verifier mirror), A6 (fixtures) not started. (The 3 pre-existing SDK/py
> cross-lang failures are stale `attestation-expired` fixtures, unrelated — A6
> regenerates them.)

- [x] **A1 (lexicon PR):** additive shapes.
  - `attestation.json`: `sigScheme: "p256" | "appattest-assertion"` discriminator;
    normative `appAttest.keyId == sha256(publicKey)` as the residency marker;
    `encScheme: "x25519" | "p256-ecies-se"` for `encryptionPubKey`.
  - `receipt.json`: `enclaveSignature`/session signatures may be assertions
    under the same `sigScheme`.
  - `defs.json`: tighten `#tier` to require the assertion identity + SE-ECIES seal.
- [ ] **A2 (SDK verifier, TS):** in `packages/sdk/src/appattest.ts` add
    **assertion** verification (parse the CBOR assertion, ECDSA over
    `sha256(authData ‖ clientDataHash)` against the attested credCert key, rpId
    check) alongside the existing object verification. In `verify-provider.ts`:
    strengthen `key-not-hardware-bound` to require `keyId == sha256(publicKey)`;
    verify `selfSignature`/session/receipt as assertions when `sigScheme` says so
    (`clientDataHash = sha256(message)`).
- [ ] **A3 (SDK seal, TS):** in `seal.ts` add the **P-256 ECIES** seal path
    (ECDH to the SE public key, `kSecKeyAlgorithmECIESEncryptionCofactorX963...`
    parity); make `requireSessionKey` the default for confidential.
- [ ] **A4 (Python mirror):** same in `sdk/py/cocore/appattest.py`, `verify.py`,
    `seal.py`.
- [ ] **A5 (Rust verifier mirror):** `provider/src/appattest.rs` assertion
    verification; receipt/attestation verify paths.
- [ ] **A6 (synthetic cross-language fixtures):** extend
    `provider/tests/cross_lang_fixture.rs` to emit an assertion-based confidential
    fixture (a synthetic App Attest credCert key acting as the identity, real
    assertions, `keyId == sha256(publicKey)`, SE-ECIES enc). Proves TS/Py/Rust
    parity **without a device**. Also regenerate the stale existing fixtures
    (fixes the pre-existing `attestation-expired` failures).
- [ ] **A7 (console/advisor wiring):** point `resolveVerifiedTier`'s residency
    check at the real predicate; keep the env phase gate.

### Phase B — provider producer (needs this Mac)

> **Progress (2026-07-05):** A5 DONE — the Rust assertion verifier
> (`appattest::verify_assertion` / `verify_assertion_b64`) + residency predicate
> (`attested_key_matches_signing_key`) are implemented + `cargo test`-green in
> `provider/src/appattest.rs`, completing verifier parity across TS/Py/Rust.
> Phase B environment VALIDATED on this Mac: the App Attest entitlement
> (`com.apple.developer.devicecheck.appattest-environment => production`), the
> `cocore provisioning profile` (ProvisionsAllDevices, exp 2044), and the
> `Developer ID Application (4L45P7CP9M)` identity are all present, and the
> `provider/spikes/app-attest` helper builds + code-signs cleanly.
> **⛔ PHASE B (App Attest producer) IS A DEAD END ON macOS.** Debugged live on
> the M1 Mac mini: the SIGKILL was an entitlement/profile mismatch (the profile
> grants `app-attest-opt-in`, not `appattest-environment`); notarization works
> fine (I notarized the helper — Accepted). But the decisive fact is that
> **`DCAppAttestService.isSupported` is always `false` on macOS** (Apple docs +
> confirmed here). App Attest is iOS/iPadOS/tvOS only. So generateKey / attestKey
> / generateAssertion cannot run on a Mac, and there is no way to remotely prove
> a Mac signing key is SE-resident → **confidential-with-residency is unachievable
> on Macs.** Do NOT regenerate profiles or pursue B1–B5 for App Attest on macOS.
> See the ADR update. The verifier hardening (A1–A5) stays and is correct
> (fail-closed: no residency proof → capped at hardware-attested). Direction:
> stop offering `attested-confidential` on Macs (top tier = `hardware-attested`),
> and scope a confidential-compute-hardware backend for real confidential.

- [ ] **B1 (Swift App Attest helper):** under `provider/enclave/` (or promote
    `provider/spikes/app-attest`): `generateKey → keyId`, `attestKey → object`
    (one-time, into the attestation record), `generateAssertion(clientDataHash)
    → per-signature`. Exposed over the `COCORE_APPATTEST_BINARY` boundary,
    extended for assertions. **Requires the App Attest entitlement provisioned
    for the provider App ID under cocore's team.**
- [ ] **B2 (Rust `AppAttestIdentity`):** in `secure_enclave.rs`, a signing
    identity whose `publicKey` is the attested key (so `keyId == sha256(publicKey)`)
    and whose `sign()` returns assertions; wire into
    `build_and_publish_attestation` (`main.rs`) and `mda_loader.rs`. Software
    fallback stays self-attested/best-effort.
- [ ] **B3 (SE ECIES encryption identity):** a separate SE-resident P-256 key
    (`SecKeyCreateRandomKey`, `kSecAttrTokenIDSecureEnclave`) for
    `encryptionPubKey`; decrypt via the SEP (private key non-extractable). Switch
    the agent's enc identity + `encScheme`.
- [ ] **B4 (WS4 hygiene):** `mlock` the prompt/session-key/KV buffers (no swap);
    zeroize after use (extends the existing UDS zeroize); scrub Metal buffers in
    the native engine; keep `metallibHash` pinned; assert no plaintext logging.
- [ ] **B5 (candidate release + install on this Mac):** build the candidate,
    **rip out the running cocore tray app**, install the candidate, `cocore agent
    serve`, confirm it earns confidential under real App Attest.

### Phase C — empirical acceptance gate (this Mac) — THE "did we close it" test

- [ ] **C1:** capture the candidate's genuine attestation; move the identity to a
    second process / second machine / a software key → confirm confidential is
    **REJECTED** (no valid assertion / `keyId != sha256(publicKey)`).
- [ ] **C2:** replay **astra's actual PDS attestation** against the candidate
    verifier → confirm rejected, and confirm **App-ID pinning** rejects any
    App Attest artifact not from cocore's team (`rpIdHash` mismatch). (Also
    resolves the open flag: her record's `teamId 4L45P7CP9M` — confirm it's an
    inert self-reported field, not something that passes pinning. If it passes,
    STOP: that's a signing-identity compromise, a separate incident.)
- [ ] **C3:** with the candidate running, attempt the operator reads: SIP-off →
    honest binary reports `sip=false` → rejected; extract enc key off disk →
    absent (SE-resident); attach debugger → denied by posture. Document what
    each attack now hits.

### Phase D — rollout + honest labeling

- [ ] **D1:** flip `COCORE_CONFIDENTIAL_REQUIRE_APP_ATTEST=true` (now backed by
    the real predicate); set `COCORE_ADVISOR_DID` for the C1 downgrade; seed a
    first-party App-Attest machine so the tier isn't empty.
- [ ] **D2:** honest copy — update `ExperimentalNotice` / confidential tier
    strings to state the Mac-tier bound explicitly (hardened vs. guaranteed);
    keep the CALM framing (see the confidentiality-copy rule).
- [ ] **D3 (WS5):** reproducible-build job in `release.yml` + a public,
    append-only known-good cdHash feed the AppView serves and the verifier can
    pin to (replaces/augments `KnownGoodSet.fromEnv`).
- [ ] **D4:** later — `COCORE_ADVISOR_REQUIRE_AUTH=true` hard escalation once the
    fleet has upgraded.

## Acceptance criteria (definition of done for "closed astra's exploit")

Phase C all green: astra's exact attack (genuine attestation + portable/software
key on other hardware) is rejected; forged App-ID artifacts are rejected; the
enc key is not extractable; posture can't be spoofed by a non-cocore binary.
"Confidential" then means: non-forgeable identity, non-portable decryption,
in-process on genuine attested hardware — with the documented residual (kernel
0-day / physical RAM) called out in the UI.

## Residual / out of scope (tracked elsewhere)

Determined-owner memory reads via kernel exploit or physical RAM attack are not
closeable in software on Apple silicon. The only path to an unconditional
guarantee is confidential-compute hardware (SEV-SNP / TDX / H100-CC / PCC-style
attested nodes) — a separate architecture track, not this plan.
