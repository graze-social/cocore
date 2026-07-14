// Requester-side, fail-closed provider verification — run BEFORE sealing a
// prompt to a provider.
//
// This is the load-bearing client-edge check for the `attested-confidential`
// tier (see lexicons/dev/cocore/compute/defs.json#tier). The AppView's
// server-side dispatch seal is always `best-effort` because a service we run
// is in the plaintext path; genuine privacy-from-the-provider requires the
// requester (SDK/browser/`sdk/py`) to verify the provider's attestation and
// the per-job ephemeral session key here, and to seal to that ephemeral key
// only when every gate passes.
//
// It composes existing primitives rather than re-implementing them:
//   * `verifyChain` (mda.ts)  — Apple-rooted MDA chain + CA constraints,
//                               and returns the leaf P-256 key for binding.
//   * `verifyP256` (p256.ts)  — ES256 over the enclave-signed session key.
//   * `Finding`/`ValidationReport` (validate.ts) — the structured result shape.
//
// The contract: returns `attested-confidential` ONLY when ALL of —
//   1. an MDA chain that verifies to the Apple Enterprise Attestation Root, and
//   2. is BOUND (leaf P-256 key === attestation.publicKey), and
//   3. a measured `cdHash` that is in the caller's known-good set, and
//   4. the hardened posture: sip && hardenedRuntime && libraryValidation &&
//      !getTaskAllow && secureBoot (with MDA-reported sip/secureBoot, when the
//      chain carries them, required to agree), and
//   5. osVersion >= the caller's floor, and
//   6. the attestation is unexpired, and
//   7. a fresh, enclave-signed SessionKey bound to the caller's nonce and to
//      this attestation's CID
// — hold. Anything weaker is `best-effort`. When the caller set
// `requireConfidential`, any unmet confidential gate makes `ok === false`
// (fail closed: the caller MUST NOT seal); otherwise the same gaps are
// recorded as warnings and `ok` stays true at the best-effort tier.

import { canonicalBytes } from "./canonical.ts";
import { type MdaResult, verifyChain, verifyChainAgainst } from "./mda.ts";
import {
  APP_ATTEST_APP_ID,
  AppAttestError,
  type AppAttestResult,
  attestedKeyMatchesSigningKey,
  verifyAppAttest,
  verifyAppAttestAssertion,
} from "./appattest.ts";
import { verifyAttestationSignature, verifyP256, SignatureVerifyError } from "./p256.ts";
import type { AttestationRecord, Tier } from "./types.ts";
import type { Finding, Severity, ValidationReport } from "./validate.ts";

/** The enclave-signed, per-job ephemeral key a confidential requester seals
 *  to. Minted fresh inside the measured engine for each request, signed by the
 *  attestation's P-256 key over a canonical `{attestationCid, ephemeralPubKey,
 *  nonce}` so the requester can prove the key was produced for THIS request
 *  (nonce) by the attested enclave (attestationCid + signature). */
export interface SessionKey {
  /** base64 X25519 public key the requester seals the input to. */
  ephemeralPubKey: string;
  /** lowercase-hex echo of the requester's fresh nonce. */
  nonce: string;
  /** CID of the attestation record this session is bound to. */
  attestationCid: string;
  /** DER ECDSA P-256 signature (base64) over the canonical bytes of
   *  `{attestationCid, ephemeralPubKey, nonce}`, verified against
   *  `attestation.publicKey`. */
  signature: string;
}

export interface VerifyProviderOptions {
  /** Hard-fail when the confidential tier cannot be proven, instead of
   *  silently downgrading to best-effort. Set this whenever the caller needs
   *  privacy from the provider. */
  requireConfidential?: boolean;
  /** Code-signing cdhashes (lowercase hex) the caller trusts — the output of
   *  the transparency log / reproducible-build set. Required for confidential;
   *  an empty/absent set means no build can earn `attested-confidential`. */
  knownGoodCdHashes?: Iterable<string>;
  /** SHA-256 hex of metallibs the caller trusts (the GPU kernels that touch
   *  plaintext). When provided, an in-process provider's `metallibHash` must be
   *  in this set. Empty/absent skips the metallib pin (cdHash already pins the
   *  binary that loads it). */
  knownGoodMetallibHashes?: Iterable<string>;
  /** SHA-256 hex of dynamic engine libraries the caller trusts. When provided,
   *  an in-process provider's `engineLibHash` must be in this set (the dylib
   *  isn't covered by the cdHash). Empty/absent skips the pin. */
  knownGoodEngineLibHashes?: Iterable<string>;
  /** Minimum acceptable macOS version, e.g. "14.6.1" or "macOS 14.6.1".
   *  Providers below the floor cannot earn confidential. */
  osFloor?: string;
  /** CID of the attestation record the caller fetched — the SessionKey MUST
   *  name this CID so a key signed for a different attestation can't be
   *  replayed. */
  attestationCid?: string;
  /** The fresh nonce the caller generated for this request and sent to the
   *  provider. The SessionKey MUST echo it. */
  nonce?: string;
  /** The enclave-signed ephemeral key returned for this request (optional;
   *  the stronger advisor-trustless freshness mode). */
  sessionKey?: SessionKey;
  /** Require a per-request enclave-signed `SessionKey` (advisor-trustless
   *  freshness). Default false: liveness is vouched by the advisor's standing
   *  5-min challenge-response and the attestation's own expiry window. */
  requireSessionKey?: boolean;
  /** The advisor's live APNs code-identity standing for this provider (from the
   *  `/providers` / `/verified-providers` feed's `codeAttested`). This is the
   *  un-forgeable code-identity signal — a self-reported cdHash can be claimed
   *  by a fork, but only the genuine, AMFI-gated binary can answer the advisor's
   *  push challenge. NOTE: unlike every other gate here, this one is NOT
   *  offline-verifiable from the receipt (the challenge is interactive); it is
   *  advisor-asserted — the deliberate coordinator-trust carve-out the
   *  confidential tier accepts (see infra/mdm + the parity ADR). */
  codeAttested?: boolean;
  /** Require {@link codeAttested} for the confidential tier. **Default true**
   *  (0.9.23): confidentiality is only as strong as binary measurement, and the
   *  cdHash is self-reported — the AMFI-gated push is the one leg an operator
   *  can't forge, so we require it by default. Set this to `false` ONLY when
   *  targeting a non-APNs advisor, explicitly accepting the weaker proof (a
   *  confidential result then rests on the self-reported cdHash + MDA chain,
   *  which a forked binary on the operator's own attested device can satisfy). */
  requireCodeAttested?: boolean;
  /** Require the signing key to be provably Secure-Enclave-resident (a bound
   *  App Attest object) for the confidential tier. **Default true** (the
   *  2026-07-05 key-residency fix). An MDA chain bound via freshness-code proves
   *  a genuine Apple device once vouched for this PUBLIC key — it does NOT prove
   *  the PRIVATE key is non-exportable, so a software signing key with a real
   *  MDA chain is portable to any host (the exploit: a genuine M4's MDA chain +
   *  an exportable `identity.pem` key replayed on a Linux/AMD box to serve
   *  "confidential" traffic). Only App Attest — a key generated inside the
   *  Secure Enclave and certified by Apple as such — closes the copy path.
   *
   *  This gate is confidential-only: a machine proven genuine-Apple via an MDA
   *  chain but NOT App-Attest-bound is capped at `hardware-attested`, never
   *  dropped to `best-effort` (it stays a genuine-hardware provider, just not a
   *  confidential one). Set to `false` ONLY as a temporary transition relaxation
   *  while the provider fleet ships App Attest, explicitly re-accepting the
   *  portable-key risk. */
  requireHardwareBoundKey?: boolean;
  /** ADR-0005: require the provider to advertise a Secure-Enclave-resident
   *  signing key (`attestation.secureEnclaveAvailable === true`) for the
   *  confidential tier. This is the workable macOS replacement for the retired
   *  App Attest gate above — `secureEnclaveAvailable` is set truthfully from the
   *  agent's `is_hardware_bound()` and authenticated by the selfSignature gate,
   *  so a copied software `identity.pem` (which reports false) can't earn
   *  confidential. **Default false** for backward-compat during the soft
   *  cutover; flip to true once the fleet has adopted SE builds (observe the
   *  advisor's `secureEnclaveAvailable` adoption first). Fail-closed when on: a
   *  machine without the SE flag caps at best-effort. ADDITIVE to — not a
   *  replacement for — the brokerage countersignature gate (ADR-0004). */
  requireSecureEnclaveKey?: boolean;
  /** Clock seam for tests. */
  now?: () => Date;
  /** ADVANCED / TEST ONLY. Verify the MDA chain against this DER trust anchor
   *  instead of the embedded Apple Enterprise Attestation Root. Production
   *  callers MUST leave this unset so the chain is rooted in Apple's CA; the
   *  cross-language fixture sets it to a synthetic root. Mirrors mda.ts's
   *  `verifyChainAgainst`. */
  trustAnchorDer?: Uint8Array;
  /** ADVANCED / TEST ONLY. Verify the App Attest object against this DER trust
   *  anchor instead of the embedded Apple App Attest Root. Production callers
   *  leave this unset; the cross-language fixture sets a synthetic root. */
  appAttestTrustAnchorDer?: Uint8Array;
  /** Accept the development App Attest AAGUID in addition to production.
   *  Default false (production only). Test/dev seam. */
  allowDevelopmentAppAttest?: boolean;
}

export interface ProviderVerifyResult extends ValidationReport {
  /** The tier the caller may rely on. Recomputed from evidence; never the
   *  provider's self-asserted value. */
  tier: Tier;
  /** When `tier === "attested-confidential"`, the base64 X25519 key the caller
   *  MUST seal to (the verified ephemeral key). Undefined otherwise — a
   *  best-effort caller seals to the provider record's `encryptionPubKey`. */
  sealToKey?: string;
}

/** The canonical message an enclave signs for a SessionKey. Pinned by a
 *  cross-language vector (Rust signs, this verifies) so the producer and this
 *  verifier never drift. */
export function sessionKeyMessage(sk: {
  attestationCid: string;
  ephemeralPubKey: string;
  nonce: string;
}): Uint8Array {
  return canonicalBytes({
    attestationCid: sk.attestationCid,
    ephemeralPubKey: sk.ephemeralPubKey,
    nonce: sk.nonce,
  });
}

/**
 * Verify a provider is safe to seal a prompt to, and at what tier.
 *
 * @param attestation the provider's current attestation record (already
 *   fetched from its PDS and shape-validated).
 * @param mdaChain the DER MDA chain (base64 strings, leaf first) — usually
 *   `attestation.mdaCertChain`. Pass `undefined`/empty for a self-attested
 *   provider.
 * @param opts caller policy + the per-job session handshake material.
 */
export async function verifyProviderForSeal(
  attestation: AttestationRecord,
  mdaChain: string[] | undefined,
  opts: VerifyProviderOptions = {},
): Promise<ProviderVerifyResult> {
  const requireConfidential = opts.requireConfidential ?? false;
  // SECURE DEFAULT (0.9.23): the confidential tier REQUIRES the live APNs
  // code-identity proof unless the caller explicitly opts out. The cdHash in the
  // attestation is self-reported — a forked binary can copy a blessed cdHash
  // string and (with the operator's own genuine MDA chain) satisfy every other
  // gate. The AMFI-gated push challenge is the one leg an operator cannot forge
  // (they don't hold the cocore team's signing identity + APNs topic), so we
  // require it by default. A caller targeting a non-APNs advisor must opt out
  // explicitly (requireCodeAttested: false) and thereby accept the weaker proof.
  const requireCodeAttested = opts.requireCodeAttested ?? true;
  // Key residency. ADR-0004 RETIRES this gate for the Mac tier: App Attest —
  // the only thing that could prove key residency — does not function on macOS
  // (ADR-0003 update), so no Mac provider can ever satisfy it. Confidential
  // residency now rests on the BROKERAGE COUNTERSIGNATURE checked at
  // receipt-validation time (see brokerage.ts): a trusted authority witnessed
  // the dispatch to the attested machine. Default is therefore FALSE. The gate
  // is kept (opt-in) for a future confidential-compute backend where remote key
  // attestation IS possible.
  const requireHardwareBoundKey = opts.requireHardwareBoundKey ?? false;
  // ADR-0005 soft cutover: default OFF so existing callers are unchanged until
  // the fleet adopts SE builds; flip to true (or wire to an env/flag) at Phase 2.
  const requireSecureEnclaveKey = opts.requireSecureEnclaveKey ?? false;
  const now = opts.now ? opts.now() : new Date();
  const knownGood = new Set<string>(
    [...(opts.knownGoodCdHashes ?? [])].map((h) => h.toLowerCase()),
  );
  const knownGoodMetallibs = new Set<string>(
    [...(opts.knownGoodMetallibHashes ?? [])].map((h) => h.toLowerCase()),
  );
  const knownGoodEngineLibs = new Set<string>(
    [...(opts.knownGoodEngineLibHashes ?? [])].map((h) => h.toLowerCase()),
  );

  // Confidential blockers are collected here. If empty at the end, the
  // provider earns `attested-confidential`; otherwise each blocker is surfaced
  // as an error (when confidential was required) or a warning (downgrade).
  const blockers: Array<{ code: string; message: string }> = [];
  const block = (code: string, message: string): void => {
    blockers.push({ code, message });
  };

  // A signature "by the attestation identity" (selfSignature, session key)
  // dispatches on `sigScheme` (ADR-0003): raw ECDSA-P256 by default, or an App
  // Attest ASSERTION over `message` when the identity is the SE App Attest key.
  // The assertion path is the one that proves the private key is non-exportable
  // — it can only be produced on the device holding the key. Resolves false on
  // any verify/shape error (never throws a SignatureVerifyError out).
  const sigScheme = (attestation as { sigScheme?: string }).sigScheme;
  const verifyIdentitySig = async (sigB64: string, message: Uint8Array): Promise<boolean> => {
    try {
      if (sigScheme === "appattest-assertion") {
        return await verifyAppAttestAssertion(
          attestation.publicKey,
          sigB64,
          message,
          APP_ATTEST_APP_ID,
        );
      }
      return await verifyP256(attestation.publicKey, sigB64, message);
    } catch (e) {
      if (e instanceof SignatureVerifyError) return false;
      throw e;
    }
  };

  // --- 0. The attestation must be self-signed by its own publicKey. ---
  // This authenticates every posture field below (cdHash, getTaskAllow,
  // encryptionPubKey, …). Without it those are unsigned claims: the MDA
  // binding only proves `publicKey` is the device key and the session-key
  // signature only covers the ephemeral key — neither covers posture. Run it
  // first; a forged/tampered attestation fails here before anything else.
  {
    let selfOk = false;
    if (sigScheme === "appattest-assertion") {
      // Assertion scheme: selfSignature is an App Attest assertion over the
      // canonical record body (sans selfSignature/$type) as clientDataHash.
      const sig = attestation.selfSignature;
      if (sig) {
        const {
          selfSignature: _s,
          $type: _t,
          ...body
        } = attestation as unknown as Record<string, unknown>;
        selfOk = await verifyIdentitySig(sig, canonicalBytes(body));
      }
    } else {
      try {
        selfOk = await verifyAttestationSignature(
          attestation as unknown as { selfSignature?: string } & Record<string, unknown>,
          attestation.publicKey,
        );
      } catch (e) {
        if (!(e instanceof SignatureVerifyError)) throw e;
        selfOk = false;
      }
    }
    if (!selfOk) {
      block(
        "attestation-signature-invalid",
        "attestation.selfSignature did not verify against attestation.publicKey — posture fields are unauthenticated",
      );
    }
  }

  // --- 1+2. Hardware attestation: a bound App Attest object OR a bound MDA
  // chain. Either proves genuine Apple hardware tied to the signing key.
  //
  // App Attest (attestation.appAttest) is the MDM-free path: the helper set
  // clientDataHash = sha256(publicKey), so a verifying object is bound to the
  // signing key by construction (verifyAppAttestB64 checks the credCert nonce
  // extension). If a bound App Attest object is present it SATISFIES the
  // hardware-attestation requirement and the MDA gate is skipped; otherwise we
  // fall back to the MDA chain exactly as before.
  let mda: MdaResult | undefined;
  const aa = attestation.appAttest;
  // Verify the App Attest object once and keep the rich result: we need both
  // whether it BINDS (genuine SE key vouched for this signing key → satisfies
  // hardware-attested) and whether the attested key IS the signing key (→ the
  // residency predicate for confidential; see below).
  let aaResult: AppAttestResult | undefined;
  if (aa?.object && aa?.keyId) {
    try {
      aaResult = verifyAppAttest(
        base64ToBytes(aa.object),
        base64ToBytes(aa.keyId),
        base64ToBytes(attestation.publicKey),
        APP_ATTEST_APP_ID,
        {
          trustAnchorDer: opts.appAttestTrustAnchorDer,
          allowDevelopment: opts.allowDevelopmentAppAttest,
          now,
        },
      );
    } catch (e) {
      if (!(e instanceof AppAttestError)) throw e;
      // an AppAttestError just means "doesn't bind" → aaResult stays undefined
    }
  }
  const appAttestBinds = aaResult?.valid === true && aaResult.bindsSigningKey === true;
  // Residency: the attested SE key must EQUAL the signing key, not merely commit
  // to it via clientData (a genuine SE key can attest a pointer to a separate
  // software signing key — still portable). Only equality proves the signing
  // private key itself is non-exportable.
  const keyIsHardwareResident =
    appAttestBinds &&
    attestedKeyMatchesSigningKey(aaResult!.attestedPubkeyUncompressed, attestation.publicKey);

  if (appAttestBinds) {
    // Hardware-attested via App Attest; no MDA chain required.
  } else if (!mdaChain || mdaChain.length === 0) {
    block(
      "no-mda-chain",
      "attestation carries no MDA certificate chain and no valid bound App Attest object",
    );
  } else {
    try {
      const chainDer = mdaChain.map((b64) => base64ToBytes(b64));
      mda = opts.trustAnchorDer
        ? verifyChainAgainst(chainDer, opts.trustAnchorDer, now)
        : verifyChain(chainDer);
    } catch (e) {
      block("mda-invalid", `MDA chain did not verify: ${(e as Error).message}`);
    }
    if (mda) {
      if (!mda.valid) {
        block("mda-invalid", "MDA chain did not verify");
      }
      // BINDING — the chain must be tied to the signing key
      // (`attestation.publicKey`), or a genuine Apple chain for one device
      // could be stapled onto an unrelated signing key. Two accepted ways:
      //   (A) the attested leaf key IS the signing key (`leaf === publicKey`).
      //       Works when the agent adopts the ACME/attested key as its signer.
      //   (B) FRESHNESS-CODE binding (the chosen production path): the Apple
      //       freshness OID (1.2.840.113635.100.8.11.1) in the leaf commits to
      //       the signing key — `freshnessCode === sha256(publicKey)`. The
      //       attestation flow sets that freshness/clientDataHash to the hash of
      //       the agent's signing pubkey, so the verifier recomputes it OFFLINE
      //       from `publicKey` alone (invariant #2 holds). This lets the agent
      //       keep its own stable signing identity, decoupled from the MDM/ACME
      //       key lifecycle. NOTE: binding proves the attestation belongs to this
      //       signer + this genuine device; the cdHash/posture gates below are
      //       what tie it to the *measured* binary (self-measured, the platform
      //       ceiling on Apple silicon — same as our reference).
      const leafBinds = !!mda.leafPublicKey && mda.leafPublicKey === attestation.publicKey;
      const freshBinds = await freshnessBindsKey(mda.freshnessCode, attestation.publicKey);
      if (!leafBinds && !freshBinds) {
        if (!mda.leafPublicKey && (!mda.freshnessCode || mda.freshnessCode.length === 0)) {
          block(
            "mda-no-binding-material",
            "MDA leaf has neither an extractable P-256 key nor a freshness code to bind",
          );
        } else {
          block(
            "mda-unbound",
            "MDA chain is not bound to attestation.publicKey (neither leaf-key nor freshness-code binding holds)",
          );
        }
      }
    }
  }

  // --- 2b. Key residency: the signing key must be provably non-exportable. ---
  // The MDA-chain path (even bound via freshness code) only proves a genuine
  // Apple device once vouched for this PUBLIC key — it says NOTHING about whether
  // the PRIVATE key can leave the machine. Since the agent's signing key can be
  // an exportable software key (`identity.pem`), an operator with one genuine
  // Apple device can mint a bound MDA chain for a software key and run that whole
  // identity — key, chain, blessed cdHash — on any non-Apple host (the 2026-07-05
  // "Strix in a trenchcoat" spoof).
  //
  // Requiring a bound App Attest object is the FIRST rung: it forces a genuine
  // Apple Secure Enclave key to attest a commitment to this signing key. NOTE
  // (ADR-0003): a bound App Attest object alone is necessary but NOT sufficient —
  // App Attest binds via `clientDataHash = sha256(publicKey)` and checks
  // `keyId == sha256(ATTESTED key)`, never that the attested SE key IS the
  // signing key. So a pointer-bound object is still portable (mint it once on a
  // real device against a software signing key). The SUFFICIENT fix is
  // assertion-based signing where the App Attest key IS the identity
  // (`keyId == sha256(publicKey)` + receipt/attestation signatures are App Attest
  // assertions, not raw ECDSA) — the provider re-architecture ADR-0003 sequences
  // behind this same gate. Confidential-only: a genuine-Apple MDA machine that
  // isn't App-Attest-bound is capped at hardware-attested (this is NOT a hardware
  // blocker), never dropped to best-effort.
  if (requireHardwareBoundKey && !keyIsHardwareResident) {
    block(
      "key-not-hardware-bound",
      appAttestBinds
        ? "App Attest object is present but its attested Secure-Enclave key is NOT the signing " +
            "key (keyId != sha256(publicKey)) — it only points at the signing key via clientData, " +
            "so the signing private key is still exportable/portable to another host"
        : "signing key is not proven Secure-Enclave-resident: no bound App Attest object whose " +
            "attested key is the signing key (an MDA-freshness binding attests the device that " +
            "vouched for the public key, not that the private key is non-exportable)",
    );
  }

  // --- 3. Measured cdHash is in the known-good set. ---
  if (!attestation.cdHash) {
    block("no-cdhash", "attestation has no measured cdHash");
  } else if (knownGood.size === 0) {
    block("no-known-good-set", "no known-good cdHash set supplied; cannot trust any build");
  } else if (!knownGood.has(attestation.cdHash.toLowerCase())) {
    block("cdhash-unknown", `cdHash ${attestation.cdHash} is not in the known-good set`);
  }

  // Metallib pin (the GPU kernels touching plaintext), when the caller supplies
  // a known-good metallib set.
  if (knownGoodMetallibs.size > 0) {
    if (!attestation.metallibHash) {
      block("no-metallib-hash", "attestation has no measured metallibHash");
    } else if (!knownGoodMetallibs.has(attestation.metallibHash.toLowerCase())) {
      block(
        "metallib-unknown",
        `metallibHash ${attestation.metallibHash} is not in the known-good set`,
      );
    }
  }

  // Engine-dylib pin (the in-process engine code the cdHash doesn't cover), when
  // the caller supplies a known-good engine-lib set.
  if (knownGoodEngineLibs.size > 0) {
    if (!attestation.engineLibHash) {
      block("no-engine-lib-hash", "attestation has no measured engineLibHash");
    } else if (!knownGoodEngineLibs.has(attestation.engineLibHash.toLowerCase())) {
      block(
        "engine-lib-unknown",
        `engineLibHash ${attestation.engineLibHash} is not in the known-good set`,
      );
    }
  }

  // --- 4. Hardened-runtime posture. getTaskAllow absent ⇒ unsafe default. ---
  if (attestation.sipEnabled !== true) block("sip-off", "SIP is not enabled");
  if (attestation.secureBootEnabled !== true) {
    block("secure-boot-off", "Secure Boot is not enabled");
  }
  if (attestation.hardenedRuntime !== true) {
    block("no-hardened-runtime", "binary is not running under the hardened runtime");
  }
  if (attestation.libraryValidation !== true) {
    block("no-library-validation", "library validation is not enforced");
  }
  if (attestation.getTaskAllow !== false) {
    block(
      "get-task-allow",
      "get-task-allow is not provably false (debugger/memory-read is possible)",
    );
  }
  // The load-bearing property: the prompt must be handled inside the measured
  // binary, not an owner-controlled subprocess. Without this, nothing else
  // about the binary's posture matters.
  if (attestation.inProcessBackend !== true) {
    block(
      "not-in-process",
      "inference does not run in-process in the measured binary (subprocess backend)",
    );
  }
  // darkbloom-parity startup hardening capabilities.
  if (attestation.antiDebug !== true) block("no-anti-debug", "PT_DENY_ATTACH not applied");
  if (attestation.coreDumpsDisabled !== true) {
    block("core-dumps-enabled", "core dumps not disabled (RLIMIT_CORE!=0)");
  }
  if (attestation.envScrubbed !== true) block("env-not-scrubbed", "DYLD_* env not scrubbed");
  // The MDA chain, when present, is the stronger source for SIP/Secure Boot;
  // a self-reported posture that contradicts the signed chain is rejected.
  if (mda?.sipEnabled === false) block("mda-sip-off", "MDA chain reports SIP disabled");
  if (mda?.secureBootEnabled === false) {
    block("mda-secure-boot-off", "MDA chain reports Secure Boot disabled");
  }

  // --- 5. OS version floor. ---
  if (opts.osFloor && compareOsVersion(attestation.osVersion, opts.osFloor) < 0) {
    block(
      "os-below-floor",
      `osVersion ${attestation.osVersion} is below the floor ${opts.osFloor}`,
    );
  }

  // --- 6. Attestation freshness. ---
  const t = now.getTime();
  if (t < Date.parse(attestation.attestedAt) || t > Date.parse(attestation.expiresAt)) {
    block("attestation-expired", "attestation is outside its [attestedAt, expiresAt] window");
  }

  // --- 7. Freshness + the key to seal to. ---
  // The confidential seal target is the attestation's `encryptionPubKey`,
  // which the selfSignature gate (#0) just authenticated as enclave-bound.
  // Forward secrecy comes from the requester's per-request ephemeral SENDER
  // key (see `sealToProvider`). Liveness has two modes:
  //   * Advisor-vouched (default): rely on the advisor's standing 5-min
  //     challenge-response — it only advertises providers it has freshly
  //     challenged — plus the attestation's own [attestedAt, expiresAt].
  //   * Advisor-trustless (opt `requireSessionKey`): demand a per-request
  //     enclave-signed `SessionKey` over the requester's nonce, so the
  //     requester proves liveness itself without trusting the advisor.
  // When a SessionKey is supplied it is always verified, and (being
  // enclave-signed) its `ephemeralPubKey` becomes the seal target.
  const sk = opts.sessionKey;
  if (sk) {
    if (!opts.nonce || sk.nonce !== opts.nonce) {
      block("session-nonce-mismatch", "session key nonce does not match the request nonce");
    }
    if (!opts.attestationCid || sk.attestationCid !== opts.attestationCid) {
      block(
        "session-attestation-mismatch",
        "session key is not bound to the supplied attestation CID",
      );
    }
    // Same identity, same sigScheme dispatch as selfSignature.
    const sigOk = await verifyIdentitySig(sk.signature, sessionKeyMessage(sk));
    if (!sigOk) {
      block(
        "session-signature-invalid",
        "session key signature did not verify against attestation.publicKey",
      );
    }
  } else if (opts.requireSessionKey) {
    block(
      "no-session-key",
      "advisor-trustless freshness was required but no enclave-signed session key was supplied",
    );
  } else if (!attestation.encryptionPubKey) {
    block("no-encryption-key", "attestation has no encryptionPubKey to seal to");
  }

  // --- 8. APNs code identity (advisor-asserted, see opts.codeAttested). ---
  // The un-forgeable complement to the self-reported cdHash: a fork can claim a
  // blessed cdHash, but cannot answer the advisor's AMFI-gated push challenge.
  // REQUIRED by default for confidential (0.9.23) — opt out only against a
  // non-enforcing advisor, accepting the weaker (self-reported-cdHash) proof.
  if (requireCodeAttested && opts.codeAttested !== true) {
    block(
      "code-not-attested",
      "provider has not passed a live APNs code-identity challenge (advisor codeAttested is not true)",
    );
  }

  // ADR-0005: the Secure-Enclave-resident-key gate. `secureEnclaveAvailable` is
  // authenticated by the selfSignature gate (#0), so a copied software key
  // (which reports false) can't clear this. Additive to the brokerage
  // countersignature — both must hold for confidential.
  if (requireSecureEnclaveKey && attestation.secureEnclaveAvailable !== true) {
    block(
      "se-key-not-available",
      "provider does not advertise a Secure-Enclave-resident signing key (attestation.secureEnclaveAvailable is not true)",
    );
  }

  // --- Resolve tier + findings. ---
  const confidential = blockers.length === 0;
  const tier: Tier = confidential ? "attested-confidential" : "best-effort";
  const severity: Severity = requireConfidential ? "error" : "warn";
  const findings: Finding[] = blockers.map((b) => ({ severity, code: b.code, message: b.message }));

  const result: ProviderVerifyResult = {
    tier,
    ok: confidential || !requireConfidential,
    findings,
  };
  // Seal to the enclave-signed ephemeral key when present, else the
  // selfSignature-authenticated long-lived encryptionPubKey.
  if (confidential) result.sealToKey = sk ? sk.ephemeralPubKey : attestation.encryptionPubKey;
  return result;
}

// ---- internals -------------------------------------------------------

function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Option-B binding: the MDA leaf's Apple freshness code commits to the signing
 *  key iff `freshnessCode === sha256(publicKey-raw-bytes)`. `publicKeyB64` is the
 *  attestation's `publicKey` (base64 of the raw 64-byte P-256 X‖Y point); the
 *  attestation flow sets the freshness/clientDataHash to its SHA-256 so this is
 *  recomputable offline. Returns false (never throws) on missing/short input. */
export async function freshnessBindsKey(
  freshnessCode: Uint8Array | undefined,
  publicKeyB64: string,
): Promise<boolean> {
  if (!freshnessCode || freshnessCode.length === 0) return false;
  let pub: Uint8Array;
  try {
    pub = base64ToBytes(publicKeyB64);
  } catch {
    return false;
  }
  if (pub.length === 0) return false;
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new Uint8Array(pub)));
  return constantTimeEqual(digest, normalizeFreshness(freshnessCode));
}

/** Apple's freshness OID value is a 32-byte SHA-256 carried in a DER OCTET
 *  STRING. Depending on the X.509 parser we may receive the wrapped form
 *  (`04 20 ‖ 32 bytes`) or the raw 32 bytes. Normalize to the inner 32 bytes so
 *  the binding compares apples-to-apples across the TS/Py/Rust verifiers. */
function normalizeFreshness(fc: Uint8Array): Uint8Array {
  if (fc.length === 34 && fc[0] === 0x04 && fc[1] === 0x20) return fc.subarray(2);
  return fc;
}

/** Length-checked constant-time byte compare (no early-out on content). */
function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

/** Compare two macOS version strings. Extracts the first dotted-numeric run
 *  from each (so "macOS 14.6.1" and "14.6.1" compare equal) and compares
 *  component-wise. Returns <0, 0, or >0. A string with no numeric run sorts
 *  lowest (treated as below any real floor) so it fails the floor check. */
export function compareOsVersion(a: string, b: string): number {
  const pa = extractVersion(a);
  const pb = extractVersion(b);
  const n = Math.max(pa.length, pb.length);
  for (let i = 0; i < n; i++) {
    const x = pa[i] ?? 0;
    const y = pb[i] ?? 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

function extractVersion(s: string): number[] {
  const m = s.match(/\d+(?:\.\d+)*/);
  if (!m) return [-1];
  return m[0].split(".").map((p) => Number.parseInt(p, 10));
}
