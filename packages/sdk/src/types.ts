// Lexicon record shapes for dev.cocore.compute.*.
//
// The lexicons under /lexicons/dev/cocore/compute/*.json are
// normative; these TypeScript types are derived by hand to match.
// When `@atproto/lex-cli` codegen lands in M5.5, this file becomes
// generated and gitignored.

export interface Money {
  amount: number;
  currency: string;
}

export interface StrongRef {
  uri: string;
  cid: string;
}

export type TrustLevel = "self-attested" | "hardware-attested";
/** Confidentiality tier — whether the prompt was provably handled only inside
 *  a measured, signed binary the owner cannot read. Distinct from TrustLevel.
 *  A verifier MUST recompute this from evidence (see {@link verifyProviderForSeal})
 *  and never trust a self-asserted value. */
export type Tier = "attested-confidential" | "best-effort";
export type SettlementStatus = "settled" | "refunded" | "disputed";

export interface ProviderRecord {
  machineLabel: string;
  chip: string;
  ramGB: number;
  gpuCores?: number;
  memoryBandwidthGBs?: number;
  supportedModels: string[];
  priceList: ModelPrice[];
  encryptionPubKey: string;
  attestationPubKey: string;
  trustLevel: TrustLevel;
  /** Highest confidentiality tier this machine advertises. Advisory; a
   *  confidential requester still verifies per-job. Absent = best-effort.
   *  Agent-published ACHIEVED tier (evidence-derived, never self-declared). */
  tier?: Tier;
  /** The tier the OWNER opted this machine into (console/tray "Upgrade
   *  security"). Owner-written INTENT; the agent reconciles toward it and only
   *  publishes a higher `tier`/`trustLevel` once earned. Absent/best-effort =
   *  not opted in (serves exactly as before). Mirrors `desiredModels`. */
  desiredTier?: Tier;
  acceptedExchanges?: string[];
  /** The owner's pro-bono election: serve matching jobs free, unmetered, with
   *  no exchange cut. `mode: "any"` serves every requester pro bono; `mode:
   *  "direct"` serves only the requesters in `dids` (the owner's direct
   *  pro-bono relationships) and bills everyone else normally. Absent ≡ off.
   *  Owner-written INTENT, like `desiredModels`/`desiredTier`. */
  proBono?: ProBonoPolicy;
  contactEndpoint?: string;
  active?: boolean;
  /** True while the agent is still loading its engine after serve start —
   *  the record is published immediately so the machine appears, then
   *  re-published with this false/absent once it's ready. */
  provisioning?: boolean;
  /** Liveness flag: true while the serve loop is up, false on graceful
   *  shutdown. `false` → show the machine as offline. Absence = unknown. */
  serving?: boolean;
  createdAt: string;
}

export interface ModelPrice {
  modelId: string;
  inputPricePerMTok: number;
  outputPricePerMTok: number;
  currency: string;
}

/** The owner's pro-bono election for a machine. Mirrors the lexicon
 *  `dev.cocore.compute.provider#proBonoPolicy`. */
export interface ProBonoPolicy {
  /** `"any"`: serve every requester pro bono. `"direct"`: serve only the
   *  requesters in `dids` pro bono; all others are normal paid jobs. An
   *  unknown value is treated as off (fail closed to paid). */
  mode: "any" | "direct";
  /** Requester DIDs served pro bono under `mode: "direct"`. Ignored when
   *  `mode` is `"any"`. */
  dids?: string[];
}

export interface AttestationRecord {
  publicKey: string;
  encryptionPubKey: string;
  chipName: string;
  hardwareModel: string;
  serialNumberHash: string;
  osVersion: string;
  binaryHash: string;
  /** Code-signing cdhash (lowercase hex) of the running binary — the
   *  OS-enforced measured identity. Supersedes binaryHash for trust. */
  cdHash?: string;
  /** Apple Developer Team Identifier from the running binary's signature. */
  teamId?: string;
  /** Hardened runtime (CS_RUNTIME) enforced. Required for confidential. */
  hardenedRuntime?: boolean;
  /** Library validation enforced. Required for confidential. */
  libraryValidation?: boolean;
  /** get-task-allow entitlement value. MUST be false for confidential;
   *  absent treated as true (unsafe default). */
  getTaskAllow?: boolean;
  /** SHA-256 hex of the precompiled Metal shader library the in-process
   *  engine loads. Absent when no native engine is loaded. */
  metallibHash?: string;
  /** SHA-256 hex of the dynamic engine library (e.g. libCoCoreMLX.dylib) — a
   *  measurable the cdHash doesn't cover. Absent for subprocess/static backends. */
  engineLibHash?: string;
  /** True iff inference runs inside this measured binary (native engine),
   *  not an owner-controlled subprocess. The load-bearing confidential bit. */
  inProcessBackend?: boolean;
  /** PT_DENY_ATTACH applied at startup. Required for confidential. */
  antiDebug?: boolean;
  /** RLIMIT_CORE=0 applied at startup. Required for confidential. */
  coreDumpsDisabled?: boolean;
  /** DYLD_* env scrubbed at startup. Required for confidential. */
  envScrubbed?: boolean;
  sipEnabled: boolean;
  secureBootEnabled: boolean;
  secureEnclaveAvailable: boolean;
  authenticatedRootEnabled: boolean;
  rdmaDisabled?: boolean;
  mdaCertChain?: string[];
  /** Apple App Attest evidence (CBOR `object` + `keyId`, both base64). The
   *  MDM-free path to hardware-attested: bound to `publicKey` via
   *  clientDataHash = sha256(publicKey). Absent on self-attested machines. */
  appAttest?: { object: string; keyId: string };
  selfSignature: string;
  attestedAt: string;
  expiresAt: string;
  /** Provider's self-asserted tier. ADVISORY ONLY — recompute from evidence. */
  tier?: Tier;
}

export interface JobRecord {
  model: string;
  inputCommitment: string;
  /** How to interpret the sealed input bytes inputCommitment covers.
   *  Absent/"text": raw prompt string. "messages-v1": UTF-8 of the
   *  canonical multimodal envelope (see multimodal-envelope.ts). */
  inputFormat?: "text" | "messages-v1";
  inputCipherURL?: string;
  maxTokensOut: number;
  priceCeiling: Money;
  acceptedProviders?: string[];
  acceptedTrustLevel: TrustLevel;
  acceptedExchanges?: string[];
  paymentAuthorization: StrongRef;
  nonce?: string;
  expiresAt: string;
  createdAt: string;
}

/** Sampling parameters a receipt commits to. Integer-only because the
 *  canonical signing form forbids floats — temperature/top_p are
 *  milliunits (value × 1000). See lexicon `#generationParams`. */
export interface GenerationParams {
  maxTokens?: number;
  seed?: number;
  temperatureMilli?: number;
  topPMilli?: number;
}

export interface ReceiptRecord {
  job: StrongRef;
  requester: string;
  model: string;
  inputCommitment: string;
  /** SHA-256 hex over the plaintext output the requester receives. */
  outputCommitment: string;
  /** Optional SHA-256 hex over the exact encrypted bytes delivered. */
  outputCipherCommitment?: string;
  /** Optional SHA-256 hex over the plaintext reasoning ('thinking') output,
   *  separate from outputCommitment. Present only when the model emitted
   *  reasoning on a distinct channel. */
  reasoningCommitment?: string;
  /** Optional SHA-256 hex over (ephemeralPubKey || sessionNonce) — proof the
   *  input was sealed to a fresh, enclave-bound ephemeral key for this job. */
  sessionKeyCommitment?: string;
  /** Optional lowercase-hex requester nonce the session key was bound to. */
  sessionNonce?: string;
  /** Optional sampling params the provider committed to. */
  params?: GenerationParams;
  outputCipherURL?: string;
  tokens: { in: number; out: number };
  startedAt: string;
  completedAt: string;
  price: Money;
  attestation: StrongRef;
  enclaveSignature: string;
  /** Confidentiality tier this job ran under. Recompute from attestation +
   *  sessionKeyCommitment; absent = best-effort. */
  tier?: Tier;
  /** True when the provider served this job pro bono under its `proBono`
   *  election — free, unmetered, no exchange cut. A pro-bono receipt MUST
   *  carry `price.amount: 0` and `tokens: { in: 0, out: 0 }`, and an exchange
   *  settling it takes no fee and moves no balance. Covered by
   *  `enclaveSignature`. Absent/false ≡ a normal metered, billable receipt. */
  proBono?: boolean;
}

export interface PaymentAuthorizationRecord {
  exchange: string;
  ceiling: Money;
  scope: "singleJob" | "session";
  sessionBudget?: Money;
  nonce: string;
  expiresAt: string;
  createdAt: string;
}

export interface SettlementRecord {
  receipt: StrongRef;
  requesterAuthorization: StrongRef;
  amountCharged: Money;
  providerPayout: Money;
  exchangeFee: Money;
  processorReference: string;
  status: SettlementStatus;
  refundOf?: StrongRef;
  /** Strong-ref to the dev.cocore.compute.exchangePolicy this
   *  settlement was computed under. Optional for back-compat with
   *  pre-v0.3.x settlements that predate the policy record. */
  policy?: StrongRef;
  /** Strong-ref to the exchange's currently-active
   *  dev.cocore.compute.exchangeAttestation pinning the signing-key
   *  + software combination. Optional; present iff `sig` is. */
  exchangeAttestation?: StrongRef;
  /** ES256 signature (base64url, no padding) over the canonical
   *  bytes of the rest of the record. Verified against the
   *  publicKey in the referenced exchangeAttestation. Optional —
   *  v0.3.x exchanges that haven't enabled signing emit settlements
   *  without it. */
  sig?: string;
  settledAt: string;
}

export interface ExchangePolicyRecord {
  exchange: string;
  fee: { bps: number; minMinor: number; currency: string };
  supportedCurrencies: string[];
  selfLoop: { feeWaived: boolean; minMinor?: number };
  processor?: string;
  termsUri?: string;
  termsVersion?: string;
  active?: boolean;
  createdAt: string;
}

export interface ExchangeAttestationRecord {
  exchange: string;
  policy: StrongRef;
  softwareVersion: string;
  signingKeyFingerprint: string;
  auditPosture?: string;
  createdAt: string;
}

export interface TermsAcceptanceRecord {
  exchange: string;
  policy: StrongRef;
  termsVersion: string;
  termsUri: string;
  userAgent?: string;
  acceptedAt: string;
}

/** Lexicon-NSID-keyed lookup for the body type of an indexed record. */
export type CocoreRecord =
  | ({ $collection: "dev.cocore.compute.provider" } & ProviderRecord)
  | ({ $collection: "dev.cocore.compute.attestation" } & AttestationRecord)
  | ({ $collection: "dev.cocore.compute.job" } & JobRecord)
  | ({ $collection: "dev.cocore.compute.receipt" } & ReceiptRecord)
  | ({ $collection: "dev.cocore.compute.paymentAuthorization" } & PaymentAuthorizationRecord)
  | ({ $collection: "dev.cocore.compute.settlement" } & SettlementRecord);

export const COLLECTIONS = [
  "dev.cocore.compute.provider",
  "dev.cocore.compute.attestation",
  "dev.cocore.compute.job",
  "dev.cocore.compute.receipt",
  "dev.cocore.compute.paymentAuthorization",
  "dev.cocore.compute.settlement",
] as const;

export type CollectionId = (typeof COLLECTIONS)[number];

/** A row as seen by an AppView indexer or an exchange firehose
 *  subscriber. The wire shape is invariant across both consumers. */
export interface IndexedRecord<T = unknown> {
  uri: string;
  cid: string;
  collection: string;
  repo: string;
  rkey: string;
  body: T;
}
