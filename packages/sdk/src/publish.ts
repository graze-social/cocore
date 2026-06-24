// Requester-side record writers.
//
// The publisher.ts in @cocore/exchange handles settlement records;
// this module is the symmetric thing for the requester: how a
// browser, a Python client, or a smoke test puts a `paymentAuthorization`
// and a `job` into the world.
//
// As with `SettlementTransport` in @cocore/exchange, the transport is
// pluggable so callers can target:
//
//   * `BridgeRecordTransport` — the in-process bridge in
//     `infra/services` (POSTs to `dev.cocore.bridge.publish`). No
//     auth, no real PDS. This is what the dev console targets.
//
//   * `PdsRecordTransport` — a real PDS via
//     `com.atproto.repo.createRecord` with a Bearer token. This is
//     what production console + Python SDK eventually call.
//
// The two transports have the same surface so callers don't care
// which one they got.

import type {
  IndexedRecord,
  JobRecord,
  Money,
  PaymentAuthorizationRecord,
  StrongRef,
  TrustLevel,
} from "./types.ts";

export interface PublishedRecord {
  uri: string;
  cid: string;
}

export interface RecordTransport {
  publish<T extends Record<string, unknown>>(args: {
    repo: string;
    collection: string;
    record: T;
  }): Promise<PublishedRecord>;
}

/** Bridge transport. Targets the in-process firehose used by
 *  `infra/services` and the local docker stack. The bridge does not
 *  authenticate writes — caller passes the requester's DID directly. */
export class BridgeRecordTransport implements RecordTransport {
  private readonly endpoint: string;

  constructor(opts: { endpoint: string }) {
    this.endpoint = opts.endpoint.replace(/\/$/, "");
  }

  async publish<T extends Record<string, unknown>>(args: {
    repo: string;
    collection: string;
    record: T;
  }): Promise<PublishedRecord> {
    const rkey = randomTid();
    const uri = `at://${args.repo}/${args.collection}/${rkey}`;
    const cid = PLACEHOLDER_CID;
    const body: IndexedRecord = {
      uri,
      cid,
      collection: args.collection,
      repo: args.repo,
      rkey,
      body: args.record,
    };
    const res = await fetch(`${this.endpoint}/xrpc/dev.cocore.bridge.publish`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      throw new Error(`bridge publish failed ${res.status}: ${await res.text()}`);
    }
    return { uri, cid };
  }
}

/** Real PDS transport. Mirrors `PdsSettlementTransport` in
 *  @cocore/exchange. Bearer auth only; DPoP-bound writes ride on
 *  the M5+ console OAuth integration. */
export class PdsRecordTransport implements RecordTransport {
  private readonly endpoint: string;
  private readonly accessToken: string;

  constructor(opts: { pdsEndpoint: string; accessToken: string }) {
    this.endpoint = opts.pdsEndpoint.replace(/\/$/, "");
    this.accessToken = opts.accessToken;
  }

  async publish<T extends Record<string, unknown>>(args: {
    repo: string;
    collection: string;
    record: T;
  }): Promise<PublishedRecord> {
    const res = await fetch(`${this.endpoint}/xrpc/com.atproto.repo.createRecord`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${this.accessToken}`,
      },
      body: JSON.stringify({
        repo: args.repo,
        collection: args.collection,
        record: args.record,
      }),
    });
    if (!res.ok) {
      throw new Error(
        `createRecord ${args.collection} returned ${res.status}: ${await res.text()}`,
      );
    }
    return (await res.json()) as PublishedRecord;
  }
}

export interface PublishPaymentAuthorizationInputs {
  exchange: string;
  ceiling: Money;
  scope?: "singleJob" | "session";
  sessionBudget?: Money;
  expiresAt?: string;
}

export interface PublishJobInputs {
  model: string;
  inputCommitment: string;
  /** How to interpret the sealed input bytes inputCommitment covers.
   *  Omit (or "text") for the raw-prompt path; "messages-v1" for the
   *  canonical multimodal envelope. */
  inputFormat?: "text" | "messages-v1";
  inputCipherURL?: string;
  maxTokensOut: number;
  priceCeiling: Money;
  acceptedTrustLevel?: TrustLevel;
  acceptedProviders?: string[];
  acceptedExchanges?: string[];
  paymentAuthorization: StrongRef;
  expiresAt?: string;
  /** Multi-output batch linkage (e.g. an `n>1` image request fanned out
   *  across machines). `batchId` is a lowercase-hex UUID shared by sibling
   *  jobs; `outputIndex` is this job's 0-based slot; `outputCount` is the
   *  total. Each sibling is still its own job + receipt — these are for
   *  indexer/UX correlation only. */
  batchId?: string;
  outputIndex?: number;
  outputCount?: number;
}

/** Build + publish a `dev.cocore.compute.paymentAuthorization` to the
 *  requester's repo. Returns the published record's strong ref so
 *  callers can chain a `publishJob` against it. */
export async function publishPaymentAuthorization(args: {
  transport: RecordTransport;
  requesterDid: string;
  inputs: PublishPaymentAuthorizationInputs;
}): Promise<{ ref: StrongRef; record: PaymentAuthorizationRecord }> {
  const now = new Date();
  const record: PaymentAuthorizationRecord = {
    exchange: args.inputs.exchange,
    ceiling: args.inputs.ceiling,
    scope: args.inputs.scope ?? "singleJob",
    nonce: random16Hex(),
    expiresAt: args.inputs.expiresAt ?? new Date(now.getTime() + 3600_000).toISOString(),
    createdAt: now.toISOString(),
    ...(args.inputs.sessionBudget ? { sessionBudget: args.inputs.sessionBudget } : {}),
  };
  const out = await args.transport.publish({
    repo: args.requesterDid,
    collection: "dev.cocore.compute.paymentAuthorization",
    record: record as unknown as Record<string, unknown>,
  });
  return { ref: { uri: out.uri, cid: out.cid }, record };
}

/** Build + publish a `dev.cocore.compute.job` to the requester's
 *  repo. Caller is responsible for hashing and (optionally) uploading
 *  the encrypted prompt before calling — `inputCommitment` is what
 *  binds the receipt back to the prompt. */
export async function publishJob(args: {
  transport: RecordTransport;
  requesterDid: string;
  inputs: PublishJobInputs;
}): Promise<{ ref: StrongRef; record: JobRecord }> {
  const now = new Date();
  const record: JobRecord = {
    model: args.inputs.model,
    inputCommitment: args.inputs.inputCommitment,
    maxTokensOut: args.inputs.maxTokensOut,
    priceCeiling: args.inputs.priceCeiling,
    acceptedTrustLevel: args.inputs.acceptedTrustLevel ?? "self-attested",
    paymentAuthorization: args.inputs.paymentAuthorization,
    nonce: random16Hex(),
    expiresAt: args.inputs.expiresAt ?? new Date(now.getTime() + 3600_000).toISOString(),
    createdAt: now.toISOString(),
    ...(args.inputs.inputFormat && args.inputs.inputFormat !== "text"
      ? { inputFormat: args.inputs.inputFormat }
      : {}),
    ...(args.inputs.inputCipherURL ? { inputCipherURL: args.inputs.inputCipherURL } : {}),
    ...(args.inputs.acceptedProviders ? { acceptedProviders: args.inputs.acceptedProviders } : {}),
    ...(args.inputs.acceptedExchanges ? { acceptedExchanges: args.inputs.acceptedExchanges } : {}),
    ...(args.inputs.batchId ? { batchId: args.inputs.batchId } : {}),
    ...(args.inputs.outputIndex !== undefined ? { outputIndex: args.inputs.outputIndex } : {}),
    ...(args.inputs.outputCount !== undefined ? { outputCount: args.inputs.outputCount } : {}),
  };
  const out = await args.transport.publish({
    repo: args.requesterDid,
    collection: "dev.cocore.compute.job",
    record: record as unknown as Record<string, unknown>,
  });
  return { ref: { uri: out.uri, cid: out.cid }, record };
}

export interface SubmitJobInputs {
  model: string;
  /** The EXACT bytes that get sealed to the provider and that
   *  `inputCommitment` is computed over. For the legacy text path these
   *  are the UTF-8 of the flattened prompt; for the multimodal path they
   *  are the canonical `messages-v1` envelope (see
   *  packages/sdk/src/multimodal-envelope.ts). The provider recomputes
   *  the same SHA-256 over the bytes it opens, so the commitment is
   *  self-consistent without either side parsing the payload. */
  inputBytes: Uint8Array;
  /** Set to "messages-v1" when `inputBytes` is the multimodal envelope so
   *  the published job is self-describing. Omitted for the text path. */
  inputFormat?: "messages-v1";
  maxTokensOut: number;
  priceCeiling: Money;
  exchangeDid: string;
  acceptedTrustLevel?: TrustLevel;
  /** Multi-output batch linkage — see {@link PublishJobInputs}. */
  batchId?: string;
  outputIndex?: number;
  outputCount?: number;
}

export interface SubmittedJob {
  authorization: { ref: StrongRef; record: PaymentAuthorizationRecord };
  job: { ref: StrongRef; record: JobRecord };
}

/** End-to-end requester submit: hash the plaintext prompt, publish a
 *  `paymentAuthorization`, then publish a `job` strong-ref'ing it.
 *  The plaintext is *not* uploaded anywhere by this helper — that is
 *  out of scope for the dev loop. In production the caller encrypts
 *  to the chosen provider's `encryptionPubKey` and uploads the
 *  ciphertext as a PDS blob, passing its URL as `inputCipherURL`. */
export async function submitJob(args: {
  transport: RecordTransport;
  requesterDid: string;
  inputs: SubmitJobInputs;
}): Promise<SubmittedJob> {
  const inputCommitment = await sha256Hex(args.inputs.inputBytes);
  const authorization = await publishPaymentAuthorization({
    transport: args.transport,
    requesterDid: args.requesterDid,
    inputs: {
      exchange: args.inputs.exchangeDid,
      ceiling: args.inputs.priceCeiling,
      scope: "singleJob",
    },
  });
  const job = await publishJob({
    transport: args.transport,
    requesterDid: args.requesterDid,
    inputs: {
      model: args.inputs.model,
      inputCommitment,
      ...(args.inputs.inputFormat ? { inputFormat: args.inputs.inputFormat } : {}),
      maxTokensOut: args.inputs.maxTokensOut,
      priceCeiling: args.inputs.priceCeiling,
      acceptedTrustLevel: args.inputs.acceptedTrustLevel,
      acceptedExchanges: [args.inputs.exchangeDid],
      paymentAuthorization: authorization.ref,
      ...(args.inputs.batchId ? { batchId: args.inputs.batchId } : {}),
      ...(args.inputs.outputIndex !== undefined ? { outputIndex: args.inputs.outputIndex } : {}),
      ...(args.inputs.outputCount !== undefined ? { outputCount: args.inputs.outputCount } : {}),
    },
  });
  return { authorization, job };
}

// ---- internals -------------------------------------------------------

const PLACEHOLDER_CID = "bafyreigh2akiscaildc5sgz5wybizysiehxiv4dhpwwqouytxnvgkpkcaq";

function randomTid(): string {
  return [...crypto.getRandomValues(new Uint8Array(8))]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** 16 random bytes, hex-encoded. Lexicon nonce shape. */
function random16Hex(): string {
  return [...crypto.getRandomValues(new Uint8Array(16))]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  // Copy into a fresh ArrayBuffer-backed view so the SubtleCrypto
  // BufferSource type is satisfied across Node's stricter typings
  // (which reject SharedArrayBuffer-backed views).
  const buf = new Uint8Array(bytes.byteLength);
  buf.set(bytes);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", buf));
  return [...digest].map((b) => b.toString(16).padStart(2, "0")).join("");
}
