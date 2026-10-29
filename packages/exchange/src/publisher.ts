// Settlement record builder + PDS write seam.
//
// Two backends:
//
//   * `MemorySettlementTransport` (default) keeps the published
//     records in-process. Used by unit tests and the dev bridge —
//     no network needed.
//   * `PdsSettlementTransport` (NEW) calls
//     `com.atproto.repo.createRecord` against a live PDS using the
//     exchange operator's session token. This is what lights the
//     stack up against `@atproto/dev-env`'s TestPDS or a real
//     bsky.network instance.
//
// The class signature is unchanged for callers that already use
// `new SettlementPublisher(did)`; the transport is an optional
// constructor argument.

import { FetchHttpClient, HttpClient, HttpClientRequest } from "@effect/platform";
import { makeRuntime } from "@cocore/o11y";
import { Effect } from "effect";

import { withRecordType } from "@cocore/sdk/record-type";
import type { Money, SettlementRecord, StrongRef } from "@cocore/sdk/types";
import { AppPasswordSession, createRecordViaSession } from "./app-password-session.ts";

export interface PublishedRecord {
  uri: string;
  cid: string;
}

// One o11y runtime for the module — provides the tracing layer that
// `Effect.withSpan` reports through. The fetch-backed HttpClient is
// supplied per-call via `Effect.provide(FetchHttpClient.layer)`;
// `FetchHttpClient.layer` reads `globalThis.fetch` at request time, so
// test fetch-mocking keeps working unchanged.
const runtime = makeRuntime({ serviceName: "cocore-exchange" });

/** POST a JSON body to `url` with bearer auth and parse a
 *  `{ uri, cid }` createRecord response. Runs on the module o11y
 *  runtime behind a span so the public async API stays a plain
 *  Promise. On a non-2xx response it rejects with `new Error(
 *  errorMessage(status, text))` — identical to the prior `fetch` path. */
function postCreateRecord(opts: {
  url: string;
  authToken: string;
  body: unknown;
  spanName: string;
  exchangeDid: string;
  errorMessage: (status: number, text: string) => string;
}): Promise<PublishedRecord> {
  const effect = Effect.gen(function* () {
    const client = yield* HttpClient.HttpClient;
    const request = yield* HttpClientRequest.post(opts.url).pipe(
      HttpClientRequest.setHeaders({
        "content-type": "application/json",
        authorization: `Bearer ${opts.authToken}`,
      }),
      HttpClientRequest.bodyJson(opts.body),
    );
    const res = yield* client.execute(request);
    if (res.status < 200 || res.status >= 300) {
      const text = yield* res.text;
      return yield* Effect.fail(new Error(opts.errorMessage(res.status, text)));
    }
    return (yield* res.json) as PublishedRecord;
  }).pipe(
    // Map any non-Error failure (HttpBodyError / transport / decode) into a
    // thrown Error so the external Promise rejects with an Error, matching
    // the old `await fetch(...)` boundary.
    Effect.catchAll((e) => Effect.fail(e instanceof Error ? e : new Error(String(e)))),
    Effect.withSpan(opts.spanName, { attributes: { exchangeDid: opts.exchangeDid } }),
    Effect.provide(FetchHttpClient.layer),
  );
  return runtime.runPromise(effect);
}

export interface SettlementInputs {
  receipt: StrongRef;
  requesterAuthorization: StrongRef;
  amountCharged: Money;
  providerPayout: Money;
  exchangeFee: Money;
  processorReference: string;
  status: SettlementRecord["status"];
  refundOf?: StrongRef;
  policy?: StrongRef;
  exchangeAttestation?: StrongRef;
}

/** Pluggable transport for writing settlement records. */
export interface SettlementTransport {
  publish(exchangeDid: string, record: SettlementRecord): Promise<PublishedRecord>;
}

/** In-process transport. Default. */
class MemorySettlementTransport implements SettlementTransport {
  async publish(exchangeDid: string, _record: SettlementRecord): Promise<PublishedRecord> {
    const rkey = randomTid();
    return {
      uri: `at://${exchangeDid}/dev.cocore.compute.settlement/${rkey}`,
      cid: `bafyreigh2akiscaildc5sgz5wybizysiehxiv4dhpwwqouytxnvgkpkcaq-mem-${rkey}`,
    };
  }
}

/** Live-PDS transport. POSTs com.atproto.repo.createRecord via
 *  plain Bearer auth (suitable for dev-env's TestPDS and any PDS
 *  that accepts legacy tokens). DPoP-bound tokens are not yet
 *  supported; we'll add that path when the cocore-shell Swift app's
 *  OAuth session blob carries DPoP material end-to-end. */
export class PdsSettlementTransport implements SettlementTransport {
  private readonly endpoint: string;
  private readonly accessToken: string;

  constructor(opts: { pdsEndpoint: string; accessToken: string }) {
    this.endpoint = opts.pdsEndpoint.replace(/\/$/, "");
    this.accessToken = opts.accessToken;
  }

  async publish(exchangeDid: string, record: SettlementRecord): Promise<PublishedRecord> {
    return postCreateRecord({
      url: `${this.endpoint}/xrpc/com.atproto.repo.createRecord`,
      authToken: this.accessToken,
      body: {
        repo: exchangeDid,
        collection: "dev.cocore.compute.settlement",
        record: withRecordType("dev.cocore.compute.settlement", record),
      },
      spanName: "exchange.pds.publish",
      exchangeDid,
      errorMessage: (status, text) => `createRecord settlement returned ${status}: ${text}`,
    });
  }
}

/** Production transport for the cocore-hosted exchange.
 *
 *  POSTs records to the cocore console's proxy endpoint
 *  (`/api/pds/createRecord`) using a Bearer API
 *  key bound to the exchange's DID. The console handles DPoP
 *  signing internally using the OAuth session for that DID — same
 *  surface the provider agent uses for its own records. The
 *  exchange therefore never needs to hold OAuth tokens directly.
 *
 *  Configuration ships through env on the services container:
 *    COCORE_EXCHANGE_API_KEY  cocore-... key minted on /api-keys
 *                             while signed in as the exchange's DID.
 *    COCORE_EXCHANGE_API_BASE console base URL (default
 *                             https://console.cocore.dev).
 */
export class ConsoleProxySettlementTransport implements SettlementTransport {
  private readonly base: string;
  private readonly apiKey: string;

  constructor(opts: { apiBase: string; apiKey: string }) {
    this.base = opts.apiBase.replace(/\/$/, "");
    this.apiKey = opts.apiKey;
  }

  async publish(exchangeDid: string, record: SettlementRecord): Promise<PublishedRecord> {
    // The proxy resolves the API key → DID and writes to that DID's
    // PDS, so we don't need to send `repo` separately.
    return postCreateRecord({
      url: `${this.base}/api/pds/createRecord`,
      authToken: this.apiKey,
      body: {
        collection: "dev.cocore.compute.settlement",
        record,
      },
      spanName: "exchange.consoleProxy.publish",
      exchangeDid,
      errorMessage: (status, text) => `proxy settlement createRecord ${status}: ${text}`,
    });
  }
}

/** Production transport that writes settlements DIRECTLY to the exchange's
 *  PDS using a self-managed app-password session — no console proxy, no
 *  OAuth. This is the lapse-proof replacement for {@link
 *  ConsoleProxySettlementTransport}: the session mints/refreshes itself from a
 *  long-lived app password (see app-password-session.ts), so a settlement
 *  write can never be blocked by an expired OAuth session needing a human
 *  re-auth (the 2026-06 root cause), nor by the console→appview hop. */
export class AppPasswordSettlementTransport implements SettlementTransport {
  // Explicit field + assignment, not a constructor parameter property — the
  // services container runs the TS source under Node's strip-only type
  // stripping, which rejects `constructor(private ...)`.
  private readonly session: AppPasswordSession;

  constructor(session: AppPasswordSession) {
    this.session = session;
  }

  async publish(exchangeDid: string, record: SettlementRecord): Promise<PublishedRecord> {
    const effect = Effect.tryPromise({
      try: () =>
        createRecordViaSession(this.session, {
          collection: "dev.cocore.compute.settlement",
          record,
        }),
      catch: (e) => (e instanceof Error ? e : new Error(String(e))),
    }).pipe(Effect.withSpan("exchange.appPassword.publish", { attributes: { exchangeDid } }));
    return runtime.runPromise(effect);
  }
}

export class SettlementPublisher {
  private readonly exchangeDid: string;
  private readonly transport: SettlementTransport;
  private readonly published: Map<string, PublishedRecord> = new Map();

  constructor(
    exchangeDid: string,
    transport: SettlementTransport = new MemorySettlementTransport(),
  ) {
    this.exchangeDid = exchangeDid;
    this.transport = transport;
  }

  exchange(): string {
    return this.exchangeDid;
  }

  build(inputs: SettlementInputs): SettlementRecord {
    return {
      receipt: inputs.receipt,
      requesterAuthorization: inputs.requesterAuthorization,
      amountCharged: inputs.amountCharged,
      providerPayout: inputs.providerPayout,
      exchangeFee: inputs.exchangeFee,
      processorReference: inputs.processorReference,
      status: inputs.status,
      ...(inputs.refundOf ? { refundOf: inputs.refundOf } : {}),
      ...(inputs.policy ? { policy: inputs.policy } : {}),
      ...(inputs.exchangeAttestation ? { exchangeAttestation: inputs.exchangeAttestation } : {}),
      settledAt: new Date().toISOString(),
    };
  }

  async publish(rec: SettlementRecord): Promise<PublishedRecord> {
    const result = await this.transport.publish(this.exchangeDid, rec);
    this.published.set(rec.receipt.uri, result);
    return result;
  }

  /** Test affordance: which receipts have we already published settlements for? */
  alreadySettled(): Set<string> {
    return new Set(this.published.keys());
  }
}

function randomTid(): string {
  return [...crypto.getRandomValues(new Uint8Array(8))]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
