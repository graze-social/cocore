// All-in-one cocore services bridge.
//
// Runs in a single process for the docker-compose stack:
//
//   * Firehose          in-process pub/sub
//   * AppView indexer   subscribes to firehose, writes to SQLite
//   * AppView API       HTTP read API over the indexed store
//   * Exchange          verifies receipts on the firehose and
//                       publishes settlement records
//   * TokenLedger       per-DID balance ledger; receipts move tokens,
//                       firehose touches trigger lazy refresh, a
//                       monthly scheduler distributes patronage
//   * Bridge endpoint   POST /xrpc/dev.cocore.bridge.publish — accept
//                       a record from outside the process and
//                       dispatch into the firehose
//   * Health            GET /healthz
//
// One container, one log stream, one set of ports. Federation still
// works because nothing here is privileged — multiple instances can
// run against different firehoses and observe the same receipts.

import { createServer } from "node:http";
import { timingSafeEqual } from "node:crypto";
import Database from "better-sqlite3";

import { HttpRouter } from "@effect/platform";
import { Config, Duration, Effect, Metric, Option, Redacted, Schedule } from "effect";

import { Firehose, type IndexedRecord } from "@cocore/sdk";
import { Indexer, RelayFirehose } from "@cocore/appview/indexer";
import { Store } from "@cocore/appview/store";
import { buildAppviewSplit } from "@cocore/appview/api";
import { AccountStore } from "@cocore/appview/account-store";
import { makeRuntime, metrics, record } from "@cocore/o11y";
import { err, header, jsonBody, makeNodeHandler, ok, searchParams } from "@cocore/o11y/http";
import { Exchange } from "@cocore/exchange";
import { bootstrapExchangeRecords } from "@cocore/exchange/bootstrap";
import {
  AppPasswordSettlementTransport,
  ConsoleProxySettlementTransport,
  SettlementPublisher,
} from "@cocore/exchange/publisher";
import { AppPasswordSession, createRecordViaSession } from "@cocore/exchange/app-password-session";
import { parsePrivateJwk, signRecord } from "@cocore/exchange/signing";
import { TokenLedger, type TokenLedgerPolicy } from "@cocore/exchange/token-balance";
import { startAutoresponder } from "./autorespond.ts";
import { createReceiptPipeline, type ReconcileOptions } from "./receipt-pipeline.ts";
import { makePdsBackedResolver } from "./resolve-record.ts";

// Optional secret: read as Redacted (never serializes into logs/traces)
// and, to match the old `if (process.env[X])` truthiness, treat an empty
// string as absent (None) — not as a present-but-empty secret.
const secretOption = (name: string) =>
  Config.redacted(name).pipe(
    Config.option,
    Config.map(Option.filter((r) => Redacted.value(r).length > 0)),
  );

// Typed, fail-fast configuration. Read ONCE at startup; a malformed
// numeric env var crashes immediately with a clear Config error rather
// than coercing to NaN later. Secrets are kept Redacted and only
// unwrapped at their point of use (signing, constant-time compare,
// transport auth). Defaults preserved exactly from the previous
// `process.env[...] ?? default` / `Number(... ?? n)` reads.
const CONFIG = Effect.runSync(
  Effect.all({
    bridgePort: Config.integer("COCORE_BRIDGE_PORT").pipe(Config.withDefault(8080)),
    appviewPort: Config.integer("COCORE_APPVIEW_PORT").pipe(Config.withDefault(8081)),
    dbPath: Config.string("COCORE_DB").pipe(Config.withDefault(":memory:")),
    appviewDid: Config.string("COCORE_APPVIEW_DID").pipe(Config.option),
    accountDb: Config.string("COCORE_ACCOUNT_DB").pipe(Config.withDefault(":memory:")),
    exchangeDid: Config.string("COCORE_EXCHANGE_DID").pipe(
      Config.withDefault("did:web:exchange.local"),
    ),
    // "1"/"0"-style flag (default-on): any value except "0" is truthy,
    // so we read the raw string and replicate `!== "0"` exactly rather
    // than risk Config.boolean's stricter truth table.
    autorespond: Config.string("COCORE_AUTORESPOND").pipe(Config.withDefault("1")),
    autorespondProviderDid: Config.string("COCORE_AUTORESPOND_PROVIDER_DID").pipe(
      Config.withDefault("did:plc:bridge-autoresponder"),
    ),
    exchangeApiKey: secretOption("COCORE_EXCHANGE_API_KEY"),
    exchangeApiBase: Config.string("COCORE_EXCHANGE_API_BASE").pipe(
      Config.withDefault("https://cocore.dev"),
    ),
    // App-password credential for the exchange's own PDS writes. When set, the
    // exchange writes settlements + bootstrap records directly to its PDS via a
    // self-healing app-password session instead of the lapse-prone console
    // OAuth proxy. Identifier defaults to the exchange DID; PDS is resolved
    // from the DID unless overridden.
    exchangeAppPassword: secretOption("COCORE_EXCHANGE_APP_PASSWORD"),
    exchangeIdentifier: Config.string("COCORE_EXCHANGE_IDENTIFIER").pipe(Config.option),
    exchangePdsUrl: Config.string("COCORE_EXCHANGE_PDS_URL").pipe(Config.option),
    exchangePrivateJwk: secretOption("COCORE_EXCHANGE_PRIVATE_KEY_JWK"),
    feeBps: Config.integer("COCORE_FEE_BPS").pipe(Config.withDefault(500)),
    feeMinMinor: Config.integer("COCORE_FEE_MIN_MINOR").pipe(Config.withDefault(0)),
    feeCurrency: Config.string("COCORE_FEE_CURRENCY").pipe(Config.withDefault("CC")),
    tokenRateInputPerMTok: Config.integer("COCORE_TOKEN_RATE_INPUT_PER_MTOK").pipe(
      Config.withDefault(10),
    ),
    tokenRateOutputPerMTok: Config.integer("COCORE_TOKEN_RATE_OUTPUT_PER_MTOK").pipe(
      Config.withDefault(10),
    ),
    tokenRateCurrency: Config.string("COCORE_TOKEN_RATE_CURRENCY").pipe(Config.option),
    tokenGrant: Config.integer("COCORE_TOKEN_GRANT").pipe(Config.withDefault(1_000_000)),
    tokenFloor: Config.integer("COCORE_TOKEN_FLOOR").pipe(Config.withDefault(100_000)),
    treasuryDid: Config.string("COCORE_TREASURY_DID").pipe(Config.option),
    weeklyRefreshAmount: Config.integer("COCORE_WEEKLY_REFRESH_AMOUNT").pipe(
      Config.withDefault(70_000),
    ),
    refreshCadenceMinutes: Config.integer("COCORE_REFRESH_CADENCE_MINUTES").pipe(
      Config.withDefault(7 * 24 * 60),
    ),
    patronageFractionBps: Config.integer("COCORE_PATRONAGE_FRACTION_BPS").pipe(
      Config.withDefault(8000),
    ),
    patronageCadenceDays: Config.integer("COCORE_PATRONAGE_CADENCE_DAYS").pipe(
      Config.withDefault(30),
    ),
    patronageAuto: Config.string("COCORE_PATRONAGE_AUTO").pipe(Config.withDefault("1")),
    tokenLedgerDb: Config.string("COCORE_TOKEN_LEDGER_DB").pipe(Config.option),
    railwayVolumeMountPath: Config.string("RAILWAY_VOLUME_MOUNT_PATH").pipe(Config.option),
    internalApiKey: secretOption("COCORE_INTERNAL_API_KEY"),
    relayUrl: Config.string("COCORE_RELAY_URL").pipe(Config.withDefault("wss://bsky.network")),
    relayUnauthenticated: Config.string("COCORE_RELAY_UNAUTHENTICATED_COMMITS").pipe(
      Config.withDefault("0"),
    ),
    reconcileIntervalSeconds: Config.integer("COCORE_RECONCILE_INTERVAL_SECONDS").pipe(
      Config.withDefault(60),
    ),
    reconcileBatchSize: Config.integer("COCORE_RECONCILE_BATCH_SIZE").pipe(Config.withDefault(200)),
    selfLoopFeeWaived: Config.string("COCORE_SELF_LOOP_FEE_WAIVED").pipe(Config.withDefault("1")),
    softwareVersion: Config.string("COCORE_SOFTWARE_VERSION").pipe(
      Config.withDefault("cocore-services@dev"),
    ),
    termsVersion: Config.string("COCORE_TERMS_VERSION").pipe(Config.withDefault("v3-2026-07-01")),
    termsUri: Config.string("COCORE_TERMS_URI").pipe(Config.option),
    consolePublicUrl: Config.string("CONSOLE_PUBLIC_URL").pipe(Config.option),
    leaderboardTtlMs: Config.integer("COCORE_LEADERBOARD_TTL_MS").pipe(Config.withDefault(60_000)),
    internalSecret: secretOption("COCORE_INTERNAL_SECRET"),
    bridgeUrl: Config.string("COCORE_BRIDGE_URL").pipe(Config.option),
    advisorUrl: Config.string("COCORE_ADVISOR_URL").pipe(Config.option),
    // Operator-only wipe gate: enabled only when set to exactly "1".
    allowWipe: Config.string("COCORE_ALLOW_WIPE").pipe(Config.withDefault("0")),
    // Comma-separated extra service DIDs whose OAuth sessions the AppView
    // should keep warm (the exchange DID is added automatically when it's a
    // real, API-key-backed exchange). See startServiceSessionKeepAlive.
    oauthKeepAliveDids: Config.string("COCORE_OAUTH_KEEPALIVE_DIDS").pipe(Config.withDefault("")),
  }),
);

const PORT = CONFIG.bridgePort;
const APPVIEW_PORT = CONFIG.appviewPort;
const DB_PATH = CONFIG.dbPath;
// Operational account state (API keys, OAuth sessions) lives in its own
// DB so it survives a receipt-cache rebuild. The dev.cocore.account.*
// methods only register when COCORE_APPVIEW_DID (the service-auth
// audience) is also set.
const APPVIEW_DID = Option.getOrUndefined(CONFIG.appviewDid);
const ACCOUNT_DB = CONFIG.accountDb;
const EXCHANGE_DID = CONFIG.exchangeDid;
const AUTORESPOND = CONFIG.autorespond !== "0";
const AUTORESPOND_PROVIDER_DID = CONFIG.autorespondProviderDid;

// Real-PDS publishing for settlements + the new tokenPatronage
// records. When COCORE_EXCHANGE_API_KEY is set, the exchange routes
// records through the cocore console's proxy (Bearer-key auth → DPoP
// OAuth → real bsky PDS write under the exchange's DID). When unset
// we use in-process transports — fine for tests, useless in prod.
// Kept Redacted (Option<Redacted<string>>); unwrapped only at the
// transport/fetch boundary.
const EXCHANGE_API_KEY = CONFIG.exchangeApiKey;
const EXCHANGE_API_BASE = CONFIG.exchangeApiBase;
const EXCHANGE_APP_PASSWORD = CONFIG.exchangeAppPassword;
const EXCHANGE_IDENTIFIER = Option.getOrUndefined(CONFIG.exchangeIdentifier) ?? EXCHANGE_DID;
const EXCHANGE_PDS_URL = Option.getOrUndefined(CONFIG.exchangePdsUrl);

const EXCHANGE_PRIVATE_JWK = CONFIG.exchangePrivateJwk;

// Treasury fee in basis points routed to the treasury DID on every
// receipt. Conservation 95/5: 500 bps = 5% to treasury, the rest
// to the provider.
const FEE_BPS = CONFIG.feeBps;
const FEE_MIN_MINOR = CONFIG.feeMinMinor;
// Currency the exchange's policy + tokenRate records advertise. The
// strict receipt verifier compares `receipt.price.currency` (set by
// the agent in `provider/src/pricing.rs`) against
// `job.priceCeiling.currency` (set in `api.v1.chat.completions.ts`).
// Both are "CC" under the closed-loop pivot. Defaulting this to "CC"
// keeps a fresh Railway env's exchange policy internally consistent
// with what every actual receipt + job carries (we previously
// defaulted to "USD", which silently drifted from the receipts and
// rejected every settlement — the deceptive failure we hit today).
const FEE_CURRENCY = CONFIG.feeCurrency;

// Per-token rate published in the policy. Rendered as informational
// only — tokens are the unit of account and there's
// no exchange rate to fiat.
const TOKEN_RATE_INPUT_PER_MTOK = CONFIG.tokenRateInputPerMTok;
const TOKEN_RATE_OUTPUT_PER_MTOK = CONFIG.tokenRateOutputPerMTok;
const TOKEN_RATE_CURRENCY = Option.getOrUndefined(CONFIG.tokenRateCurrency) ?? FEE_CURRENCY;

// Onboarding grant + admission floor.
const TOKEN_GRANT = CONFIG.tokenGrant;
const TOKEN_FLOOR = CONFIG.tokenFloor;

// Treasury identity. Defaults to the exchange's own DID — the
// cooperative's treasury IS the exchange's balance sheet.
const TREASURY_DID = Option.getOrUndefined(CONFIG.treasuryDid) ?? EXCHANGE_DID;

// Weekly refresh: amount + cadence. Lazy — only fires on balance
// touch (receipt, getBalance, governance act).
const WEEKLY_REFRESH_AMOUNT = CONFIG.weeklyRefreshAmount;
const REFRESH_CADENCE_MINUTES = CONFIG.refreshCadenceMinutes;

// Patronage rebate: monthly distribution of 80% of treasury to
// active members in proportion to their patronage during the period.
const PATRONAGE_FRACTION_BPS = CONFIG.patronageFractionBps;
const PATRONAGE_CADENCE_DAYS = CONFIG.patronageCadenceDays;
const PATRONAGE_AUTO = CONFIG.patronageAuto !== "0";

// Sqlite path for the TokenLedger. Defaults to Railway volume so
// balances survive redeploys; :memory: for dev/CI. Blast the file
// to reset.
const RAILWAY_VOLUME_MOUNT_PATH = Option.getOrUndefined(CONFIG.railwayVolumeMountPath);
const TOKEN_LEDGER_DB =
  Option.getOrUndefined(CONFIG.tokenLedgerDb) ??
  (RAILWAY_VOLUME_MOUNT_PATH
    ? `${RAILWAY_VOLUME_MOUNT_PATH.replace(/\/$/, "")}/token-ledger.sqlite`
    : ":memory:");

// Shared secret for operator-only endpoints (wipe, manual
// distributePatronage, etc.). Unset → those endpoints reject. Kept
// Redacted; unwrapped only inside the constant-time compare in authOk.
const INTERNAL_API_KEY = CONFIG.internalApiKey;

// AT Protocol relay to subscribe to for the AppView indexer. Default
// is the Bluesky public relay, which mirrors every PDS that subscribes
// to its repo-subscribe protocol (including porcini.us-east.host.bsky
// .network where most cocore agents live today). The subscription is
// idempotent with the bridge endpoint — both feed into the same
// in-process Firehose, and the indexer's store.upsert is keyed by
// uri, so duplicate dispatches are no-ops. Set to "" or "off" to
// disable (useful for dev / tests that don't want to hit the wire).
const RELAY_URL = CONFIG.relayUrl;
const RELAY_ENABLED = !!RELAY_URL && RELAY_URL !== "off";
// unauthenticatedCommits: false in production — the IdResolver checks
// every commit's signing key against the publishing DID's document
// via plc.directory. Tests that drive a local PDS without a real PLC
// flip this to true.
const RELAY_UNAUTHENTICATED = CONFIG.relayUnauthenticated === "1";

// Reconcile loop cadence. Every N seconds the services container
// scans the indexed-receipt table for receipts that don't yet have a
// settlement record, and re-invokes `exchange.onReceipt` for each.
// This is the catch-all for receipts that failed `resolve-failed` on
// first observation (the dependency record — job, payment auth,
// attestation — arrived seconds later but the exchange doesn't
// retry on its own). Also catches anything that landed during a
// services-container restart.
const RECONCILE_INTERVAL_SECONDS = CONFIG.reconcileIntervalSeconds;
// Maximum number of receipts to attempt per reconcile tick. Caps work
// done per pass on a large backfill; the loop will pick up where it
// left off on the next tick.
const RECONCILE_BATCH_SIZE = CONFIG.reconcileBatchSize;

// Self-loop: waive the treasury fee when requester DID == provider
// DID. Settlement record is still published as audit trail.
const SELF_LOOP_FEE_WAIVED = CONFIG.selfLoopFeeWaived !== "0";

const SOFTWARE_VERSION = CONFIG.softwareVersion;

// Terms-of-service version. Bumping forces re-acceptance — the next
// bootstrap publishes a fresh exchangePolicy with the new version
// and console clients prompt the user.
const TERMS_VERSION = CONFIG.termsVersion;
const CONSOLE_PUBLIC_URL = Option.getOrUndefined(CONFIG.consolePublicUrl);
const TERMS_URI =
  Option.getOrUndefined(CONFIG.termsUri) ??
  (CONSOLE_PUBLIC_URL
    ? `${CONSOLE_PUBLIC_URL.replace(/\/$/, "")}/terms`
    : "https://cocore.dev/terms");

// Shared secret used to authenticate the bridge's internal write path.
// Kept Redacted; unwrapped only where buildAppviewSplit consumes it.
const INTERNAL_SECRET = CONFIG.internalSecret;
// Bridge runs in this same process; default to the local loopback URL
// derived from the bridge port when COCORE_BRIDGE_URL is unset.
const BRIDGE_URL = Option.getOrUndefined(CONFIG.bridgeUrl) ?? `http://127.0.0.1:${PORT}`;
const ADVISOR_URL = Option.getOrUndefined(CONFIG.advisorUrl);
// Operator-only wipe gate: enabled only when COCORE_ALLOW_WIPE === "1".
const ALLOW_WIPE = CONFIG.allowWipe === "1";
// Aggregating the ledger three ways per request would be wasteful for
// a page that turns over slowly; memoize per-limit for a short TTL.
const LEADERBOARD_TTL_MS = CONFIG.leaderboardTtlMs;

async function main() {
  const firehose = new Firehose();
  const store = new Store(DB_PATH);

  // 1. AppView indexer.
  const indexer = new Indexer(store);
  indexer.subscribe(firehose);

  // 1a. Relay subscription. The AT Protocol firehose at
  //     `wss://bsky.network` mirrors every PDS commit from
  //     subscribed PDSes (including porcini, which hosts most
  //     cocore agents today). Subscribing here means the AppView
  //     stops depending on the bridge endpoint as a correctness
  //     checkpoint — the bridge is now an optimization for
  //     console-published records, not the only path.
  //
  //     Cursor persistence: we store the relay's last-seen seq in
  //     the same SQLite the indexed records live in. On boot we
  //     hand the cursor back to @atproto/sync so the relay resumes
  //     from where we left off (no backfill on every restart).
  //
  //     Disabled when COCORE_RELAY_URL="off" or empty — useful for
  //     unit tests that don't want to hit the wire.
  let relay: RelayFirehose | undefined;
  if (RELAY_ENABLED) {
    const initialCursor = (() => {
      const raw = store.getCursor("relay");
      const n = raw ? Number(raw) : Number.NaN;
      return Number.isFinite(n) ? n : undefined;
    })();
    relay = new RelayFirehose({
      service: RELAY_URL,
      out: firehose,
      unauthenticatedCommits: RELAY_UNAUTHENTICATED,
      ...(initialCursor !== undefined ? { initialCursor } : {}),
      setCursor: async (cursor: number) => {
        // Best-effort: cursor persistence on every event would dwarf
        // the actual indexing work. The runner debounces internally.
        try {
          store.setCursor("relay", String(cursor));
        } catch (e) {
          console.error(`relay: setCursor failed: ${(e as Error).message}`);
        }
      },
    });
    relay.start();
    console.error(
      `relay: subscribed to ${RELAY_URL} cursor=${initialCursor ?? "head"} unauthenticatedCommits=${RELAY_UNAUTHENTICATED}`,
    );
  } else {
    console.error("relay: disabled (COCORE_RELAY_URL unset or 'off')");
  }

  // 2. Exchange. Verifies receipts + publishes settlement records.
  //    Tokens move via the TokenLedger in the firehose hook below.
  //
  // o11y runtime for the processing boundary (no-op until OTEL_* is set).
  // Created here so the exchange session, settlement transport, and dependency
  // resolver below all share one runtime.
  const runtime = makeRuntime({ serviceName: "cocore-services" });

  const exchangeApiKeyStr = Option.isSome(EXCHANGE_API_KEY)
    ? Redacted.value(EXCHANGE_API_KEY.value)
    : undefined;

  // App-password session for the exchange's OWN PDS writes. When configured,
  // settlements + bootstrap records are written DIRECTLY to the exchange's PDS
  // via a self-healing app-password session — no console OAuth proxy that can
  // lapse and demand a human re-auth (the 2026-06 root cause), and no
  // console→appview hop that was independently 502'ing. Falls back to the
  // console-proxy transport when only an API key is configured.
  const exchangeSession = Option.isSome(EXCHANGE_APP_PASSWORD)
    ? new AppPasswordSession({
        identifier: EXCHANGE_IDENTIFIER,
        appPassword: Redacted.value(EXCHANGE_APP_PASSWORD.value),
        did: EXCHANGE_DID,
        ...(EXCHANGE_PDS_URL ? { pdsEndpoint: EXCHANGE_PDS_URL } : {}),
        onEvent: (e) => record(runtime, Metric.increment(metrics.exchangeSession(e))),
        log: (l) => console.error(l),
      })
    : undefined;
  if (exchangeSession) {
    console.error(
      `exchange: app-password session enabled for ${EXCHANGE_IDENTIFIER} (direct PDS writes)`,
    );
  }

  const transport = exchangeSession
    ? new AppPasswordSettlementTransport(exchangeSession)
    : exchangeApiKeyStr
      ? new ConsoleProxySettlementTransport({
          apiBase: EXCHANGE_API_BASE,
          apiKey: exchangeApiKeyStr,
        })
      : undefined;
  const publisher = new SettlementPublisher(EXCHANGE_DID, transport);
  const signingKey = Option.isSome(EXCHANGE_PRIVATE_JWK)
    ? parsePrivateJwk(Redacted.value(EXCHANGE_PRIVATE_JWK.value))
    : undefined;
  const feePolicy = { bps: FEE_BPS, minMinor: FEE_MIN_MINOR };
  const selfLoop = { feeWaived: SELF_LOOP_FEE_WAIVED };

  // 2a. Bootstrap policy + attestation records. Skipped without a write path
  //     (no app-password session and no API key → no real PDS to publish to).
  let policyRef: { uri: string; cid: string } | undefined;
  let attestationRef: { uri: string; cid: string } | undefined;
  if (exchangeSession || exchangeApiKeyStr) {
    try {
      const refs = await bootstrapExchangeRecords({
        exchangeDid: EXCHANGE_DID,
        // Same write path as the settlement transport: app-password direct-PDS
        // when configured, else the console proxy.
        ...(exchangeSession
          ? {
              writeRecord: (collection: string, record: Record<string, unknown>) =>
                createRecordViaSession(exchangeSession, { collection, record }),
            }
          : { apiBase: EXCHANGE_API_BASE, apiKey: exchangeApiKeyStr }),
        feePolicy,
        feeCurrency: FEE_CURRENCY,
        supportedCurrencies: [FEE_CURRENCY],
        selfLoop,
        softwareVersion: SOFTWARE_VERSION,
        signingKey,
        auditPosture: "single-tenant Railway deployment",
        termsUri: TERMS_URI,
        termsVersion: TERMS_VERSION,
        tokenRate: {
          inputPricePerMTok: TOKEN_RATE_INPUT_PER_MTOK,
          outputPricePerMTok: TOKEN_RATE_OUTPUT_PER_MTOK,
          currency: TOKEN_RATE_CURRENCY,
        },
        tokenGrant: TOKEN_GRANT,
        tokenFloor: TOKEN_FLOOR,
        treasuryDid: TREASURY_DID,
        weeklyRefresh: {
          amountPerDid: WEEKLY_REFRESH_AMOUNT,
          cadenceMinutes: REFRESH_CADENCE_MINUTES,
        },
        patronageDistribution: {
          fractionBps: PATRONAGE_FRACTION_BPS,
          cadenceDays: PATRONAGE_CADENCE_DAYS,
        },
      });
      policyRef = refs.policyRef;
      attestationRef = refs.attestationRef;
      console.error(
        `exchange: bootstrapped policy=${refs.policyRef.uri} attestation=${refs.attestationRef.uri}`,
      );
    } catch (e) {
      console.error(
        `exchange: bootstrap failed (continuing without policy/attestation refs): ${(e as Error).message}`,
      );
    }
  }

  // TokenLedger's sqlite handle, created here (before the Exchange) so the
  // Exchange can share it for its durable settlement state — settlement
  // idempotency (M4) and single-use / sessionBudget authorization consumption
  // (H1). Without a `db` the Exchange falls back to in-memory-only idempotency,
  // which resets on restart and can't stop a second receipt from re-spending
  // one authorization. Same handle → both live in one sqlite file.
  const ledgerDb = new Database(TOKEN_LEDGER_DB);
  const exchange = new Exchange({
    exchangeDid: EXCHANGE_DID,
    feePolicy,
    selfLoop,
    // H1/M4: durable settlement state (consumed authorizations + settled
    // receipts) in the shared ledger db.
    db: ledgerDb,
    ...(policyRef ? { policyRef } : {}),
    ...(attestationRef ? { attestationRef } : {}),
    ...(signingKey ? { signingKey } : {}),
    publisher,
    // Store-first, PDS-backed resolution. A local-store miss falls back to
    // the record's PDS (the source of truth) and back-fills the cache, so a
    // dead relay or a dropped mirror hint can no longer strand a receipt in
    // resolve-failed forever (the 2026-06 settlement stall). See
    // resolve-record.ts.
    resolveRecord: makePdsBackedResolver({ store, runtime, log: (l) => console.error(l) }),
  });
  // Wrap publisher.publish so settlements re-enter the firehose for
  // any subscriber that watches it directly (tests, etc.).
  const originalPublish = publisher.publish.bind(publisher);
  publisher.publish = async (rec) => {
    const published = await originalPublish(rec);
    await firehose.dispatch({
      uri: published.uri,
      cid: published.cid,
      collection: "dev.cocore.compute.settlement",
      repo: EXCHANGE_DID,
      rkey: published.uri.split("/").pop() ?? "",
      body: rec,
    });
    return published;
  };

  // 2b. TokenLedger. Single source of truth for per-DID balances.
  //     Lazy refresh runs as a side effect of every receipt;
  //     monthly patronage is on a scheduler below. Shares `ledgerDb` with the
  //     Exchange (created above).
  const ledger = new TokenLedger(ledgerDb);
  const ledgerPolicy: TokenLedgerPolicy = {
    tokenGrant: TOKEN_GRANT,
    tokenFloor: TOKEN_FLOOR,
    treasuryDid: TREASURY_DID,
    treasuryFeeBps: FEE_BPS,
    // M5: mirror the settlement fee floor so the ledger fee and the settlement
    // fee are driven from the same numbers (no divergence).
    feeMinMinor: FEE_MIN_MINOR,
    selfLoopFeeWaived: SELF_LOOP_FEE_WAIVED,
    weeklyRefreshAmount: WEEKLY_REFRESH_AMOUNT,
    refreshCadenceMinutes: REFRESH_CADENCE_MINUTES,
    patronageFractionBps: PATRONAGE_FRACTION_BPS,
    patronageCadenceDays: PATRONAGE_CADENCE_DAYS,
  };
  console.error(
    `token-ledger: db=${TOKEN_LEDGER_DB} grant=${TOKEN_GRANT} floor=${TOKEN_FLOOR} treasuryFee=${FEE_BPS}bps treasury=${TREASURY_DID}`,
  );

  // Settlement pipeline: wires exchange.onReceipt + the pending-
  // receipt queue + token-ledger application together. See
  // `receipt-pipeline.ts` for the full design rationale.
  const pipeline = createReceiptPipeline({
    exchange,
    ledger,
    ledgerPolicy,
    firehose,
    store,
    treasuryDid: TREASURY_DID,
    feeBps: FEE_BPS,
    reconcileBatchSize: RECONCILE_BATCH_SIZE,
    runtime,
  });
  pipeline.attach();

  // 2c. Settlement reconcile loop. Periodically scans the indexer
  //     for indexed receipts that don't yet have a settlement
  //     record, and re-invokes `exchange.onReceipt` for each. This
  //     is the durability backstop for three failure modes:
  //
  //       1. Receipt arrives at the firehose before its dependency
  //          records (the resolve-failed race we just fixed
  //          reactively above) and the dep arrives during a window
  //          where the reactive `firehose.on(null, …)` handler
  //          missed it (e.g. the dep was already in the store
  //          before the receipt was parked).
  //       2. Services container restart. The pending-receipt map
  //          lives in memory; after a restart we re-scan from the
  //          indexed store.
  //       3. The reactive retry's `MAX_RETRIES` budget was exhausted
  //          but the dependency landed later — the reconcile
  //          ignores retry budgets and just tries to settle once
  //          per tick.
  //
  //     `exchange.onReceipt` is idempotent on receipt URI via the
  //     publisher's `settledByReceiptUri` set; the reconcile passes
  //     just no-op once a settlement exists.
  // Kick off the reconcile loop. The actual work lives in
  // `pipeline.reconcileUnsettledReceipts()` — see receipt-pipeline.ts
  // for the design. A single Effect (`reconcileEffect`) holds one
  // pass; `Effect.repeat(Schedule.spaced(...))` gives the fixed-delay
  // cadence (the next pass starts N seconds after the previous one
  // *finishes*, so a slow pass never overlaps/shifts the schedule —
  // the same property the old setInterval-with-unref relied on). A
  // failed pass is caught + logged so the fiber survives (matches the
  // old try/catch).
  const reconcileEffect = Effect.tryPromise(() => pipeline.reconcileUnsettledReceipts()).pipe(
    Effect.tap((summary) =>
      Effect.sync(() => {
        if (summary.attempted > 0) {
          console.error(
            `reconcile: scanned ${summary.scanned} receipts, attempted ${summary.attempted}, settled ${summary.settled}, still resolve-failed ${summary.stillResolveFailed}, rejected ${summary.rejected}, skipped-terminal ${summary.skippedRejected}`,
          );
        }
      }),
    ),
    Effect.catchAll((e) =>
      Effect.sync(() => console.error(`reconcile: pass failed: ${(e as Error).message}`)),
    ),
    Effect.withSpan("services.reconcile"),
  );
  if (RECONCILE_INTERVAL_SECONDS > 0) {
    // One eager pass at boot — catches receipts indexed during a
    // services-container outage. Run after a short delay so the
    // appview API + bridge are listening; we want operators to be
    // able to peek at /xrpc state while the reconcile is grinding.
    // `Effect.sleep("5 seconds")` is the boot delay; the first repeat
    // execution IS the eager pass, then `Schedule.spaced` fires every
    // N seconds thereafter. Forked onto the o11y runtime so spans
    // export; the running HTTP servers keep the process alive (the
    // fiber replaces the old `.unref()`'d timers).
    runtime.runFork(
      Effect.sleep("5 seconds").pipe(
        Effect.zipRight(
          reconcileEffect.pipe(
            Effect.repeat(Schedule.spaced(Duration.seconds(RECONCILE_INTERVAL_SECONDS))),
          ),
        ),
      ),
    );
    console.error(
      `reconcile: enabled (every ${RECONCILE_INTERVAL_SECONDS}s, batch=${RECONCILE_BATCH_SIZE})`,
    );
  }

  // 2d. Monthly patronage scheduler. One pass distributes patronage
  //     for the window covering the prior calendar month; the ledger's
  //     idempotency on (start, end) makes re-runs for the same period
  //     a no-op, so firing on boot AND on every month boundary is
  //     safe. `Effect.repeat(Schedule.cron(...))` runs the effect once
  //     immediately (the boot run for the prior month) then repeats at
  //     00:00 UTC on the first of each month. Disabled with
  //     COCORE_PATRONAGE_AUTO=0 (manual trigger still works via the
  //     internal endpoint below).
  const patronageApiKey = Option.getOrUndefined(Option.map(EXCHANGE_API_KEY, Redacted.value));
  const distributePatronageEffect = Effect.tryPromise(async () => {
    const now = new Date();
    const start = firstOfPriorMonthUtc(now);
    const end = firstOfMonthUtc(now);
    const result = ledger.distributePatronage(start, end, ledgerPolicy);
    if (result.alreadyDistributed) {
      console.error(
        `patronage: period ${start.toISOString()}/${end.toISOString()} already distributed`,
      );
    } else if (result.totalDistributed > 0) {
      console.error(
        `patronage: distributed ${result.totalDistributed} tokens to ${result.recipients.length} recipients`,
      );
      if (patronageApiKey && policyRef && result.recipients.length > 0) {
        await emitPatronageRecords(
          EXCHANGE_API_BASE,
          patronageApiKey,
          ledgerPolicy.treasuryDid,
          policyRef,
          { start, end },
          result,
        ).catch((e) => {
          console.error(`patronage: emit records failed: ${(e as Error).message}`);
        });
      }
    } else {
      console.error(`patronage: no recipients in period ${start.toISOString()}`);
    }
  }).pipe(
    Effect.catchAll((e) =>
      Effect.sync(() => console.error(`patronage: distribution failed: ${(e as Error).message}`)),
    ),
    Effect.withSpan("services.patronage"),
  );
  if (PATRONAGE_AUTO && PATRONAGE_FRACTION_BPS > 0) {
    // "0 0 1 * *" — second/minute/hour are the leading fields here?
    // No: this is standard 5-field cron (minute hour day-of-month
    // month day-of-week) = 00:00 on the 1st of every month, UTC.
    runtime.runFork(
      distributePatronageEffect.pipe(Effect.repeat(Schedule.cron("0 0 1 * *", "UTC"))),
    );
  }

  if (AUTORESPOND) {
    await startAutoresponder({
      firehose,
      providerDid: AUTORESPOND_PROVIDER_DID,
      tokenRate: {
        inputPerMTok: TOKEN_RATE_INPUT_PER_MTOK,
        outputPerMTok: TOKEN_RATE_OUTPUT_PER_MTOK,
        currency: TOKEN_RATE_CURRENCY,
      },
    });
  }

  const accountStore = APPVIEW_DID ? new AccountStore(ACCOUNT_DB) : undefined;
  // Build BOTH AppView views from ONE set of shared resources (single OAuth
  // client + session store + PairStore). `full` includes the shared-secret
  // /internal/* endpoints; `public` excludes them. We serve `full` on the
  // private :8081 listener (the console reaches it over the Railway internal
  // network) and `public` on the bridge port below — keeping /internal off
  // the wire while still answering appview.* reads / account.* / /pds there.
  // Keep the exchange DID's OAuth session warm so it can't lapse from disuse
  // and 401 every settlement write (the 2026-06 root cause). Only for a real,
  // API-key-backed exchange — the did:web:exchange.local default is a dev
  // placeholder with no session. Operators can add more DIDs via
  // COCORE_OAUTH_KEEPALIVE_DIDS.
  const keepAliveDids = (() => {
    const set = new Set(
      CONFIG.oauthKeepAliveDids
        .split(",")
        .map((s) => s.trim())
        .filter((s) => s.startsWith("did:")),
    );
    // Only keep-alive the exchange DID when it actually has an OAuth session to
    // warm — i.e. the console-proxy path. With an app-password session the
    // exchange self-manages its own session, so there's nothing to keep warm
    // (and a restore attempt would just fail + log noise).
    if (
      !exchangeSession &&
      Option.isSome(EXCHANGE_API_KEY) &&
      EXCHANGE_DID.startsWith("did:") &&
      EXCHANGE_DID !== "did:web:exchange.local"
    ) {
      set.add(EXCHANGE_DID);
    }
    return [...set];
  })();

  const appview = buildAppviewSplit(store, {
    accountStore,
    appviewDid: APPVIEW_DID,
    // The bridge runs in this same process; mirror PDS writes to it.
    bridgeUrl: BRIDGE_URL,
    internalSecret: Option.isSome(INTERNAL_SECRET)
      ? Redacted.value(INTERNAL_SECRET.value)
      : undefined,
    // inference.dispatch routes through the advisor and publishes the job
    // under the requester's AppView-owned session; both enable the SSE route.
    advisorUrl: ADVISOR_URL,
    exchangeDid: EXCHANGE_DID,
    keepAliveDids,
  });

  // Internal :8081 listener serves the FULL app (incl /internal/*). Traced
  // via @effect/platform under makeNodeHandler (a span per request, exported
  // to Honeycomb when OTLP is configured).
  const appviewFull = await makeNodeHandler(appview.full, { serviceName: "cocore-appview" });
  const appviewServer = createServer(appviewFull);
  await new Promise<void>((r) => appviewServer.listen(APPVIEW_PORT, r));
  console.error(
    `appview-api: listening on :${APPVIEW_PORT} db=${DB_PATH}` +
      (APPVIEW_DID ? ` account=on(aud=${APPVIEW_DID} db=${ACCOUNT_DB})` : ""),
  );

  // 4. Bridge HTTP, as an @effect/platform HttpRouter. Each route is an
  //    Effect returning an HttpServerResponse (`ok(data)` for 200, `err(status,
  //    {...})` for everything else) under a `services.*` span. Bodies are read
  //    via `Effect.either(jsonBody)` (400 on malformed JSON); operator-gated
  //    routes re-use the constant-time `authOk` check on the Authorization
  //    header. All the original closures (firehose, store, publisher, ledger,
  //    signingKey, refs, pipeline, caches, emit helpers) are captured here.

  // admin.reconcile answers GET (read-only audit) and POST (audit + rebuild
  // on drift); share one handler parameterised by `wantsRebuild`.
  const reconcileHandler = (wantsRebuild: boolean) =>
    Effect.gen(function* () {
      if (!authOk(yield* header("authorization"))) return err(401, { error: "unauthorized" });
      try {
        let report = ledger.reconcile();
        let rebuilt: { changed: number } | null = null;
        if (wantsRebuild && report.balanceCacheDrifts.length > 0) {
          rebuilt = ledger.rebuildBalanceCache();
          report = ledger.reconcile();
        }
        if (!report.ok) {
          console.error(
            `admin.reconcile: drift detected — ${JSON.stringify({
              drifts: report.balanceCacheDrifts.length,
              negatives: report.negativeBalances.length,
              totalDeltaMatchesMints: report.totalDeltaMatchesMints,
              totalBalanceMatchesMints: report.totalBalanceMatchesMints,
            })}`,
          );
        }
        return ok({ report, ...(rebuilt ? { rebuilt } : {}) });
      } catch (e) {
        return err(500, { error: (e as Error).message });
      }
    }).pipe(Effect.withSpan("services.admin.reconcile"));

  const bridgeRouter = HttpRouter.empty.pipe(
    // NB: no `/healthz` here. `appview.public` (concatenated below) already
    // registers `GET /healthz`, and `HttpRouter.concatAll` throws
    // "Method 'GET' already declared for route '/healthz'" on a duplicate —
    // which fails the *entire* merged router, 500ing every bridge request.
    // The liveness contract (Railway healthcheckPath, docker-compose probe,
    // infra/smoke.ts) only needs a 200; appview's `/healthz` provides it.
    // Internal-only: the console mirrors a just-written PDS record into the
    // AppView cache the instant an owner edits a setting. Gated on the same
    // constant-time `authOk` the other operator routes use — an unauthed caller
    // could otherwise dispatch an attacker-chosen (uri/cid/collection/repo/body)
    // straight into the firehose and poison the index (the AppView is a cache,
    // but a poisoned cache still misleads every dashboard read). Two extra
    // structural gates make the mirror faithful even for an authed-but-buggy
    // caller: the collection must be `dev.cocore.*`, and the record `repo` must
    // match the DID authority of its own `at://<did>/…` URI (a receipt is only
    // authoritative in its own repo).
    HttpRouter.post(
      "/xrpc/dev.cocore.bridge.publish",
      Effect.gen(function* () {
        if (!authOk(yield* header("authorization"))) return err(401, { error: "unauthorized" });
        const parsed = yield* Effect.either(jsonBody);
        if (parsed._tag === "Left") return err(400, { error: "body must be JSON" });
        const body = parsed.right as IndexedRecord;
        if (!body.uri || !body.cid || !body.collection || !body.repo) {
          return err(400, { error: "missing uri/cid/collection/repo" });
        }
        if (!body.collection.startsWith("dev.cocore.")) {
          return err(400, { error: "collection must be under dev.cocore.*" });
        }
        const uriAuthority = didFromAtUri(body.uri);
        if (!uriAuthority) return err(400, { error: "uri must be an at:// record URI" });
        if (uriAuthority !== body.repo) {
          return err(400, { error: "repo does not match the record uri authority" });
        }
        yield* Effect.promise(() => firehose.dispatch(body));
        return err(202, { ok: true });
      }).pipe(Effect.withSpan("services.bridge.publish")),
    ),
    // Countersign a terms-of-service acceptance with the exchange's signing
    // key, so the published record is a cocore ATTESTATION the exchange
    // witnessed the acceptance — not merely a record the user wrote
    // unilaterally. Internal-only (the signing key never leaves this
    // container); the console calls it with COCORE_INTERNAL_API_KEY, gets back
    // the COMPLETE signed record, and persists it verbatim to the user's PDS
    // under their OAuth session. We build the exact record here (incl `$type` +
    // the `attestation` strong-ref) and sign over its canonical bytes minus
    // `sig`, so a verifier strips `sig`, re-canonicalises, and checks against
    // the key in the referenced exchangeAttestation — the same chain
    // receipts/settlements use.
    HttpRouter.post(
      "/xrpc/dev.cocore.exchange.signTermsAcceptance",
      Effect.gen(function* () {
        if (!authOk(yield* header("authorization"))) return err(401, { error: "unauthorized" });
        if (!signingKey) return err(503, { error: "exchange signing key not configured" });
        const parsed = yield* Effect.either(jsonBody);
        if (parsed._tag === "Left") return err(400, { error: "body must be JSON" });
        const body = parsed.right as {
          policyUri?: string;
          policyCid?: string;
          termsVersion?: string;
          termsUri?: string;
          userAgent?: string;
        };
        if (!body.policyUri || !body.policyCid || !body.termsVersion || !body.termsUri) {
          return err(400, { error: "missing policyUri/policyCid/termsVersion/termsUri" });
        }
        const record: Record<string, unknown> = {
          $type: "dev.cocore.compute.termsAcceptance",
          exchange: EXCHANGE_DID,
          policy: { uri: body.policyUri, cid: body.policyCid },
          termsVersion: body.termsVersion,
          termsUri: body.termsUri,
          ...(body.userAgent ? { userAgent: body.userAgent } : {}),
          acceptedAt: new Date().toISOString(),
          ...(attestationRef
            ? { attestation: { uri: attestationRef.uri, cid: attestationRef.cid } }
            : {}),
        };
        const sig = yield* Effect.promise(() => signRecord(record, signingKey));
        return ok({ record: { ...record, sig } });
      }).pipe(Effect.withSpan("services.exchange.signTermsAcceptance")),
    ),
    // Internal-only: drop a single cached record (console fires this when an
    // owner deletes a record from their PDS). Same auth gate as publish — an
    // unauthed caller could otherwise evict arbitrary rows from the index.
    HttpRouter.post(
      "/xrpc/dev.cocore.bridge.unpublish",
      Effect.gen(function* () {
        if (!authOk(yield* header("authorization"))) return err(401, { error: "unauthorized" });
        const parsed = yield* Effect.either(jsonBody);
        if (parsed._tag === "Left") return err(400, { error: "body must be JSON" });
        const body = parsed.right as { uri?: string };
        if (!body.uri) return err(400, { error: "missing uri" });
        store.delete(body.uri);
        return ok({ ok: true });
      }).pipe(Effect.withSpan("services.bridge.unpublish")),
    ),
    // Internal-only: the console's "wipe my data" affordance evicts every
    // cached row for a DID. Unauthed this is arbitrary data destruction (any
    // DID's index rows), so gate it on the same constant-time `authOk`.
    HttpRouter.post(
      "/xrpc/dev.cocore.bridge.purge",
      Effect.gen(function* () {
        if (!authOk(yield* header("authorization"))) return err(401, { error: "unauthorized" });
        const parsed = yield* Effect.either(jsonBody);
        if (parsed._tag === "Left") return err(400, { error: "body must be JSON" });
        const body = parsed.right as { did?: string };
        if (!body.did) return err(400, { error: "missing did" });
        const removed = store.purgeForDid(body.did);
        return ok({ ok: true, removed });
      }).pipe(Effect.withSpan("services.bridge.purge")),
    ),
    HttpRouter.get(
      "/xrpc/dev.cocore.bridge.stats",
      Effect.sync(() =>
        ok({
          settled: publisher.alreadySettled().size,
          treasuryBalance: ledger.peekBalance(TREASURY_DID),
        }),
      ).pipe(Effect.withSpan("services.bridge.stats")),
    ),
    // Read-only diagnostic surface for the receipt pipeline. No auth: the data
    // is pipeline state (URIs, outcome kinds, retry counts) — nothing secret,
    // all of it derivable from public PDS records anyway. Without this endpoint
    // a settlement bug is invisible from outside Railway (the silent-bail
    // failure mode that hit us today). With it, operators can curl this and see
    // exactly why each receipt did or didn't settle:
    //
    //   curl /xrpc/dev.cocore.admin.pipelineState | jq .recentOutcomes
    //
    // Optional ?since=<ISO-8601> filters the recentOutcomes ring to entries
    // newer than the cursor. ?limit=<N> caps the count (default 50, max 200 —
    // the ring buffer size).
    HttpRouter.get(
      "/xrpc/dev.cocore.admin.pipelineState",
      Effect.gen(function* () {
        const sp = yield* searchParams;
        const since = sp.get("since");
        const limitRaw = sp.get("limit");
        const limit = (() => {
          const n = limitRaw ? Number(limitRaw) : 50;
          if (!Number.isFinite(n) || n <= 0) return 50;
          return Math.min(n, 200);
        })();
        const sinceMs = since ? Date.parse(since) : null;
        let recent = pipeline.recentOutcomes();
        if (sinceMs !== null && Number.isFinite(sinceMs)) {
          recent = recent.filter((e) => Date.parse(e.at) > sinceMs);
        }
        recent = recent.slice(0, limit);
        return ok({
          generatedAt: new Date().toISOString(),
          pending: pipeline.pendingSnapshot(),
          recentOutcomes: recent,
          publisherSettled: publisher.alreadySettled().size,
          // Relay/indexer liveness: a large idleMs while the process is up
          // means the upstream feed (the store's durable backstop) has gone
          // silent — the failure that starved resolution in 2026-06. null
          // when the relay is disabled in this deployment.
          relay: relay ? relay.getLiveness() : null,
          // Quick at-a-glance counters across the ring buffer: helps operators
          // see "are we mostly resolve-failing, or mostly settling, or mostly
          // rejecting?" without scrolling the per-receipt list.
          summary: pipeline.recentOutcomes().reduce(
            (acc, e) => {
              acc[e.kind] = (acc[e.kind] ?? 0) + 1;
              return acc;
            },
            {} as Record<string, number>,
          ),
        });
      }).pipe(Effect.withSpan("services.admin.pipelineState")),
    ),
    // Operator-triggered settlement backfill. Re-drives unsettled receipts
    // through the same idempotent pipeline the periodic reconcile uses, but
    // uncapped/targeted and clearing the in-memory rejected set so receipts a
    // prior pass rejected (e.g. before a verification fix shipped) get a fresh
    // attempt. Idempotent — safe to run repeatedly. Operator-secret gated.
    //
    //   curl -XPOST -H "authorization: Bearer $SECRET" \
    //     -d '{"limit":5000,"providers":["did:plc:…"],"since":"2026-06-20T00:00:00Z"}' \
    //     .../xrpc/dev.cocore.admin.backfillSettlements
    //
    // Body (all optional): limit (default 5000, max 20000), clearRejected
    // (default true), providers[] (filter by receipt repo DID), since/until
    // (RFC3339, filter by receipt.completedAt). Returns a summary bucketed by
    // outcome + per-finding-code rejection reasons, so you can see exactly what
    // settled and why the rest couldn't (e.g. authorization-expired).
    HttpRouter.post(
      "/xrpc/dev.cocore.admin.backfillSettlements",
      Effect.gen(function* () {
        if (!authOk(yield* header("authorization"))) return err(401, { error: "unauthorized" });
        const parsed = yield* Effect.either(jsonBody);
        const b = (parsed._tag === "Right" ? parsed.right : {}) as Record<string, unknown>;
        const limit =
          typeof b["limit"] === "number" && b["limit"] > 0
            ? Math.min(Math.floor(b["limit"]), 20_000)
            : 5000;
        const clearRejected = b["clearRejected"] !== false;
        const providers = Array.isArray(b["providers"])
          ? (b["providers"].filter(
              (x) => typeof x === "string" && x.startsWith("did:"),
            ) as string[])
          : undefined;
        const since = typeof b["since"] === "string" ? Date.parse(b["since"]) : Number.NaN;
        const until = typeof b["until"] === "string" ? Date.parse(b["until"]) : Number.NaN;
        const needsTime = Number.isFinite(since) || Number.isFinite(until);
        const filter =
          (providers && providers.length > 0) || needsTime
            ? (rec: IndexedRecord): boolean => {
                if (providers && providers.length > 0 && !providers.includes(rec.repo))
                  return false;
                if (needsTime) {
                  const body = rec.body as { completedAt?: string } | null;
                  const t = body?.completedAt ? Date.parse(body.completedAt) : Number.NaN;
                  if (Number.isFinite(since) && !(t >= since)) return false;
                  if (Number.isFinite(until) && !(t <= until)) return false;
                }
                return true;
              }
            : undefined;
        const backfillOpts: ReconcileOptions = {
          limit,
          clearRejected,
          ...(filter ? { filter } : {}),
        };
        const summary = yield* Effect.promise(() =>
          pipeline.reconcileUnsettledReceipts(backfillOpts),
        );
        console.error(
          `backfill: scanned=${summary.scanned} attempted=${summary.attempted} settled=${summary.settled} rejected=${summary.rejected} resolveFailed=${summary.stillResolveFailed} clearedRejected=${summary.clearedRejected} byCode=${JSON.stringify(summary.rejectedByCode)}`,
        );
        return ok({ ok: true, summary });
      }).pipe(Effect.withSpan("services.admin.backfillSettlements")),
    ),
    // --- Token-ledger HTTP surface -------------------------------
    HttpRouter.get(
      "/xrpc/dev.cocore.exchange.getBalance",
      Effect.gen(function* () {
        const sp = yield* searchParams;
        const did = sp.get("did") || "";
        if (!did.startsWith("did:")) return err(400, { error: "invalid did" });
        // Use touchAndGetBalance so a balance read also (a) mints the one-time
        // onboarding grant on first touch and (b) applies any pending weekly
        // refresh. The old peekBalance read was a catch-22: balance read
        // returns 0, admission needs >=floor, grant only fires inside admission
        // or applyReceipt — neither of which a fresh user can reach with a 0
        // balance.
        const touched = ledger.touchAndGetBalance(did, ledgerPolicy);
        // If the grant just fired, publish the tokenGrant record onto the
        // exchange's PDS so the audit trail is durable beyond the local ledger
        // DB.
        if (touched.pendingGrant && Option.isSome(EXCHANGE_API_KEY)) {
          emitTokenGrantRecord(did, ledgerPolicy.tokenGrant, policyRef).catch((e) => {
            console.error(`grant: emit record failed for ${did}: ${(e as Error).message}`);
          });
        }
        return ok({
          did,
          balance: touched.balance,
          policy: {
            tokenGrant: ledgerPolicy.tokenGrant,
            tokenFloor: ledgerPolicy.tokenFloor,
            treasuryFeeBps: ledgerPolicy.treasuryFeeBps,
            weeklyRefreshAmount: ledgerPolicy.weeklyRefreshAmount,
            refreshCadenceMinutes: ledgerPolicy.refreshCadenceMinutes,
            patronageFractionBps: ledgerPolicy.patronageFractionBps,
            patronageCadenceDays: ledgerPolicy.patronageCadenceDays,
            // Back-compat for the earnings/jobs/machines dashboards that still
            // render USD-equivalents. Display only; not a real exchange rate.
            averagePricePerMTok: Math.floor(
              (TOKEN_RATE_INPUT_PER_MTOK + TOKEN_RATE_OUTPUT_PER_MTOK) / 2,
            ),
          },
        });
      }).pipe(Effect.withSpan("services.exchange.getBalance")),
    ),
    HttpRouter.get(
      "/xrpc/dev.cocore.exchange.leaderboard",
      Effect.gen(function* () {
        // Public leaderboard: largest wallets + biggest earners + biggest
        // spenders. Reads straight off the token ledger (the source of truth
        // for balances and receipt flows). System DIDs (treasury, exchange,
        // autoresponder) are excluded so the board reflects real members, not
        // the cooperative's own books.
        //
        // Memoized for LEADERBOARD_TTL_MS so a hot page doesn't re-scan the
        // ledger per request. The cache key folds in the requested limit.
        const sp = yield* searchParams;
        const limit = Math.min(Math.max(Number(sp.get("limit") ?? 20), 1), 100);
        const cached = readLeaderboardCache(limit);
        if (cached) return ok(cached);
        const board = ledger.leaderboard({
          limit,
          excludeDids: [TREASURY_DID, EXCHANGE_DID, AUTORESPOND_PROVIDER_DID],
        });
        writeLeaderboardCache(limit, board);
        return ok(board);
      }).pipe(Effect.withSpan("services.exchange.leaderboard")),
    ),
    HttpRouter.get(
      "/xrpc/dev.cocore.exchange.listEvents",
      Effect.gen(function* () {
        const sp = yield* searchParams;
        const did = sp.get("did") || "";
        if (!did.startsWith("did:")) return err(400, { error: "invalid did" });
        const limit = Math.min(Number(sp.get("limit") ?? 100), 500);
        return ok({ events: ledger.listEvents(did, limit) });
      }).pipe(Effect.withSpan("services.exchange.listEvents")),
    ),
    // Account-page activity bundle: lifetime per-kind aggregates (credited /
    // debited / patronage roll-ups) PLUS a newest-first recent feed, in one
    // round-trip. The summary is over the whole history (so the headline
    // numbers don't drift as the feed window scrolls); `recent` is "desc" so a
    // just-landed patronage rebate shows at the top instead of falling off the
    // end of an oldest-first window — the reason rebates were invisible before.
    HttpRouter.get(
      "/xrpc/dev.cocore.exchange.eventSummary",
      Effect.gen(function* () {
        const sp = yield* searchParams;
        const did = sp.get("did") || "";
        if (!did.startsWith("did:")) return err(400, { error: "invalid did" });
        const limit = Math.min(Number(sp.get("limit") ?? 100), 500);
        return ok({
          summary: ledger.summarizeEvents(did),
          recent: ledger.listEvents(did, limit, "desc"),
        });
      }).pipe(Effect.withSpan("services.exchange.eventSummary")),
    ),
    HttpRouter.post(
      "/xrpc/dev.cocore.exchange.checkAdmission",
      Effect.gen(function* () {
        const parsed = yield* Effect.either(jsonBody);
        if (parsed._tag === "Left") return err(400, { error: "body must be JSON" });
        const body = parsed.right as { did?: string; priceCeilingTokens?: number };
        if (!body.did || typeof body.priceCeilingTokens !== "number") {
          return err(400, { error: "missing did or priceCeilingTokens" });
        }
        return ok(ledger.checkAdmission(body.did, body.priceCeilingTokens, ledgerPolicy));
      }).pipe(Effect.withSpan("services.exchange.checkAdmission")),
    ),
    // --- Operator-only ---
    HttpRouter.post(
      "/xrpc/dev.cocore.exchange.distributePatronage",
      Effect.gen(function* () {
        if (!authOk(yield* header("authorization"))) return err(401, { error: "unauthorized" });
        const parsed = yield* Effect.either(jsonBody);
        if (parsed._tag === "Left") return err(400, { error: "body must be JSON" });
        const body = parsed.right as { start?: string; end?: string };
        // Default window: prior calendar month in UTC. The scheduler uses the
        // same default; this manual endpoint exists so an operator can backfill
        // a missed cycle or run a one-off out-of-cadence rebate.
        const now = new Date();
        const start = body.start ? new Date(body.start) : firstOfPriorMonthUtc(now);
        const end = body.end ? new Date(body.end) : firstOfMonthUtc(now);
        const result = ledger.distributePatronage(start, end, ledgerPolicy);
        // Best-effort emit one tokenPatronage record per recipient.
        if (Option.isSome(EXCHANGE_API_KEY) && policyRef && result.recipients.length > 0) {
          const ref = policyRef;
          const apiKey = Redacted.value(EXCHANGE_API_KEY.value);
          yield* Effect.promise(() =>
            emitPatronageRecords(
              EXCHANGE_API_BASE,
              apiKey,
              EXCHANGE_DID,
              ref,
              { start, end },
              result,
            ).catch((e) => {
              console.error(`patronage: emit records failed: ${(e as Error).message}`);
            }),
          );
        }
        return ok(result);
      }).pipe(Effect.withSpan("services.exchange.distributePatronage")),
    ),
    // GET: read-only audit, returns the report. POST: same, but also rebuilds
    // the balance cache if drift is detected. Both gated behind the internal
    // API key — even a read leaks the balance snapshot for every DID, and we'd
    // rather not expose that publicly.
    HttpRouter.get("/xrpc/dev.cocore.admin.reconcile", reconcileHandler(false)),
    HttpRouter.post("/xrpc/dev.cocore.admin.reconcile", reconcileHandler(true)),
    HttpRouter.post(
      "/xrpc/dev.cocore.admin.wipe",
      Effect.gen(function* () {
        if (!authOk(yield* header("authorization"))) return err(401, { error: "unauthorized" });
        if (!ALLOW_WIPE) {
          return err(403, {
            error: "wipe disabled; set COCORE_ALLOW_WIPE=1 on the services container",
          });
        }
        try {
          const counts: Record<string, number> = {};
          counts.records = store.db.prepare("DELETE FROM records").run().changes;
          if (store.db.prepare("SELECT 1 FROM sqlite_master WHERE name='cursor'").get()) {
            counts.cursor = store.db.prepare("DELETE FROM cursor").run().changes;
          }
          for (const table of [
            "token_balance",
            "token_event",
            "processed_receipt",
            "processed_period",
          ]) {
            if (ledgerDb.prepare("SELECT 1 FROM sqlite_master WHERE name=?").get(table)) {
              counts[table] = ledgerDb.prepare(`DELETE FROM ${table}`).run().changes;
            }
          }
          console.error(`admin.wipe: cleared ${JSON.stringify(counts)}`);
          return ok({ ok: true, counts });
        } catch (e) {
          return err(500, { error: (e as Error).message });
        }
      }).pipe(Effect.withSpan("services.admin.wipe")),
    ),
  );

  // Public bridge port: bridge routes + the PUBLIC AppView routes (appview.*
  // reads, account.*, /pds). /internal/* is NOT in `appview.public`, so it's
  // reachable only on the private :8081 listener (the console reaches it over
  // services.railway.internal) — keeping it off the public wire. Unmatched
  // paths 404 via the platform default.
  const bridgeApp = HttpRouter.concatAll(bridgeRouter, appview.public);
  const bridgeHandler = await makeNodeHandler(bridgeApp, { serviceName: "cocore-services" });
  const bridge = createServer(bridgeHandler);
  await new Promise<void>((r) => bridge.listen(PORT, r));
  console.error(`bridge: listening on :${PORT}`);

  await new Promise(() => {});
}

// ─── leaderboard cache ───────────────────────────────────────────
// Memoize per-limit for LEADERBOARD_TTL_MS (defined with the rest of
// the config above).
const leaderboardCache = new Map<number, { at: number; body: unknown }>();

function readLeaderboardCache(limit: number): unknown | null {
  const hit = leaderboardCache.get(limit);
  if (hit && Date.now() - hit.at < LEADERBOARD_TTL_MS) return hit.body;
  return null;
}

function writeLeaderboardCache(limit: number, body: unknown): void {
  leaderboardCache.set(limit, { at: Date.now(), body });
}

/** Extract the DID authority from an `at://<did>/<collection>/<rkey>` URI.
 *  Returns null when the URI isn't an at:// record URI whose authority is a
 *  DID. Used to bind a mirrored record's `repo` to its own URI, so an authed
 *  caller can't publish a record under one repo that claims to live in another
 *  (a record is only authoritative in its own repo). */
function didFromAtUri(uri: string): string | null {
  const m = /^at:\/\/(did:[^/]+)\//.exec(uri);
  return m ? (m[1] ?? null) : null;
}

function authOk(header: string | string[] | undefined): boolean {
  if (Option.isNone(INTERNAL_API_KEY)) return false;
  const key = Redacted.value(INTERNAL_API_KEY.value);
  if (typeof header !== "string") return false;
  const m = /^Bearer\s+(.+)$/.exec(header);
  if (!m) return false;
  const presented = m[1] ?? "";
  if (presented.length !== key.length) return false;
  return timingSafeEqual(Buffer.from(presented), Buffer.from(key));
}

function firstOfMonthUtc(d: Date): Date {
  return new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), 1, 0, 0, 0, 0));
}

function firstOfPriorMonthUtc(d: Date): Date {
  return new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() - 1, 1, 0, 0, 0, 0));
}

interface PatronageResult {
  treasuryBefore: number;
  recipients: Array<{ did: string; patronageScore: number; tokensCredited: number }>;
}

/** Publish a `dev.cocore.account.tokenGrant` record onto the
 *  exchange's PDS when the lazy onboarding grant fires for a fresh
 *  DID. The record is the durable audit trail that survives a local
 *  ledger DB wipe — anyone re-deriving balances offline from
 *  firehose history starts each DID at this amount.
 *
 *  Closures over the bridge's `exchangeDid`, `apiBase`, and `apiKey`
 *  via the call site; failures are logged and swallowed so a grant
 *  is still credited locally even if PDS publish flakes. */
async function emitTokenGrantRecord(
  recipientDid: string,
  amount: number,
  policyRef: { uri: string; cid: string } | undefined,
): Promise<void> {
  if (Option.isNone(EXCHANGE_API_KEY)) return;
  const apiKey = Redacted.value(EXCHANGE_API_KEY.value);
  if (!policyRef) {
    console.error(
      `grant: skipping PDS publish for ${recipientDid}: no active policyRef yet (bootstrap incomplete?)`,
    );
    return;
  }
  const record = {
    exchange: EXCHANGE_DID,
    recipient: recipientDid,
    amount,
    policy: { uri: policyRef.uri, cid: policyRef.cid },
    createdAt: new Date().toISOString(),
  };
  const r = await fetch(`${EXCHANGE_API_BASE.replace(/\/$/, "")}/api/pds/createRecord`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify({ collection: "dev.cocore.account.tokenGrant", record }),
  });
  if (!r.ok) {
    const body = await r.text().catch(() => "");
    throw new Error(`createRecord tokenGrant ${r.status}: ${body.slice(0, 300)}`);
  }
  console.error(`grant: published tokenGrant record for ${recipientDid} (${amount} tokens)`);
}

async function emitPatronageRecords(
  apiBase: string,
  apiKey: string,
  exchangeDid: string,
  policyRef: { uri: string; cid: string },
  period: { start: Date; end: Date },
  result: PatronageResult,
): Promise<void> {
  const totalPatronage = result.recipients.reduce((s, r) => s + r.patronageScore, 0);
  const periodLex = {
    start: period.start.toISOString(),
    end: period.end.toISOString(),
  };
  for (const r of result.recipients) {
    const record = {
      exchange: exchangeDid,
      recipient: r.did,
      period: periodLex,
      patronageScore: r.patronageScore,
      totalPatronage,
      tokensCredited: r.tokensCredited,
      treasuryBefore: result.treasuryBefore,
      policy: { uri: policyRef.uri, cid: policyRef.cid },
      createdAt: new Date().toISOString(),
    };
    await fetch(`${apiBase.replace(/\/$/, "")}/api/pds/createRecord`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({ collection: "dev.cocore.account.tokenPatronage", record }),
    });
  }
}

// Process-level crash guards. This is a single process running the AppView
// read API, the exchange, the bridge, the indexer, and the relay — without
// these, one stray unhandled rejection or uncaught exception in *any* of them
// (a malformed firehose event, a settlement publish that rejects, a bad
// timer) crashes the whole thing and takes XRPC serving down for every reader.
// We log content-safe (message + stack only; never request/record bodies) and
// keep serving: a genuinely wedged process is caught by the Railway
// healthcheck on /healthz, and splitting the read path from the writers (see
// docs/adr/0001-services-resilience.md) is the structural fix. Availability
// over purity — staying up degraded beats a slow boot-install restart loop.
process.on("unhandledRejection", (reason) => {
  const e = reason instanceof Error ? reason : new Error(String(reason));
  console.error(`services: unhandledRejection — ${e.message}\n${e.stack ?? ""}`);
});
process.on("uncaughtException", (e) => {
  console.error(`services: uncaughtException — ${e.message}\n${e.stack ?? ""}`);
});

main().catch((e) => {
  console.error("cocore-services: fatal", e);
  process.exit(1);
});
