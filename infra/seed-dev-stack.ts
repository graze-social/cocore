// Publishes a minimal, valid-looking dev fixture through the local bridge:
// one provider profile + paymentAuthorization → job → attestation → signed receipt.
// Used by `infra/smoke.ts` and `infra/bootstrap-dev.ts` (mise dev).
//
// Bootstrap runs `DEV_BOOTSTRAP_FIXTURES` tuples (spread across hours / models /
// machines) so the console earnings + machines dashboards have plausible series.

import { canonicalize } from "@cocore/sdk";

const EXCHANGE_DID_DEFAULT = "did:web:exchange.local";
export const DEV_SEED_DEFAULT_REQUESTER_DID = "did:plc:smoke-requester";
export const DEV_SEED_DEFAULT_PROVIDER_DID = "did:plc:smoke-provider";
const PROVIDER_DEFAULT = DEV_SEED_DEFAULT_PROVIDER_DID;
const PLACEHOLDER_CID = "bafyreigh2akiscaildc5sgz5wybizysiehxiv4dhpwwqouytxnvgkpkcaq";

export type SeedDevStackResult = {
  receiptUri: string;
  jobUri: string;
  authUri: string;
  attUri: string;
  providerUri: string;
  requesterDid: string;
  providerDid: string;
};

function rkey(): string {
  return [...crypto.getRandomValues(new Uint8Array(8))]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function fakeCid(_seed: string): string {
  return PLACEHOLDER_CID;
}

function hex32(seed: number): string {
  return seed.toString(16).padStart(64, "0");
}

function b64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

function rawToDer(rawSig: Uint8Array): Uint8Array {
  const r = encodeInt(rawSig.slice(0, 32));
  const s = encodeInt(rawSig.slice(32, 64));
  return new Uint8Array([0x30, r.length + s.length, ...r, ...s]);
}

function encodeInt(b: Uint8Array): number[] {
  let i = 0;
  while (i < b.length - 1 && b[i] === 0) i++;
  const trimmed = b.slice(i);
  const pad = (trimmed[0]! & 0x80) !== 0;
  return [0x02, trimmed.length + (pad ? 1 : 0), ...(pad ? [0x00] : []), ...trimmed];
}

async function publish(bridge: string, record: Record<string, unknown>): Promise<void> {
  const res = await fetch(`${bridge}/xrpc/dev.cocore.bridge.publish`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(process.env["COCORE_INTERNAL_API_KEY"]
        ? { authorization: `Bearer ${process.env["COCORE_INTERNAL_API_KEY"]}` }
        : {}),
    },
    body: JSON.stringify(record),
  });
  if (!res.ok) throw new Error(`publish ${record["uri"]}: ${res.status} ${await res.text()}`);
}

export type SeedDevStackOptions = {
  /** Default http://localhost:8080 */
  bridge?: string;
  exchangeDid?: string;
  requester?: string;
  provider?: string;
  /** Overrides `dev.cocore.compute.provider` display fields. */
  machineLabel?: string;
  chip?: string;
  ramGB?: number;
  gpuCores?: number;
  /**
   * Receipt `completedAt` / `startedAt` and attestation `attestedAt`.
   * Defaults: completed ≈ now − receiptCompletedHoursAgo, started a few seconds earlier,
   * attested one minute before completed.
   */
  receiptCompletedAt?: string;
  receiptStartedAt?: string;
  attestedAt?: string;
  /** Default 2. Ignored when `receiptCompletedAt` is set. */
  receiptCompletedHoursAgo?: number;
  /** Minor units for receipt `price.amount` when currency is USD. Default 50 ($0.50). */
  receiptPriceAmount?: number;
  /** Job + paymentAuthorization ceiling for this receipt (minor units USD). Must be >= receipt price. Default 100. */
  pricingCeilingAmount?: number;
  /** Job / receipt model id. Must appear in provider `supportedModels`. Default `"smoke-model"`. */
  model?: string;
  /** Receipt token counts. Default `{ in: 1, out: 1 }`. */
  tokens?: { in: number; out: number };
};

/** Extra tuples for local `pnpm dev:seed` so charts and model splits have points to render. First row is `{}` (legacy single-seed parity). */
export type DevBootstrapFixture = Omit<SeedDevStackOptions, "bridge">;

export const DEV_BOOTSTRAP_FIXTURES: DevBootstrapFixture[] = [
  {},
  {
    machineLabel: "seed-a100",
    chip: "NVIDIA A100 80GB",
    ramGB: 512,
    gpuCores: 108,
    receiptCompletedHoursAgo: 5,
    receiptPriceAmount: 62,
    model: "gpt-dev",
    tokens: { in: 2400, out: 910 },
    pricingCeilingAmount: 250,
  },
  {
    machineLabel: "seed-h100",
    chip: "NVIDIA H100",
    ramGB: 256,
    gpuCores: 132,
    receiptCompletedHoursAgo: 11,
    receiptPriceAmount: 88,
    model: "llama-70b-chat",
    tokens: { in: 800, out: 2048 },
    pricingCeilingAmount: 250,
  },
  {
    machineLabel: "seed-studio",
    chip: "Apple M3 Ultra",
    ramGB: 256,
    gpuCores: 76,
    receiptCompletedHoursAgo: 26,
    receiptPriceAmount: 45,
    model: "claude-dev",
    tokens: { in: 300, out: 420 },
    pricingCeilingAmount: 200,
  },
  {
    machineLabel: "seed-4090",
    chip: "NVIDIA RTX 4090",
    ramGB: 64,
    gpuCores: 128,
    receiptCompletedHoursAgo: 36,
    receiptPriceAmount: 38,
    model: "gpt-dev",
    tokens: { in: 610, out: 512 },
    pricingCeilingAmount: 200,
  },
  {
    machineLabel: "seed-l40s",
    chip: "NVIDIA L40S",
    ramGB: 96,
    gpuCores: 142,
    receiptCompletedHoursAgo: 52,
    receiptPriceAmount: 71,
    model: "smoke-model",
    tokens: { in: 50, out: 120 },
    pricingCeilingAmount: 250,
  },
  {
    machineLabel: "seed-m3max",
    chip: "Apple M3 Max",
    ramGB: 128,
    gpuCores: 40,
    receiptCompletedHoursAgo: 72,
    receiptPriceAmount: 29,
    model: "gpt-dev",
    tokens: { in: 400, out: 180 },
    pricingCeilingAmount: 120,
  },
  {
    machineLabel: "seed-rx7900",
    chip: "AMD RX 7900 XTX",
    ramGB: 32,
    gpuCores: 96,
    receiptCompletedHoursAgo: 110,
    receiptPriceAmount: 55,
    model: "llama-70b-chat",
    tokens: { in: 2000, out: 980 },
    pricingCeilingAmount: 200,
  },
  {
    machineLabel: "seed-a10g",
    chip: "NVIDIA A10G",
    ramGB: 64,
    gpuCores: 96,
    receiptCompletedHoursAgo: 140,
    receiptPriceAmount: 41,
    model: "claude-dev",
    tokens: { in: 780, out: 650 },
    pricingCeilingAmount: 200,
  },
  {
    machineLabel: "seed-3060ti",
    chip: "NVIDIA RTX 3060 Ti",
    ramGB: 32,
    gpuCores: 48,
    receiptCompletedHoursAgo: 190,
    receiptPriceAmount: 19,
    model: "smoke-model",
    tokens: { in: 128, out: 64 },
    pricingCeilingAmount: 100,
  },
  {
    machineLabel: "seed-h200",
    chip: "NVIDIA H200",
    ramGB: 192,
    gpuCores: 132,
    receiptCompletedHoursAgo: 240,
    receiptPriceAmount: 95,
    model: "gpt-dev",
    tokens: { in: 3000, out: 4096 },
    pricingCeilingAmount: 300,
  },
  {
    machineLabel: "seed-orin",
    chip: "NVIDIA Jetson Orin AGX",
    ramGB: 64,
    gpuCores: 2048,
    receiptCompletedHoursAgo: 300,
    receiptPriceAmount: 33,
    model: "llama-70b-chat",
    tokens: { in: 90, out: 200 },
    pricingCeilingAmount: 150,
  },
  {
    machineLabel: "seed-m2pro",
    chip: "Apple M2 Pro",
    ramGB: 32,
    gpuCores: 19,
    receiptCompletedHoursAgo: 360,
    receiptPriceAmount: 67,
    model: "claude-dev",
    tokens: { in: 412, out: 1200 },
    pricingCeilingAmount: 250,
  },
  {
    machineLabel: "seed-rtx6000ada",
    chip: "NVIDIA RTX 6000 Ada",
    ramGB: 128,
    gpuCores: 142,
    receiptCompletedHoursAgo: 420,
    receiptPriceAmount: 52,
    model: "smoke-model",
    tokens: { in: 200, out: 400 },
    pricingCeilingAmount: 200,
  },
];

/** One coherent tuple + provider row; bridge must already be listening. */
export async function seedDevStack(options: SeedDevStackOptions = {}): Promise<SeedDevStackResult> {
  const bridge = options.bridge ?? process.env["BRIDGE"] ?? "http://localhost:8080";
  const EXCHANGE_DID =
    options.exchangeDid ?? process.env["COCORE_EXCHANGE_DID"] ?? EXCHANGE_DID_DEFAULT;
  const REQUESTER =
    options.requester ??
    process.env["COCORE_SEED_REQUESTER_DID"]?.trim() ??
    process.env["DEV_SEED_DEFAULT_REQUESTER_DID"]?.trim() ??
    DEV_SEED_DEFAULT_REQUESTER_DID;
  const PROVIDER =
    options.provider ??
    process.env["COCORE_SEED_PROVIDER_DID"]?.trim() ??
    process.env["DEV_SEED_DEFAULT_PROVIDER_DID"]?.trim() ??
    PROVIDER_DEFAULT;

  const completedAt =
    options.receiptCompletedAt ??
    new Date(Date.now() - (options.receiptCompletedHoursAgo ?? 2) * 60 * 60 * 1000).toISOString();
  const startedAt =
    options.receiptStartedAt ?? new Date(new Date(completedAt).getTime() - 10_000).toISOString();
  const attestedAtIso =
    options.attestedAt ?? new Date(new Date(completedAt).getTime() - 60_000).toISOString();

  const machineLabel = options.machineLabel ?? "Dev seed machine";
  const chip = options.chip ?? "Apple M3";
  const ramGB = options.ramGB ?? 16;
  const providerExtras = options.gpuCores != null ? { gpuCores: options.gpuCores } : {};
  const modelId = options.model ?? "smoke-model";
  const tokenCounts = options.tokens ?? { in: 1, out: 1 };
  const receiptMinor =
    typeof options.receiptPriceAmount === "number" ? options.receiptPriceAmount : 50;
  const ceilingMinor = options.pricingCeilingAmount ?? 100;
  if (ceilingMinor < receiptMinor) {
    throw new Error(
      `pricingCeilingAmount (${ceilingMinor}) must be >= receipt price (${receiptMinor})`,
    );
  }
  const maxTokensOut = Math.max(tokenCounts.out, 100);

  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ]);
  const rawPub = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  const pubB64 = b64(rawPub.slice(1));

  const k = rkey();
  const providerRkey = rkey();
  const authUri = `at://${REQUESTER}/dev.cocore.compute.paymentAuthorization/${k}`;
  const jobUri = `at://${REQUESTER}/dev.cocore.compute.job/${k}`;
  const attUri = `at://${PROVIDER}/dev.cocore.compute.attestation/${k}`;
  const receiptUri = `at://${PROVIDER}/dev.cocore.compute.receipt/${k}`;
  const providerUri = `at://${PROVIDER}/dev.cocore.compute.provider/${providerRkey}`;

  await publish(bridge, {
    uri: providerUri,
    cid: fakeCid(`prov:${providerRkey}`),
    collection: "dev.cocore.compute.provider",
    repo: PROVIDER,
    rkey: providerRkey,
    body: {
      machineLabel,
      chip,
      ramGB,
      ...providerExtras,
      supportedModels: ["smoke-model", "gpt-dev", "llama-70b-chat", "claude-dev"],
      priceList: [
        {
          modelId: "smoke-model",
          inputPricePerMTok: 100,
          outputPricePerMTok: 200,
          currency: "USD",
        },
        {
          modelId: "gpt-dev",
          inputPricePerMTok: 120,
          outputPricePerMTok: 380,
          currency: "USD",
        },
        {
          modelId: "llama-70b-chat",
          inputPricePerMTok: 90,
          outputPricePerMTok: 290,
          currency: "USD",
        },
        {
          modelId: "claude-dev",
          inputPricePerMTok: 150,
          outputPricePerMTok: 450,
          currency: "USD",
        },
      ],
      encryptionPubKey: "XX",
      attestationPubKey: pubB64,
      trustLevel: "self-attested",
      createdAt: new Date().toISOString(),
    },
  });

  await publish(bridge, {
    uri: authUri,
    cid: fakeCid(`auth:${k}`),
    collection: "dev.cocore.compute.paymentAuthorization",
    repo: REQUESTER,
    rkey: k,
    body: {
      exchange: EXCHANGE_DID,
      ceiling: { amount: ceilingMinor, currency: "USD" },
      scope: "singleJob",
      nonce: rkey() + rkey(),
      expiresAt: "2030-01-01T00:00:00Z",
      createdAt: new Date().toISOString(),
    },
  });

  await publish(bridge, {
    uri: jobUri,
    cid: fakeCid(`job:${k}`),
    collection: "dev.cocore.compute.job",
    repo: REQUESTER,
    rkey: k,
    body: {
      model: modelId,
      inputCommitment: hex32(0xa),
      maxTokensOut,
      priceCeiling: { amount: ceilingMinor, currency: "USD" },
      acceptedTrustLevel: "self-attested",
      acceptedExchanges: [EXCHANGE_DID],
      paymentAuthorization: { uri: authUri, cid: fakeCid(`auth:${k}`) },
      nonce: rkey() + rkey(),
      expiresAt: "2030-01-01T00:00:00Z",
      createdAt: new Date().toISOString(),
    },
  });

  await publish(bridge, {
    uri: attUri,
    cid: fakeCid(`att:${k}`),
    collection: "dev.cocore.compute.attestation",
    repo: PROVIDER,
    rkey: k,
    body: {
      publicKey: pubB64,
      encryptionPubKey: "XX",
      chipName: "M-smk",
      hardwareModel: "Mac-smk",
      serialNumberHash: hex32(1),
      osVersion: "15",
      binaryHash: hex32(2),
      sipEnabled: true,
      secureBootEnabled: true,
      secureEnclaveAvailable: true,
      authenticatedRootEnabled: true,
      selfSignature: "self-sig-not-checked-in-this-test",
      attestedAt: attestedAtIso,
      expiresAt: "2030-01-01T00:00:00Z",
    },
  });

  const receiptBody = {
    job: { uri: jobUri, cid: fakeCid(`job:${k}`) },
    requester: REQUESTER,
    model: modelId,
    inputCommitment: hex32(0xa),
    outputCommitment: hex32(0xb),
    tokens: tokenCounts,
    startedAt,
    completedAt,
    price: { amount: receiptMinor, currency: "USD" },
    attestation: { uri: attUri, cid: fakeCid(`att:${k}`) },
  };
  const canonical = new TextEncoder().encode(canonicalize(receiptBody));
  const rawSig = new Uint8Array(
    await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, kp.privateKey, canonical),
  );
  const sigB64 = b64(rawToDer(rawSig));

  await publish(bridge, {
    uri: receiptUri,
    cid: fakeCid(`rcpt:${k}`),
    collection: "dev.cocore.compute.receipt",
    repo: PROVIDER,
    rkey: k,
    body: { ...receiptBody, enclaveSignature: sigB64 },
  });

  return {
    receiptUri,
    jobUri,
    authUri,
    attUri,
    providerUri,
    requesterDid: REQUESTER,
    providerDid: PROVIDER,
  };
}

/** Publish paymentAuthorization + job only (no receipt) for `/jobs` pending / expired fixtures. */
export type SeedJobWithoutReceiptOptions = {
  bridge?: string;
  /** Default: `COCORE_SEED_REQUESTER_DID` or smoke requester DID */
  requester?: string;
  exchangeDid?: string;
  kind: "pending" | "expired";
  model?: string;
  /** Ceiling minor units USD */
  pricingCeilingAmount?: number;
  /** Unique-ish input commitment hex (64) for the job */
  inputCommitmentSeed?: number;
};

export async function seedJobWithoutReceipt(
  options: SeedJobWithoutReceiptOptions,
): Promise<{ jobUri: string; authUri: string }> {
  const bridge = options.bridge ?? process.env["BRIDGE"] ?? "http://localhost:8080";
  const EXCHANGE_DID =
    options.exchangeDid ?? process.env["COCORE_EXCHANGE_DID"] ?? EXCHANGE_DID_DEFAULT;
  const REQUESTER =
    options.requester ??
    process.env["COCORE_SEED_REQUESTER_DID"]?.trim() ??
    process.env["DEV_SEED_DEFAULT_REQUESTER_DID"]?.trim() ??
    DEV_SEED_DEFAULT_REQUESTER_DID;

  const k = rkey();
  const ceilingMinor = options.pricingCeilingAmount ?? 180;
  const modelId = options.model ?? "gpt-dev";
  const seed = options.inputCommitmentSeed ?? Math.floor(Math.random() * 0xffff_ffff);
  const authUri = `at://${REQUESTER}/dev.cocore.compute.paymentAuthorization/${k}`;
  const jobUri = `at://${REQUESTER}/dev.cocore.compute.job/${k}`;
  const now = Date.now();
  const expiresAtIso =
    options.kind === "expired"
      ? new Date(now - 5 * 24 * 60 * 60 * 1000).toISOString()
      : "2035-06-01T00:00:00.000Z";

  await publish(bridge, {
    uri: authUri,
    cid: fakeCid(`auth:${k}`),
    collection: "dev.cocore.compute.paymentAuthorization",
    repo: REQUESTER,
    rkey: k,
    body: {
      exchange: EXCHANGE_DID,
      ceiling: { amount: ceilingMinor, currency: "USD" },
      scope: "singleJob",
      nonce: rkey() + rkey(),
      expiresAt: "2035-01-01T00:00:00.000Z",
      createdAt: new Date(now).toISOString(),
    },
  });

  await publish(bridge, {
    uri: jobUri,
    cid: fakeCid(`job:${k}`),
    collection: "dev.cocore.compute.job",
    repo: REQUESTER,
    rkey: k,
    body: {
      model: modelId,
      inputCommitment: hex32(seed),
      maxTokensOut: 2048,
      priceCeiling: { amount: ceilingMinor, currency: "USD" },
      acceptedTrustLevel: "self-attested",
      acceptedExchanges: [EXCHANGE_DID],
      paymentAuthorization: { uri: authUri, cid: fakeCid(`auth:${k}`) },
      nonce: rkey() + rkey(),
      expiresAt: expiresAtIso,
      createdAt: new Date(
        now - (options.kind === "expired" ? 14 : 0) * 24 * 60 * 60 * 1000,
      ).toISOString(),
    },
  });

  return { jobUri, authUri };
}

/** Extra cocore directory rows for `/friends` add/remove testing.
 *
 * Each entry is a synthetic `did:web:` repo with a `dev.cocore.account.profile`
 * so `listAccounts` surfaces them. They are **not** on Bluesky; use **Discover
 * cocore members** to add them (the handle box uses `getProfile`, which 404s
 * for these DIDs/handles). Handles share the `friendtest.` prefix so typeahead
 * can find them once you have any directory hits. */
export const DEV_DIRECTORY_FRIEND_FIXTURES: ReadonlyArray<{
  did: string;
  handle: string;
  displayName: string;
}> = [
  {
    did: "did:web:friendtest-alpha.cocore.invalid",
    handle: "friendtest.alpha.cocore.invalid",
    displayName: "Dev friend Alpha",
  },
  {
    did: "did:web:friendtest-beta.cocore.invalid",
    handle: "friendtest.beta.cocore.invalid",
    displayName: "Dev friend Beta",
  },
  {
    did: "did:web:friendtest-gamma.cocore.invalid",
    handle: "friendtest.gamma.cocore.invalid",
    displayName: "Dev friend Gamma",
  },
];

/** Publishes {@link DEV_DIRECTORY_FRIEND_FIXTURES} through the dev bridge. */
export async function seedDirectoryFriendProfiles(options?: { bridge?: string }): Promise<void> {
  const bridge = options?.bridge ?? process.env["BRIDGE"] ?? "http://localhost:8080";
  const now = new Date().toISOString();
  for (const f of DEV_DIRECTORY_FRIEND_FIXTURES) {
    await publish(bridge, {
      uri: `at://${f.did}/dev.cocore.account.profile/self`,
      cid: fakeCid(`profile:${f.did}`),
      collection: "dev.cocore.account.profile",
      repo: f.did,
      rkey: "self",
      body: {
        handle: f.handle,
        displayName: f.displayName,
        createdAt: now,
      },
    });
  }
}
