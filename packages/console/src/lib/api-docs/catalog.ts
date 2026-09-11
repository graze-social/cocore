import type { loadApiDocsFixtures } from "./fixtures";

export type ApiDocsAuthClass = "none" | "required" | "optional-did";

export type ApiDocsCatalogEntry = {
  nsid: string;
  method: "query" | "procedure";
  section: string;
  description: string;
  auth: ApiDocsAuthClass;
  status: "shipped" | "planned";
  /** Which service hosts the method. "appview" → `<appview>/xrpc/<nsid>`
   *  (the public AppView XRPC API); "console" → `<console>/api/xrpc/<nsid>`
   *  (still served by the console). Defaults to "appview". */
  host?: "appview" | "console";
  params: Array<{ name: string; type: string; required?: boolean }>;
  example: {
    autoRun: boolean;
    params?:
      | Record<string, string>
      | ((fixtures: ReturnType<typeof loadApiDocsFixtures>) => Record<string, string>);
    body?:
      | Record<string, unknown>
      | ((fixtures: ReturnType<typeof loadApiDocsFixtures>) => Record<string, unknown>);
  };
};

interface EntryOpts {
  host?: "appview" | "console";
  status?: "shipped" | "planned";
}

function makeEntry(
  method: "query" | "procedure",
  nsid: string,
  section: string,
  description: string,
  auth: ApiDocsAuthClass,
  params: ApiDocsCatalogEntry["params"],
  example: ApiDocsCatalogEntry["example"],
  opts?: EntryOpts,
): ApiDocsCatalogEntry {
  return {
    nsid,
    method,
    section,
    description,
    auth,
    status: opts?.status ?? "shipped",
    params,
    example,
    ...(opts?.host ? { host: opts.host } : {}),
  };
}

function q(
  nsid: string,
  section: string,
  description: string,
  auth: ApiDocsAuthClass,
  params: ApiDocsCatalogEntry["params"],
  example: ApiDocsCatalogEntry["example"],
  opts?: EntryOpts,
): ApiDocsCatalogEntry {
  return makeEntry("query", nsid, section, description, auth, params, example, opts);
}

function p(
  nsid: string,
  section: string,
  description: string,
  auth: ApiDocsAuthClass,
  params: ApiDocsCatalogEntry["params"],
  example: ApiDocsCatalogEntry["example"],
  opts?: EntryOpts,
): ApiDocsCatalogEntry {
  return makeEntry("procedure", nsid, section, description, auth, params, example, opts);
}

export const API_DOCS_CATALOG: Array<ApiDocsCatalogEntry> = [
  q(
    "dev.cocore.compute.listProviders",
    "Directory",
    "List indexed provider records (`dev.cocore.compute.provider`).",
    "none",
    [],
    { autoRun: true, params: {} },
  ),
  q(
    "dev.cocore.account.listProfiles",
    "Directory",
    "List indexed account profile records (`dev.cocore.account.profile`).",
    "none",
    [],
    { autoRun: true, params: {} },
  ),
  q(
    "dev.cocore.account.getProfile",
    "Directory",
    "Full profile payload for one DID — machines, activity counts, and social context.",
    "none",
    [{ name: "did", type: "did", required: true }],
    {
      autoRun: true,
      params: (f) => ({ did: f.providerDid }),
    },
  ),
  q(
    "dev.cocore.account.listAccounts",
    "Directory",
    "Discovery directory of signed-up DIDs with profile and provider counts.",
    "none",
    [
      { name: "limit", type: "integer" },
      { name: "offset", type: "integer" },
      { name: "sortBy", type: "string" },
      { name: "providersOnly", type: "boolean" },
      { name: "viewerDid", type: "did" },
      { name: "excludeViewerFriends", type: "boolean" },
      { name: "q", type: "string" },
    ],
    {
      autoRun: true,
      params: (f) => ({ limit: "12", q: f.listQuery }),
    },
  ),
  q(
    "dev.cocore.account.listIncomingFriends",
    "Social graph",
    "Friend records whose subject is the queried DID.",
    "none",
    [
      { name: "did", type: "did", required: true },
      { name: "limit", type: "integer" },
    ],
    {
      autoRun: true,
      params: (f) => ({ did: f.requesterDid, limit: "10" }),
    },
  ),
  q(
    "dev.cocore.account.listFriendEdges",
    "Social graph",
    "Every directed trust edge in the indexed network (friender → subject).",
    "none",
    [{ name: "limit", type: "integer" }],
    { autoRun: true, params: { limit: "100" } },
  ),
  q(
    "dev.cocore.compute.listReceipts",
    "Compute index",
    "Indexed receipt records with optional provider, requester, or job filters.",
    "none",
    [
      { name: "provider", type: "did" },
      { name: "requester", type: "did" },
      { name: "job", type: "at-uri" },
    ],
    {
      autoRun: true,
      params: (f) => ({ provider: f.providerDid }),
    },
  ),
  q(
    "dev.cocore.compute.listJobs",
    "Compute index",
    "Indexed job records for a requester DID.",
    "none",
    [{ name: "requester", type: "did", required: true }],
    {
      autoRun: true,
      params: (f) => ({ requester: f.requesterDid }),
    },
  ),
  q(
    "dev.cocore.compute.listSettlements",
    "Compute index",
    "Indexed settlement records with optional receipt or requester filters.",
    "none",
    [
      { name: "receipt", type: "at-uri" },
      { name: "requester", type: "did" },
    ],
    {
      autoRun: true,
      params: (f) => ({ receipt: f.receiptUri }),
    },
  ),
  q(
    "dev.cocore.compute.verifyReceipt",
    "Verification",
    "Structural + cryptographic verification of an indexed receipt against its job and attestation.",
    "none",
    [{ name: "uri", type: "at-uri", required: true }],
    {
      autoRun: false,
      params: (f) => ({ uri: f.receiptUri }),
    },
  ),
  q(
    "dev.cocore.compute.verifySettlement",
    "Verification",
    "Verify a settlement chain against indexed receipt and authorization records.",
    "none",
    [{ name: "uri", type: "at-uri", required: true }],
    {
      autoRun: false,
      params: (f) => ({ uri: f.settlementUri }),
    },
  ),
  q(
    "dev.cocore.compute.modelActivity",
    "Analytics",
    "Aggregate receipt activity per model across rolling time windows.",
    "none",
    [],
    { autoRun: true, params: {} },
  ),
  q(
    "dev.cocore.compute.latency",
    "Analytics",
    "Network latency rollup derived from indexed receipt timestamps.",
    "none",
    [],
    { autoRun: true, params: {} },
  ),

  // --- API keys (AppView; AT Protocol service auth via #cocore_appview) ---
  p(
    "dev.cocore.account.createApiKey",
    "API keys",
    "Mint a new API key for the authenticated account. The full secret is returned exactly once. Authenticate via AT Protocol service auth — your PDS proxies the call to the AppView's `#cocore_appview` service.",
    "required",
    [
      { name: "name", type: "string", required: true },
      { name: "expiresAt", type: "datetime" },
    ],
    { autoRun: false, body: { name: "my-laptop" } },
  ),
  q(
    "dev.cocore.account.listApiKeys",
    "API keys",
    "List the authenticated account's API keys, newest first. Secrets are never returned.",
    "required",
    [],
    { autoRun: false },
  ),
  p(
    "dev.cocore.account.revokeApiKey",
    "API keys",
    "Revoke one of your API keys. The key stops authenticating immediately but the row is kept (revoked) for audit.",
    "required",
    [{ name: "id", type: "string", required: true }],
    { autoRun: false, body: { id: "<key-id>" } },
  ),
  p(
    "dev.cocore.account.deleteApiKey",
    "API keys",
    "Hard-delete one of your API keys (no audit-trail recovery).",
    "required",
    [{ name: "id", type: "string", required: true }],
    { autoRun: false, body: { id: "<key-id>" } },
  ),

  // --- Inference (served by the AppView; the console route forwards) ---
  p(
    "dev.cocore.inference.dispatch",
    "Inference",
    "Submit an inference request and stream the result as Server-Sent Events: the job + payment authorization are published, then plaintext output chunks until completion.",
    "required",
    [
      { name: "model", type: "string", required: true },
      { name: "prompt", type: "string", required: true },
      { name: "maxTokensOut", type: "integer", required: true },
      { name: "priceCeiling", type: "object", required: true },
      { name: "targetProviderDid", type: "did" },
    ],
    {
      autoRun: false,
      body: {
        model: "llama3.2",
        prompt: "Say hello.",
        maxTokensOut: 256,
        priceCeiling: { amount: 1000, currency: "CC" },
      },
    },
    { host: "appview" },
  ),

  // --- Device pairing (served by the AppView; the console route forwards) ---
  p(
    "dev.cocore.devicePair.start",
    "Device pairing",
    "Begin a device-pairing flow (OAuth device-authorization style). Returns a `deviceId` plus a short `userCode` to approve at the verification URI. An application connecting on a user's behalf passes `appDid` (its `dev.cocore.app.registration` record names it), `keyName`, and a registered `returnUrl`.",
    "none",
    [
      { name: "appDid", type: "string", required: false },
      { name: "keyName", type: "string", required: false },
      { name: "returnUrl", type: "string", required: false },
    ],
    {
      autoRun: false,
      body: {
        appDid: "did:plc:yourapp",
        keyName: "Your App",
        returnUrl: "https://yourapp.example/settings/connections",
      },
    },
    { host: "appview" },
  ),
  q(
    "dev.cocore.devicePair.describe",
    "Device pairing",
    "Describe a pending pairing by `userCode`: the requesting app's verified identity (`app`), the key name, the return URL, status, and time left. Public; never returns the `deviceId`.",
    "none",
    [{ name: "userCode", type: "string", required: true }],
    { autoRun: false, params: { userCode: "K7PX2M4Q" } },
    { host: "appview" },
  ),
  q(
    "dev.cocore.devicePair.poll",
    "Device pairing",
    "Poll a pairing attempt by `deviceId` until it is approved (then returns the granted session), denied, expired, or consumed.",
    "none",
    [{ name: "deviceId", type: "string", required: true }],
    { autoRun: false, params: {} },
    { host: "appview" },
  ),
  p(
    "dev.cocore.devicePair.confirm",
    "Device pairing",
    "Approve or deny a pending pairing attempt, identified by the `userCode` the device displayed. Called from the verification UI by a signed-in user.",
    "required",
    [
      { name: "userCode", type: "string", required: true },
      { name: "decision", type: "string", required: true },
    ],
    { autoRun: false, body: { userCode: "ABCD-1234", decision: "approve" } },
    { host: "appview" },
  ),
];

export function catalogEntryByNsid(nsid: string): ApiDocsCatalogEntry | undefined {
  return API_DOCS_CATALOG.find((entry) => entry.nsid === nsid);
}

export function autoRunnableCatalogEntries(): Array<ApiDocsCatalogEntry> {
  return API_DOCS_CATALOG.filter((entry) => entry.status === "shipped" && entry.example.autoRun);
}

export const API_DOCS_SECTIONS = [
  "Directory",
  "Social graph",
  "Compute index",
  "Verification",
  "Analytics",
  "API keys",
  "Inference",
  "Device pairing",
] as const;
