// Server side of Apple Managed Device Attestation (MDA) — the
// coordinator endpoints that drive guided MDM enrollment for the
// "Secure Mode" upgrade. The live backend (proven end-to-end 2026-06-20)
// is NanoMDM + step-ca on Railway; this module is the HTTP surface the
// provider app's wizard calls, templating per-device profiles against
// that backend and capturing the Apple attestation chain.
//
// ENROLLMENT MODEL (SCEP + bundled ACME attestation)
// --------------------------------------------------
// `enroll-profile` mints ONE per-device .mobileconfig that, on install:
//   1. installs step-ca's root as a trust anchor (so the Mac trusts
//      step-ca's TLS for SCEP + ACME),
//   2. enrolls a device identity via SCEP against step-ca's `cocore-scep`
//      provisioner (each device generates its own key; no CA-issuing
//      secret ever lives in the console, no PKCS12 packing),
//   3. enrolls the Mac into NanoMDM (`com.apple.mdm`, AccessRights=3,
//      SignMessage=true — the device signs check-ins via Mdm-Signature
//      since Railway's TLS-terminating edge strips client certs), and
//   4. (when COCORE_MDM_ACME_URL is set) runs ACME `device-attest-01`
//      against step-ca's `cocore-attest` provisioner via a per-serial
//      `com.apple.security.acme` payload — so the Mac hardware-attests on
//      install, no separate MDM push required. step-ca validates the
//      Apple attestation and forwards the captured x5c chain to the
//      ingest endpoint, keyed by serial.
//
// FAIL-CLOSED: when the SCEP/MDM backend env isn't configured,
// `buildEnrollmentProfile` returns null and the route answers 503 — we
// never hand a Mac a structurally-broken profile (the old empty-PKCS12
// stub is gone).
//
// REQUIRED ENV (Secure Mode is unavailable until these are set on the
// console service; see infra/mdm/README.md for the values)
// ----------------------------------------------------------------------
//   COCORE_MDM_SCEP_URL        step-ca SCEP URL, e.g.
//                              https://<step-ca-host>/scep/cocore-scep
//   COCORE_MDM_SCEP_NAME       SCEP CA-IDENT / provisioner name
//                              (default "cocore-scep").
//   COCORE_MDM_SCEP_CHALLENGE  SCEP shared-secret challenge (sensitive).
//   COCORE_MDM_SERVER_URL      NanoMDM MDM ServerURL (the device check-in
//                              URL embedded in the MDM payload).
//   COCORE_MDM_CHECKIN_URL     MDM CheckInURL (defaults to ServerURL).
//   COCORE_MDM_TOPIC           APNs push topic (the MDM payload Topic,
//                              com.apple.mgmt.External.<uuid>).
//   COCORE_MDM_ROOT_CA_PEM     step-ca root cert (PEM) — trust anchor.
//   COCORE_MDM_INTERMEDIATE_CA_PEM  step-ca intermediate (PEM), optional.
//   COCORE_MDM_ACME_URL        step-ca ACME directory for cocore-attest,
//                              e.g. https://<host>/acme/cocore-attest/directory.
//                              When set, attestation is bundled into the
//                              enrollment profile (recommended).
//   COCORE_NANOMDM_URL         NanoMDM base URL (for the push refresh path
//                              in push-attestation). Optional when
//                              attestation is bundled.
//   COCORE_NANOMDM_API_KEY     NanoMDM API key (HTTP Basic password).
//   COCORE_MDM_CHAIN_STORE_URL Optional external chain store (fallback to
//                              the console-local SQLite store).
//   COCORE_MDM_CHAIN_INGEST_KEY Bearer secret step-ca's attestation
//                              webhook presents to POST captured chains.
//   COCORE_MDM_SIGNING_CERT_PEM / _KEY_PEM  CMS-sign the profile (TODO).

import { createHash } from "node:crypto";

import { resolveBearerKey, type ResolvedKey } from "@/lib/api-keys.server.ts";
import { getAttestationChain, putAttestationChain } from "@/lib/mdm-chain-store.server.ts";

// ---------------------------------------------------------------------------
// Auth — same bearer-API-key surface every other /api/agent/* route uses.
// ---------------------------------------------------------------------------

export type MdmAuthResult = { ok: true; caller: ResolvedKey } | { ok: false; response: Response };

function readBearer(request: Request): string | null {
  const h = request.headers.get("authorization");
  if (!h) return null;
  const m = /^Bearer\s+(.+)$/i.exec(h);
  return m ? m[1]!.trim() : null;
}

export function mdmJson(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

/** Authenticate an agent caller via its bearer API key — identical
 *  posture to /api/agent/whoami and /api/agent/status. Returns the
 *  resolved key on success, or a ready-to-send 401 Response. */
export function authenticateAgent(request: Request): MdmAuthResult {
  const bearer = readBearer(request);
  if (!bearer) {
    return { ok: false, response: mdmJson({ error: "missing Authorization: Bearer header" }, 401) };
  }
  const caller = resolveBearerKey(bearer);
  if (!caller) {
    return { ok: false, response: mdmJson({ error: "invalid API key" }, 401) };
  }
  return { ok: true, caller };
}

/** Authenticate step-ca's attestation webhook (the chain ingest). This
 *  caller is NOT an agent — it's our own CA infra — so it presents the
 *  shared COCORE_MDM_CHAIN_INGEST_KEY as a bearer. Constant-time compare;
 *  401 when unset (fail-closed — never accept an unauthenticated chain). */
export function authenticateChainIngest(request: Request): boolean {
  const expected = env("COCORE_MDM_CHAIN_INGEST_KEY");
  if (!expected) return false;
  const got = readBearer(request);
  if (!got || got.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= got.charCodeAt(i) ^ expected.charCodeAt(i);
  return diff === 0;
}

// ---------------------------------------------------------------------------
// Validation helpers.
// ---------------------------------------------------------------------------

/** Apple device serials are alphanumeric (historically 10–12 chars; the
 *  newer randomized serials are longer). Keep this permissive but strict
 *  enough to reject obvious garbage / injection into the templated
 *  profile. */
const SERIAL_RE = /^[A-Za-z0-9]{8,24}$/;

/** A UDID is a 40-hex string (legacy) or a UUID-shaped string on newer
 *  hardware. Accept both forms. */
const UDID_RE =
  /^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$/;

export function isValidSerial(v: unknown): v is string {
  return typeof v === "string" && SERIAL_RE.test(v);
}

export function isValidUdid(v: unknown): v is string {
  return typeof v === "string" && UDID_RE.test(v);
}

function env(name: string): string | undefined {
  const v = process.env[name];
  return v && v.length > 0 ? v : undefined;
}

/** XML-escape a value going into the .mobileconfig. Serials are already
 *  alphanumeric, but URLs / SCEP challenge / names are operator-supplied,
 *  so escape everything defensively. */
function xmlEscape(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

/** Base64 of a PEM cert's DER body — the form a `com.apple.security.*`
 *  PayloadContent expects. Strips PEM armor and re-emits the inner
 *  base64 (already DER-base64). Returns "" when no PEM is configured. */
function pemBodyB64(pem: string | undefined): string {
  if (!pem) return "";
  return pem
    .replace(/-----BEGIN [^-]+-----/g, "")
    .replace(/-----END [^-]+-----/g, "")
    .replace(/\s+/g, "");
}

// ---------------------------------------------------------------------------
// Secure Mode config — resolved from env, fail-closed when incomplete.
// ---------------------------------------------------------------------------

interface SecureMdmConfig {
  scepUrl: string;
  scepName: string;
  scepChallenge: string;
  mdmServerUrl: string;
  checkInUrl: string;
  topic: string;
  rootCaB64: string;
  intermediateCaB64: string;
  /** ACME directory URL for cocore-attest; null disables bundled attestation. */
  acmeUrl: string | null;
}

export type SecureMdmConfigResult =
  | { ok: true; config: SecureMdmConfig }
  | { ok: false; missing: string[] };

/** Resolve the Secure Mode MDM config from env, or report which required
 *  keys are missing so the route can answer 503 with a clear reason. */
export function secureMdmConfig(): SecureMdmConfigResult {
  const missing: string[] = [];
  const scepUrl = env("COCORE_MDM_SCEP_URL");
  if (!scepUrl) missing.push("COCORE_MDM_SCEP_URL");
  const scepChallenge = env("COCORE_MDM_SCEP_CHALLENGE");
  if (!scepChallenge) missing.push("COCORE_MDM_SCEP_CHALLENGE");
  const mdmServerUrl = env("COCORE_MDM_SERVER_URL");
  if (!mdmServerUrl) missing.push("COCORE_MDM_SERVER_URL");
  const topic = env("COCORE_MDM_TOPIC");
  if (!topic) missing.push("COCORE_MDM_TOPIC");
  const rootPem = env("COCORE_MDM_ROOT_CA_PEM");
  if (!rootPem) missing.push("COCORE_MDM_ROOT_CA_PEM");

  if (missing.length > 0) return { ok: false, missing };

  return {
    ok: true,
    config: {
      scepUrl: scepUrl!,
      scepName: env("COCORE_MDM_SCEP_NAME") ?? "cocore-scep",
      scepChallenge: scepChallenge!,
      mdmServerUrl: mdmServerUrl!,
      checkInUrl: env("COCORE_MDM_CHECKIN_URL") ?? mdmServerUrl!,
      topic: topic!,
      rootCaB64: pemBodyB64(rootPem),
      intermediateCaB64: pemBodyB64(env("COCORE_MDM_INTERMEDIATE_CA_PEM")),
      acmeUrl: env("COCORE_MDM_ACME_URL") ?? null,
    },
  };
}

/** Whether attestation is bundled into the enrollment profile (vs. pushed
 *  separately via NanoMDM). True iff a cocore-attest ACME URL is set. */
export function attestationIsBundled(): boolean {
  return Boolean(env("COCORE_MDM_ACME_URL"));
}

// ---------------------------------------------------------------------------
// enroll-profile — mint a per-device SCEP+MDM(+ACME) .mobileconfig.
// ---------------------------------------------------------------------------

export interface EnrollProfileResult {
  /** The .mobileconfig body. */
  profile: string;
  /** Whether the profile was CMS-signed (false until signing is wired). */
  signed: boolean;
  /** The per-enrollment id callers thread into push-attestation. */
  enrollmentId: string;
}

function rootTrustPayload(b64: string, serial: string, uuid: string): string {
  return `    <dict>
      <key>PayloadType</key><string>com.apple.security.root</string>
      <key>PayloadIdentifier</key><string>dev.cocore.mdm.trust.root.${serial}</string>
      <key>PayloadUUID</key><string>${uuid}</string>
      <key>PayloadVersion</key><integer>1</integer>
      <key>PayloadDisplayName</key><string>co/core Trust Root</string>
      <key>PayloadCertificateFileName</key><string>cocore-root-ca.cer</string>
      <key>PayloadContent</key>
      <data>${b64}</data>
    </dict>`;
}

function intermediateTrustPayload(b64: string, serial: string, uuid: string): string {
  return `    <dict>
      <key>PayloadType</key><string>com.apple.security.pkcs1</string>
      <key>PayloadIdentifier</key><string>dev.cocore.mdm.trust.intermediate.${serial}</string>
      <key>PayloadUUID</key><string>${uuid}</string>
      <key>PayloadVersion</key><integer>1</integer>
      <key>PayloadDisplayName</key><string>co/core Trust Intermediate</string>
      <key>PayloadCertificateFileName</key><string>cocore-intermediate-ca.cer</string>
      <key>PayloadContent</key>
      <data>${b64}</data>
    </dict>`;
}

function scepIdentityPayload(c: SecureMdmConfig, serial: string, uuid: string): string {
  // Each device generates its own key and enrolls it against step-ca's
  // SCEP provisioner — no CA-issuing secret or PKCS12 in the console.
  return `    <dict>
      <key>PayloadType</key><string>com.apple.security.scep</string>
      <key>PayloadIdentifier</key><string>dev.cocore.mdm.scep.${serial}</string>
      <key>PayloadUUID</key><string>${uuid}</string>
      <key>PayloadVersion</key><integer>1</integer>
      <key>PayloadDisplayName</key><string>co/core Device Identity (SCEP)</string>
      <key>PayloadContent</key>
      <dict>
        <key>URL</key><string>${xmlEscape(c.scepUrl)}</string>
        <key>Name</key><string>${xmlEscape(c.scepName)}</string>
        <key>Subject</key>
        <array>
          <array><array><string>CN</string><string>${serial}</string></array></array>
        </array>
        <key>Challenge</key><string>${xmlEscape(c.scepChallenge)}</string>
        <key>Key Type</key><string>RSA</string>
        <key>Key Usage</key><integer>5</integer>
        <key>Keysize</key><integer>2048</integer>
        <key>Retries</key><integer>3</integer>
        <key>RetryDelay</key><integer>10</integer>
      </dict>
    </dict>`;
}

function mdmPayload(
  c: SecureMdmConfig,
  serial: string,
  uuid: string,
  identityUuid: string,
): string {
  return `    <dict>
      <key>PayloadType</key><string>com.apple.mdm</string>
      <key>PayloadIdentifier</key><string>dev.cocore.mdm.payload.${serial}</string>
      <key>PayloadUUID</key><string>${uuid}</string>
      <key>PayloadVersion</key><integer>1</integer>
      <key>PayloadDisplayName</key><string>co/core Device Management</string>
      <key>IdentityCertificateUUID</key><string>${identityUuid}</string>
      <key>Topic</key><string>${xmlEscape(c.topic)}</string>
      <key>ServerURL</key><string>${xmlEscape(c.mdmServerUrl)}</string>
      <key>CheckInURL</key><string>${xmlEscape(c.checkInUrl)}</string>
      <key>AccessRights</key><integer>3</integer>
      <key>SignMessage</key><true/>
      <key>CheckOutWhenRemoved</key><true/>
      <!-- Newer macOS rejects an MDM payload that doesn't declare it supports
           the per-user connection channel ("Profile installation failed: MDM
           payload is missing ServerCapabilities key..."). NanoMDM serves the
           user channel, so advertise it. -->
      <key>ServerCapabilities</key>
      <array><string>com.apple.mdm.per-user-connections</string></array>
    </dict>`;
}

/** Per-serial ACME `device-attest-01` payload. ClientIdentifier AND the
 *  Subject CN MUST both equal the device serial — step-ca matches them
 *  against the hardware identifiers inside Apple's attestation statement
 *  (a mismatch fails with badAttestationStatement / badCSR). */
function acmeAttestPayload(acmeUrl: string, serial: string, uuid: string): string {
  return `    <dict>
      <key>PayloadType</key><string>com.apple.security.acme</string>
      <key>PayloadIdentifier</key><string>dev.cocore.mdm.acme.${serial}</string>
      <key>PayloadUUID</key><string>${uuid}</string>
      <key>PayloadVersion</key><integer>1</integer>
      <key>PayloadDisplayName</key><string>co/core Device Attestation (ACME)</string>
      <key>DirectoryURL</key><string>${xmlEscape(acmeUrl)}</string>
      <key>ClientIdentifier</key><string>${serial}</string>
      <key>KeyType</key><string>ECSECPrimeRandom</string>
      <key>KeySize</key><integer>384</integer>
      <key>HardwareBound</key><true/>
      <key>Attest</key><true/>
      <key>KeyIsExtractable</key><false/>
      <key>UsageFlags</key><integer>5</integer>
      <key>Subject</key>
      <array>
        <array><array><string>CN</string><string>${serial}</string></array></array>
        <array><array><string>O</string><string>Graze Social PBC</string></array></array>
      </array>
    </dict>`;
}

/** Build a per-device enrollment .mobileconfig for {serial, udid}, or
 *  null when the Secure Mode backend isn't configured (route → 503).
 *
 *  CMS signing is the remaining ops seam (TODO below); today we return
 *  the templated profile unsigned (it installs with the standard
 *  "unverified profile" review prompt). */
export function buildEnrollmentProfile(serial: string, udid: string): EnrollProfileResult | null {
  const cfg = secureMdmConfig();
  if (!cfg.ok) return null;
  const c = cfg.config;
  void udid; // reserved for future per-UDID templating; serial drives everything today.

  const enrollmentId = crypto.randomUUID();
  const identityUuid = crypto.randomUUID().toUpperCase();

  const payloads: string[] = [];
  if (c.rootCaB64)
    payloads.push(rootTrustPayload(c.rootCaB64, serial, crypto.randomUUID().toUpperCase()));
  if (c.intermediateCaB64)
    payloads.push(
      intermediateTrustPayload(c.intermediateCaB64, serial, crypto.randomUUID().toUpperCase()),
    );
  payloads.push(scepIdentityPayload(c, serial, identityUuid));
  payloads.push(mdmPayload(c, serial, crypto.randomUUID().toUpperCase(), identityUuid));
  if (c.acmeUrl)
    payloads.push(acmeAttestPayload(c.acmeUrl, serial, crypto.randomUUID().toUpperCase()));

  const profile = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadDisplayName</key>
  <string>co/core Secure Mode Enrollment (${serial})</string>
  <key>PayloadDescription</key>
  <string>Enrolls this Mac with co/core device management and hardware-attests it so requesters can verify it.</string>
  <key>PayloadOrganization</key>
  <string>co/core</string>
  <key>PayloadIdentifier</key>
  <string>dev.cocore.mdm.enroll.${serial}</string>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>${enrollmentId.toUpperCase()}</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
  <key>PayloadContent</key>
  <array>
${payloads.join("\n")}
  </array>
</dict>
</plist>
`;

  // TODO(ops): when COCORE_MDM_SIGNING_CERT_PEM + _KEY_PEM are set,
  // CMS-sign the profile so it installs without the "unverified profile"
  // prompt. Until then we return the unsigned-but-complete profile.
  const signed = false;

  return { profile, signed, enrollmentId };
}

// ---------------------------------------------------------------------------
// push-attestation — (re)trigger the ACME attestation.
// ---------------------------------------------------------------------------

export interface PushAttestationResult {
  queued: boolean;
  /** NanoMDM command UUID when a real push happened; null otherwise. */
  commandUuid: string | null;
  /** "bundled" (attestation runs from the enroll profile), "queued"
   *  (sent to NanoMDM or stubbed), "queued-no-push", or "error". */
  status: string;
  /** True when no real NanoMDM call was made. */
  stubbed: boolean;
  detail: string | null;
}

/** Build the ACME attestation .mobileconfig that NanoMDM delivers as an
 *  InstallProfile command (the push/refresh path — initial attestation
 *  is bundled into the enrollment profile). ClientIdentifier + Subject CN
 *  are pinned to the device serial. */
function buildAttestationCommandProfile(serial: string): string {
  const acmeUrl =
    env("COCORE_MDM_ACME_URL") ?? "https://ca.cocore.dev/acme/cocore-attest/directory";
  const uuid = crypto.randomUUID().toUpperCase();
  const inner = acmeAttestPayload(acmeUrl, serial, crypto.randomUUID().toUpperCase());
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadDisplayName</key><string>co/core Device Attestation (${serial})</string>
  <key>PayloadIdentifier</key><string>dev.cocore.mdm.attest.${serial}</string>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadUUID</key><string>${uuid}</string>
  <key>PayloadVersion</key><integer>1</integer>
  <key>PayloadContent</key>
  <array>
${inner}
  </array>
</dict>
</plist>
`;
}

/** Wrap a mobileconfig in NanoMDM's InstallProfile command plist. */
function buildInstallProfileCommand(commandUuid: string, profile: string): string {
  const payloadB64 = Buffer.from(profile, "utf8").toString("base64");
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CommandUUID</key>
  <string>${commandUuid}</string>
  <key>Command</key>
  <dict>
    <key>RequestType</key>
    <string>InstallProfile</string>
    <key>Payload</key>
    <data>${payloadB64}</data>
  </dict>
</dict>
</plist>
`;
}

/** (Re)trigger hardware attestation for a device.
 *
 *  Initial attestation runs from the bundled ACME payload in the
 *  enrollment profile, so when no explicit MDM `target` (the device's
 *  NanoMDM enrollment id, i.e. its UDID) is supplied we ACK without a
 *  push — this is the path the guided wizard hits, and it must NOT 400.
 *  When a target + NanoMDM creds are present we enqueue+push the
 *  attestation profile as an InstallProfile command (the refresh path). */
export async function pushAttestationCommand(
  serial: string,
  target: string | null,
): Promise<PushAttestationResult> {
  const base = env("COCORE_NANOMDM_URL");
  const apiKey = env("COCORE_NANOMDM_API_KEY");

  // No MDM target → attestation is driven by the enrollment profile.
  if (!target) {
    return {
      queued: true,
      commandUuid: null,
      status: attestationIsBundled() ? "bundled" : "acknowledged",
      stubbed: true,
      detail: attestationIsBundled()
        ? "attestation runs from the enrollment profile (ACME device-attest-01 on install)"
        : "no MDM target supplied; attestation runs from the enrollment profile",
    };
  }

  if (!base || !apiKey) {
    return {
      queued: true,
      commandUuid: null,
      status: "queued",
      stubbed: true,
      detail: "NanoMDM not configured (COCORE_NANOMDM_URL/API_KEY unset); enqueue stubbed",
    };
  }

  const root = base.replace(/\/$/, "");
  const authHeader = `Basic ${Buffer.from(`nanomdm:${apiKey}`).toString("base64")}`;
  const enc = encodeURIComponent(target);
  const commandUuid = crypto.randomUUID().toUpperCase();
  const enqueueBody = buildInstallProfileCommand(
    commandUuid,
    buildAttestationCommandProfile(serial),
  );

  try {
    const enqueueResp = await fetch(`${root}/v1/enqueue/${enc}`, {
      method: "POST",
      headers: { authorization: authHeader, "content-type": "application/xml" },
      body: enqueueBody,
    });
    if (!enqueueResp.ok) {
      const text = await enqueueResp.text().catch(() => "");
      return {
        queued: false,
        commandUuid,
        status: "error",
        stubbed: false,
        detail: `NanoMDM enqueue failed (${enqueueResp.status}): ${text.slice(0, 200)}`,
      };
    }
    const pushResp = await fetch(`${root}/v1/push/${enc}`, {
      method: "GET",
      headers: { authorization: authHeader },
    });
    if (!pushResp.ok) {
      const text = await pushResp.text().catch(() => "");
      return {
        queued: true,
        commandUuid,
        status: "queued-no-push",
        stubbed: false,
        detail: `enqueued but push failed (${pushResp.status}): ${text.slice(0, 200)}`,
      };
    }
    return { queued: true, commandUuid, status: "queued", stubbed: false, detail: null };
  } catch (e) {
    return {
      queued: false,
      commandUuid,
      status: "error",
      stubbed: false,
      detail: `NanoMDM request error: ${(e as Error).message}`,
    };
  }
}

// ---------------------------------------------------------------------------
// attestation-chain — store (ingest) + read the captured Apple x5c chain.
// ---------------------------------------------------------------------------

export interface AttestationChainResult {
  /** Captured Apple x5c chain (base64 DER, leaf-first) or null. */
  chain: string[] | null;
  /** "captured" | "pending" | "error". */
  status: string;
  /** True when neither store had it and we report pending without a backend. */
  stubbed: boolean;
  detail: string | null;
  /** When captured, when the chain was ingested. */
  capturedAt?: string;
}

/** Persist a captured Apple attestation chain (the step-ca webhook calls
 *  this after a successful device-attest-01). `nowIso` is the caller's
 *  timestamp so this stays a pure persistence step. */
export function ingestAttestationChain(serial: string, chain: string[], nowIso: string): void {
  putAttestationChain(serial, chain, nowIso);
}

/** Return the captured Apple x5c attestation chain for `serial`.
 *
 *  Checks the console-local SQLite store first (where the step-ca
 *  attestation webhook writes), then falls back to an external store at
 *  COCORE_MDM_CHAIN_STORE_URL when one is configured. Returns
 *  status:"pending" until a chain has been captured. */
export async function fetchAttestationChain(serial: string): Promise<AttestationChainResult> {
  const local = getAttestationChain(serial);
  if (local) {
    return {
      chain: local.chain,
      status: "captured",
      stubbed: false,
      detail: null,
      capturedAt: local.capturedAt,
    };
  }

  const base = env("COCORE_MDM_CHAIN_STORE_URL");
  if (!base) {
    return { chain: null, status: "pending", stubbed: true, detail: "no chain captured yet" };
  }
  const root = base.replace(/\/$/, "");
  try {
    const resp = await fetch(`${root}/${encodeURIComponent(serial)}`, {
      headers: env("COCORE_MDM_CHAIN_STORE_API_KEY")
        ? { authorization: `Bearer ${env("COCORE_MDM_CHAIN_STORE_API_KEY")}` }
        : {},
    });
    if (resp.status === 404) {
      return { chain: null, status: "pending", stubbed: false, detail: "no chain captured yet" };
    }
    if (!resp.ok) {
      const text = await resp.text().catch(() => "");
      return {
        chain: null,
        status: "error",
        stubbed: false,
        detail: `chain store error (${resp.status}): ${text.slice(0, 200)}`,
      };
    }
    const body = (await resp.json()) as { chain?: unknown };
    const chain =
      Array.isArray(body.chain) && body.chain.every((c) => typeof c === "string")
        ? (body.chain as string[])
        : null;
    return {
      chain,
      status: chain ? "captured" : "pending",
      stubbed: false,
      detail: chain ? null : "chain store returned no chain",
    };
  } catch (e) {
    return {
      chain: null,
      status: "error",
      stubbed: false,
      detail: `chain store request error: ${(e as Error).message}`,
    };
  }
}

// ---------------------------------------------------------------------------
// Option-B (freshness-code) hardware attestation via MDM DeviceInformation.
//
// The ACME path above attests an OS-managed P-384 key whose leaf can't bind to
// the agent's P-256 receipt key (see the option-A analysis in
// infra/mdm/RUNBOOK.md). The DeviceInformation path lets US choose the
// attestation's freshness: Apple sets the leaf's freshness OID
// (1.2.840.113635.100.8.11.1) to the `DeviceAttestationNonce` the MDM sends
// (Apple security guide: "the freshness code is the value of the
// DeviceAttestationNonce specified in the request"). Setting
//
//     DeviceAttestationNonce = sha256(agent P-256 pubkey)
//
// makes the freshness commit to the receipt-signing key — exactly the option-B
// binding the verifiers (mda.rs `freshness_binds`, verify-provider
// `freshnessBindsKey`, py `_freshness_binds_key`) already check. No App Attest,
// no forked step-ca.
//
// Apple rate-limits DeviceInformation attestation to ~1 per device / 7 days, so
// this is a weekly (re)bind, not per-refresh; the captured chain is reused
// across the 24h attestation publishes while the signing key is stable.
//
// ⚠️ ENCODING TO CONFIRM ON FIRST LIVE CAPTURE: we carry the 32-byte nonce as a
// base64 <string> (the MDM-compatible form). The verifier expects the freshness
// OID to contain the raw 32 bytes of sha256(pubkey). If Apple stores the nonce
// string verbatim (rather than its decoded bytes), the freshness normalizer is
// the single one-line place to adjust — use scripts/inspect-mda-freshness.sh on
// the first captured leaf to confirm. See infra/mdm/RUNBOOK.md "Option-B".
// ---------------------------------------------------------------------------

/** The `DeviceAttestationNonce` that binds an attestation to `publicKeyB64`
 *  (the agent's raw 64-byte P-256 X‖Y key, base64). The bytes are
 *  `sha256(pubkey)` — what the leaf's freshness OID must equal for the
 *  verifiers' `freshness == sha256(publicKey)` check to hold. */
export function attestationNonceBytes(publicKeyB64: string): Buffer {
  const raw = Buffer.from(publicKeyB64, "base64");
  return createHash("sha256").update(raw).digest(); // 32 bytes
}

/** Build the MDM `DeviceInformation` command that requests a fresh hardware
 *  attestation bound to `nonceBytes`. `Queries: [DevicePropertiesAttestation]`
 *  asks for the attestation; `DeviceAttestationNonce` forces a fresh one whose
 *  freshness OID equals the nonce. */
export function buildDeviceInformationAttestationCommand(
  commandUuid: string,
  nonceBytes: Buffer,
): string {
  const nonceB64 = nonceBytes.toString("base64");
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CommandUUID</key>
  <string>${commandUuid}</string>
  <key>Command</key>
  <dict>
    <key>RequestType</key>
    <string>DeviceInformation</string>
    <key>Queries</key>
    <array>
      <string>DevicePropertiesAttestation</string>
    </array>
    <key>DeviceAttestationNonce</key>
    <string>${nonceB64}</string>
  </dict>
</dict>
</plist>
`;
}

/** Enqueue + push a DeviceInformation attestation command, binding the
 *  resulting Apple attestation to `publicKeyB64` via the nonce. `target` is the
 *  device's NanoMDM enrollment id (UDID). Mirrors `pushAttestationCommand`. */
export async function requestDeviceInformationAttestation(
  serial: string,
  target: string | null,
  publicKeyB64: string,
): Promise<PushAttestationResult> {
  const base = env("COCORE_NANOMDM_URL");
  const apiKey = env("COCORE_NANOMDM_API_KEY");

  if (!target) {
    return {
      queued: false,
      commandUuid: null,
      status: "error",
      stubbed: true,
      detail: "DeviceInformation attestation requires an MDM target (device UDID)",
    };
  }
  if (!base || !apiKey) {
    return {
      queued: true,
      commandUuid: null,
      status: "queued",
      stubbed: true,
      detail: "NanoMDM not configured (COCORE_NANOMDM_URL/API_KEY unset); enqueue stubbed",
    };
  }

  const root = base.replace(/\/$/, "");
  const authHeader = `Basic ${Buffer.from(`nanomdm:${apiKey}`).toString("base64")}`;
  const enc = encodeURIComponent(target);
  const commandUuid = crypto.randomUUID().toUpperCase();
  const enqueueBody = buildDeviceInformationAttestationCommand(
    commandUuid,
    attestationNonceBytes(publicKeyB64),
  );

  try {
    const enqueueResp = await fetch(`${root}/v1/enqueue/${enc}`, {
      method: "POST",
      headers: { authorization: authHeader, "content-type": "application/xml" },
      body: enqueueBody,
    });
    if (!enqueueResp.ok) {
      const text = await enqueueResp.text().catch(() => "");
      return {
        queued: false,
        commandUuid,
        status: "error",
        stubbed: false,
        detail: `NanoMDM enqueue failed (${enqueueResp.status}): ${text.slice(0, 200)}`,
      };
    }
    const pushResp = await fetch(`${root}/v1/push/${enc}`, {
      method: "GET",
      headers: { authorization: authHeader },
    });
    if (!pushResp.ok) {
      const text = await pushResp.text().catch(() => "");
      return {
        queued: true,
        commandUuid,
        status: "queued-no-push",
        stubbed: false,
        detail: `enqueued but push failed (${pushResp.status}): ${text.slice(0, 200)}`,
      };
    }
    return { queued: true, commandUuid, status: "queued", stubbed: false, detail: null };
  } catch (e) {
    return {
      queued: false,
      commandUuid,
      status: "error",
      stubbed: false,
      detail: `NanoMDM request error: ${(e as Error).message}`,
    };
  }
}

/** Authenticate a NanoMDM webhook POST (the device's command results).
 *
 *  Secret = COCORE_NANOMDM_WEBHOOK_KEY, constant-time, fail-closed when unset.
 *  NanoMDM's `-webhook-url` does NOT send an Authorization header, so the
 *  operator embeds the secret in the URL as `?key=<secret>` — that's the
 *  primary check. A Bearer header is also accepted (e.g. for manual posts /
 *  a future webhook proxy that adds one). */
export function authenticateNanomdmWebhook(request: Request): boolean {
  const expected = env("COCORE_NANOMDM_WEBHOOK_KEY");
  if (!expected) return false;
  const fromQuery = (() => {
    try {
      return new URL(request.url).searchParams.get("key");
    } catch {
      return null;
    }
  })();
  const got = fromQuery ?? readBearer(request);
  if (!got || got.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= got.charCodeAt(i) ^ expected.charCodeAt(i);
  return diff === 0;
}

/** Parse a NanoMDM webhook payload for a DeviceInformation attestation result.
 *
 *  NanoMDM posts MDM events as JSON; a command-result event carries the
 *  device's raw response plist (base64) under `command_results` / `raw_command`
 *  (field names vary by NanoMDM webhook version, so we scan defensively). The
 *  device's DeviceInformation response contains a `DevicePropertiesAttestation`
 *  array of base64-DER certs (leaf-first) — the Apple x5c chain we persist.
 *
 *  Returns `{ serial, chain }` when an attestation chain is present, else null.
 *  Pure (no I/O) so it's unit-tested against a sample payload; the exact NanoMDM
 *  field layout is confirmed on first live capture (see RUNBOOK "Option-B"). */
export function parseNanomdmAttestationWebhook(
  payload: unknown,
): { serial: string | null; chain: string[] } | null {
  if (!payload || typeof payload !== "object") return null;
  const obj = payload as Record<string, unknown>;

  // Pull a candidate raw command-result plist (base64 or inline XML) from the
  // common NanoMDM webhook shapes.
  const rawCandidates: string[] = [];
  const pushStr = (v: unknown) => {
    if (typeof v === "string" && v.length > 0) rawCandidates.push(v);
  };
  pushStr(obj["raw_command_response"]);
  pushStr(obj["command_response"]);
  if (obj["command_results"] && typeof obj["command_results"] === "object") {
    const cr = obj["command_results"] as Record<string, unknown>;
    pushStr(cr["raw"]);
    pushStr(cr["payload"]);
  }
  // Some webhook configs nest the device plist under `checkin`/`acknowledge`.
  pushStr(
    (obj["acknowledge_event"] as Record<string, unknown> | undefined)?.["raw_payload"] as unknown,
  );

  const serial = typeof obj["serial"] === "string" ? (obj["serial"] as string) : null;

  for (const raw of rawCandidates) {
    // raw may be base64 of a plist, or a plist string directly.
    let xml = raw;
    if (!/[<]plist/i.test(raw)) {
      try {
        xml = Buffer.from(raw, "base64").toString("utf8");
      } catch {
        continue;
      }
    }
    const chain = extractDevicePropertiesAttestation(xml);
    if (chain && chain.length > 0) {
      return { serial: serial ?? extractSerialFromPlist(xml), chain };
    }
  }
  return null;
}

/** Extract the `DevicePropertiesAttestation` cert array (base64 DER, leaf-first)
 *  from a device's DeviceInformation response plist. Minimal, dependency-free:
 *  finds the keyed <array> of <data> entries. */
function extractDevicePropertiesAttestation(plistXml: string): string[] | null {
  const keyIdx = plistXml.search(/<key>\s*DevicePropertiesAttestation\s*<\/key>/i);
  if (keyIdx < 0) return null;
  const after = plistXml.slice(keyIdx);
  const arrMatch = after.match(/<array>([\s\S]*?)<\/array>/i);
  if (!arrMatch) return null;
  const datas = [...arrMatch[1]!.matchAll(/<data>([\s\S]*?)<\/data>/gi)].map((m) =>
    m[1]!.replace(/\s+/g, ""),
  );
  return datas.length > 0 ? datas : null;
}

function extractSerialFromPlist(plistXml: string): string | null {
  const m = plistXml.match(/<key>\s*SerialNumber\s*<\/key>\s*<string>([^<]+)<\/string>/i);
  return m ? m[1]!.trim() : null;
}
