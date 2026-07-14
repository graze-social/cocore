// APNs code-identity sender. The advisor's half of the AMFI-gated code-identity
// challenge: it seals a fresh nonce to the provider's X25519 key `K` and pushes
// it to the measured agent's device token over APNs. Only the genuine,
// team-signed binary can receive that push (AMFI gates the topic to our code
// signature) and open it (K lives in the agent's protected memory), so a valid
// response proves code identity in a way a self-reported cdHash cannot.
//
// Token-auth (.p8) ES256 JWT, production gateway. The .p8 is a secret and is
// read from the environment (never the repo). Proven end-to-end by the S5 spike
// (provider/spikes/apns) — this is the same flow in TypeScript.

import { eciesSeal } from "@cocore/sdk/ecies";
import crypto from "node:crypto";
import http2 from "node:http2";
import nacl from "tweetnacl";

const APNS_HOST = "https://api.push.apple.com";
// Apple rejects a provider token refreshed more than once per ~20 min
// (TooManyProviderTokenUpdates) and expires it after 60 min. Refresh well
// inside that window and reuse otherwise.
const JWT_TTL_MS = 40 * 60_000;

export interface ApnsConfig {
  /** PEM contents of the .p8 token-auth key (APNS_AUTH_KEY). */
  authKeyPem: string;
  /** 10-char Key ID of the .p8 (APNS_KEY_ID). */
  keyId: string;
  /** 10-char Apple Team ID (APNS_TEAM_ID). */
  teamId: string;
  /** Push topic = the agent's bundle id, e.g. dev.cocore.provider (APNS_TOPIC). */
  topic: string;
}

/** Read APNs config from the environment. Returns null (feature disabled, no
 *  enforcement) unless all four vars are present — so an advisor without APNs
 *  configured keeps its current behavior and never blocks confidential. */
export function loadApnsConfig(
  env: Record<string, string | undefined> = process.env,
): ApnsConfig | null {
  const authKeyPem = env.APNS_AUTH_KEY;
  const keyId = env.APNS_KEY_ID;
  const teamId = env.APNS_TEAM_ID;
  const topic = env.APNS_TOPIC;
  if (!authKeyPem || !keyId || !teamId || !topic) return null;
  return { authKeyPem, keyId, teamId, topic };
}

function b64url(b: Buffer): string {
  return b.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Build (and cache) the ES256 provider JWT. Exported for testing. */
export function buildApnsJwt(
  cfg: ApnsConfig,
  now = Date.now(),
  cache: { jwt?: string; iat?: number } = jwtCache,
): string {
  if (cache.jwt && cache.iat && now - cache.iat < JWT_TTL_MS) return cache.jwt;
  const header = { alg: "ES256", kid: cfg.keyId };
  const payload = { iss: cfg.teamId, iat: Math.floor(now / 1000) };
  const signingInput =
    b64url(Buffer.from(JSON.stringify(header))) +
    "." +
    b64url(Buffer.from(JSON.stringify(payload)));
  const key = crypto.createPrivateKey(cfg.authKeyPem);
  // JOSE requires the raw R||S form (ieee-p1363), not DER.
  const sig = crypto.sign("SHA256", Buffer.from(signingInput), {
    key,
    dsaEncoding: "ieee-p1363",
  });
  const jwt = signingInput + "." + b64url(sig);
  cache.jwt = jwt;
  cache.iat = now;
  return jwt;
}
const jwtCache: { jwt?: string; iat?: number } = {};

/** Seal `nonce` to the provider's encryption key, picking the codec from the
 *  provider's advertised `encScheme`. Returns the push payload's `cc` object
 *  (`{ epk, n }` — the ephemeral pub + sealed nonce; the provider recomputes the
 *  shared secret from `epk`). Exported for testing.
 *
 *  * `p256-ecies-se` — ephemeral-static P-256 ECIES to the Secure-Enclave key,
 *    so a copied software key can't recover the nonce off-box (ADR-0005). Shared
 *    byte-for-byte with the SDK/provider via `@cocore/sdk/ecies`.
 *  * `x25519` / absent (older agents) — the NaCl box path. Kept as the default
 *    so a pre-SE agent's challenge still seals correctly. */
export async function sealCodeChallenge(
  nonce: string,
  encryptionPubKeyB64: string,
  encScheme?: string,
): Promise<{ epk: string; n: string }> {
  const recipient = new Uint8Array(Buffer.from(encryptionPubKeyB64, "base64"));
  const msg = new TextEncoder().encode(nonce);
  if (encScheme === "p256-ecies-se") {
    const { epk, blob } = await eciesSeal(recipient, msg);
    return {
      epk: Buffer.from(epk).toString("base64"),
      n: Buffer.from(blob).toString("base64"),
    };
  }
  const eph = nacl.box.keyPair();
  const boxNonce = nacl.randomBytes(nacl.box.nonceLength);
  const body = nacl.box(msg, boxNonce, recipient, eph.secretKey);
  const framed = new Uint8Array(boxNonce.length + body.length);
  framed.set(boxNonce, 0);
  framed.set(body, boxNonce.length);
  return {
    epk: Buffer.from(eph.publicKey).toString("base64"),
    n: Buffer.from(framed).toString("base64"),
  };
}

export interface ApnsSendResult {
  ok: boolean;
  status: number;
  /** Apple's reason string on failure (BadDeviceToken, TopicDisallowed, …). */
  reason?: string;
  apnsId?: string;
}

/** How long to wait for the whole APNs round-trip before giving up. */
const APNS_TIMEOUT_MS = 10_000;

/** Store-and-forward window for the code-identity push (`apns-expiration`).
 *
 *  Background pushes (`content-available`, priority 5) are heavily throttled
 *  per-device; with `apns-expiration: 0` ("deliver this instant or discard")
 *  a device that's momentarily throttled or asleep drops the challenge outright
 *  — which is exactly the field symptom (Apple ACKs the push 200, but it's
 *  never delivered, so no `code-attestation OK` ever comes back). A non-zero
 *  expiration tells APNs to STORE the push and retry until this deadline, so a
 *  brief throttle/sleep no longer loses the challenge. Kept comfortably under
 *  the code re-challenge cadence (~5 min) so a stored push is delivered before
 *  the next challenge rotates `pendingCodeNonce` and would make a late response
 *  stale. */
const CODE_CHALLENGE_EXPIRATION_SECS = 240;

/** Push a sealed code-identity challenge to a provider's device token.
 *
 *  APNs REQUIRES HTTP/2. Node's global `fetch` (undici) is HTTP/1.1 only and
 *  fails every push to `api.push.apple.com` with `TypeError: fetch failed`
 *  (status 0) — which is exactly why code-attestation never completed in the
 *  field. We therefore open an HTTP/2 session with `node:http2` directly. The
 *  S5 spike used Swift/URLSession (HTTP/2 by default), so this gap only
 *  surfaced once the TypeScript advisor tried to send. */
export async function sendCodeChallenge(
  cfg: ApnsConfig,
  deviceToken: string,
  encryptionPubKeyB64: string,
  nonce: string,
  encScheme?: string,
): Promise<ApnsSendResult> {
  const cc = await sealCodeChallenge(nonce, encryptionPubKeyB64, encScheme);
  const body = Buffer.from(JSON.stringify({ aps: { "content-available": 1 }, cc }));
  let jwt: string;
  try {
    jwt = buildApnsJwt(cfg);
  } catch (e) {
    return { ok: false, status: 0, reason: `jwt: ${String(e)}` };
  }
  return await new Promise<ApnsSendResult>((resolve) => {
    let settled = false;
    const client = http2.connect(APNS_HOST);
    const finish = (r: ApnsSendResult): void => {
      if (settled) return;
      settled = true;
      try {
        client.close();
      } catch {
        // already closing
      }
      resolve(r);
    };
    client.on("error", (e) => finish({ ok: false, status: 0, reason: String(e) }));
    const req = client.request({
      ":method": "POST",
      ":path": `/3/device/${deviceToken}`,
      authorization: `bearer ${jwt}`,
      "apns-topic": cfg.topic,
      "apns-push-type": "background",
      "apns-priority": "5",
      // Store-and-forward (see CODE_CHALLENGE_EXPIRATION_SECS) instead of
      // deliver-now-or-discard, so a momentarily throttled/asleep device still
      // gets the challenge.
      "apns-expiration": String(Math.floor(Date.now() / 1000) + CODE_CHALLENGE_EXPIRATION_SECS),
      "content-type": "application/json",
      "content-length": String(body.length),
    });
    req.setTimeout(APNS_TIMEOUT_MS, () => {
      req.close();
      finish({ ok: false, status: 0, reason: "apns request timeout" });
    });
    let status = 0;
    let apnsId: string | undefined;
    const chunks: Buffer[] = [];
    req.on("response", (headers) => {
      status = Number(headers[":status"]) || 0;
      apnsId = (headers["apns-id"] as string | undefined) ?? undefined;
    });
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("error", (e) => finish({ ok: false, status: 0, reason: String(e) }));
    req.on("end", () => {
      if (status === 200) {
        finish({ ok: true, status: 200, apnsId });
        return;
      }
      let reason: string | undefined;
      try {
        reason = (JSON.parse(Buffer.concat(chunks).toString()) as { reason?: string }).reason;
      } catch {
        // non-JSON body; leave reason undefined
      }
      finish({ ok: false, status, reason, apnsId });
    });
    req.write(body);
    req.end();
  });
}
