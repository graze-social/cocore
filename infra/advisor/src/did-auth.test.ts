// Unit tests for the advisor's service-auth JWT verification (C1 / M3).
//
// We mint a real ES256 JWT with a fresh P-256 keypair and verify it against a
// STUB DID resolver that returns a DID document carrying that keypair's public
// key — so the crypto path is exercised end-to-end without touching the network
// (the resolver is injectable exactly for this).

import { describe, expect, it } from "vitest";

import { P256PrivateKeyExportable } from "@atcute/crypto";

import { type DidDocumentResolver, LXM_REGISTER, verifyServiceAuthToken } from "./did-auth.ts";

const AUDIENCE = "did:web:advisor.cocore.dev";

function b64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlJson(obj: unknown): string {
  return b64url(new TextEncoder().encode(JSON.stringify(obj)));
}

/** Mint an ES256 service-auth JWT signed by `key` for the given claims. */
async function mintJwt(
  key: P256PrivateKeyExportable,
  claims: { iss: string; aud: string; lxm: string; exp?: number; nbf?: number },
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "ES256", typ: "JWT" };
  const payload = { exp: now + 60, ...claims };
  const signingInput = `${b64urlJson(header)}.${b64urlJson(payload)}`;
  const sig = await key.sign(new TextEncoder().encode(signingInput));
  return `${signingInput}.${b64url(sig)}`;
}

/** A resolver that hands back a DID document carrying `multikey` as the atproto
 *  signing key for `did`, and rejects anything else. */
function stubResolver(did: string, multikey: string): DidDocumentResolver {
  return {
    resolve(reqDid) {
      if (reqDid !== did) return Promise.reject(new Error("unknown did"));
      return Promise.resolve({
        id: did,
        verificationMethod: [
          { id: `${did}#atproto`, type: "Multikey", controller: did, publicKeyMultibase: multikey },
        ],
      });
    },
  };
}

async function setup(did: string): Promise<{
  jwt: (
    claims?: Partial<{ aud: string; lxm: string; exp: number; nbf: number }>,
  ) => Promise<string>;
  resolver: DidDocumentResolver;
}> {
  const key = await P256PrivateKeyExportable.createKeypair();
  const multikey = await key.exportPublicKey("multikey");
  const resolver = stubResolver(did, multikey);
  return {
    resolver,
    jwt: (claims = {}) => mintJwt(key, { iss: did, aud: AUDIENCE, lxm: LXM_REGISTER, ...claims }),
  };
}

describe("verifyServiceAuthToken", () => {
  it("accepts a valid JWT and returns the issuer DID", async () => {
    const did = "did:plc:provider1";
    const { jwt, resolver } = await setup(did);
    const res = await verifyServiceAuthToken(await jwt(), {
      audience: AUDIENCE,
      lxm: LXM_REGISTER,
      resolver,
    });
    expect(res.ok).toBe(true);
    if (res.ok) expect(res.did).toBe(did);
  });

  it("rejects a JWT signed by a different key than the DID publishes", async () => {
    const did = "did:plc:provider1";
    // Mint with a DIFFERENT key than the resolver publishes → bad signature.
    const attacker = await P256PrivateKeyExportable.createKeypair();
    const victim = await P256PrivateKeyExportable.createKeypair();
    const resolver = stubResolver(did, await victim.exportPublicKey("multikey"));
    const jwt = await mintJwt(attacker, { iss: did, aud: AUDIENCE, lxm: LXM_REGISTER });
    const res = await verifyServiceAuthToken(jwt, {
      audience: AUDIENCE,
      lxm: LXM_REGISTER,
      resolver,
    });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.status).toBe(401);
  });

  it("rejects a wrong audience", async () => {
    const did = "did:plc:provider1";
    const { jwt, resolver } = await setup(did);
    const res = await verifyServiceAuthToken(await jwt({ aud: "did:web:someone-else" }), {
      audience: AUDIENCE,
      lxm: LXM_REGISTER,
      resolver,
    });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.error).toBe("BadJwtAudience");
  });

  it("rejects a wrong lxm", async () => {
    const did = "did:plc:provider1";
    const { jwt, resolver } = await setup(did);
    const res = await verifyServiceAuthToken(await jwt({ lxm: "dev.cocore.compute.control" }), {
      audience: AUDIENCE,
      lxm: LXM_REGISTER,
      resolver,
    });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.error).toBe("BadJwtLexicon");
  });

  it("rejects an expired JWT", async () => {
    const did = "did:plc:provider1";
    const { jwt, resolver } = await setup(did);
    const res = await verifyServiceAuthToken(
      await jwt({ exp: Math.floor(Date.now() / 1000) - 300 }),
      {
        audience: AUDIENCE,
        lxm: LXM_REGISTER,
        resolver,
      },
    );
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.error).toBe("JwtExpired");
  });

  it("rejects a missing token", async () => {
    const res = await verifyServiceAuthToken(null, { audience: AUDIENCE, lxm: LXM_REGISTER });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.error).toBe("AuthRequired");
  });

  it("rejects a malformed (non-3-part) token", async () => {
    const res = await verifyServiceAuthToken("not.a.valid.jwt.x", {
      audience: AUDIENCE,
      lxm: LXM_REGISTER,
    });
    expect(res.ok).toBe(false);
  });
});
