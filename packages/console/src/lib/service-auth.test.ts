// Verifies verifyServiceAuth end-to-end against a real signature: we
// generate a P-256 keypair (the curve a did:plc signing key commonly
// uses), mint a JWT the way a PDS would for service proxying, and stub
// only the DID-document resolution so the test doesn't hit the network.
// The signature check itself runs for real via @atcute/crypto.

import { P256PrivateKeyExportable } from "@atcute/crypto";
import { toBase64Url } from "@atcute/multibase";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

// Mutable state the module mocks read. vi.hoisted keeps it valid inside
// the hoisted vi.mock factories.
const state = vi.hoisted(() => ({
  material: undefined as { type: string; publicKeyMultibase: string } | undefined,
  throwOnResolve: false,
}));

vi.mock("@atcute/identity-resolver", () => ({
  CompositeDidDocumentResolver: class {
    async resolve() {
      if (state.throwOnResolve) throw new Error("resolve failed");
      return {}; // shape irrelevant; getAtprotoVerificationMaterial is mocked
    }
  },
  PlcDidDocumentResolver: class {},
  WebDidDocumentResolver: class {},
}));

vi.mock("@atcute/identity", () => ({
  getAtprotoVerificationMaterial: () => state.material,
}));

import { verifyServiceAuth } from "./service-auth.server.ts";

const CONSOLE_DID = "did:web:console.test";
const ISS = "did:plc:ewvi7nxzyoun6zhxrhs64oiz";

function b64urlJson(obj: unknown): string {
  return toBase64Url(new TextEncoder().encode(JSON.stringify(obj)));
}

async function mintJwt(
  signer: P256PrivateKeyExportable,
  payload: Record<string, unknown>,
  alg = "ES256",
): Promise<string> {
  const signingInput = `${b64urlJson({ alg, typ: "JWT" })}.${b64urlJson(payload)}`;
  const sig = await signer.sign(new TextEncoder().encode(signingInput));
  return `${signingInput}.${toBase64Url(sig)}`;
}

function reqWith(jwt?: string): Request {
  return new Request("https://console.test/xrpc/dev.cocore.account.listApiKeys", {
    headers: jwt ? { authorization: `Bearer ${jwt}` } : {},
  });
}

function freshPayload(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    iss: ISS,
    aud: CONSOLE_DID,
    lxm: "dev.cocore.account.listApiKeys",
    exp: Math.floor(Date.now() / 1000) + 60,
    ...over,
  };
}

let keypair: P256PrivateKeyExportable;

beforeEach(async () => {
  process.env["COCORE_CONSOLE_DID"] = CONSOLE_DID;
  keypair = await P256PrivateKeyExportable.createKeypair();
  state.material = {
    type: "Multikey",
    publicKeyMultibase: await keypair.exportPublicKey("multikey"),
  };
  state.throwOnResolve = false;
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("verifyServiceAuth", () => {
  test("valid token resolves to the issuer DID", async () => {
    const jwt = await mintJwt(keypair, freshPayload());
    const res = await verifyServiceAuth(reqWith(jwt), "dev.cocore.account.listApiKeys");
    expect(res).toEqual({ ok: true, did: ISS });
  });

  test("missing Authorization header is AuthRequired", async () => {
    const res = await verifyServiceAuth(reqWith(), "dev.cocore.account.listApiKeys");
    expect(res).toMatchObject({ ok: false, status: 401, error: "AuthRequired" });
  });

  test("wrong audience is rejected", async () => {
    const jwt = await mintJwt(keypair, freshPayload({ aud: "did:web:someone-else" }));
    const res = await verifyServiceAuth(reqWith(jwt), "dev.cocore.account.listApiKeys");
    expect(res).toMatchObject({ ok: false, error: "BadJwtAudience" });
  });

  test("wrong lexicon method is rejected", async () => {
    const jwt = await mintJwt(keypair, freshPayload({ lxm: "dev.cocore.account.createApiKey" }));
    const res = await verifyServiceAuth(reqWith(jwt), "dev.cocore.account.listApiKeys");
    expect(res).toMatchObject({ ok: false, error: "BadJwtLexicon" });
  });

  test("expired token is rejected", async () => {
    const jwt = await mintJwt(keypair, freshPayload({ exp: Math.floor(Date.now() / 1000) - 120 }));
    const res = await verifyServiceAuth(reqWith(jwt), "dev.cocore.account.listApiKeys");
    expect(res).toMatchObject({ ok: false, error: "JwtExpired" });
  });

  test("signature from a different key is rejected", async () => {
    // Sign with an attacker key but advertise the legitimate key as the
    // resolved material — the signature must not verify.
    const attacker = await P256PrivateKeyExportable.createKeypair();
    const jwt = await mintJwt(attacker, freshPayload());
    const res = await verifyServiceAuth(reqWith(jwt), "dev.cocore.account.listApiKeys");
    expect(res).toMatchObject({ ok: false, error: "BadJwtSignature" });
  });

  test("non-plc/web issuer is rejected", async () => {
    const jwt = await mintJwt(keypair, freshPayload({ iss: "did:example:nope" }));
    const res = await verifyServiceAuth(reqWith(jwt), "dev.cocore.account.listApiKeys");
    expect(res).toMatchObject({ ok: false, error: "BadJwtIssuer" });
  });

  test("unresolvable issuer DID is rejected", async () => {
    state.throwOnResolve = true;
    const jwt = await mintJwt(keypair, freshPayload());
    const res = await verifyServiceAuth(reqWith(jwt), "dev.cocore.account.listApiKeys");
    expect(res).toMatchObject({ ok: false, error: "BadJwtIssuer" });
  });
});
