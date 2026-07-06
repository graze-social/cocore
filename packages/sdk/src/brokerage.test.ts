import { generateKeyPairSync, sign as nodeSign } from "node:crypto";
import assert from "node:assert/strict";
import { test } from "vitest";

import { canonicalize } from "./canonical.ts";
import {
  brokerageKeyFromDidDoc,
  brokerageWitnessMessage,
  didDocumentUrl,
  makeBrokerageKeyResolver,
  verifyBrokerageCountersignature,
  verifyConfidentialReceipt,
} from "./brokerage.ts";

// A P-256 authority: raw key (for the DID-doc JWK) + a DER signer.
function makeAuthority(): {
  jwk: { kty: "EC"; crv: "P-256"; x: string; y: string };
  sign: (m: Uint8Array) => string;
} {
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = publicKey.export({ format: "jwk" }) as { x: string; y: string };
  return {
    jwk: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y },
    sign: (m) => nodeSign("SHA256", Buffer.from(m), privateKey).toString("base64"),
  };
}

test("didDocumentUrl: did:web (host + path) and did:plc, unsupported → null", () => {
  assert.equal(
    didDocumentUrl("did:web:advisor.cocore.dev"),
    "https://advisor.cocore.dev/.well-known/did.json",
  );
  assert.equal(
    didDocumentUrl("did:web:example.com:brokerage:a"),
    "https://example.com/brokerage/a/did.json",
  );
  assert.equal(didDocumentUrl("did:plc:abc123"), "https://plc.directory/did%3Aplc%3Aabc123");
  assert.equal(didDocumentUrl("did:key:zabc"), null);
});

test("brokerageKeyFromDidDoc: extracts the P-256 JWK, ignores non-P-256", () => {
  const a = makeAuthority();
  const key = brokerageKeyFromDidDoc({
    verificationMethod: [
      { type: "Ed25519VerificationKey2020" },
      { type: "JsonWebKey2020", publicKeyJwk: a.jwk },
    ],
  });
  assert.ok(key && key.length > 0);
  // A doc with no EC P-256 key → null.
  assert.equal(
    brokerageKeyFromDidDoc({
      verificationMethod: [{ publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: "z" } }],
    }),
    null,
  );
  assert.equal(brokerageKeyFromDidDoc({}), null);
});

const DID = "did:web:advisor.cocore.dev";
const FIELDS = {
  authority: DID,
  attestation: "at://did:plc:prov/dev.cocore.compute.attestation/a1",
  jobCid: "bafyjob",
  jobUri: "at://did:plc:req/dev.cocore.compute.job/j1",
  machineId: "3mplnovbfjc2a",
  nonce: "0011223344556677",
  requester: "did:plc:req",
};

function receipt(sig: string) {
  return {
    requester: FIELDS.requester,
    job: { uri: FIELDS.jobUri, cid: FIELDS.jobCid },
    attestation: { uri: FIELDS.attestation },
    brokerageCountersignature: {
      authority: DID,
      machineId: FIELDS.machineId,
      nonce: FIELDS.nonce,
      sig,
    },
  };
}

test("end-to-end: resolve the authority key from a DID doc and verify the countersignature", async () => {
  const a = makeAuthority();
  const sig = a.sign(brokerageWitnessMessage(FIELDS));

  // A stub fetch serving the authority's DID document (P-256 JWK).
  const stubFetch = (async (url: string) => {
    assert.equal(url, "https://advisor.cocore.dev/.well-known/did.json");
    return {
      ok: true,
      json: async () => ({ verificationMethod: [{ publicKeyJwk: a.jwk }] }),
    };
  }) as unknown as typeof fetch;

  const resolveAuthorityKeyB64 = makeBrokerageKeyResolver({ fetchImpl: stubFetch });

  const ok = await verifyBrokerageCountersignature(receipt(sig), {
    trustedAuthorities: [DID],
    resolveAuthorityKeyB64,
  });
  assert.equal(ok.ok, true, ok.reason);

  // A tampered receipt fails even with a resolvable key.
  const bad = await verifyBrokerageCountersignature(
    { ...receipt(sig), requester: "did:plc:someone-else" },
    { trustedAuthorities: [DID], resolveAuthorityKeyB64 },
  );
  assert.equal(bad.ok, false);
});

test("resolver returns null (fail-closed) when the DID doc is unreachable", async () => {
  const stubFetch = (async () => ({
    ok: false,
    json: async () => ({}),
  })) as unknown as typeof fetch;
  const resolve = makeBrokerageKeyResolver({ fetchImpl: stubFetch });
  assert.equal(await resolve(DID), null);
});

test("verifyConfidentialReceipt: requires BOTH the provider signature and a trusted brokerage witness", async () => {
  // Provider identity (signs the receipt body → enclaveSignature).
  const { publicKey: provPub, privateKey: provPriv } = generateKeyPairSync("ec", {
    namedCurve: "P-256",
  });
  const pj = provPub.export({ format: "jwk" }) as { x: string; y: string };
  const providerPublicKeyB64 = Buffer.concat([
    Buffer.from(pj.x, "base64url"),
    Buffer.from(pj.y, "base64url"),
  ]).toString("base64");

  const body = {
    requester: FIELDS.requester,
    job: { uri: FIELDS.jobUri, cid: FIELDS.jobCid },
    attestation: { uri: FIELDS.attestation },
    model: "m",
    tokens: { in: 1, out: 2 },
  };
  const enclaveSignature = nodeSign(
    "SHA256",
    Buffer.from(new TextEncoder().encode(canonicalize(body))),
    provPriv,
  ).toString("base64");

  // Brokerage authority (signs the witness → brokerageCountersignature).
  const authority = makeAuthority();
  const witnessSig = authority.sign(brokerageWitnessMessage(FIELDS));
  const resolveAuthorityKeyB64 = makeBrokerageKeyResolver({
    fetchImpl: (async () => ({
      ok: true,
      json: async () => ({ verificationMethod: [{ publicKeyJwk: authority.jwk }] }),
    })) as unknown as typeof fetch,
  });

  const full = {
    ...body,
    enclaveSignature,
    brokerageCountersignature: {
      authority: DID,
      machineId: FIELDS.machineId,
      nonce: FIELDS.nonce,
      sig: witnessSig,
    },
  };

  const opts = { trustedAuthorities: [DID], resolveAuthorityKeyB64, providerPublicKeyB64 };

  // Both valid → confidential-valid.
  assert.equal((await verifyConfidentialReceipt(full, opts)).ok, true);

  // Missing the brokerage witness → NOT confidential (the astra case: a
  // self-published receipt with a good provider sig but no trusted witness).
  const noWitness = { ...full, brokerageCountersignature: undefined };
  const r1 = await verifyConfidentialReceipt(noWitness, opts);
  assert.equal(r1.ok, false);
  assert.match(r1.reason!, /no brokerage countersignature/);

  // Tampered provider body → provider signature fails first.
  const r2 = await verifyConfidentialReceipt({ ...full, model: "evil" }, opts);
  assert.equal(r2.ok, false);
  assert.match(r2.reason!, /enclaveSignature did not verify/);
});
