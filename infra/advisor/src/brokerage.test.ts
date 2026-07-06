// The brokerage authority signs a witness (advisor side) and the SDK verifier
// accepts it (requester side) — the ADR-0004 cross-module contract. If the
// canonical witness message ever drifts between signer and verifier, this fails.

import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";

import { brokerageKeyFromDidDoc, verifyBrokerageCountersignature } from "@cocore/sdk/brokerage";

import { brokerageDidDocument, loadBrokerageAuthority } from "./brokerage.ts";

const DID = "did:web:advisor.cocore.dev";

function authorityEnv(): { env: Record<string, string>; pem: string } {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const pem = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
  return {
    pem,
    env: { COCORE_BROKERAGE_DID: DID, COCORE_BROKERAGE_SIGNING_KEY_PEM: pem },
  };
}

const FIELDS = {
  jobUri: "at://did:plc:req/dev.cocore.compute.job/j1",
  jobCid: "bafyjob",
  machineId: "3mplnovbfjc2a",
  attestation: "at://did:plc:prov/dev.cocore.compute.attestation/a1",
  requester: "did:plc:req",
};

/** Build the receipt shape the SDK verifier reads from a signed block. */
function receiptFrom(cs: { authority: string; machine_id: string; nonce: string; sig: string }) {
  return {
    requester: FIELDS.requester,
    job: { uri: FIELDS.jobUri, cid: FIELDS.jobCid },
    attestation: { uri: FIELDS.attestation },
    brokerageCountersignature: {
      authority: cs.authority,
      machineId: cs.machine_id,
      nonce: cs.nonce,
      sig: cs.sig,
    },
  };
}

describe("brokerage countersignature round-trip (advisor signs → SDK verifies)", () => {
  it("verifies a valid witness against the authority key, in the trust set", async () => {
    const { env } = authorityEnv();
    const authority = loadBrokerageAuthority(env)!;
    expect(authority).toBeTruthy();
    const cs = authority.sign(FIELDS);

    const res = await verifyBrokerageCountersignature(receiptFrom(cs), {
      trustedAuthorities: [DID],
      resolveAuthorityKeyB64: async () => authority.publicKeyB64,
    });
    expect(res.ok).toBe(true);
    expect(res.authority).toBe(DID);
  });

  it("fails when the authority is not in the trust set (validity is relative to a trusted authority)", async () => {
    const { env } = authorityEnv();
    const authority = loadBrokerageAuthority(env)!;
    const cs = authority.sign(FIELDS);
    const res = await verifyBrokerageCountersignature(receiptFrom(cs), {
      trustedAuthorities: ["did:web:someone-else.example"],
      resolveAuthorityKeyB64: async () => authority.publicKeyB64,
    });
    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/not in the trust set/);
  });

  it("fails when a bound field is altered (witness can't be lifted onto another receipt)", async () => {
    const { env } = authorityEnv();
    const authority = loadBrokerageAuthority(env)!;
    const cs = authority.sign(FIELDS);
    const receipt = receiptFrom(cs);
    // Swap the job the witness was bound to.
    receipt.job.uri = "at://did:plc:req/dev.cocore.compute.job/EVIL";
    const res = await verifyBrokerageCountersignature(receipt, {
      trustedAuthorities: [DID],
      resolveAuthorityKeyB64: async () => authority.publicKeyB64,
    });
    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/did not verify/);
  });

  it("fails when the machineId is swapped (names the specific serving machine)", async () => {
    const { env } = authorityEnv();
    const authority = loadBrokerageAuthority(env)!;
    const cs = authority.sign(FIELDS);
    const receipt = receiptFrom({ ...cs, machine_id: "some-other-machine" });
    const res = await verifyBrokerageCountersignature(receipt, {
      trustedAuthorities: [DID],
      resolveAuthorityKeyB64: async () => authority.publicKeyB64,
    });
    expect(res.ok).toBe(false);
  });

  it("returns null-config when the signing key/DID env is absent (fail-closed, no crash)", () => {
    expect(loadBrokerageAuthority({})).toBeNull();
    expect(loadBrokerageAuthority({ COCORE_BROKERAGE_DID: DID })).toBeNull();
  });

  it("the served DID document round-trips: SDK resolver extracts the authority's own key", () => {
    const { env } = authorityEnv();
    const authority = loadBrokerageAuthority(env)!;
    const doc = brokerageDidDocument(authority.did, authority.publicKeyB64);
    // The SDK's resolver (brokerageKeyFromDidDoc) must recover EXACTLY the raw
    // key the advisor signs with — otherwise countersignatures wouldn't verify.
    expect(brokerageKeyFromDidDoc(doc as Parameters<typeof brokerageKeyFromDidDoc>[0])).toBe(
      authority.publicKeyB64,
    );
  });
});
