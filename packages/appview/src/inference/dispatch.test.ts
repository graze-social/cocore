import { describe, expect, it } from "vitest";
import nacl from "tweetnacl";

import {
  NoProvidersConnectedError,
  NoProvidersForCountryError,
  NoProvidersForModelError,
  ProviderPayoutsNotEligibleError,
  TargetProviderNotConnectedError,
  classifyDispatchError,
  filterByPayoutsEligibility,
  openFromProvider,
  sealToProvider,
} from "./dispatch.ts";

describe("seal/open round-trip", () => {
  it("a prompt sealed to the provider opens back to plaintext", () => {
    const provider = nacl.box.keyPair();
    const ephemeral = nacl.box.keyPair();
    const plaintext = new TextEncoder().encode("hello, inference");

    const framed = sealToProvider(plaintext, provider.publicKey, ephemeral.secretKey);
    // The provider decrypts with its secret + the requester's ephemeral pub.
    const opened = openFromProvider(framed, ephemeral.publicKey, provider.secretKey);
    expect(opened).not.toBeNull();
    expect(new TextDecoder().decode(opened!)).toBe("hello, inference");
  });

  it("a tampered ciphertext fails to open", () => {
    const provider = nacl.box.keyPair();
    const ephemeral = nacl.box.keyPair();
    const framed = sealToProvider(
      new TextEncoder().encode("secret"),
      provider.publicKey,
      ephemeral.secretKey,
    );
    framed[framed.length - 1] ^= 0xff;
    expect(openFromProvider(framed, ephemeral.publicKey, provider.secretKey)).toBeNull();
  });

  it("a too-short frame is rejected without throwing", () => {
    const provider = nacl.box.keyPair();
    expect(openFromProvider(new Uint8Array(5), provider.publicKey, provider.secretKey)).toBeNull();
  });
});

describe("filterByPayoutsEligibility", () => {
  const rows = [{ did: "did:plc:a" }, { did: "did:plc:b" }, { did: "did:plc:c" }];

  it("passes through verbatim when no eligibility set", () => {
    expect(
      filterByPayoutsEligibility(rows, { payoutsEligibleDids: null, selfLoopExempt: null }),
    ).toEqual(rows);
  });

  it("keeps only eligible DIDs", () => {
    const out = filterByPayoutsEligibility(rows, {
      payoutsEligibleDids: new Set(["did:plc:b"]),
      selfLoopExempt: null,
    });
    expect(out.map((r) => r.did)).toEqual(["did:plc:b"]);
  });

  it("exempts the self-loop DID even when not in the eligible set", () => {
    const out = filterByPayoutsEligibility(rows, {
      payoutsEligibleDids: new Set(["did:plc:b"]),
      selfLoopExempt: "did:plc:a",
    });
    expect(out.map((r) => r.did).sort()).toEqual(["did:plc:a", "did:plc:b"]);
  });
});

describe("classifyDispatchError", () => {
  it("maps each known error class to its code", () => {
    expect(classifyDispatchError(new NoProvidersConnectedError())).toBe("no-providers-connected");
    expect(classifyDispatchError(new NoProvidersForModelError("m", 2))).toBe(
      "no-providers-for-model",
    );
    expect(classifyDispatchError(new TargetProviderNotConnectedError("did:plc:x"))).toBe(
      "target-provider-not-connected",
    );
    expect(classifyDispatchError(new ProviderPayoutsNotEligibleError("did:plc:y"))).toBe(
      "provider-payouts-not-eligible",
    );
    expect(classifyDispatchError(new NoProvidersForCountryError("m", "US", 3))).toBe(
      "no-providers-for-country",
    );
  });

  it("falls back to advisor-transport for unknown errors", () => {
    expect(classifyDispatchError(new Error("socket hang up"))).toBe("advisor-transport");
  });
});
