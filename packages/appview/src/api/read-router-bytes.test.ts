import { describe, expect, it } from "vitest";

import { decodeBytesFields } from "./read-router.ts";

describe("decodeBytesFields (verifyReceipt lexicon pass)", () => {
  it("decodes every bytes field of a receipt, including the brokerage witness sig", () => {
    const sig = Buffer.from([1, 2, 3]).toString("base64");
    const out = decodeBytesFields({
      enclaveSignature: sig,
      price: { amount: 2100, currency: "CC" },
      brokerageCountersignature: {
        authority: "did:web:advisor.cocore.dev",
        machineId: "m1",
        nonce: "n",
        sig,
      },
    });
    expect(out["enclaveSignature"]).toEqual(Uint8Array.from([1, 2, 3]));
    const cs = out["brokerageCountersignature"] as Record<string, unknown>;
    expect(cs["sig"]).toEqual(Uint8Array.from([1, 2, 3]));
    expect(cs["authority"]).toBe("did:web:advisor.cocore.dev");
    // Untouched fields pass through by reference-equal value.
    expect(out["price"]).toEqual({ amount: 2100, currency: "CC" });
  });

  it("leaves a receipt without a countersignature alone and never throws on odd shapes", () => {
    expect(
      decodeBytesFields({ enclaveSignature: "AQ==" })["brokerageCountersignature"],
    ).toBeUndefined();
    expect(
      decodeBytesFields({ brokerageCountersignature: "nope" })["brokerageCountersignature"],
    ).toBe("nope");
    expect(decodeBytesFields({ brokerageCountersignature: { sig: 7 } })).toEqual({
      brokerageCountersignature: { sig: 7 },
    });
  });
});
