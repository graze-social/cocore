import { describe, expect, it } from "vitest";

import { admissionEnforced, admit, INSUFFICIENT_CREDITS } from "./admission.server.ts";

const rich = async () => ({
  ok: true,
  balance: 2_806_415,
  required: 200_000,
  shortBy: 0,
  pendingGrant: false,
});
const broke = async () => ({
  ok: false,
  balance: 12_000,
  required: 200_000,
  shortBy: 188_000,
  pendingGrant: false,
});
const down = async () => {
  throw new Error("connect ECONNREFUSED");
};

describe("admission floor", () => {
  it("is off unless COCORE_ENFORCE_ADMISSION is truthy", () => {
    expect(admissionEnforced({})).toBe(false);
    expect(admissionEnforced({ COCORE_ENFORCE_ADMISSION: "0" })).toBe(false);
    expect(admissionEnforced({ COCORE_ENFORCE_ADMISSION: "1" })).toBe(true);
    expect(admissionEnforced({ COCORE_ENFORCE_ADMISSION: "true" })).toBe(true);
  });

  it("lets a funded requester through in either mode", async () => {
    for (const enforce of [false, true]) {
      const d = await admit("did:plc:rich", 100_000, { enforce, check: rich, log: () => {} });
      expect(d.refusal).toBeNull();
      expect(d.result?.ok).toBe(true);
    }
  });

  it("observe mode logs the would-be refusal and still dispatches", async () => {
    const lines: string[] = [];
    const d = await admit("did:plc:broke", 100_000, {
      enforce: false,
      check: broke,
      log: (l) => lines.push(l),
    });
    expect(d.refusal).toBeNull();
    expect(d.note).toMatch(/would refuse/);
    expect(lines[0]).toMatch(/short by 188,000/);
  });

  it("enforce mode answers 402 with the insufficient_credits code and the numbers", async () => {
    const d = await admit("did:plc:broke", 100_000, { enforce: true, check: broke, log: () => {} });
    expect(d.refusal?.status).toBe(402);
    const body = await d.refusal!.json();
    expect(body.error.code).toBe(INSUFFICIENT_CREDITS);
    expect(body.error.message).toMatch(/balance 12,000 CC/);
    expect(body.error.message).toMatch(/needs 200,000 CC/);
  });

  it("fails open when the ledger is unreachable, even in enforce mode", async () => {
    const lines: string[] = [];
    const d = await admit("did:plc:any", 100_000, {
      enforce: true,
      check: down,
      log: (l) => lines.push(l),
    });
    expect(d.refusal).toBeNull();
    expect(d.result).toBeNull();
    expect(lines[0]).toMatch(/ledger unreachable/);
  });
});
