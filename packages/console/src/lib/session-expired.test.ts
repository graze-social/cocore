import { describe, expect, it } from "vitest";

import { isSessionExpiredError } from "./session-expired.ts";

describe("isSessionExpiredError", () => {
  it("matches the AppView dead-session 401 as surfaced by PDS helpers", () => {
    const e = new Error(
      'createRecord termsAcceptance 401: {"error":"AuthRequired","message":"underlying ATProto session no longer valid; re-authenticate"}',
    );
    expect(isSessionExpiredError(e)).toBe(true);
  });

  it("ignores other failures", () => {
    expect(
      isSessionExpiredError(new Error("createRecord termsAcceptance 400: InvalidRecord")),
    ).toBe(false);
    expect(isSessionExpiredError(new Error("exchange signTermsAcceptance 401: bad key"))).toBe(
      false,
    );
    expect(isSessionExpiredError(undefined)).toBe(false);
  });
});
