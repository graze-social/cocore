import { describe, expect, it, afterEach } from "vitest";

import { cocoreConfig } from "./cocore-config.ts";

/**
 * The console's service DID and the DID document it publishes must agree.
 *
 * They did not, between the cocore.dev cutover and 2026-09-15: the verifier
 * defaulted to did:web:console.cocore.dev while /.well-known/did.json published
 * did:web:cocore.dev. Every third-party service-auth call was unservable —
 * one audience is rejected here, the other is unresolvable by the caller's PDS.
 */
const KEY = "CONSOLE_PUBLIC_URL";
const OVERRIDE = "COCORE_CONSOLE_DID";

afterEach(() => {
  delete process.env[KEY];
  delete process.env[OVERRIDE];
});

describe("consoleDid", () => {
  it("matches the document published for the production URL", () => {
    process.env[KEY] = "https://cocore.dev";
    expect(cocoreConfig().consoleDid).toBe("did:web:cocore.dev");
  });

  it("tracks CONSOLE_PUBLIC_URL wherever it points", () => {
    process.env[KEY] = "https://console.cocore.dev";
    expect(cocoreConfig().consoleDid).toBe("did:web:console.cocore.dev");
  });

  it("ignores a trailing path and encodes a port per did:web", () => {
    process.env[KEY] = "http://127.0.0.1:3000/";
    expect(cocoreConfig().consoleDid).toBe("did:web:127.0.0.1%3A3000");
  });

  it("still honours an explicit override", () => {
    process.env[KEY] = "https://cocore.dev";
    process.env[OVERRIDE] = "did:web:example.test";
    expect(cocoreConfig().consoleDid).toBe("did:web:example.test");
  });

  it("falls back rather than throwing on an unparseable URL", () => {
    process.env[KEY] = "not a url";
    expect(cocoreConfig().consoleDid).toBe("did:web:console.cocore.dev");
  });
});
