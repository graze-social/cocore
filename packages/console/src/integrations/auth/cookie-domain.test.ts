// Pins the cookie-scoping rule for the cocore.dev cutover: the auth session
// cookie must be shared across the apex and *.cocore.dev (so a login on
// cocore.dev is also valid on console.cocore.dev), but MUST stay host-only on
// localhost and Railway preview domains.

import assert from "node:assert/strict";
import { test } from "vitest";

import { authCookieDomain } from "@/integrations/auth/cookie-domain.ts";

test("cocore.dev apex + subdomains share the registrable domain", () => {
  assert.equal(authCookieDomain("cocore.dev"), "cocore.dev");
  assert.equal(authCookieDomain("console.cocore.dev"), "cocore.dev");
  assert.equal(authCookieDomain("www.cocore.dev"), "cocore.dev");
  assert.equal(authCookieDomain("cocore.dev:443"), "cocore.dev");
  assert.equal(authCookieDomain("CONSOLE.COCORE.DEV"), "cocore.dev");
});

test("dev/preview/other hosts stay host-only (undefined)", () => {
  assert.equal(authCookieDomain("localhost:3000"), undefined);
  assert.equal(authCookieDomain("127.0.0.1:5599"), undefined);
  assert.equal(authCookieDomain("console-production-de0d.up.railway.app"), undefined);
  assert.equal(authCookieDomain("evilcocore.dev"), undefined);
  assert.equal(authCookieDomain(null), undefined);
  assert.equal(authCookieDomain(""), undefined);
});
