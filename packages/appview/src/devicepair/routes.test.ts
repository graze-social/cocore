import { describe, expect, it } from "vitest";

import { AccountStore } from "../operational/account-store.ts";
import { withAppviewServer } from "../api/http-app.ts";
import { buildDevicePairRouter } from "./routes.ts";
import { PairStore } from "./pair-store.ts";

function router(overrides: Partial<Parameters<typeof buildDevicePairRouter>[1]> = {}) {
  return buildDevicePairRouter(new PairStore("https://console.test"), {
    accountStore: new AccountStore(":memory:"),
    appviewDid: "did:web:appview.test",
    apiBase: "https://console.test",
    returnHosts: ["www.graze.social"],
    ...overrides,
  });
}

describe("devicePair routes", () => {
  it("start returns a deviceId + userCode + console verification URI", async () => {
    await withAppviewServer(router(), async (base) => {
      const r = await fetch(`${base}/xrpc/dev.cocore.devicePair.start`, { method: "POST" });
      expect(r.status).toBe(200);
      const b = (await r.json()) as {
        deviceId: string;
        userCode: string;
        verificationUri: string;
      };
      expect(b.deviceId).toBeTruthy();
      expect(b.userCode).toBeTruthy();
      expect(b.verificationUri).toContain("https://console.test/devices/new?code=");
    });
  });

  it("poll is pending after start and 404 for an unknown device", async () => {
    await withAppviewServer(router(), async (base) => {
      const start = (await (
        await fetch(`${base}/xrpc/dev.cocore.devicePair.start`, { method: "POST" })
      ).json()) as { deviceId: string };
      const pending = await fetch(
        `${base}/xrpc/dev.cocore.devicePair.poll?deviceId=${start.deviceId}`,
      );
      expect(pending.status).toBe(200);
      expect(((await pending.json()) as { status: string }).status).toBe("pending");

      const unknown = await fetch(`${base}/xrpc/dev.cocore.devicePair.poll?deviceId=nope`);
      expect(unknown.status).toBe(404);
    });
  });

  it("confirm requires service auth (401 without a token)", async () => {
    await withAppviewServer(router(), async (base) => {
      const r = await fetch(`${base}/xrpc/dev.cocore.devicePair.confirm`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ userCode: "ABCD1234", decision: "approve" }),
      });
      expect(r.status).toBe(401);
    });
  });

  it("405s on the wrong method", async () => {
    await withAppviewServer(router(), async (base) => {
      expect((await fetch(`${base}/xrpc/dev.cocore.devicePair.start`)).status).toBe(405); // GET
    });
  });
});

describe("devicePair routes: application metadata", () => {
  it("start accepts app metadata and describe echoes it, with the return URL allowlisted", async () => {
    await withAppviewServer(router(), async (base) => {
      const r = await fetch(`${base}/xrpc/dev.cocore.devicePair.start`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          appName: "Graze",
          keyName: "Graze Feed Pulse",
          returnUrl: "https://www.graze.social/app/account?cocore=connected",
        }),
      });
      expect(r.status).toBe(200);
      const started = (await r.json()) as { userCode: string };
      const d = await fetch(
        `${base}/xrpc/dev.cocore.devicePair.describe?userCode=${started.userCode.toLowerCase()}`,
      );
      expect(d.status).toBe(200);
      const described = (await d.json()) as Record<string, unknown>;
      expect(described).toMatchObject({
        status: "pending",
        appName: "Graze",
        keyName: "Graze Feed Pulse",
        returnUrl: "https://www.graze.social/app/account?cocore=connected",
      });
      expect(typeof described.expiresInSecs).toBe("number");
      expect(described).not.toHaveProperty("deviceId");
    });
  });

  it("drops a return URL whose host is not allowlisted, and tolerates a garbage body", async () => {
    await withAppviewServer(router(), async (base) => {
      const r = await fetch(`${base}/xrpc/dev.cocore.devicePair.start`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ appName: "Graze", returnUrl: "https://evil.example/steal" }),
      });
      const started = (await r.json()) as { userCode: string };
      const described = (await (
        await fetch(`${base}/xrpc/dev.cocore.devicePair.describe?userCode=${started.userCode}`)
      ).json()) as Record<string, unknown>;
      expect(described.appName).toBe("Graze");
      expect(described).not.toHaveProperty("returnUrl");

      const junk = await fetch(`${base}/xrpc/dev.cocore.devicePair.start`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "this is not json",
      });
      expect(junk.status).toBe(200);
    });
  });

  it("describe is 400 without a code and 404 for an unknown one", async () => {
    await withAppviewServer(router(), async (base) => {
      expect((await fetch(`${base}/xrpc/dev.cocore.devicePair.describe`)).status).toBe(400);
      expect(
        (await fetch(`${base}/xrpc/dev.cocore.devicePair.describe?userCode=ZZZZZZZZ`)).status,
      ).toBe(404);
    });
  });

  it("rate-limits start per client", async () => {
    await withAppviewServer(
      router({ rateLimits: { windowMs: 60_000, start: 2, describe: 100, confirm: 100 } }),
      async (base) => {
        const hit = (ip: string) =>
          fetch(`${base}/xrpc/dev.cocore.devicePair.start`, {
            method: "POST",
            headers: { "x-forwarded-for": ip },
          });
        expect((await hit("1.1.1.1")).status).toBe(200);
        expect((await hit("1.1.1.1")).status).toBe(200);
        expect((await hit("1.1.1.1")).status).toBe(429);
        expect((await hit("2.2.2.2")).status).toBe(200); // a different client is unaffected
      },
    );
  });
});
