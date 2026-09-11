import { describe, expect, it } from "vitest";

import {
  createAppResolver,
  matchesRegisteredReturnUrl,
  parseRegistration,
} from "./app-registration.ts";

const APP = "did:plc:graze";
const RECORD = {
  $type: "dev.cocore.app.registration",
  name: "  Graze  ",
  description: "Daily feed summaries",
  website: "https://www.graze.social",
  returnUrls: [
    "https://www.graze.social/app/account",
    "http://insecure.example/x",
    "javascript:alert(1)",
  ],
  createdAt: "2026-09-11T00:00:00Z",
};

function fakeFetch(routes: Record<string, () => Response | Promise<Response>>): typeof fetch {
  return (async (input: string | URL | Request) => {
    const url =
      typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    for (const [prefix, handler] of Object.entries(routes)) {
      if (url.startsWith(prefix)) return handler();
    }
    return new Response("not found", { status: 404 });
  }) as typeof fetch;
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

describe("parseRegistration", () => {
  it("cleans the name and keeps only https return URLs", () => {
    const reg = parseRegistration(APP, RECORD)!;
    expect(reg.name).toBe("Graze");
    expect(reg.returnUrls).toEqual(["https://www.graze.social/app/account"]);
    expect(reg.website).toBe("https://www.graze.social/");
  });
  it("is null without a name", () => {
    expect(parseRegistration(APP, { returnUrls: [] })).toBeNull();
    expect(parseRegistration(APP, "nope")).toBeNull();
  });
});

describe("matchesRegisteredReturnUrl", () => {
  const registered = ["https://www.graze.social/app/account"];
  it("matches on origin + path, allowing a query string", () => {
    expect(
      matchesRegisteredReturnUrl(
        "https://www.graze.social/app/account?cocore=connected",
        registered,
      ),
    ).toBe(true);
    expect(matchesRegisteredReturnUrl("https://www.graze.social/app/account/", registered)).toBe(
      true,
    );
  });
  it("rejects other paths, hosts, and schemes", () => {
    expect(matchesRegisteredReturnUrl("https://www.graze.social/app/other", registered)).toBe(
      false,
    );
    expect(matchesRegisteredReturnUrl("https://evil.example/app/account", registered)).toBe(false);
    expect(matchesRegisteredReturnUrl("http://www.graze.social/app/account", registered)).toBe(
      false,
    );
  });
});

describe("createAppResolver", () => {
  it("reads the record from the app's PDS and verifies the host via well-known", async () => {
    let recordFetches = 0;
    const resolver = createAppResolver({
      resolvePds: async (did) => (did === APP ? "https://pds.example" : null),
      fetch: fakeFetch({
        "https://pds.example/xrpc/com.atproto.repo.getRecord": () => {
          recordFetches += 1;
          return json({ uri: "at://x", value: RECORD });
        },
        "https://www.graze.social/.well-known/cocore-app.json": () => json({ did: APP }),
        "https://evil.example/.well-known/cocore-app.json": () =>
          json({ did: "did:plc:someoneelse" }),
      }),
    });
    const reg = await resolver.resolve(APP);
    expect(reg?.name).toBe("Graze");
    await resolver.resolve(APP);
    expect(recordFetches).toBe(1); // cached
    expect(await resolver.verifyHost("www.graze.social", APP)).toBe(true);
    expect(await resolver.verifyHost("evil.example", APP)).toBe(false);
    expect(await resolver.verifyHost("nowhere.example", APP)).toBe(false);
  });
  it("returns null for an unregistered DID and for a non-DID", async () => {
    const resolver = createAppResolver({
      resolvePds: async () => "https://pds.example",
      fetch: fakeFetch({}),
    });
    expect(await resolver.resolve("did:plc:nobody")).toBeNull();
    expect(await resolver.resolve("not-a-did")).toBeNull();
  });
});
