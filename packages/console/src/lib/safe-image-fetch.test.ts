// Unit tests for the SSRF guard (assertPublicUrl / safeFetchImage).
//
// The guard is the sole thing standing between caller-supplied image URLs
// and the internal network, so it gets exercised against every blocked
// range plus DNS-rebind-to-internal (a public hostname resolving to a
// private IP). DNS is mocked so the tests are hermetic.

import assert from "node:assert/strict";
import { describe, test } from "vitest";

import {
  assertPublicUrl,
  isBlockedAddress,
  safeFetchImage,
  UnsafeImageUrlError,
} from "./safe-image-fetch.server.ts";

const publicDns = async (_host: string) => ["93.184.216.34"]; // example.com-ish

describe("isBlockedAddress", () => {
  const blocked = [
    "127.0.0.1",
    "0.0.0.0",
    "10.1.2.3",
    "172.16.5.5",
    "172.31.255.255",
    "192.168.1.1",
    "169.254.169.254", // cloud metadata
    "100.64.0.1", // CGNAT
    "::1",
    "::",
    "fe80::1",
    "fc00::1",
    "fd12:3456::1",
    "::ffff:127.0.0.1", // IPv4-mapped loopback
    "::ffff:10.0.0.1", // IPv4-mapped private
    "224.0.0.1", // multicast
  ];
  for (const ip of blocked) {
    test(`blocks ${ip}`, () => {
      assert.equal(isBlockedAddress(ip), true);
    });
  }

  const allowed = ["93.184.216.34", "8.8.8.8", "1.1.1.1", "2606:2800:220:1::"];
  for (const ip of allowed) {
    test(`allows ${ip}`, () => {
      assert.equal(isBlockedAddress(ip), false);
    });
  }
});

describe("assertPublicUrl", () => {
  test("rejects non-http(s) schemes", async () => {
    await assert.rejects(
      () => assertPublicUrl("file:///etc/passwd", publicDns),
      UnsafeImageUrlError,
    );
    await assert.rejects(() => assertPublicUrl("ftp://host/x", publicDns), UnsafeImageUrlError);
    await assert.rejects(
      () => assertPublicUrl("data:image/png;base64,AAAA", publicDns),
      UnsafeImageUrlError,
    );
  });

  test("rejects a literal loopback IP URL", async () => {
    await assert.rejects(
      () => assertPublicUrl("http://127.0.0.1/x", publicDns),
      UnsafeImageUrlError,
    );
  });

  test("rejects the cloud metadata IP", async () => {
    await assert.rejects(
      () => assertPublicUrl("http://169.254.169.254/latest/meta-data/", publicDns),
      UnsafeImageUrlError,
    );
  });

  test("rejects a literal private IP URL", async () => {
    await assert.rejects(
      () => assertPublicUrl("http://10.0.0.5/x", publicDns),
      UnsafeImageUrlError,
    );
  });

  test("rejects an IPv6 loopback literal URL", async () => {
    await assert.rejects(() => assertPublicUrl("http://[::1]/x", publicDns), UnsafeImageUrlError);
  });

  test("rejects a hostname that resolves to a private IP (DNS rebinding)", async () => {
    const rebindDns = async (_host: string) => ["10.0.0.5"];
    await assert.rejects(
      () => assertPublicUrl("http://evil.example.com/x", rebindDns),
      UnsafeImageUrlError,
    );
  });

  test("rejects when ANY resolved address is private", async () => {
    const mixedDns = async (_host: string) => ["93.184.216.34", "127.0.0.1"];
    await assert.rejects(
      () => assertPublicUrl("http://mixed.example.com/x", mixedDns),
      UnsafeImageUrlError,
    );
  });

  test("allows a normal public hostname (mocked DNS)", async () => {
    const { url, pinnedAddress } = await assertPublicUrl(
      "https://images.example.com/cat.png",
      publicDns,
    );
    assert.equal(url.hostname, "images.example.com");
    assert.equal(pinnedAddress, "93.184.216.34");
  });

  test("allows a public literal IP URL", async () => {
    const { pinnedAddress } = await assertPublicUrl("https://8.8.8.8/x", publicDns);
    assert.equal(pinnedAddress, "8.8.8.8");
  });
});

describe("safeFetchImage", () => {
  test("fetches and returns bytes+mime for a public image", async () => {
    const fetchImpl = (async () =>
      new Response(new Uint8Array([1, 2, 3]), {
        status: 200,
        headers: { "content-type": "image/png" },
      })) as unknown as typeof fetch;
    const { bytes, mime } = await safeFetchImage("https://images.example.com/a.png", {
      maxBytes: 1024,
      dnsLookup: publicDns,
      fetchImpl,
    });
    assert.equal(mime, "image/png");
    assert.deepEqual([...bytes], [1, 2, 3]);
  });

  test("never fetches a blocked URL (generic error, fetch not called)", async () => {
    let called = false;
    const fetchImpl = (async () => {
      called = true;
      return new Response(null, { status: 200 });
    }) as unknown as typeof fetch;
    await assert.rejects(
      () =>
        safeFetchImage("http://169.254.169.254/latest/meta-data/", {
          maxBytes: 1024,
          dnsLookup: publicDns,
          fetchImpl,
        }),
      UnsafeImageUrlError,
    );
    assert.equal(called, false);
  });

  test("rejects a non-image content-type with a generic error", async () => {
    const fetchImpl = (async () =>
      new Response("<html>internal</html>", {
        status: 200,
        headers: { "content-type": "text/html" },
      })) as unknown as typeof fetch;
    await assert.rejects(
      () =>
        safeFetchImage("https://images.example.com/a.png", {
          maxBytes: 1024,
          dnsLookup: publicDns,
          fetchImpl,
        }),
      (e: Error) => {
        assert.ok(e instanceof UnsafeImageUrlError);
        // Generic message — no upstream mime/status leaked.
        assert.doesNotMatch(e.message, /text\/html|200/);
        return true;
      },
    );
  });

  test("rejects an oversized response", async () => {
    const fetchImpl = (async () =>
      new Response(new Uint8Array(4096), {
        status: 200,
        headers: { "content-type": "image/png" },
      })) as unknown as typeof fetch;
    await assert.rejects(
      () =>
        safeFetchImage("https://images.example.com/big.png", {
          maxBytes: 1024,
          dnsLookup: publicDns,
          fetchImpl,
        }),
      UnsafeImageUrlError,
    );
  });

  test("collapses an upstream error status to a generic error", async () => {
    const fetchImpl = (async () =>
      new Response("boom", { status: 500 })) as unknown as typeof fetch;
    await assert.rejects(
      () =>
        safeFetchImage("https://images.example.com/a.png", {
          maxBytes: 1024,
          dnsLookup: publicDns,
          fetchImpl,
        }),
      (e: Error) => {
        assert.ok(e instanceof UnsafeImageUrlError);
        assert.doesNotMatch(e.message, /500|boom/);
        return true;
      },
    );
  });
});
