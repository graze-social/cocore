import { test } from "vitest";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { Store } from "../store.ts";
import { AccountStore } from "../operational/account-store.ts";
import { buildAppviewApp } from "./server.ts";
import { withAppviewServer } from "./http-app.ts";

const APPVIEW_DID = "did:web:appview.test";

function setup(): { store: Store; accountStore: AccountStore } {
  const dir = mkdtempSync(join(tmpdir(), "cocore-bugreport-"));
  return {
    store: new Store(join(dir, "appview.db")),
    accountStore: new AccountStore(join(dir, "account.db")),
  };
}

const bundle = gzipSync(Buffer.from("fake diagnostic bundle"));

test("POST /api/agent/bug-report: 401 without a bearer key", async () => {
  const { store, accountStore } = setup();
  await withAppviewServer(
    buildAppviewApp(store, { accountStore, appviewDid: APPVIEW_DID }),
    async (base) => {
      const res = await fetch(`${base}/api/agent/bug-report`, {
        method: "POST",
        headers: { "content-type": "application/gzip" },
        body: bundle,
      });
      assert.equal(res.status, 401);
    },
  );
});

test("POST /api/agent/bug-report: 415 on a non-gzip content-type", async () => {
  const { store, accountStore } = setup();
  const { secret } = accountStore.createKey({ did: "did:plc:p", name: "m" });
  await withAppviewServer(
    buildAppviewApp(store, { accountStore, appviewDid: APPVIEW_DID }),
    async (base) => {
      const res = await fetch(`${base}/api/agent/bug-report`, {
        method: "POST",
        headers: { authorization: `Bearer ${secret}`, "content-type": "application/json" },
        body: "{}",
      });
      assert.equal(res.status, 415);
    },
  );
});

test("POST /api/agent/bug-report: stores the bundle and returns a ticket id", async () => {
  const { store, accountStore } = setup();
  const did = "did:plc:provider1";
  const { secret } = accountStore.createKey({ did, name: "m" });
  await withAppviewServer(
    buildAppviewApp(store, { accountStore, appviewDid: APPVIEW_DID }),
    async (base) => {
      const res = await fetch(`${base}/api/agent/bug-report`, {
        method: "POST",
        headers: { authorization: `Bearer ${secret}`, "content-type": "application/gzip" },
        body: bundle,
      });
      assert.equal(res.status, 201);
      const body = (await res.json()) as { ticketId: string };
      assert.match(body.ticketId, /^br_[0-9a-f]{8}$/);

      // The metadata row + on-disk bytes landed (bytes untouched).
      const row = accountStore.db
        .prepare(`SELECT did, file_path, size_bytes FROM bug_reports WHERE ticket_id = ?`)
        .get(body.ticketId) as { did: string; file_path: string; size_bytes: number };
      assert.equal(row.did, did);
      assert.equal(row.size_bytes, bundle.byteLength);
      assert.deepEqual(readFileSync(row.file_path), bundle);
    },
  );
});

test("POST /api/agent/bug-report: 400 on an empty body", async () => {
  const { store, accountStore } = setup();
  const { secret } = accountStore.createKey({ did: "did:plc:p", name: "m" });
  await withAppviewServer(
    buildAppviewApp(store, { accountStore, appviewDid: APPVIEW_DID }),
    async (base) => {
      const res = await fetch(`${base}/api/agent/bug-report`, {
        method: "POST",
        headers: { authorization: `Bearer ${secret}`, "content-type": "application/gzip" },
        body: new Uint8Array(0),
      });
      assert.equal(res.status, 400);
    },
  );
});

test("POST /api/agent/bug-report: persists the reporter's X-Cocore-Note", async () => {
  const { store, accountStore } = setup();
  const did = "did:plc:provider2";
  const { secret } = accountStore.createKey({ did, name: "m" });
  const note = "confidential stuck on Applying and the tray keeps restarting";
  await withAppviewServer(
    buildAppviewApp(store, { accountStore, appviewDid: APPVIEW_DID }),
    async (base) => {
      const res = await fetch(`${base}/api/agent/bug-report`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${secret}`,
          "content-type": "application/gzip",
          "x-cocore-note": note,
        },
        body: bundle,
      });
      assert.equal(res.status, 201);
      const { ticketId } = (await res.json()) as { ticketId: string };
      // The reporter's own account of the problem is the whole point of the
      // header; dropping it (as both upload routes used to) forced triage of
      // br_57cef8d6 to infer the symptom from logs alone.
      const row = accountStore.db
        .prepare(`SELECT note FROM bug_reports WHERE ticket_id = ?`)
        .get(ticketId) as { note: string };
      assert.equal(row.note, note);
    },
  );
});

test("POST /api/agent/bug-report: a missing note stores an empty string", async () => {
  const { store, accountStore } = setup();
  const { secret } = accountStore.createKey({ did: "did:plc:provider3", name: "m" });
  await withAppviewServer(
    buildAppviewApp(store, { accountStore, appviewDid: APPVIEW_DID }),
    async (base) => {
      const res = await fetch(`${base}/api/agent/bug-report`, {
        method: "POST",
        headers: { authorization: `Bearer ${secret}`, "content-type": "application/gzip" },
        body: bundle,
      });
      const { ticketId } = (await res.json()) as { ticketId: string };
      const row = accountStore.db
        .prepare(`SELECT note FROM bug_reports WHERE ticket_id = ?`)
        .get(ticketId) as { note: string };
      assert.equal(row.note, "");
    },
  );
});
