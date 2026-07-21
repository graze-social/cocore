import { spawn, type ChildProcess } from "node:child_process";
import { createServer, type Server } from "node:http";
import { mkdtemp, mkdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { WebSocket, WebSocketServer } from "ws";

import {
  runDispatch,
  type DispatchEvent,
} from "../../../packages/appview/src/inference/dispatch.ts";

const ROOT = resolve(fileURLToPath(new URL("../../..", import.meta.url)));
const PROVIDER_DID = "did:plc:resume-fault-provider";
const MACHINE_ID = "resume-fault-machine";
type FaultMode = "none" | "prefill" | "repeated" | "completion" | "expiry";
type Status = { invocations: number; active: boolean };

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

async function waitFor<T>(
  read: () => Promise<T>,
  accept: (value: T) => boolean,
  label: string,
  timeoutMs = 10_000,
): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  let lastError: unknown;
  while (Date.now() < deadline) {
    try {
      const value = await read();
      if (accept(value)) return value;
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error(`timed out waiting for ${label}${lastError ? `: ${String(lastError)}` : ""}`);
}

async function readStatus(path: string): Promise<Status> {
  try {
    return JSON.parse(await readFile(path, "utf8")) as Status;
  } catch (error) {
    throw new Error(`invalid provider status: ${String(error)}`);
  }
}

const trackedChildren: ChildProcess[] = [];
function startChild(
  command: string,
  args: string[],
  env: NodeJS.ProcessEnv,
): {
  child: ChildProcess;
  output: () => string;
} {
  let log = "";
  const child = spawn(command, args, { cwd: ROOT, env, stdio: ["ignore", "pipe", "pipe"] });
  trackedChildren.push(child);
  child.stdout?.on("data", (data) => (log += data.toString()));
  child.stderr?.on("data", (data) => (log += data.toString()));
  return { child, output: () => log };
}

// Backstop: if the script exits via an uncaught throw/rejection before the
// finally runs, kill every spawned child synchronously so no advisor/provider
// process is orphaned to poison the next run.
process.on("exit", () => {
  for (const child of trackedChildren) {
    if (child.exitCode === null) {
      try {
        child.kill("SIGKILL");
      } catch {
        // already gone
      }
    }
  }
});

/** Tag a spawned child so an unexpected exit is visible in failure logs. */
function watchExit(child: ChildProcess, label: string): void {
  child.on("exit", (code, signal) => {
    if (code !== 0 && code !== null) {
      console.error(`[harness] ${label} exited unexpectedly code=${code} signal=${signal}`);
    }
  });
}

async function stopChild(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null) return;
  child.kill("SIGTERM");
  await Promise.race([
    new Promise<void>((resolve) => child.once("exit", () => resolve())),
    new Promise<void>((resolve) => setTimeout(resolve, 1_000)),
  ]);
  if (child.exitCode === null) child.kill("SIGKILL");
}

async function closeServer(server: Server): Promise<void> {
  await new Promise<void>((resolve) => server.close(() => resolve()));
}

async function readBody(request: import("node:http").IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) chunks.push(Buffer.from(chunk));
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new Error("request body is not valid JSON");
  }
}

async function main(): Promise<void> {
  const work = await mkdtemp(join(tmpdir(), "cocore-resume-e2e-"));
  const home = join(work, "home");
  const statusPath = join(work, "provider-status.json");
  await mkdir(home);

  let receipts = 0;
  const pds = createServer((request, response) => {
    void (async () => {
      if (request.url === "/api/pds/createRecord") {
        const body = (await readBody(request)) as { collection?: string };
        if (body.collection === "dev.cocore.compute.receipt") receipts += 1;
        response.writeHead(200, { "content-type": "application/json" });
        response.end(
          JSON.stringify({
            uri: `at://${PROVIDER_DID}/dev.cocore.compute.receipt/${receipts}`,
            cid: `bafyreceipt${receipts}`,
          }),
        );
        return;
      }
      response.writeHead(503, { "content-type": "application/json" });
      response.end('{"error":"service auth disabled in local fault test"}');
    })().catch((error) => {
      response.writeHead(500);
      response.end(String(error));
    });
  });
  await new Promise<void>((resolve) => pds.listen(0, "127.0.0.1", resolve));
  const pdsAddress = pds.address();
  assert(pdsAddress && typeof pdsAddress === "object", "mock PDS failed to listen");
  const pdsBase = `http://127.0.0.1:${pdsAddress.port}`;

  // PORT=0 → the advisor binds an ephemeral port and logs it; parsing that
  // line instead of reserve-and-release avoids the TOCTOU where another
  // process (a concurrent CI job) grabs the released port before spawn.
  const advisor = startChild(
    process.execPath,
    ["--experimental-strip-types", "infra/advisor/src/main.ts"],
    {
      ...process.env,
      PORT: "0",
      COCORE_ADVISOR_SESSION_RESUME_GRACE_MS: "1000",
      COCORE_ADVISOR_PREFLIGHT_TIMEOUT_MS: "1000",
      COCORE_ADVISOR_WS_KEEPALIVE_MS: "1000",
    },
  );

  watchExit(advisor.child, "advisor");
  const advisorPort = Number(
    await waitFor(
      // eslint-disable-next-line @typescript-eslint/require-await
      async () => advisor.output().match(/advisor: http\+ws on :(\d+)/)?.[1],
      (port) => Boolean(port),
      "advisor bound port",
      30_000,
    ),
  );
  const advisorHttp = `http://127.0.0.1:${advisorPort}`;
  const advisorWs = `ws://127.0.0.1:${advisorPort}/v1/agent`;
  let mode: FaultMode = "none";
  let stage = 0;
  let invocationBaseline = 0;
  let blockedUntil = 0;
  let injectedDrops = 0;
  const proxy = new WebSocketServer({ host: "127.0.0.1", port: 0, path: "/v1/agent" });
  await new Promise<void>((resolve) => proxy.once("listening", resolve));
  const proxyAddress = proxy.address();
  assert(proxyAddress !== null && typeof proxyAddress === "object", "fault proxy failed to listen");

  const arm = (nextMode: FaultMode, baseline: number): void => {
    mode = nextMode;
    stage = 0;
    invocationBaseline = baseline;
    blockedUntil = 0;
    injectedDrops = 0;
  };

  proxy.on("connection", (providerSocket) => {
    if (Date.now() < blockedUntil) {
      providerSocket.terminate();
      return;
    }
    // A reconnecting upstream: a transient advisorSocket error/close must
    // NOT tear down the provider's connection (which causes a reconnect
    // storm). Instead we re-establish the upstream and buffer the
    // provider's frames until it opens. Only an injected `drop()` kills
    // both sides (and sets `closed` so the upstream won't reconnect).
    let advisorSocket: WebSocket | null = null;
    const pending: Array<{ data: WebSocket.RawData; binary: boolean }> = [];
    let closed = false;
    const drop = (): void => {
      if (closed) return;
      closed = true;
      injectedDrops += 1;
      providerSocket.terminate();
      advisorSocket?.terminate();
    };
    const sendToAdvisor = (data: WebSocket.RawData, binary: boolean): void => {
      if (advisorSocket && advisorSocket.readyState === WebSocket.OPEN) {
        advisorSocket.send(data, { binary });
      } else {
        pending.push({ data, binary });
      }
    };
    const connectUpstream = (): void => {
      const upstream = new WebSocket(advisorWs);
      advisorSocket = upstream;
      upstream.on("error", () => {
        // Swallow; the "close" handler reconnects.
      });
      upstream.on("open", () => {
        for (const message of pending) upstream.send(message.data, { binary: message.binary });
        pending.length = 0;
      });
      upstream.on("close", () => {
        if (closed) return;
        // Transient upstream loss — reconnect shortly, keeping the
        // provider's connection alive across the blip.
        setTimeout(() => {
          if (!closed && providerSocket.readyState === WebSocket.OPEN) connectUpstream();
        }, 100);
      });
      upstream.on("message", (data, binary) => {
        let frame: { type?: string; next_seq?: number } = {};
        try {
          frame = JSON.parse(data.toString()) as { type?: string; next_seq?: number };
        } catch {
          // Forward non-JSON transport frames unchanged.
        }
        if (
          mode === "repeated" &&
          stage === 1 &&
          frame.type === "inference_ack" &&
          (frame.next_seq ?? 0) > 0
        ) {
          mode = "none";
          stage = 2;
          drop();
          return;
        }
        providerSocket.send(data, { binary }, (error) => {
          if (error || frame.type !== "inference_request") return;
          if (mode !== "prefill" && mode !== "expiry") return;
          const activeMode = mode;
          mode = "none";
          void waitFor(
            () => readStatus(statusPath),
            (status) => status.invocations > invocationBaseline,
            "provider invocation to enter prefill",
          ).then(() => {
            // The block window is bounded on BOTH sides: it must outlast the
            // 1s resume grace (so the session expires) but end before the
            // fault provider's 3.6s prefill finishes (so the post-block
            // resume rejection aborts the job before any receipt publishes).
            // 2.5s sits ~1.5s clear of the grace and ~1s clear of generation
            // end — wide margins for a loaded CI runner (the old 1.3s window
            // left only 300ms above the grace and flaked).
            if (activeMode === "expiry") blockedUntil = Date.now() + 2_500;
            drop();
          });
        });
      });
    };
    connectUpstream();
    providerSocket.on("message", (data, binary) => {
      let frame: { type?: string } = {};
      try {
        frame = JSON.parse(data.toString()) as { type?: string };
      } catch {
        // Forward non-JSON transport frames unchanged.
      }
      if (mode === "repeated" && stage === 0 && frame.type === "inference_chunk") {
        stage = 1;
        drop();
        return;
      }
      if (mode === "completion" && frame.type === "inference_complete") {
        mode = "none";
        drop();
        return;
      }
      sendToAdvisor(data, binary);
    });
    providerSocket.on("close", () => {
      closed = true;
      advisorSocket?.terminate();
    });
  });

  const provider = startChild(
    "provider/target/debug/examples/resume_fault_provider",
    [`ws://127.0.0.1:${proxyAddress.port}/v1/agent`, pdsBase, statusPath],
    {
      ...process.env,
      HOME: home,
      COCORE_ALLOW_INSECURE_ADVISOR: "1",
      RUST_LOG: "warn",
    },
  );

  watchExit(provider.child, "provider");

  const providerRows = async (): Promise<
    Array<{ did: string; machineId: string; attestedAt: string | null }>
  > => {
    const response = await fetch(`${advisorHttp}/providers`);
    return (await response.json()) as Array<{
      did: string;
      machineId: string;
      attestedAt: string | null;
    }>;
  };
  // Gate on ATTESTATION, not mere registration. `runDispatch` → `pickProvider`
  // only considers providers whose `attestedAt` is set (it filters the pool by
  // it), so waiting for the row to merely appear is a race: under a loaded CI
  // runner the attestation challenge/response round-trip lags registration, and
  // a dispatch fired in that window fails with NoProvidersConnectedError — the
  // job never runs, and the (misleading) "inference ran more than once" invocation
  // assertion trips on invocations=0. Requiring `attestedAt` closes the window.
  const waitForProvider = () =>
    waitFor(
      providerRows,
      (rows) =>
        rows.some(
          (row) => row.did === PROVIDER_DID && row.machineId === MACHINE_ID && row.attestedAt,
        ),
      "provider registration",
      30_000,
    );
  const health = async (): Promise<{ sessions: number }> => {
    const response = await fetch(`${advisorHttp}/healthz`);
    return (await response.json()) as { sessions: number };
  };

  let published = 0;
  const runConversation = async (scenario: FaultMode, expectCompletion: boolean): Promise<void> => {
    await waitForProvider();
    const before = await readStatus(statusPath);
    const receiptsBefore = receipts;
    arm(scenario, before.invocations);
    const events: DispatchEvent[] = [];
    const collect = async (): Promise<void> => {
      for await (const event of runDispatch(
        {
          did: "did:plc:resume-fault-requester",
          model: "stub",
          prompt: `conversation-${published + 1}`,
          maxTokensOut: 64,
          priceCeiling: { amount: 1000, currency: "USD" },
          targetProviderDid: PROVIDER_DID,
          targetMachineId: MACHINE_ID,
        },
        {
          advisorUrl: advisorHttp,
          exchangeDid: "did:plc:resume-fault-exchange",
          transport: {
            async publish({ collection }) {
              published += 1;
              return {
                uri: `at://did:plc:resume-fault-requester/${collection}/${published}`,
                cid: `bafyjob${published}`,
              };
            },
          },
          getProfile: async () => null,
        },
      )) {
        events.push(event);
      }
    };
    await Promise.race([
      collect(),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error(`${scenario} conversation timed out`)), 20_000),
      ),
    ]);

    // Best-effort provider-side cleanup: the terminal ACK that removes the
    // provider's invocation travels through the fault proxy, which can lose
    // it during a transient upstream reconnect (a test artifact — production
    // has no proxy). Wait for it but don't hard-fail: the provider's bounded
    // retention timer is the real backstop, and a leaked job doesn't affect
    // the per-scenario invocation-count or delivery assertions below.
    try {
      await waitFor(
        () => readStatus(statusPath),
        (status) => status.invocations === before.invocations + 1 && !status.active,
        `${scenario} invocation cleanup`,
        5_000,
      );
    } catch {
      // Ack lost in the proxy; the retention timer will reclaim it.
    }
    await waitFor(health, (value) => value.sessions === 0, `${scenario} advisor session cleanup`);
    const finalInvocations = (await readStatus(statusPath)).invocations;
    assert(
      finalInvocations === before.invocations + 1,
      // NB: fires for BOTH too-few and too-many — spell out the actual counts so
      // a "0 vs 1" dispatch failure isn't misread as a "2 vs 1" double-run.
      `${scenario}: expected exactly one inference (before=${before.invocations}, after=${finalInvocations})`,
    );

    const completions = events.filter((event) => event.kind === "complete");
    const errors = events.filter((event) => event.kind === "error");
    if (expectCompletion) {
      assert(completions.length === 1, `${scenario}: expected one completion`);
      assert(errors.length === 0, `${scenario}: unexpected terminal error`);
      assert(receipts === receiptsBefore + 1, `${scenario}: expected exactly one receipt`);
      const chunks = events.filter((event) => event.kind === "chunk");
      const sequences = chunks.map((event) => event.seq);
      assert(new Set(sequences).size === sequences.length, `${scenario}: duplicate chunk sequence`);
      assert(
        sequences.every((sequence, index) => sequence === index),
        `${scenario}: chunks were not contiguous and ordered`,
      );
      assert(
        chunks
          .map((event) => event.text)
          .join("")
          .includes("cocore stub provider"),
        `${scenario}: incomplete output (missing stub header)`,
      );
      assert(
        chunks
          .map((event) => event.text)
          .join("")
          .includes("max_tokens_out="),
        `${scenario}: truncated output (missing terminal field)`,
      );
    } else {
      assert(completions.length === 0, `${scenario}: completion arrived after expiry`);
      assert(errors.length === 1, `${scenario}: expected one terminal error`);
      assert(
        errors[0]?.reason.includes("resume-expired"),
        `${scenario}: expected resume-expired reason, got ${errors[0]?.reason}`,
      );
      assert(receipts === receiptsBefore, `${scenario}: receipt published after expiry`);
    }
    let expectedDrops: number;
    if (scenario === "repeated") expectedDrops = 2;
    else if (scenario === "none") expectedDrops = 0;
    else expectedDrops = 1;
    assert(
      injectedDrops === expectedDrops,
      `${scenario}: expected ${expectedDrops} injected reset(s), got ${injectedDrops}`,
    );
    console.log(
      `PASS ${scenario}: events=${events.length} receipts=${receipts} invocations=${before.invocations + 1}`,
    );
  };

  try {
    await waitFor(
      async () => (await fetch(`${advisorHttp}/healthz`)).ok,
      Boolean,
      "advisor startup",
      30_000,
    );
    await waitFor(
      () => readStatus(statusPath),
      () => true,
      "provider status",
      30_000,
    );
    await runConversation("prefill", true);
    await runConversation("repeated", true);
    await runConversation("completion", true);
    await runConversation("none", true);
    await runConversation("none", true);
    await runConversation("none", true);
    await runConversation("expiry", false);
    console.log("provider resume fault matrix passed");
  } catch (error) {
    console.error(`\n--- advisor ---\n${advisor.output().slice(-8_000)}`);
    console.error(`\n--- provider ---\n${provider.output().slice(-8_000)}`);
    throw error;
  } finally {
    await stopChild(provider.child);
    await stopChild(advisor.child);
    for (const socket of proxy.clients) socket.terminate();
    await new Promise<void>((resolve) => proxy.close(() => resolve()));
    await closeServer(pds);
    await rm(work, { recursive: true, force: true });
  }
}

await main();
