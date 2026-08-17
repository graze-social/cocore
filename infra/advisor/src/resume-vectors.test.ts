// Advisor half of the shared stream-resume state-machine vectors
// (fixtures/stream-resume-vectors.json). The provider half lives in
// provider/src/advisor.rs; both consume the same numbers so the two
// hand-written implementations cannot drift apart silently.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, test } from "vitest";

import { SessionManager } from "./sessions.ts";

interface ChunkVector {
  name: string;
  nextSeq?: number;
  preAccept?: number[];
  seq: number;
  accept: boolean;
  nextSeqAfter: number;
}
interface ResumeVector {
  name: string;
  advisorNextSeq?: number;
  producedSeq?: number;
  status?: string;
  nextSeq?: number;
}
interface CompletionVector {
  name: string;
  nextSeq: number;
  finalSeq: number;
  accepted: boolean;
}

const vectors = JSON.parse(
  readFileSync(join(import.meta.dirname, "../../../fixtures/stream-resume-vectors.json"), "utf8"),
) as { chunk: ChunkVector[]; resume: ResumeVector[]; completion: CompletionVector[] };

function fakeRes() {
  return {
    statusCode: 0,
    writableEnded: false,
    chunks: [] as string[],
    setHeader() {},
    flushHeaders() {},
    write(s: string) {
      this.chunks.push(s);
      return true;
    },
    end() {
      this.writableEnded = true;
    },
  };
}

/** A resumable session pre-advanced to `nextSeq` by accepting in-order chunks. */
function sessionAt(nextSeq: number): { sm: SessionManager; res: ReturnType<typeof fakeRes> } {
  const sm = new SessionManager({ idleTimeoutMs: 60_000, resumeGraceMs: 30_000 });
  const res = fakeRes();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  sm.open("s", "did:plc:p", "m", "did:plc:r", res as any, undefined, "tok");
  for (let seq = 0; seq < nextSeq; seq++) {
    sm.acceptChunk("s", seq, { type: "chunk", sessionId: "s", seq, ciphertext: [seq] });
  }
  return { sm, res };
}

test.for(vectors.chunk)("chunk vector: $name", (v) => {
  const { sm, res } = sessionAt(v.preAccept ? v.preAccept.length : (v.nextSeq ?? 0));
  const before = res.chunks.length;
  const r = sm.acceptChunk("s", v.seq, {
    type: "chunk",
    sessionId: "s",
    seq: v.seq,
    ciphertext: [v.seq],
  });
  expect(r?.nextSeq).toBe(v.nextSeqAfter);
  // "accept" means the chunk was delivered to the requester this call.
  expect(res.chunks.length > before).toBe(v.accept);
});

test.for(vectors.resume.filter((v) => v.status !== undefined))("resume vector: $name", (v) => {
  const { sm } = sessionAt(v.advisorNextSeq ?? 0);
  sm.detachForMachine("did:plc:p", "m");
  const r = sm.resume("s", "did:plc:p", "m", "tok", v.producedSeq ?? 0);
  expect(r.status).toBe(v.status);
  expect(r.nextSeq).toBe(v.nextSeq);
});

test.for(vectors.completion)("completion vector: $name", (v) => {
  const { sm } = sessionAt(v.nextSeq);
  const r = sm.complete("s", { tokensIn: 1, tokensOut: 1, receiptUri: "at://r" }, v.finalSeq);
  expect(r?.accepted).toBe(v.accepted);
});
