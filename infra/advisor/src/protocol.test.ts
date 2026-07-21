import { describe, expect, it } from "vitest";

import { validateFrame } from "./protocol.ts";

describe("stream resume wire contract", () => {
  it("accepts an additive provider resume frame", () => {
    const frame = {
      type: "inference_resume",
      session_id: "session-1",
      resume_token: "token-1",
      produced_seq: 7,
    };

    expect(validateFrame(frame)).toEqual({ ok: true, msg: frame });
  });

  it.each([
    [
      {
        type: "inference_resume",
        resume_token: "token-1",
        produced_seq: 1,
      },
      "session_id",
    ],
    [
      {
        type: "inference_resume",
        session_id: "session-1",
        produced_seq: 1,
      },
      "resume_token",
    ],
    [
      {
        type: "inference_resume",
        session_id: "session-1",
        resume_token: "token-1",
        produced_seq: -1,
      },
      "produced_seq",
    ],
    [
      {
        type: "inference_resume",
        session_id: "session-1",
        resume_token: "token-1",
        produced_seq: 1.5,
      },
      "produced_seq",
    ],
    [
      {
        type: "inference_resume",
        session_id: "session-1",
        resume_token: "token-1",
        produced_seq: 0x1_0000_0000,
      },
      "produced_seq",
    ],
  ])("rejects malformed resume frame %j", (frame, field) => {
    const result = validateFrame(frame);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain(field);
  });

  it("rejects an invalid advertised protocol version", () => {
    const register = {
      type: "register",
      provider_did: "did:plc:p",
      supported_models: ["stub"],
      encryption_pub_key: "e",
      attestation_pub_key: "a",
      stream_resume_version: 0,
    };
    expect(validateFrame(register)).toEqual({
      ok: false,
      reason: "register: stream_resume_version",
    });
  });

  it("keeps final_seq optional for legacy completion frames", () => {
    const legacy = {
      type: "inference_complete",
      session_id: "session-1",
      tokens_in: 1,
      tokens_out: 2,
      receipt_uri: "at://receipt/one",
    };
    expect(validateFrame(legacy)).toEqual({ ok: true, msg: legacy });
    expect(validateFrame({ ...legacy, final_seq: -1 })).toEqual({
      ok: false,
      reason: "inference_complete: final_seq",
    });
  });

  it.each([
    [
      {
        type: "inference_complete",
        session_id: "s",
        tokens_in: -1,
        tokens_out: 2,
        receipt_uri: "at://r",
      },
      "tokens_in",
    ],
    [
      {
        type: "inference_complete",
        session_id: "s",
        tokens_in: 1,
        tokens_out: -1,
        receipt_uri: "at://r",
      },
      "tokens_out",
    ],
    [
      {
        type: "inference_complete",
        session_id: "s",
        tokens_in: 1,
        tokens_out: 2,
        receipt_uri: 42,
      },
      "receipt_uri",
    ],
  ])("rejects malformed inference_complete accounting fields %j", (frame, field) => {
    const result = validateFrame(frame);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain(field);
  });
});
