import { describe, expect, it } from "vitest";

import { MAX_NOTE_CHARS, normalizeNote } from "./bug-reports.server.ts";

// The reporter's note arrives as an HTTP header (X-Cocore-Note) that the tray
// has always sent and the upload routes used to discard — triage of
// br_57cef8d6 had to reconstruct the reported symptoms from logs alone. It's
// now persisted, so pin the normalisation that makes header text safe to
// store: never null (the column is NOT NULL), no control characters, bounded.
describe("normalizeNote", () => {
  it("returns an empty string for absent input", () => {
    expect(normalizeNote(undefined)).toBe("");
    expect(normalizeNote(null)).toBe("");
    expect(normalizeNote("")).toBe("");
  });

  it("keeps ordinary prose intact", () => {
    expect(normalizeNote("  confidential is stuck on Applying  ")).toBe(
      "confidential is stuck on Applying",
    );
  });

  it("replaces control characters that header transport can smuggle in", () => {
    const raw = ["two", "lines", "and one"].join("\r\n") + "\ttabbed";
    expect(normalizeNote(raw)).toBe("two lines and one tabbed");
  });

  it("truncates to the cap", () => {
    expect(normalizeNote("x".repeat(MAX_NOTE_CHARS + 500)).length).toBe(MAX_NOTE_CHARS);
  });
});
