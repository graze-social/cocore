import { describe, expect, it } from "vitest";

import {
  buildImagesEnvelopeBytes,
  type EnvelopeImage,
  IMAGES_ENVELOPE_VERSION,
  IMAGES_V1,
  parseImagesEnvelope,
} from "./images-envelope.ts";
import { sha256Hex } from "./publish.ts";

// Cross-language parity fixture. The SAME canonical string + SHA-256 are
// asserted on the Rust side (provider/src/images_envelope.rs cross_lang
// test), so a divergence in either canonicalizer is caught. If you change
// the envelope shape, update both.
const FIXTURE_IMAGES: EnvelopeImage[] = [{ mime: "image/png", data: "aGVsbG8=" }];
const FIXTURE_CANONICAL = '{"images":[{"data":"aGVsbG8=","mime":"image/png"}],"v":1}';
const FIXTURE_SHA256 = "87727768fff8767ca20fdc4880a22a2899216722d446d498da395ef1ada58681";

describe("images envelope", () => {
  it("serializes to the canonical (sorted-key) bytes", () => {
    const bytes = buildImagesEnvelopeBytes(FIXTURE_IMAGES);
    expect(new TextDecoder().decode(bytes)).toBe(FIXTURE_CANONICAL);
  });

  it("commitment over the canonical bytes matches the cross-language fixture", async () => {
    const commitment = await sha256Hex(buildImagesEnvelopeBytes(FIXTURE_IMAGES));
    expect(commitment).toBe(FIXTURE_SHA256);
  });

  it("round-trips through parseImagesEnvelope", () => {
    const parsed = parseImagesEnvelope(buildImagesEnvelopeBytes(FIXTURE_IMAGES));
    expect(parsed.v).toBe(1);
    expect(parsed.images).toEqual(FIXTURE_IMAGES);
  });

  it("serializes multiple images in order", () => {
    const bytes = buildImagesEnvelopeBytes([
      { mime: "image/png", data: "AAAA" },
      { mime: "image/jpeg", data: "BBBB" },
    ]);
    expect(new TextDecoder().decode(bytes)).toBe(
      '{"images":[{"data":"AAAA","mime":"image/png"},{"data":"BBBB","mime":"image/jpeg"}],"v":1}',
    );
  });

  it("rejects an unknown envelope version", () => {
    const bad = new TextEncoder().encode('{"v":2,"images":[]}');
    expect(() => parseImagesEnvelope(bad)).toThrow(/version/);
  });

  it("rejects a malformed image entry", () => {
    const bad = new TextEncoder().encode('{"v":1,"images":[{"mime":"image/png"}]}');
    expect(() => parseImagesEnvelope(bad)).toThrow(/data/);
  });

  it("exports the wire constant + version", () => {
    expect(IMAGES_V1).toBe("images-v1");
    expect(IMAGES_ENVELOPE_VERSION).toBe(1);
  });
});
