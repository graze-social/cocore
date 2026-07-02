// Sorted-key canonical JSON serialization.
//
// This MUST produce byte-identical output to provider/src/canonical.rs.
// The provider signs `to_canonical_bytes(record)` with its Secure Enclave;
// the AppView verifies that signature by re-canonicalizing here and
// recomputing. Any divergence breaks every receipt.
//
// Rules (matched in canonical.rs):
//   * UTF-8 output, no BOM.
//   * Object keys sorted lexicographically (UTF-16 code unit order, which
//     matches Rust's String <-> String comparison for the BMP and is
//     identical for ASCII keys — every key in our lexicons is ASCII).
//   * No insignificant whitespace.
//   * Strings escaped with the smallest legal form: \", \\, \b, \f, \n,
//     \r, \t, and \u00XX (lowercase hex) for control characters.
//   * Numbers: integers only. Floats throw. Lexicon-defined numeric
//     fields are integer; we never sign over a float. Integer magnitude
//     is capped to the JS safe-integer range (|n| <= 2^53-1); anything
//     larger throws rather than emitting a silently-rounded value. This
//     stays inside Rust's i64/u64 range (canonical.rs), so the byte
//     contract holds for every value we can faithfully round-trip.
//
// Byte-identical contract: this serializer, provider/src/canonical.rs, and
// sdk/py/cocore/canonical.py MUST emit the same bytes for the same value.
// The one subtle divergence is object-key ordering — Rust sorts by UTF-8
// byte order (== Unicode code point order) and Python by code point, but
// JS Array.prototype.sort orders by UTF-16 code unit, which disagrees for
// astral-plane (surrogate-pair) keys. Every key in our lexicons is ASCII,
// so rather than reimplement a code-point sort we REJECT any non-ASCII
// object key here (and Python rejects the same). That keeps all three
// implementations provably byte-identical.
//   * Booleans: true / false.
//   * null is allowed.
//   * Bytes (signatures etc.) are base64-encoded by callers BEFORE
//     entering this serializer; this layer treats them as strings.

export class CanonicalError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CanonicalError";
  }
}

export function canonicalize(value: unknown): string {
  const parts: string[] = [];
  emit(parts, value);
  return parts.join("");
}

export function canonicalBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalize(value));
}

function emit(out: string[], v: unknown): void {
  if (v === null) {
    out.push("null");
    return;
  }
  if (v === true) {
    out.push("true");
    return;
  }
  if (v === false) {
    out.push("false");
    return;
  }
  if (typeof v === "number") {
    if (!Number.isInteger(v)) {
      throw new CanonicalError("floating-point numbers are not allowed in signed records");
    }
    // Cap to the JS safe-integer range. Above it, `String(v)` emits a
    // silently-rounded value that no other implementation would reproduce,
    // so reject rather than sign over an ambiguous number.
    if (!Number.isSafeInteger(v)) {
      throw new CanonicalError(
        `integer ${v} exceeds the safe-integer range (|n| <= 2^53-1) and cannot be canonicalised`,
      );
    }
    out.push(String(v));
    return;
  }
  if (typeof v === "bigint") {
    // Bound to Rust's i64/u64 range (canonical.rs uses as_i64 || as_u64).
    if (v < -(2n ** 63n) || v > 2n ** 64n - 1n) {
      throw new CanonicalError(
        `bigint ${v} is outside the signed/unsigned 64-bit range and cannot be canonicalised`,
      );
    }
    out.push(v.toString());
    return;
  }
  if (typeof v === "string") {
    emitString(out, v);
    return;
  }
  if (Array.isArray(v)) {
    out.push("[");
    for (let i = 0; i < v.length; i++) {
      if (i > 0) out.push(",");
      emit(out, v[i]);
    }
    out.push("]");
    return;
  }
  if (typeof v === "object") {
    const obj = v as Record<string, unknown>;
    const keys = Object.keys(obj);
    // Reject non-ASCII keys: Array.prototype.sort orders by UTF-16 code unit,
    // which diverges from the code-point order Rust/Python use for astral-plane
    // keys. Every key in our lexicons is ASCII, so rejecting keeps all three
    // canonicalisers byte-identical instead of risking a silent sort mismatch.
    for (const k of keys) {
      for (let i = 0; i < k.length; i++) {
        if (k.charCodeAt(i) > 0x7f) {
          throw new CanonicalError(
            `object key ${JSON.stringify(k)} contains a non-ASCII character; ` +
              "canonical keys must be ASCII for cross-language byte parity",
          );
        }
      }
    }
    keys.sort();
    out.push("{");
    for (let i = 0; i < keys.length; i++) {
      if (i > 0) out.push(",");
      emitString(out, keys[i]!);
      out.push(":");
      emit(out, obj[keys[i]!]);
    }
    out.push("}");
    return;
  }
  throw new CanonicalError(`unsupported value type: ${typeof v}`);
}

function emitString(out: string[], s: string): void {
  out.push('"');
  for (const ch of s) {
    const cp = ch.codePointAt(0)!;
    if (ch === '"') out.push('\\"');
    else if (ch === "\\") out.push("\\\\");
    else if (ch === "\b") out.push("\\b");
    else if (ch === "\f") out.push("\\f");
    else if (ch === "\n") out.push("\\n");
    else if (ch === "\r") out.push("\\r");
    else if (ch === "\t") out.push("\\t");
    else if (cp < 0x20) out.push("\\u" + cp.toString(16).padStart(4, "0"));
    else out.push(ch);
  }
  out.push('"');
}
