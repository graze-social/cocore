"""Sorted-key canonical JSON serialization.

MUST produce byte-identical output to provider/src/canonical.rs and
packages/sdk/src/canonical.ts — the provider signs the canonical bytes with its
Secure Enclave key and this module re-canonicalizes to verify. Any divergence
breaks every signature.

Rules (matched across all three implementations): UTF-8, object keys sorted
lexicographically, no insignificant whitespace, minimal string escapes, integers
only (floats raise), booleans true/false, null allowed, bytes are base64 strings
before they reach this layer.

Byte-identical contract (L6): this module, packages/sdk/src/canonical.ts, and
provider/src/canonical.rs MUST emit the same bytes for the same value.
  * Object keys are restricted to ASCII. JS Array.prototype.sort orders by
    UTF-16 code unit, which disagrees with Rust/Python code-point ordering for
    astral-plane keys; every key in our lexicons is ASCII, so all three
    implementations REJECT a non-ASCII key rather than risk a silent sort
    mismatch.
  * Integer magnitude is capped to Rust's i64/u64 range (canonical.rs uses
    as_i64 || as_u64); anything outside raises rather than emitting a value the
    other implementations can't reproduce.
"""

from __future__ import annotations

from typing import Any


class CanonicalError(ValueError):
    pass


def canonicalize(value: Any) -> str:
    parts: list[str] = []
    _emit(parts, value)
    return "".join(parts)


def canonical_bytes(value: Any) -> bytes:
    return canonicalize(value).encode("utf-8")


def _emit(out: list[str], v: Any) -> None:
    if v is None:
        out.append("null")
    elif v is True:
        out.append("true")
    elif v is False:
        out.append("false")
    elif isinstance(v, int):  # note: bool handled above (bool is a subclass)
        # Cap to Rust's i64/u64 range (canonical.rs uses as_i64 || as_u64).
        # Python ints are unbounded, so an out-of-range value would serialize to
        # digits no other implementation can reproduce — reject instead.
        if v < -(2**63) or v > 2**64 - 1:
            raise CanonicalError(
                f"integer {v} is outside the signed/unsigned 64-bit range "
                "and cannot be canonicalised"
            )
        out.append(str(v))
    elif isinstance(v, float):
        raise CanonicalError("floating-point numbers are not allowed in signed records")
    elif isinstance(v, str):
        _emit_string(out, v)
    elif isinstance(v, (list, tuple)):
        out.append("[")
        for i, item in enumerate(v):
            if i > 0:
                out.append(",")
            _emit(out, item)
        out.append("]")
    elif isinstance(v, dict):
        # Reject non-ASCII keys for cross-language byte parity (see module docstring).
        for key in v.keys():
            if not isinstance(key, str):
                raise CanonicalError(f"object key must be a string, got {type(key).__name__}")
            if not key.isascii():
                raise CanonicalError(
                    f"object key {key!r} contains a non-ASCII character; "
                    "canonical keys must be ASCII for cross-language byte parity"
                )
        out.append("{")
        for i, key in enumerate(sorted(v.keys())):
            if i > 0:
                out.append(",")
            _emit_string(out, key)
            out.append(":")
            _emit(out, v[key])
        out.append("}")
    else:
        raise CanonicalError(f"unsupported value type: {type(v).__name__}")


_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


def _emit_string(out: list[str], s: str) -> None:
    out.append('"')
    for ch in s:
        esc = _ESCAPES.get(ch)
        if esc is not None:
            out.append(esc)
        elif ord(ch) < 0x20:
            out.append("\\u" + format(ord(ch), "04x"))
        else:
            out.append(ch)
    out.append('"')
