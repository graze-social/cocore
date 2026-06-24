#!/usr/bin/env python3
"""End-to-end smoke test for the cocore OpenAI-compatible endpoint.

Usage:
  pip install --user openai
  COCORE_API_KEY=cocore-... ./scripts/openai-e2e.py

Defaults the base URL to https://console.cocore.dev/api/v1; override
with COCORE_BASE_URL for a local console (e.g. http://localhost:3000/api/v1).

The script runs both chat code paths:
  1. Streaming — prints chunks as they arrive
  2. Non-streaming — buffered JSON, prints content + token usage

and the image-generation path:
  3. images.generate — text-to-image, writes the returned PNG to disk

Requires at least one attested provider on the configured advisor; the
provider's stub is non-deterministic but produces a short reply, and
`stub-flux` emits a fixed 1x1 PNG (no GPU needed).
"""

from __future__ import annotations

import os
import sys

try:
    from openai import OpenAI
except ImportError:
    print("openai not installed. Run: pip install --user openai", file=sys.stderr)
    sys.exit(1)


def main() -> int:
    api_key = os.environ.get("COCORE_API_KEY")
    if not api_key:
        print("COCORE_API_KEY not set. Generate one in /api-keys and export it.", file=sys.stderr)
        return 2

    base_url = os.environ.get("COCORE_BASE_URL", "https://console.cocore.dev/api/v1")
    model = os.environ.get("COCORE_MODEL", "stub")

    print(f"Base URL: {base_url}")
    print(f"Model:    {model}")
    print()

    client = OpenAI(base_url=base_url, api_key=api_key)
    messages = [{"role": "user", "content": "Say hello in three words."}]

    print("--- streaming ---")
    stream = client.chat.completions.create(model=model, messages=messages, stream=True)
    out = ""
    for chunk in stream:
        if not chunk.choices:
            continue
        delta = chunk.choices[0].delta
        text = getattr(delta, "content", None) or ""
        if text:
            out += text
            print(text, end="", flush=True)
    print()
    print(f"(streamed bytes: {len(out)})")
    print()

    print("--- buffered ---")
    resp = client.chat.completions.create(model=model, messages=messages, stream=False)
    print(resp.choices[0].message.content)
    if resp.usage:
        print(
            f"(usage: {resp.usage.prompt_tokens} prompt / "
            f"{resp.usage.completion_tokens} completion)"
        )
    print()

    # Image generation. cocore returns inline base64 (b64_json) only — point
    # COCORE_IMAGE_MODEL at `stub-flux` for a no-GPU smoke test, or a real
    # FLUX id on a capable Mac.
    image_model = os.environ.get("COCORE_IMAGE_MODEL", "stub-flux")
    print(f"--- images.generate ({image_model}) ---")
    import base64

    img = client.images.generate(
        model=image_model,
        prompt="a watercolor fox in a misty forest",
        n=1,
        response_format="b64_json",
    )
    b64 = img.data[0].b64_json
    out_path = os.environ.get("COCORE_IMAGE_OUT", "cocore-image.png")
    with open(out_path, "wb") as fh:
        fh.write(base64.b64decode(b64))
    print(f"wrote {out_path} ({len(b64)} b64 chars)")
    # The non-standard x_cocore block names who served it (OpenAI SDK exposes
    # unknown fields via model_extra).
    extra = getattr(img, "model_extra", None) or {}
    if extra.get("x_cocore"):
        print(f"x_cocore: {extra['x_cocore']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
