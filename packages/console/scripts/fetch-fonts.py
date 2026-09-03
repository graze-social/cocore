#!/usr/bin/env python3
"""Re-vendor the self-hosted web fonts from Google Fonts.

We serve Space Grotesk + Space Mono ourselves (see the header of
src/styles.css for why). This script refetches them and regenerates the
@font-face block at the top of src/styles.css.

Run from packages/console:  python3 scripts/fetch-fonts.py

Filenames get a content hash so /fonts/ can be cached immutably by the
asset-cache plugin in vite.config.ts. unicode-range is copied verbatim from
Google's payload so browsers still fetch only the subsets they need.
"""

import hashlib
import os
import re
import urllib.request

QUERY = (
    "https://fonts.googleapis.com/css2"
    "?family=Space+Grotesk:wght@300..700"
    "&family=Space+Mono:ital,wght@0,400;0,700;1,400;1,700&display=swap"
)
# A modern desktop UA, or Google serves legacy formats instead of woff2.
UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)
FONT_DIR = "public/fonts"
STYLES = "src/styles.css"
HEADER_MARKER = "/* Self-hosted Space Grotesk"


def main() -> None:
    req = urllib.request.Request(QUERY, headers={"User-Agent": UA})
    css = urllib.request.urlopen(req).read().decode()

    for stale in os.listdir(FONT_DIR):
        if stale.endswith(".woff2"):
            os.remove(os.path.join(FONT_DIR, stale))

    faces = []
    for subset, body in re.findall(r"/\* (\S+) \*/\s*@font-face \{(.*?)\}", css, re.S):
        family = re.search(r"font-family: '([^']+)'", body).group(1)
        style = re.search(r"font-style: (\S+);", body).group(1)
        weight = re.search(r"font-weight: ([^;]+);", body).group(1).strip()
        url = re.search(r"url\((https://fonts\.gstatic\.com/[^)]+\.woff2)\)", body).group(1)
        urange = re.search(r"unicode-range: ([^;]+);", body).group(1).strip()

        data = urllib.request.urlopen(url).read()
        digest = hashlib.sha256(data).hexdigest()[:8]
        slug = family.lower().replace(" ", "-")
        name = f"{slug}-{subset}-{weight.replace(' ', '-')}-{style}-{digest}.woff2"
        with open(os.path.join(FONT_DIR, name), "wb") as fh:
            fh.write(data)
        faces.append((family, style, weight, name, urange))

    block = [
        HEADER_MARKER + " + Space Mono (SIL Open Font License 1.1;",
        " * see public/fonts/OFL.txt). Previously these came from a render-blocking",
        " * fonts.googleapis.com stylesheet, which put two extra third-party origins",
        " * (googleapis for the CSS, then gstatic for the files) in the critical",
        " * render path. Serving them ourselves removes both.",
        " *",
        " * Filenames carry a content hash so /fonts/ can be cached immutably (see the",
        " * asset-cache plugin in vite.config.ts). `unicode-range` is preserved",
        " * verbatim, so browsers still fetch only the subsets they actually need.",
        " * Regenerate with scripts/fetch-fonts.py if the families ever change. */",
        "",
    ]
    for family, style, weight, name, urange in faces:
        block += [
            "@font-face {",
            f"  font-family: '{family}';",
            f"  font-style: {style};",
            f"  font-weight: {weight};",
            "  font-display: swap;",
            f"  src: url('/fonts/{name}') format('woff2');",
            f"  unicode-range: {urange};",
            "}",
            "",
        ]

    existing = open(STYLES).read()
    tail = existing.split("*/", 1)[1].lstrip("\n") if existing.startswith(HEADER_MARKER) else existing
    open(STYLES, "w").write("\n".join(block) + "\n" + tail)
    print(f"vendored {len(faces)} faces into {FONT_DIR}/ and rewrote {STYLES}")


if __name__ == "__main__":
    main()
