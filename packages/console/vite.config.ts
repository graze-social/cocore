import path from "node:path";
import { fileURLToPath } from "node:url";

import mdx from "@mdx-js/rollup";
import { browserslistToTargets } from "lightningcss";
import browserslist from "browserslist";
import rehypeSlug from "rehype-slug";
import remarkFrontmatter from "remark-frontmatter";
import remarkGfm from "remark-gfm";
import remarkMdxFrontmatter from "remark-mdx-frontmatter";
import { tanstackStart } from "@tanstack/react-start/plugin/vite";
import stylexPlugin from "@stylexjs/unplugin";
import viteReact from "@vitejs/plugin-react";
import { defineConfig, mergeConfig, type Plugin } from "vite";
import { defineConfig as defineVitestConfig } from "vitest/config";

const rootDir = path.dirname(fileURLToPath(import.meta.url));

/**
 * Production is served by `vite preview` (see the `start` script), and Vite's
 * preview server hands static files to sirv, which hardcodes
 * `Cache-Control: no-cache` on every hit regardless of filename:
 *
 *   headers["Cache-Control"] = isEtag ? "no-cache" : "no-store";
 *
 * Every file Vite emits under `/assets/` is content-hashed, so `no-cache` buys
 * nothing and costs a great deal: the browser must revalidate ~60 files on
 * every navigation, and Railway's edge can't cache any of them. Measured on
 * console.cocore.dev before this plugin: a *warm* load transferred only 23KB
 * of JS yet still spent 1.66s on 50 conditional GETs.
 *
 * sirv writes the header itself via `res.writeHead(code, headers)`, so a plain
 * pre-middleware loses the race — we have to intercept the write. Unhashed
 * files from `public/` (favicon, goobies, fonts) get a short revalidatable TTL
 * instead of `immutable`, since their URLs are stable across deploys.
 *
 * Matching is a deliberate allowlist of paths that are served straight off
 * disk, NOT a file-extension test: plenty of real routes set their own
 * Cache-Control on purpose (`/og.png` caches for a day, `/lexicons/*` for an
 * hour, `/agent.*` are no-store), and an extension rule silently stomped
 * `/og.png` down to an hour.
 */
const IMMUTABLE_CACHE = "public, max-age=31536000, immutable";
const PUBLIC_ASSET_CACHE = "public, max-age=3600";
/** Everything Vite emits here is content-hashed; no route serves from it. */
const IMMUTABLE_PREFIX = "/assets/";
/** Static, unhashed files copied verbatim out of `public/`. */
const PUBLIC_ASSET_PREFIXES = ["/goobies/", "/og-fonts/"];
const PUBLIC_ASSET_PATHS = new Set(["/favicon.svg", "/app-icon.svg", "/robots.txt"]);

function assetCacheHeaders(): Plugin {
  return {
    name: "cocore:preview-asset-cache-headers",
    configurePreviewServer(server) {
      // `configurePreviewServer` runs before Vite installs its own
      // middlewares, so this sees the request first.
      server.middlewares.use((req, res, next) => {
        const pathname = (req.url ?? "").split("?")[0] ?? "";
        const isPublicAsset =
          PUBLIC_ASSET_PATHS.has(pathname) ||
          PUBLIC_ASSET_PREFIXES.some((prefix) => pathname.startsWith(prefix));
        const cacheControl = pathname.startsWith(IMMUTABLE_PREFIX)
          ? IMMUTABLE_CACHE
          : isPublicAsset
            ? PUBLIC_ASSET_CACHE
            : null;
        if (cacheControl === null) return next();

        const originalWriteHead = res.writeHead.bind(res);
        res.writeHead = function patchedWriteHead(status: number, ...rest: unknown[]) {
          // Drop sirv's own Cache-Control from the headers object it passes
          // positionally, then set ours — `writeHead` merges what
          // `setHeader` has recorded with the object argument.
          for (const arg of rest) {
            if (arg && typeof arg === "object" && !Array.isArray(arg)) {
              for (const key of Object.keys(arg as Record<string, unknown>)) {
                if (key.toLowerCase() === "cache-control") {
                  delete (arg as Record<string, unknown>)[key];
                }
              }
            }
          }
          res.setHeader("Cache-Control", cacheControl);
          return originalWriteHead(status, ...(rest as []));
        } as typeof res.writeHead;
        next();
      });
    },
  };
}

export default mergeConfig(
  defineConfig({
    resolve: {
      tsconfigPaths: true,
      // Explicit `@/` → src alias so Vitest (which doesn't apply
      // `tsconfigPaths`) resolves the same paths the app does. Scoped to
      // `@/` so it never rewrites `@scope/pkg` imports.
      alias: [{ find: /^@\//, replacement: `${path.join(rootDir, "src")}/` }],
    },
    // Native bindings: Rolldown's dep optimizer reads js-binding.js, which
    // embeds/loads the .node binary and fails UTF-8 decoding.
    optimizeDeps: { exclude: ["@resvg/resvg-js"] },
    ssr: { external: ["@resvg/resvg-js"] },
    server: { port: 3000 },
    preview: {
      port: 3000,
      // Allow the production reverse proxy + any *.railway.app subdomain
      // when running behind Railway. CONSOLE_ALLOWED_HOSTS is a
      // comma-separated env knob for additional public hostnames.
      allowedHosts: [
        ".cocore.dev",
        ".railway.app",
        ...(process.env["CONSOLE_ALLOWED_HOSTS"]
          ?.split(",")
          .map((s) => s.trim())
          .filter(Boolean) ?? []),
      ],
    },
    plugins: [
      // MDX must run before viteReact so the React plugin sees compiled JSX,
      // not raw .mdx. `enforce: "pre"` is set by @mdx-js/rollup.
      {
        enforce: "pre",
        ...mdx({
          jsxImportSource: "react",
          providerImportSource: "@mdx-js/react",
          remarkPlugins: [
            remarkGfm,
            [remarkFrontmatter, "yaml"],
            [remarkMdxFrontmatter, { name: "frontmatter" }],
          ],
          rehypePlugins: [rehypeSlug],
        }),
      },
      stylexPlugin.vite({
        treeshakeCompensation: true,
        dev: process.env.NODE_ENV !== "production",
        // Pin StyleX's collected CSS into our global `styles.css` asset (the
        // one linked on every page in __root.tsx). Without this, the plugin
        // appends its CSS to the *first* CSS asset in the bundle, which
        // silently moves to a route chunk (e.g. ChatPage's `katex.min.css`)
        // the moment any component adds a side-effect CSS import — leaving the
        // rest of the app unstyled in production. Match `assets/styles-<hash>.css`.
        cssInjectionTarget: (fileName: string) =>
          /(^|\/)styles(-[A-Za-z0-9_-]+)?\.css$/.test(fileName),
        aliases: {
          "@/*": [path.join(rootDir, "./src/*")],
        },
        lightningcssOptions: {
          targets: browserslistToTargets(browserslist("baseline 2024")),
        },
      }),
      tanstackStart(),
      viteReact({ include: /\.(mdx|js|jsx|ts|tsx)$/ }),
      assetCacheHeaders(),
    ],
  }),
  defineVitestConfig({
    test: {
      environment: "node",
      include: ["src/**/*.test.ts"],
      pool: "forks",
    },
  }),
);
