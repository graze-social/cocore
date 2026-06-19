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
import { defineConfig, mergeConfig } from "vite";
import { defineConfig as defineVitestConfig } from "vitest/config";

const rootDir = path.dirname(fileURLToPath(import.meta.url));

export default mergeConfig(
  defineConfig({
    resolve: { tsconfigPaths: true },
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
        aliases: {
          "@/*": [path.join(rootDir, "./src/*")],
        },
        lightningcssOptions: {
          targets: browserslistToTargets(browserslist("baseline 2024")),
        },
      }),
      tanstackStart(),
      viteReact({ include: /\.(mdx|js|jsx|ts|tsx)$/ }),
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
