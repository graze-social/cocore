export const INFERENCE_DOCS_SECTIONS = ["Getting started", "API reference", "Tool setup"] as const;

export const COMMUNITY_TOOLS_PATH = "/docs/community-tools" as const;
export const COMMUNITY_TOOLS_NAV_ID = "community-tools" as const;

export type InferenceDocsSection = (typeof INFERENCE_DOCS_SECTIONS)[number];

export type InferenceDocsSlug =
  | "quickstart"
  | "connect-your-app"
  | "api-reference"
  | "opencode"
  | "cursor"
  | "claude-code";

export type InferenceDocsEntry = {
  slug: InferenceDocsSlug | null;
  /** When set, sidebar links here instead of `/docs/inference/{slug}`. */
  href?: typeof COMMUNITY_TOOLS_PATH;
  section: InferenceDocsSection;
  label: string;
  title: string;
  description: string;
};

export const INFERENCE_DOCS_CATALOG: Array<InferenceDocsEntry> = [
  {
    slug: null,
    section: "Getting started",
    label: "Overview",
    title: "Inference API",
    description: "OpenAI-compatible chat completions routed to attested co/core providers.",
  },
  {
    slug: "quickstart",
    section: "Getting started",
    label: "Quickstart",
    title: "Quickstart",
    description: "Create an API key, then swap the base URL and key in your OpenAI client.",
  },
  {
    slug: "connect-your-app",
    section: "Getting started",
    label: "Connect your app",
    title: "Connect your app",
    description:
      "Sign in with co/core: let users connect their account to your app in one click, via device pairing.",
  },
  {
    slug: "api-reference",
    section: "API reference",
    label: "API reference",
    title: "API reference",
    description: "HTTP endpoints, parameters, curl examples, and error codes.",
  },
  {
    slug: "opencode",
    section: "Tool setup",
    label: "OpenCode",
    title: "OpenCode",
    description: "Configure co/core as a custom OpenAI-compatible provider.",
  },
  {
    slug: "cursor",
    section: "Tool setup",
    label: "Cursor",
    title: "Cursor",
    description: "Point Cursor's OpenAI override at co/core.",
  },
  {
    slug: "claude-code",
    section: "Tool setup",
    label: "Claude Code",
    title: "Claude Code",
    description: "Route Claude Code through a local Anthropic→OpenAI proxy.",
  },
  {
    slug: null,
    href: COMMUNITY_TOOLS_PATH,
    section: "Tool setup",
    label: "Community tools",
    title: "Community tools",
    description: "Extensions and integrations built by the community.",
  },
];

const SLUG_SET = new Set(
  INFERENCE_DOCS_CATALOG.map((entry) => entry.slug).filter(
    (slug): slug is InferenceDocsSlug => slug != null,
  ),
);

export function inferenceDocsHref(slug: InferenceDocsSlug | null): string {
  return slug == null ? "/docs/inference" : `/docs/inference/${slug}`;
}

export function inferenceDocsEntryHref(entry: InferenceDocsEntry): string {
  return entry.href ?? inferenceDocsHref(entry.slug);
}

export function isCommunityToolsPath(pathname: string): boolean {
  const normalized =
    pathname.length > 1 && pathname.endsWith("/") ? pathname.slice(0, -1) : pathname;
  return normalized === COMMUNITY_TOOLS_PATH;
}

export type InferenceDocsLinkTarget =
  | { to: "/docs/inference" }
  | { to: "/docs/inference/$slug"; params: { slug: InferenceDocsSlug } };

export function inferenceDocsLink(slug: InferenceDocsSlug | null): InferenceDocsLinkTarget {
  if (slug == null) return { to: "/docs/inference" };
  return { to: "/docs/inference/$slug", params: { slug } };
}

export function inferenceDocsEntryForSlug(
  slug: InferenceDocsSlug | null,
): InferenceDocsEntry | undefined {
  return INFERENCE_DOCS_CATALOG.find((entry) => entry.slug === slug);
}

export function isInferenceDocsSlug(value: string): value is InferenceDocsSlug {
  return SLUG_SET.has(value as InferenceDocsSlug);
}

export type InferenceDocsJumpNavGroup = {
  label: string;
  options: Array<{ id: string; label: string; href: string }>;
};

export function inferenceDocsJumpNavGroups(): Array<InferenceDocsJumpNavGroup> {
  return INFERENCE_DOCS_SECTIONS.map((section) => ({
    label: section,
    options: INFERENCE_DOCS_CATALOG.filter((entry) => entry.section === section).map((entry) => ({
      id:
        entry.href != null ? COMMUNITY_TOOLS_NAV_ID : entry.slug == null ? "overview" : entry.slug,
      label: entry.label,
      href: inferenceDocsEntryHref(entry),
    })),
  }));
}
