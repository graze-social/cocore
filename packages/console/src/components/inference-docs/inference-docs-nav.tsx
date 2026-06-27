"use client";

import * as stylex from "@stylexjs/stylex";
import { Link, useRouterState } from "@tanstack/react-router";

import { docsStyles } from "@/components/docs/docs-page.stylex.tsx";
import { useDocsScrollSpyActive } from "@/components/docs/docs-scroll-spy-context.tsx";
import {
  INFERENCE_API_CATALOG,
  INFERENCE_API_ERROR_SECTIONS,
  INFERENCE_API_TOPIC_SECTIONS,
} from "@/lib/inference-docs/catalog.ts";
import { INFERENCE_API_INTRO_ID } from "@/lib/inference-docs/navigation-api.ts";
import {
  INFERENCE_DOCS_CATALOG,
  INFERENCE_DOCS_SECTIONS,
  isCommunityToolsPath,
  type InferenceDocsSlug,
} from "@/lib/inference-docs/navigation.ts";

function normalizeInferenceDocsPath(pathname: string): string {
  if (pathname.length > 1 && pathname.endsWith("/")) {
    return pathname.slice(0, -1);
  }
  return pathname;
}

function isApiReferencePath(pathname: string): boolean {
  return normalizeInferenceDocsPath(pathname) === "/docs/inference/api-reference";
}

function isInferenceOverviewActive(pathname: string): boolean {
  return normalizeInferenceDocsPath(pathname) === "/docs/inference";
}

function isInferenceSlugActive(pathname: string, slug: InferenceDocsSlug): boolean {
  return normalizeInferenceDocsPath(pathname) === `/docs/inference/${slug}`;
}

export function InferenceDocsNav() {
  const pathname = useRouterState({ select: (state) => state.location.pathname });
  const onApiReference = isApiReferencePath(pathname);
  const active = useDocsScrollSpyActive();

  return (
    <nav {...stylex.props(docsStyles.refNav)} aria-label="Inference docs">
      {INFERENCE_DOCS_SECTIONS.map((section) => {
        const entries = INFERENCE_DOCS_CATALOG.filter((entry) => entry.section === section);

        if (section === "API reference") {
          return (
            <div key={section} {...stylex.props(docsStyles.refNavGroup)}>
              <div {...stylex.props(docsStyles.refNavHeadingRow)}>
                <span {...stylex.props(docsStyles.refNavHeading)}>{section}</span>
                <span {...stylex.props(docsStyles.refNavHeadingCount)}>
                  {INFERENCE_API_CATALOG.length +
                    INFERENCE_API_TOPIC_SECTIONS.length +
                    INFERENCE_API_ERROR_SECTIONS.length}
                </span>
              </div>
              {onApiReference ? (
                <a
                  href={`#${INFERENCE_API_INTRO_ID}`}
                  {...stylex.props(
                    docsStyles.refNavLink,
                    (active === INFERENCE_API_INTRO_ID || active == null) &&
                      docsStyles.refNavLinkActive,
                  )}
                >
                  Overview
                </a>
              ) : (
                <Link
                  to="/docs/inference/$slug"
                  params={{ slug: "api-reference" }}
                  {...stylex.props(
                    docsStyles.refNavLink,
                    isInferenceSlugActive(pathname, "api-reference") && docsStyles.refNavLinkActive,
                  )}
                >
                  Overview
                </Link>
              )}
              {INFERENCE_API_CATALOG.map((entry) =>
                onApiReference ? (
                  <a
                    key={entry.id}
                    href={`#${entry.id}`}
                    {...stylex.props(
                      docsStyles.refNavLink,
                      docsStyles.refNavLinkMono,
                      active === entry.id && docsStyles.refNavLinkActive,
                    )}
                  >
                    {entry.navLabel}
                  </a>
                ) : (
                  <Link
                    key={entry.id}
                    to="/docs/inference/$slug"
                    params={{ slug: "api-reference" }}
                    hash={entry.id}
                    {...stylex.props(docsStyles.refNavLink, docsStyles.refNavLinkMono)}
                  >
                    {entry.navLabel}
                  </Link>
                ),
              )}
              {INFERENCE_API_TOPIC_SECTIONS.map((entry) =>
                onApiReference ? (
                  <a
                    key={entry.id}
                    href={`#${entry.id}`}
                    {...stylex.props(
                      docsStyles.refNavLink,
                      docsStyles.refNavLinkMono,
                      active === entry.id && docsStyles.refNavLinkActive,
                    )}
                  >
                    {entry.navLabel}
                  </a>
                ) : (
                  <Link
                    key={entry.id}
                    to="/docs/inference/$slug"
                    params={{ slug: "api-reference" }}
                    hash={entry.id}
                    {...stylex.props(docsStyles.refNavLink, docsStyles.refNavLinkMono)}
                  >
                    {entry.navLabel}
                  </Link>
                ),
              )}
              {INFERENCE_API_ERROR_SECTIONS.map((entry) =>
                onApiReference ? (
                  <a
                    key={entry.id}
                    href={`#${entry.id}`}
                    {...stylex.props(
                      docsStyles.refNavLink,
                      docsStyles.refNavLinkMono,
                      active === entry.id && docsStyles.refNavLinkActive,
                    )}
                  >
                    {entry.navLabel}
                  </a>
                ) : (
                  <Link
                    key={entry.id}
                    to="/docs/inference/$slug"
                    params={{ slug: "api-reference" }}
                    hash={entry.id}
                    {...stylex.props(docsStyles.refNavLink, docsStyles.refNavLinkMono)}
                  >
                    {entry.navLabel}
                  </Link>
                ),
              )}
            </div>
          );
        }

        return (
          <div key={section} {...stylex.props(docsStyles.refNavGroup)}>
            <div {...stylex.props(docsStyles.refNavHeadingRow)}>
              <span {...stylex.props(docsStyles.refNavHeading)}>{section}</span>
              <span {...stylex.props(docsStyles.refNavHeadingCount)}>{entries.length}</span>
            </div>
            {entries.map((entry) =>
              entry.href != null ? (
                <Link
                  key={entry.label}
                  to={entry.href}
                  {...stylex.props(
                    docsStyles.refNavLink,
                    isCommunityToolsPath(pathname) && docsStyles.refNavLinkActive,
                  )}
                >
                  {entry.label}
                </Link>
              ) : entry.slug == null ? (
                <Link
                  key={entry.label}
                  to="/docs/inference"
                  {...stylex.props(
                    docsStyles.refNavLink,
                    isInferenceOverviewActive(pathname) && docsStyles.refNavLinkActive,
                  )}
                >
                  {entry.label}
                </Link>
              ) : (
                <Link
                  key={entry.label}
                  to="/docs/inference/$slug"
                  params={{ slug: entry.slug }}
                  {...stylex.props(
                    docsStyles.refNavLink,
                    isInferenceSlugActive(pathname, entry.slug) && docsStyles.refNavLinkActive,
                  )}
                >
                  {entry.label}
                </Link>
              ),
            )}
          </div>
        );
      })}
    </nav>
  );
}
