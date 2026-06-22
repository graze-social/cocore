// Collapsible "thinking" block for a reasoning model's trace.
//
// Built on react-aria-components' Disclosure DIRECTLY (not the design-system
// wrapper) so it can be styled to read as a quiet, inline part of the chat
// transcript rather than a standalone DS panel. The reasoning text streams on
// a separate channel from the answer (see chat-dispatch.ts) and is rendered
// with the same markdown pipeline as the answer.

import * as stylex from "@stylexjs/stylex";
import { ChevronRight } from "lucide-react";
import type { ReactElement } from "react";
import { Button, Disclosure, DisclosurePanel, Heading } from "react-aria-components";

import { uiColor } from "@/design-system/theme/color.stylex";
import { mediaQueries } from "@/design-system/theme/media-queries.stylex";
import { radius } from "@/design-system/theme/radius.stylex";
import { gap, size as sizeSpace } from "@/design-system/theme/semantic-spacing.stylex";
import { fontFamily, fontSize, fontWeight } from "@/design-system/theme/typography.stylex";

import { ChatMarkdown } from "@/components/chat/chat-markdown.tsx";

const styles = stylex.create({
  root: {
    display: "flex",
    flexDirection: "column",
    marginBottom: sizeSpace.sm,
  },
  trigger: {
    display: "flex",
    alignItems: "center",
    gap: gap.xs,
    width: "fit-content",
    padding: 0,
    borderWidth: 0,
    backgroundColor: "transparent",
    cursor: "pointer",
    color: { default: uiColor.text2, ":is([data-hovered=true])": uiColor.text1 },
    fontFamily: fontFamily.sans,
    fontSize: fontSize.sm,
    fontWeight: fontWeight.medium,
    textAlign: "left",
  },
  chevron: {
    flexShrink: 0,
    transition: {
      default: "rotate 200ms ease-in-out",
      [mediaQueries.reducedMotion]: "none",
    },
    rotate: { default: "0deg", ":is([aria-expanded=true] *)": "90deg" },
  },
  panel: {
    overflow: "hidden",
    marginTop: sizeSpace.xs,
    paddingLeft: sizeSpace.sm,
    // A subtle left rail visually nests the reasoning under its toggle and
    // distinguishes it from the answer below.
    borderLeftWidth: 2,
    borderLeftStyle: "solid",
    borderLeftColor: uiColor.border1,
    borderTopLeftRadius: radius.xs,
    color: uiColor.text2,
    fontSize: fontSize.sm,
  },
});

export interface ThinkingDisclosureProps {
  reasoning: string;
  /** True while this turn is the one currently streaming — auto-expands the
   *  block so the user watches the model think in real time. */
  streaming: boolean;
}

export function ThinkingDisclosure({
  reasoning,
  streaming,
}: ThinkingDisclosureProps): ReactElement {
  return (
    <Disclosure defaultExpanded={streaming} {...stylex.props(styles.root)}>
      <Heading>
        <Button slot="trigger" {...stylex.props(styles.trigger)}>
          <ChevronRight size={14} {...stylex.props(styles.chevron)} aria-hidden />
          <span>Thinking</span>
        </Button>
      </Heading>
      <DisclosurePanel {...stylex.props(styles.panel)}>
        <ChatMarkdown streaming={streaming} text={reasoning} />
      </DisclosurePanel>
    </Disclosure>
  );
}
