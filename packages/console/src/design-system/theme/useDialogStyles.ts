import * as stylex from "@stylexjs/stylex";
import { use } from "react";

import type { Size } from "../theme/types";

import { SizeContext } from "../context";
import { animationDuration, animationTimingFunction, animations } from "../theme/animations.stylex";
import { radius } from "../theme/radius.stylex";
import { shadow } from "../theme/shadow.stylex";
import { ui } from "./semantic-color.stylex";

const styles = stylex.create({
  overlay: {
    animationDuration: animationDuration.default,
    animationName: animations.fadeIn,
    animationTimingFunction: animationTimingFunction.easeIn,
    backgroundColor: "rgba(0, 0, 0, 0.5)",
    opacity: {
      default: 1,
      ":is([data-exiting])": 0,
    },
    position: "absolute",
    transitionDuration: {
      ":is([data-exiting])": animationDuration.fast,
    },
    transitionProperty: "opacity",
    transitionTimingFunction: {
      default: animationTimingFunction.easeOut,
      ":is([data-exiting])": animationTimingFunction.easeIn,
    },
    // Sit above the sticky navbar (zIndex 1000) so the backdrop dims the top
    // menu too, and below toasts (9999) so confirmations still surface.
    zIndex: 1100,
    height: "var(--page-height)",
    left: 0,
    top: 0,
    width: "100vw",
  },
  modal: {
    borderRadius: radius.xl,
    cornerShape: "squircle",
    outline: "none",
    overflow: "hidden",
    boxShadow: shadow["lg"],
    display: "flex",
    flexDirection: "column",
    position: "fixed",
    translate: "-50% -50%",
    left: "50%",
    maxHeight: "calc(var(--visual-viewport-height) * 0.8)",
    maxWidth: "90vw",
    top: "calc(var(--visual-viewport-height) / 2)",

    animationDuration: animationDuration.slow,
    animationName: {
      ":is([data-entering])": animations.zoomIn,
      ":is([data-exiting])": animations.zoomOut,
    },
    animationTimingFunction: animationTimingFunction.easeElasticInOut,
  },
  dialog: {
    outline: "none",
    flexGrow: 1,
    minHeight: 0,
  },
  size: (size: Size) => ({
    width: size === "sm" ? 400 : size === "md" ? 600 : 800,
  }),
});

export function useDialogStyles({ size: sizeProp }: { size?: Size }) {
  const size = sizeProp || use(SizeContext);

  return {
    overlay: styles.overlay,
    modal: [styles.modal, ui.bg, ui.text, ui.border, styles.size(size)],
    dialog: styles.dialog,
  };
}
