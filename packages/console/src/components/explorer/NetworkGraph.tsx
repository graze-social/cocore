"use client";

import * as stylex from "@stylexjs/stylex";
import { useEffect, useMemo, useRef, useState } from "react";

import type { ExplorerEdge, ExplorerNode } from "@/components/explorer/explorer.functions.ts";
import { explorerLayout } from "@/components/explorer/explorer.stylex.ts";
import { green } from "@/design-system/theme/colors/green.stylex";
import { purple } from "@/design-system/theme/colors/purple.stylex";
import { uiColor } from "@/design-system/theme/color.stylex";
import { radius } from "@/design-system/theme/radius.stylex";

// World coordinate space; the SVG viewBox maps this onto the rendered
// box. Pan/zoom is a transform on the inner <g>, so all hit-testing
// converts the pointer into this space via the SVG's own CTM.
const VIEW = 1000;
const CENTER = VIEW / 2;

interface Pt {
  x: number;
  y: number;
  vx: number;
  vy: number;
}

export interface NetworkGraphProps {
  nodes: ExplorerNode[];
  edges: ExplorerEdge[];
  selectedDid: string | null;
  onSelect: (did: string | null) => void;
  /** Lowercased search term; matching nodes are emphasized, the rest dimmed. */
  query: string;
  /** Show only providers (and edges between them). */
  providersOnly: boolean;
  /** When set, show only these DIDs (and edges between them) — the page
   *  computes the set from its version filter so the sentinel semantics
   *  ("unversioned") stay out of the graph. Null = no version filter. */
  versionDids: ReadonlySet<string> | null;
}

function nodeRadius(n: ExplorerNode): number {
  const r = 6 + 3 * Math.sqrt(n.machines) + 1.1 * Math.sqrt(n.trustedByIn + n.trustsOut);
  return Math.max(6, Math.min(26, r));
}

const styles = stylex.create({
  wrap: {
    position: "relative",
    width: "100%",
    height: explorerLayout.graphHeight,
    borderColor: uiColor.border1,
    borderStyle: "solid",
    borderWidth: 1,
    borderRadius: radius.lg,
    backgroundColor: uiColor.bgSubtle,
    overflow: "hidden",
    touchAction: "none",
  },
  svg: { width: "100%", height: "100%", display: "block", cursor: "grab" },
  svgDragging: { cursor: "grabbing" },
  edge: { stroke: uiColor.border2, strokeWidth: 1, pointerEvents: "none" },
  edgeHot: { stroke: uiColor.solid1, strokeWidth: 1.75, pointerEvents: "none" },
  edgeDim: { stroke: uiColor.border1, strokeWidth: 0.75, opacity: 0.4, pointerEvents: "none" },
  node: {
    fill: purple.component3,
    stroke: purple.border2,
    strokeWidth: 1.5,
    cursor: "pointer",
  },
  nodeProvider: { fill: green.solid1, stroke: green.solid2 },
  nodeSelected: { stroke: uiColor.text2, strokeWidth: 3 },
  nodeDim: { opacity: 0.25 },
  label: {
    fill: uiColor.text2,
    fontSize: 11,
    fontFamily: "var(--font-mono, ui-monospace, monospace)",
    pointerEvents: "none",
    userSelect: "none",
  },
  labelDim: { opacity: 0.2 },
  hint: {
    position: "absolute",
    right: 10,
    bottom: 8,
    fontSize: 11,
    color: uiColor.text1,
    fontFamily: "var(--font-mono, ui-monospace, monospace)",
    pointerEvents: "none",
    userSelect: "none",
  },
  empty: {
    position: "absolute",
    inset: 0,
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    color: uiColor.text1,
    fontSize: 13,
  },
});

function shortDid(did: string): string {
  return did.length > 22 ? `${did.slice(0, 14)}…${did.slice(-4)}` : did;
}

function nodeLabel(n: ExplorerNode): string {
  return n.displayName?.trim() || (n.handle ? `@${n.handle}` : shortDid(n.did));
}

export function NetworkGraph({
  nodes,
  edges,
  selectedDid,
  onSelect,
  query,
  providersOnly,
  versionDids,
}: NetworkGraphProps) {
  const svgRef = useRef<SVGSVGElement | null>(null);
  const wrapRef = useRef<HTMLDivElement | null>(null);
  const viewRef = useRef({ tx: 0, ty: 0, s: 1 });
  const posRef = useRef<Map<string, Pt>>(new Map());
  const alphaRef = useRef(1);
  const rafRef = useRef<number | null>(null);
  const stepRef = useRef<(() => void) | null>(null);
  const dragRef = useRef<{ did: string | null; moved: boolean; tx: number; ty: number } | null>(
    null,
  );
  const lastRef = useRef<{ x: number; y: number } | null>(null);
  const [, setFrame] = useState(0);
  const [view, setView] = useState({ tx: 0, ty: 0, s: 1 });
  viewRef.current = view;
  const [hovered, setHovered] = useState<string | null>(null);

  // Filtered view of the graph.
  const { vizNodes, vizEdges } = useMemo(() => {
    if (!providersOnly && !versionDids) return { vizNodes: nodes, vizEdges: edges };
    const keep = new Set(
      nodes
        .filter((n) => !providersOnly || n.isProvider)
        .filter((n) => !versionDids || versionDids.has(n.did))
        .map((n) => n.did),
    );
    return {
      vizNodes: nodes.filter((n) => keep.has(n.did)),
      vizEdges: edges.filter((e) => keep.has(e.source) && keep.has(e.target)),
    };
  }, [nodes, edges, providersOnly, versionDids]);

  const degree = useMemo(() => {
    const d = new Map<string, number>();
    for (const e of vizEdges) {
      d.set(e.source, (d.get(e.source) ?? 0) + 1);
      d.set(e.target, (d.get(e.target) ?? 0) + 1);
    }
    return d;
  }, [vizEdges]);

  // Seed positions deterministically on a ring (SSR-stable: no random
  // at init), keeping any node already placed from a prior render.
  useEffect(() => {
    const pos = posRef.current;
    const present = new Set(vizNodes.map((n) => n.did));
    for (const k of pos.keys()) if (!present.has(k)) pos.delete(k);
    const n = vizNodes.length;
    vizNodes.forEach((node, i) => {
      if (pos.has(node.did)) return;
      const a = (i / Math.max(1, n)) * Math.PI * 2;
      const ring = 120 + (i % 5) * 36;
      pos.set(node.did, {
        x: CENTER + Math.cos(a) * ring,
        y: CENTER + Math.sin(a) * ring,
        vx: 0,
        vy: 0,
      });
    });
    alphaRef.current = 1; // reheat on graph change
  }, [vizNodes]);

  // Force simulation: repulsion (all pairs) + spring (edges) +
  // centering, with velocity damping and alpha cooling. Stops when
  // settled; interactions reheat it.
  useEffect(() => {
    const pos = posRef.current;
    const idIndex = vizNodes.map((n) => n.did);

    const step = () => {
      const alpha = alphaRef.current;
      const k = 1; // base
      // Repulsion.
      for (let i = 0; i < idIndex.length; i++) {
        const a = pos.get(idIndex[i]!);
        if (!a) continue;
        for (let j = i + 1; j < idIndex.length; j++) {
          const b = pos.get(idIndex[j]!);
          if (!b) continue;
          let dx = a.x - b.x;
          let dy = a.y - b.y;
          let d2 = dx * dx + dy * dy;
          if (d2 < 0.01) {
            dx = (i - j) * 0.5 + 0.1;
            dy = 0.3;
            d2 = dx * dx + dy * dy;
          }
          const f = (9000 * k) / d2;
          const d = Math.sqrt(d2);
          const fx = (dx / d) * f;
          const fy = (dy / d) * f;
          a.vx += fx * alpha;
          a.vy += fy * alpha;
          b.vx -= fx * alpha;
          b.vy -= fy * alpha;
        }
      }
      // Springs along edges.
      const REST = 90;
      for (const e of vizEdges) {
        const a = pos.get(e.source);
        const b = pos.get(e.target);
        if (!a || !b) continue;
        const dx = b.x - a.x;
        const dy = b.y - a.y;
        const d = Math.hypot(dx, dy) || 0.01;
        const f = 0.02 * (d - REST);
        const fx = (dx / d) * f;
        const fy = (dy / d) * f;
        a.vx += fx * alpha;
        a.vy += fy * alpha;
        b.vx -= fx * alpha;
        b.vy -= fy * alpha;
      }
      // Centering + integrate + damp.
      const pinned = dragRef.current?.did ?? null;
      for (const id of idIndex) {
        const p = pos.get(id);
        if (!p) continue;
        if (id === pinned) {
          p.vx = 0;
          p.vy = 0;
          continue;
        }
        p.vx += (CENTER - p.x) * 0.0016 * alpha;
        p.vy += (CENTER - p.y) * 0.0016 * alpha;
        p.vx *= 0.86;
        p.vy *= 0.86;
        p.x += p.vx;
        p.y += p.vy;
      }
      alphaRef.current = Math.max(0, alpha * 0.985 - 0.0006);
      setFrame((f) => f + 1);
      rafRef.current = alphaRef.current > 0.02 ? requestAnimationFrame(step) : null;
    };

    stepRef.current = step;
    if (rafRef.current === null) rafRef.current = requestAnimationFrame(step);
    return () => {
      if (rafRef.current !== null) cancelAnimationFrame(rafRef.current);
      rafRef.current = null;
    };
  }, [vizNodes, vizEdges]);

  const reheat = () => {
    alphaRef.current = Math.max(alphaRef.current, 0.35);
    if (rafRef.current === null && stepRef.current !== null) {
      rafRef.current = requestAnimationFrame(stepRef.current);
    }
  };

  // Pointer → world (VIEW space, inside the pan/zoom transform).
  const toWorld = (clientX: number, clientY: number): { x: number; y: number } => {
    const svg = svgRef.current;
    if (!svg) return { x: 0, y: 0 };
    const ctm = svg.getScreenCTM();
    if (!ctm) return { x: 0, y: 0 };
    const pt = svg.createSVGPoint();
    pt.x = clientX;
    pt.y = clientY;
    const vb = pt.matrixTransform(ctm.inverse()); // viewBox coords
    return { x: (vb.x - view.tx) / view.s, y: (vb.y - view.ty) / view.s };
  };
  const toViewBox = (clientX: number, clientY: number): { x: number; y: number } => {
    const svg = svgRef.current;
    if (!svg) return { x: 0, y: 0 };
    const ctm = svg.getScreenCTM();
    if (!ctm) return { x: 0, y: 0 };
    const pt = svg.createSVGPoint();
    pt.x = clientX;
    pt.y = clientY;
    return pt.matrixTransform(ctm.inverse());
  };

  const onPointerDown = (e: React.PointerEvent, did: string | null) => {
    if (e.button !== 0) return;
    e.preventDefault();
    svgRef.current?.setPointerCapture(e.pointerId);
    dragRef.current = { did, moved: false, tx: view.tx, ty: view.ty };
    lastRef.current = did ? null : toViewBox(e.clientX, e.clientY);
    if (did) {
      const w = toWorld(e.clientX, e.clientY);
      const p = posRef.current.get(did);
      if (p) {
        p.x = w.x;
        p.y = w.y;
      }
      e.stopPropagation();
    }
  };

  const onPointerMove = (e: React.PointerEvent) => {
    const drag = dragRef.current;
    if (!drag) {
      return;
    }
    drag.moved = true;
    if (drag.did) {
      const w = toWorld(e.clientX, e.clientY);
      const p = posRef.current.get(drag.did);
      if (p) {
        p.x = w.x;
        p.y = w.y;
        p.vx = 0;
        p.vy = 0;
      }
      reheat();
      setFrame((f) => f + 1);
    } else {
      // Pan: move by the viewBox-space delta under the cursor.
      const vb = toViewBox(e.clientX, e.clientY);
      const prev = lastRef.current;
      if (prev) {
        const dx = vb.x - prev.x;
        const dy = vb.y - prev.y;
        // Capture deltas locally — endPointer clears lastRef before this
        // updater runs if pointerup races the batched setState.
        setView((v) => ({
          ...v,
          tx: v.tx + dx,
          ty: v.ty + dy,
        }));
      }
      lastRef.current = vb;
    }
  };

  const endPointer = (e: React.PointerEvent) => {
    if (svgRef.current?.hasPointerCapture(e.pointerId)) {
      svgRef.current.releasePointerCapture(e.pointerId);
    }
    const drag = dragRef.current;
    dragRef.current = null;
    lastRef.current = null;
    if (drag && !drag.moved) {
      // A click (no drag): select the node under the press, or clear
      // when the press was on empty background (drag.did === null).
      onSelect(drag.did);
    }
    if (drag?.did) reheat();
  };

  useEffect(() => {
    const el = wrapRef.current;
    if (!el) return;

    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      e.stopPropagation();
      const svg = svgRef.current;
      if (!svg) return;
      const ctm = svg.getScreenCTM();
      if (!ctm) return;
      const pt = svg.createSVGPoint();
      pt.x = e.clientX;
      pt.y = e.clientY;
      const vb = pt.matrixTransform(ctm.inverse());
      const v = viewRef.current;
      const f = e.deltaY < 0 ? 1.12 : 1 / 1.12;
      const s = Math.max(0.3, Math.min(4, v.s * f));
      const realF = s / v.s;
      setView({ s, tx: vb.x - realF * (vb.x - v.tx), ty: vb.y - realF * (vb.y - v.ty) });
    };

    el.addEventListener("wheel", onWheel, { passive: false });
    return () => el.removeEventListener("wheel", onWheel);
  }, []);

  const pos = posRef.current;
  const active = hovered ?? selectedDid;
  const neighbors = useMemo(() => {
    if (!active) return null;
    const set = new Set<string>([active]);
    for (const e of vizEdges) {
      if (e.source === active) set.add(e.target);
      if (e.target === active) set.add(e.source);
    }
    return set;
  }, [active, vizEdges]);

  const q = query.trim().toLowerCase();
  const matches = (n: ExplorerNode): boolean =>
    q.length === 0 ||
    (n.handle?.toLowerCase().includes(q) ?? false) ||
    (n.displayName?.toLowerCase().includes(q) ?? false) ||
    n.did.toLowerCase().includes(q);

  const dragging = dragRef.current !== null;

  return (
    <div ref={wrapRef} {...stylex.props(styles.wrap)}>
      {vizNodes.length === 0 ? (
        <div {...stylex.props(styles.empty)}>No machines or people indexed yet.</div>
      ) : null}
      <svg
        ref={svgRef}
        viewBox={`0 0 ${VIEW} ${VIEW}`}
        preserveAspectRatio="xMidYMid meet"
        {...stylex.props(styles.svg, dragging && styles.svgDragging)}
        onPointerDown={(e) => onPointerDown(e, null)}
        onPointerMove={onPointerMove}
        onPointerUp={endPointer}
        onPointerCancel={endPointer}
      >
        <g transform={`translate(${view.tx} ${view.ty}) scale(${view.s})`}>
          {vizEdges.map((e, i) => {
            const a = pos.get(e.source);
            const b = pos.get(e.target);
            if (!a || !b) return null;
            const hot = active != null && (e.source === active || e.target === active);
            const dim = active != null && !hot;
            return (
              <line
                key={i}
                x1={a.x}
                y1={a.y}
                x2={b.x}
                y2={b.y}
                {...stylex.props(hot ? styles.edgeHot : dim ? styles.edgeDim : styles.edge)}
              />
            );
          })}
          {vizNodes.map((n) => {
            const p = pos.get(n.did);
            if (!p) return null;
            const r = nodeRadius(n);
            const isSel = n.did === selectedDid;
            const inNeighborhood = neighbors ? neighbors.has(n.did) : true;
            const matched = matches(n);
            const dim = (!inNeighborhood || !matched) && !isSel;
            const showLabel =
              isSel ||
              n.did === hovered ||
              (degree.get(n.did) ?? 0) >= 2 ||
              (matched && q.length > 0);
            return (
              <g key={n.did}>
                <circle
                  cx={p.x}
                  cy={p.y}
                  r={r}
                  {...stylex.props(
                    styles.node,
                    n.isProvider && styles.nodeProvider,
                    isSel && styles.nodeSelected,
                    dim && styles.nodeDim,
                  )}
                  onPointerDown={(e) => onPointerDown(e, n.did)}
                  onPointerEnter={() => setHovered(n.did)}
                  onPointerLeave={() => setHovered((h) => (h === n.did ? null : h))}
                >
                  <title>{nodeLabel(n)}</title>
                </circle>
                {showLabel ? (
                  <text
                    x={p.x + r + 3}
                    y={p.y + 3}
                    {...stylex.props(styles.label, dim && styles.labelDim)}
                  >
                    {nodeLabel(n)}
                  </text>
                ) : null}
              </g>
            );
          })}
        </g>
      </svg>
      <div {...stylex.props(styles.hint)}>drag to pan · scroll to zoom · click a node</div>
    </div>
  );
}
