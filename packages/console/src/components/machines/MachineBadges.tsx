// Small, shared visual indicators for a machine's advisory region and its
// pro-bono election. Used in both the fleet table (MachinesDashboard) and the
// machine detail header so the two stay in sync.

import { Badge } from "@/design-system/badge";

/** Turn an ISO 3166-1 alpha-2 country code into a flag emoji by mapping each
 *  ASCII letter to its regional-indicator symbol. Returns null for anything
 *  that isn't exactly two letters (the region field is advisory and may be
 *  absent or malformed). */
function regionFlagEmoji(code: string | undefined | null): string | null {
  if (!code) return null;
  const cc = code.trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(cc)) return null;
  const base = 0x1f1e6; // regional indicator "A"
  return String.fromCodePoint(base + (cc.charCodeAt(0) - 65), base + (cc.charCodeAt(1) - 65));
}

/** Flag emoji for a machine's self-declared region. Renders nothing when the
 *  region is absent or not a recognizable country code. */
export function RegionFlag({ region }: { region?: string }) {
  const flag = regionFlagEmoji(region);
  if (!flag) return null;
  const code = region?.trim().toUpperCase();
  return (
    <span role="img" aria-label={`region ${code}`} title={`Self-declared region: ${code}`}>
      {flag}
    </span>
  );
}

/** Chip marking a machine that volunteers free, unmetered compute. `any` serves
 *  every requester free; `direct` serves only the owner's listed friends free. */
export function ProBonoBadge({ mode }: { mode?: "any" | "direct" }) {
  if (mode !== "any" && mode !== "direct") return null;
  return (
    <Badge
      variant="success"
      size="sm"
      title={
        mode === "any"
          ? "Pro bono: serving every requester free"
          : "Pro bono: serving specific friends free"
      }
    >
      {mode === "direct" ? "pro bono · friends" : "pro bono"}
    </Badge>
  );
}
