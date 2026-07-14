// Small, shared visual indicators for a machine's advisory region, its
// pro-bono election, and its live network standing. Used in both the fleet
// table (MachinesDashboard) and the machine detail header so the two stay
// in sync.

import { Badge } from "@/design-system/badge";

import { machineNetworkStanding, type Machine } from "./machines-data.ts";

/** Live network-standing chip: "on network" when the advisor holds a live
 *  connection to this machine, "not reachable" when the machine should be
 *  serving but the network can't hear from it (absent from the advisor's
 *  registry, and/or its agent published an `advisorFault`). Renders nothing
 *  when a claim would be a guess — machine paused/offline/provisioning, or
 *  live standing unavailable with no agent-reported fault. */
export function NetworkStandingBadge({ m }: { m: Machine }) {
  const standing = machineNetworkStanding(m);
  if (standing === null) return null;
  if (standing === "on-network") {
    return (
      <Badge
        variant="success"
        size="sm"
        title="Connected to the co/core network — reachable for jobs"
      >
        on network
      </Badge>
    );
  }
  return (
    <Badge
      variant="warning"
      size="sm"
      title={
        m.advisorFaultReason ??
        "This machine is serving locally but the co/core network can't reach it — no jobs will arrive until it reconnects."
      }
    >
      not reachable
    </Badge>
  );
}

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
