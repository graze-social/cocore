// Minimal version comparison for routing version-gated jobs.
//
// Provider binary versions come from Cargo's `CARGO_PKG_VERSION` (e.g.
// `0.9.32`), so we only need dotted-numeric comparison. We tolerate a
// leading `v` and drop any pre-release/build suffix (`-rc.1`, `+sha`) by
// comparing the numeric release components only — a pre-release of a
// version counts as that version for gating purposes (good enough; we
// never ship feature-bearing pre-releases to the fleet).

function parts(version: string): number[] {
  const trimmed = version.trim().replace(/^v/i, "");
  const release = trimmed.split(/[-+]/, 1)[0] ?? "";
  return release.split(".").map((n) => {
    const v = Number.parseInt(n, 10);
    return Number.isFinite(v) ? v : 0;
  });
}

/** Compare two dotted-numeric versions. Returns <0 if `a` < `b`, 0 if
 *  equal, >0 if `a` > `b`. Missing trailing components count as 0
 *  (`0.9` === `0.9.0`). */
export function compareVersions(a: string, b: string): number {
  const pa = parts(a);
  const pb = parts(b);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i += 1) {
    const diff = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (diff !== 0) return diff < 0 ? -1 : 1;
  }
  return 0;
}

/** True iff `version` is present and >= `min`. A null/empty version is
 *  NEVER good enough (fail-closed): a machine that can't prove its version
 *  must not receive a version-gated job. */
export function meetsMinVersion(version: string | null | undefined, min: string): boolean {
  if (!version) return false;
  return compareVersions(version, min) >= 0;
}
