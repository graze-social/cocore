/** Domain attribute for the auth session cookie.
 *
 * Once cocore.dev is the canonical console host, a session set on cocore.dev
 * should also be valid on console.cocore.dev (and any other *.cocore.dev the
 * browser visits), so the cookie is scoped to the registrable domain. We only
 * do this for cocore.dev hosts — localhost, 127.0.0.1, and Railway preview
 * domains (*.up.railway.app) get a host-only cookie (return undefined), which
 * is the correct, safe default for dev/preview.
 *
 * `host` is the request's Host (may include a :port, which we strip).
 */
export function authCookieDomain(host: string | null | undefined): string | undefined {
  if (!host) return undefined;
  const h = host.split(":")[0]?.toLowerCase() ?? "";
  if (h === "cocore.dev" || h.endsWith(".cocore.dev")) return "cocore.dev";
  return undefined;
}
