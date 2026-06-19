// Body parsing/validation shared by the dev.cocore.account.* key
// management routes. The service-auth-gated /xrpc/* handlers reuse these
// so request validation stays identical across the surface.

export interface CreateApiKeyInput {
  name: string;
  expiresAt: string | null;
}

interface CreateRawBody {
  name?: unknown;
  expiresAt?: unknown;
}

/** Validate a createApiKey body. Returns the parsed input, or an error
 *  message string the caller turns into a 400. */
export function parseCreateApiKeyBody(raw: CreateRawBody): CreateApiKeyInput | string {
  if (typeof raw.name !== "string" || raw.name.length < 1 || raw.name.length > 100) {
    return "name must be a string of 1–100 characters";
  }
  if (raw.expiresAt !== undefined && raw.expiresAt !== null && typeof raw.expiresAt !== "string") {
    return "expiresAt must be an RFC3339 string, null, or omitted";
  }
  if (typeof raw.expiresAt === "string" && Number.isNaN(Date.parse(raw.expiresAt))) {
    return "expiresAt must be a valid RFC3339 datetime";
  }
  return {
    name: raw.name,
    expiresAt: typeof raw.expiresAt === "string" ? raw.expiresAt : null,
  };
}

/** Validate the `id` field shared by revoke/delete. Returns the id or
 *  null when invalid. */
export function parseApiKeyId(raw: { id?: unknown }): string | null {
  if (typeof raw.id !== "string" || raw.id.length < 1 || raw.id.length > 200) return null;
  return raw.id;
}
