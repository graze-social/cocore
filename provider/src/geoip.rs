//! Best-effort coarse-location resolution for the optional, opt-in
//! `region` field on the `dev.cocore.compute.provider` record.
//!
//! IMPORTANT — this is an ADVISORY, self-asserted signal, not a proof of
//! location. We resolve the machine's country from its public IP at serve
//! start; a VPN/proxy moves it, and Apple exposes no signed-location
//! primitive, so verifiers MUST treat the published `region` as unverified
//! (the same trust posture as the `tier` field). The provider writes the
//! claim to its OWN PDS; no coordinator owns or gates it.
//!
//! The lookup endpoint is configurable via `COCORE_GEOIP_URL` so an operator
//! can point at their own geo service — nothing here is bound to cocore
//! infrastructure. The default returns an ISO 3166-1 alpha-2 code as plain
//! text. Any failure (network, timeout, unparseable body) resolves to
//! `None`: the caller simply omits the field and never blocks serving on it.

use std::time::Duration;

/// Value stamped into the provider record's `regionSource` so consumers can
/// see the provenance — and thus the trust ceiling — of the coarse location.
pub const REGION_SOURCE_IP_GEO: &str = "ip-geo";

/// Default keyless endpoint that returns this machine's country as a bare
/// ISO 3166-1 alpha-2 code in the response body. Overridable.
const DEFAULT_ENDPOINT: &str = "https://ifconfig.co/country-iso";

/// Cap on the response body we buffer. A country code is 2 bytes and a small
/// JSON envelope is well under this; anything larger is a misbehaving (or
/// compromised) endpoint, so we discard it rather than buffer it unbounded.
const MAX_BODY_BYTES: usize = 4096;

fn endpoint() -> String {
    std::env::var("COCORE_GEOIP_URL")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_ENDPOINT.to_string())
}

/// Resolve this machine's country as an ISO 3166-1 alpha-2 code (uppercased)
/// from its public IP, best-effort. Returns `None` on any failure so the
/// caller can omit `region` rather than block or publish a bad value.
pub async fn resolve_country(http: &reqwest::Client) -> Option<String> {
    let url = endpoint();
    if url == DEFAULT_ENDPOINT {
        // The default public endpoint rate-limits unauthenticated clients to
        // ~1 req/min per IP, so providers behind shared/CGNAT egress can be
        // silently throttled and resolve to `None` every serve. Nudge the
        // operator toward a self-hosted geo service for reliable results.
        tracing::warn!(
            endpoint = DEFAULT_ENDPOINT,
            "using the default public geoip endpoint (rate-limited to ~1 req/min \
             per IP); set COCORE_GEOIP_URL to a self-hosted service for reliable \
             region resolution on shared or CGNAT egress IPs"
        );
    }
    let mut resp = http
        .get(&url)
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    // Stream with a hard cap instead of `resp.text()` so a custom (or
    // compromised) endpoint can't make us buffer an arbitrarily large body.
    let mut buf = Vec::new();
    while let Some(chunk) = resp.chunk().await.ok()? {
        buf.extend_from_slice(&chunk);
        if buf.len() > MAX_BODY_BYTES {
            tracing::warn!(
                limit = MAX_BODY_BYTES,
                "geoip response body exceeded the size cap — discarding"
            );
            return None;
        }
    }
    let body = String::from_utf8(buf).ok()?;
    parse_country(&body)
}

/// Extract a 2-letter ISO 3166-1 alpha-2 country code from a response body.
/// Accepts a bare code (`"US"`, `"us\n"`) or a small JSON object carrying it
/// under a common key, so a custom `COCORE_GEOIP_URL` returning JSON still
/// works. Returns the code uppercased, or `None` if nothing valid is found.
pub fn parse_country(body: &str) -> Option<String> {
    let trimmed = body.trim();
    if is_alpha2(trimmed) {
        return Some(trimmed.to_ascii_uppercase());
    }
    let v: serde_json::Value = serde_json::from_str(trimmed).ok()?;
    for key in ["country_code", "countryCode", "country_iso", "country"] {
        if let Some(code) = v.get(key).and_then(|x| x.as_str()) {
            let code = code.trim();
            if is_alpha2(code) {
                return Some(code.to_ascii_uppercase());
            }
        }
    }
    None
}

fn is_alpha2(s: &str) -> bool {
    s.len() == 2 && s.bytes().all(|b| b.is_ascii_alphabetic())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bare_code() {
        assert_eq!(parse_country("US").as_deref(), Some("US"));
        assert_eq!(parse_country("us\n").as_deref(), Some("US"));
        assert_eq!(parse_country("  de  ").as_deref(), Some("DE"));
    }

    #[test]
    fn parses_json_body() {
        assert_eq!(
            parse_country(r#"{"country_code":"GB"}"#).as_deref(),
            Some("GB")
        );
        assert_eq!(
            parse_country(r#"{"countryCode":"fr","other":1}"#).as_deref(),
            Some("FR")
        );
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(parse_country("not a country"), None);
        assert_eq!(parse_country("USA"), None); // alpha-3, not alpha-2
        assert_eq!(parse_country(""), None);
        assert_eq!(parse_country("12"), None);
        assert_eq!(parse_country(r#"{"foo":"bar"}"#), None);
    }
}
