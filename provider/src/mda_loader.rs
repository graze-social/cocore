//! Production-side counterpart to [`mda`].
//!
//! Where `mda.rs` verifies a cert chain, this module *produces* one
//! to embed in a fresh `dev.cocore.compute.attestation` record.
//!
//! Three acquisition strategies, tried in order:
//!
//!   1. **`COCORE_MDA_CERT_CHAIN_PATH`** — path to a PEM file
//!      containing one or more `-----BEGIN CERTIFICATE-----` blocks.
//!      Leaf cert first, then any intermediates, in the order
//!      `mda::verify_chain` expects (cert[i] signed by cert[i+1],
//!      top-of-chain signed by Apple's Enterprise Attestation Root
//!      CA). This is the operator-managed flow: an MDM agent or a
//!      one-shot Swift helper writes the chain to disk and the
//!      Rust agent picks it up at boot.
//!
//!   2. **`COCORE_MDA_CHAIN_URL`** — a coordinator URL the Secure
//!      Mode wizard provisions per device (the device serial baked
//!      into the query string). At each refresh we `curl` it; the
//!      response is either a raw PEM chain or JSON
//!      `{"chain": ["<pem>", …] | null}` (the shape the console's
//!      `/api/agent/mdm/attestation-chain` endpoint returns once step-ca
//!      has captured the device's Apple attestation). A `null`/absent
//!      chain is "not captured yet" → empty, not an error.
//!
//!   3. **`COCORE_MDA_ATTEST_BINARY`** — path to an executable. On
//!      each attestation refresh we invoke it with no arguments,
//!      pipe its stdout (expected: PEM-formatted chain), parse the
//!      blocks. Exit code 0 = success; non-zero or empty stdout =
//!      treated as "no chain available." stderr is captured but
//!      not logged (it may contain device-identifying material).
//!      This is the dynamic flow we'll use once the Swift companion
//!      `cocore-mda-attest` ships — that binary will call
//!      `DCAppAttestService` / DeviceCheck APIs and emit the chain
//!      Apple signs on the spot.
//!
//! ## BINDING CONTRACT (load-bearing) — RESOLVED: freshness-code (option b)
//!
//! Whichever flow produces the chain, it **MUST bind to this agent's
//! receipt-signing P-256 key** (the `SigningIdentity` public key — the
//! same value published as the attestation's `publicKey`), or a genuine
//! Apple chain for an unrelated device could be stapled onto this signer.
//! Two bindings are accepted (see `mda::MdaResult::binds_key`):
//!
//!   - **(a)** the attested leaf key IS the signing key
//!     (`leaf.publicKey == attestation.publicKey`), or
//!   - **(b)** the **freshness-code** binding (the chosen path): the leaf's
//!     Apple freshness OID commits to the signing key —
//!     `freshness_code == sha256(signing pubkey)`. The agent keeps its own
//!     stable signing identity; the enrollment flow sets the attestation's
//!     freshness / `clientDataHash` to that hash. The verifier recomputes
//!     it offline from `publicKey` alone.
//!
//! `attestation::build` enforces the same on the way out — it drops any
//! chain that doesn't verify Apple-rooted AND bind to the signing key (by
//! either rule), staying self-attested rather than publishing an unbacked
//! hardware claim.
//!
//! If both env vars are set, the file path wins (lets operators
//! pin a chain across binary upgrades without re-attesting).
//!
//! Failure mode for a missing or malformed chain: return `Ok(empty)`,
//! NOT `Err`. The agent should keep running with a self-attested
//! posture rather than refusing to boot — the attestation record's
//! `mdaCertChain` field is optional and the AppView's verifier
//! already treats absent chains as "self-attested." Hard errors
//! here would create an operational footgun where a bad path turns
//! into an outage. The diagnostic goes through tracing instead.
//!
//! ## Why this can't be pure Rust today
//!
//! The cert chain has to be signed by Apple. The signing path runs
//! through:
//!
//! - **App Attest** (`DCAppAttestService`, `DeviceCheck.framework`)
//!   — produces an attestation rooted at Apple's App Attest CA.
//!   Requires a code-signed app with the App Attest entitlement
//!   (`com.apple.developer.devicecheck.appattest-environment`) +
//!   Apple Developer Program membership.
//!
//! - **Managed Device Attestation** (MDM-mediated, RFC 8555 ACME
//!   `device-attest-01`) — produces an attestation rooted at
//!   Apple's Enterprise Attestation Root CA (which `mda.rs`
//!   already embeds). Requires an MDM enrolled device + an MDM
//!   server that requests attestation via ACME.
//!
//! Either way, a Swift / Objective-C binary linked against
//! Apple's framework is the only supported way to drive these
//! APIs from user space. That binary is tracked as a separate
//! deliverable; this module's contract is "if you can get a
//! chain into a file or stdout, the agent will pick it up."

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};

/// Environment knobs. Lifted to constants so a single grep finds
/// every consumer.
pub const ENV_CHAIN_PATH: &str = "COCORE_MDA_CERT_CHAIN_PATH";
pub const ENV_CHAIN_URL: &str = "COCORE_MDA_CHAIN_URL";
pub const ENV_ATTEST_BINARY: &str = "COCORE_MDA_ATTEST_BINARY";

/// Path to the signed App Attest helper (`cocore-appattest`). Distinct from
/// `ENV_ATTEST_BINARY` (which yields a PEM MDA chain): this helper is invoked
/// with the signing pubkey as argv[1] and emits JSON `{object, keyId}` for the
/// App Attest path to hardware-attested. See `provider/spikes/app-attest`.
///
/// NOTE: App Attest is non-functional on macOS (DCAppAttestService.isSupported
/// is false); this seam is retained for a future iOS companion. The live macOS
/// path to hardware-attested is MDA option-B (the request below + freshness).
pub const ENV_APPATTEST_BINARY: &str = "COCORE_APPATTEST_BINARY";

/// Console endpoint that triggers a key-bound MDA option-B attestation
/// (`POST /api/agent/mdm/request-attestation`). When set (with the serial +
/// UDID below), the agent asks the coordinator to send an MDM DeviceInformation
/// attestation with `DeviceAttestationNonce = sha256(pubkey)`, so the captured
/// Apple chain's freshness OID commits to the signing key. The chain then
/// arrives via `ENV_CHAIN_URL` as usual. See infra/mdm/RUNBOOK.md "Option-B".
pub const ENV_REQUEST_URL: &str = "COCORE_MDA_REQUEST_URL";
/// Device serial + NanoMDM enrollment UDID for the request above (set by the
/// Secure Mode wizard / installer next to `ENV_REQUEST_URL`).
pub const ENV_DEVICE_SERIAL: &str = "COCORE_MDA_DEVICE_SERIAL";
pub const ENV_DEVICE_UDID: &str = "COCORE_MDA_DEVICE_UDID";
/// Bearer API key the agent presents to the console.
pub const ENV_CONSOLE_API_KEY: &str = "COCORE_API_KEY";

/// Max time the attest-binary subprocess may run before we give
/// up. Apple's DeviceCheck call typically resolves in well under
/// a second; a 10-second ceiling is generous-but-bounded so a
/// wedged binary can't block agent boot indefinitely.
const ATTEST_BINARY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Try every configured acquisition strategy in order. Returns an
/// empty `Vec` if nothing is configured (or if every configured
/// path failed) — the caller should treat that as "self-attested
/// only, no chain to embed."
pub fn try_load() -> Vec<Vec<u8>> {
    if let Ok(path) = std::env::var(ENV_CHAIN_PATH) {
        let path = PathBuf::from(path);
        match load_from_file(&path) {
            Ok(chain) if !chain.is_empty() => {
                tracing::info!(
                    path = %path.display(),
                    certs = chain.len(),
                    "loaded MDA cert chain from file",
                );
                return chain;
            }
            Ok(_) => {
                tracing::warn!(
                    path = %path.display(),
                    "{ENV_CHAIN_PATH} set but file contained no CERTIFICATE blocks; falling through",
                );
            }
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "{ENV_CHAIN_PATH} set but file could not be loaded; falling through",
                );
            }
        }
    }

    if let Ok(url) = std::env::var(ENV_CHAIN_URL) {
        match load_from_url(&url) {
            Ok(chain) if !chain.is_empty() => {
                tracing::info!(
                    certs = chain.len(),
                    "loaded MDA cert chain from coordinator URL",
                );
                return chain;
            }
            Ok(_) => {
                tracing::info!(
                    "{ENV_CHAIN_URL} set but coordinator has no chain captured yet; falling through",
                );
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "{ENV_CHAIN_URL} set but fetch failed; falling through",
                );
            }
        }
    }

    if let Ok(bin) = std::env::var(ENV_ATTEST_BINARY) {
        let bin = PathBuf::from(bin);
        match load_from_binary(&bin) {
            Ok(chain) if !chain.is_empty() => {
                tracing::info!(
                    binary = %bin.display(),
                    certs = chain.len(),
                    "loaded MDA cert chain from attest binary",
                );
                return chain;
            }
            Ok(_) => {
                tracing::warn!(
                    binary = %bin.display(),
                    "{ENV_ATTEST_BINARY} set but stdout contained no CERTIFICATE blocks",
                );
            }
            Err(e) => {
                tracing::warn!(
                    binary = %bin.display(),
                    error = %e,
                    "{ENV_ATTEST_BINARY} set but invocation failed",
                );
            }
        }
    }

    Vec::new()
}

/// Acquire Apple App Attest evidence bound to `signing_pubkey_b64`.
///
/// Runs the helper named by `COCORE_APPATTEST_BINARY` with the base64 signing
/// public key as argv[1]; the helper sets `clientDataHash = sha256(pubkey)` and
/// emits JSON `{ "object": "<b64 CBOR>", "keyId": "<b64>", ... }` on stdout.
///
/// Returns `None` when the env var is unset, the helper fails / times out, or
/// the output is malformed — the agent stays self-attested on the App Attest
/// path rather than refusing to boot (same fail-soft posture as `try_load`).
/// Note the caller (`attestation::build`) still re-verifies the evidence
/// locally before embedding it, so a buggy helper can never elevate trust.
pub fn load_appattest(signing_pubkey_b64: &str) -> Option<crate::attestation::AppAttestEvidence> {
    let bin = std::env::var(ENV_APPATTEST_BINARY).ok()?;
    match run_appattest_binary(Path::new(&bin), signing_pubkey_b64) {
        Ok(ev) => {
            tracing::info!(binary = %bin, "acquired App Attest evidence");
            Some(ev)
        }
        Err(e) => {
            tracing::warn!(binary = %bin, error = %e, "App Attest helper invocation failed; staying self-attested");
            None
        }
    }
}

/// Invoke the App Attest helper with the signing pubkey and parse its JSON.
fn run_appattest_binary(
    binary: &Path,
    signing_pubkey_b64: &str,
) -> Result<crate::attestation::AppAttestEvidence> {
    use std::io::Read;
    use std::process::{Command, Stdio};
    use std::time::Instant;

    let mut child = Command::new(binary)
        .arg(signing_pubkey_b64)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped()) // captured but never logged (may carry device IDs)
        .spawn()
        .with_context(|| format!("spawning {}", binary.display()))?;

    let deadline = Instant::now() + ATTEST_BINARY_TIMEOUT;
    loop {
        if let Some(status) = child.try_wait()? {
            if !status.success() {
                bail!("App Attest helper exited with {status}");
            }
            break;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            bail!(
                "App Attest helper did not exit within {}s; killed",
                ATTEST_BINARY_TIMEOUT.as_secs()
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    let mut stdout_buf = Vec::new();
    if let Some(mut s) = child.stdout.take() {
        s.read_to_end(&mut stdout_buf)
            .context("reading App Attest helper stdout")?;
    }
    parse_appattest_json(&stdout_buf)
}

/// Parse the helper's stdout JSON into an [`AppAttestEvidence`]. Only `object`
/// and `keyId` are consumed; the helper's other fields (clientDataHashHex,
/// appId, environment) are diagnostic and ignored here.
pub fn parse_appattest_json(stdout: &[u8]) -> Result<crate::attestation::AppAttestEvidence> {
    #[derive(serde::Deserialize)]
    struct Out {
        object: String,
        #[serde(rename = "keyId")]
        key_id: String,
    }
    let s = std::str::from_utf8(stdout).context("App Attest helper stdout is not UTF-8")?;
    let out: Out = serde_json::from_str(s.trim()).context("parsing App Attest helper JSON")?;
    if out.object.is_empty() || out.key_id.is_empty() {
        bail!("App Attest helper returned empty object or keyId");
    }
    Ok(crate::attestation::AppAttestEvidence {
        object: out.object,
        keyId: out.key_id,
    })
}

/// Build the JSON body for `POST /api/agent/mdm/request-attestation`. Pure so
/// it's unit-tested; the coordinator computes the DeviceAttestationNonce as
/// `sha256(publicKey)` from this `publicKey`.
pub fn build_request_body(serial: &str, udid: &str, public_key_b64: &str) -> String {
    serde_json::json!({
        "serial": serial,
        "udid": udid,
        "publicKey": public_key_b64,
    })
    .to_string()
}

/// Trigger a key-bound MDA option-B attestation: ask the console coordinator to
/// send the device an MDM DeviceInformation attestation whose nonce commits to
/// `public_key_b64`. Best-effort and fail-soft — a failure just means no fresh
/// chain is requested this boot; the agent stays self-attested and the next
/// boot retries. Reads serial/UDID/console-key/URL from the environment; a
/// no-op (returns `false`) unless all are configured.
///
/// Apple rate-limits DeviceInformation attestation to ~1/device/7 days, so the
/// coordinator/device may ignore rapid repeats — that's fine, the previously
/// captured chain remains valid and bound while the signing key is stable.
pub fn request_attestation(public_key_b64: &str) -> bool {
    let (Ok(url), Ok(serial), Ok(udid)) = (
        std::env::var(ENV_REQUEST_URL),
        std::env::var(ENV_DEVICE_SERIAL),
        std::env::var(ENV_DEVICE_UDID),
    ) else {
        return false;
    };
    let api_key = std::env::var(ENV_CONSOLE_API_KEY).unwrap_or_default();
    post_request_attestation(&url, &api_key, &serial, &udid, public_key_b64)
}

/// POST the request-attestation body to `url` (the coordinator). Shells out to
/// curl (matches `load_from_url` — boot is synchronous and the agent's reqwest
/// is async-only); 20s ceiling so it never blocks boot for long. `api_key` may
/// be empty (the endpoint then relies on other auth / fails closed server-side).
fn post_request_attestation(
    url: &str,
    api_key: &str,
    serial: &str,
    udid: &str,
    public_key_b64: &str,
) -> bool {
    use std::process::Command;
    let body = build_request_body(serial, udid, public_key_b64);
    let mut args = vec![
        "-fsS".to_string(),
        "--max-time".to_string(),
        "20".to_string(),
        "-X".to_string(),
        "POST".to_string(),
        "-H".to_string(),
        "content-type: application/json".to_string(),
    ];
    if !api_key.is_empty() {
        args.push("-H".to_string());
        args.push(format!("authorization: Bearer {api_key}"));
    }
    args.push("-d".to_string());
    args.push(body);
    args.push(url.to_string());

    match Command::new("curl").args(&args).output() {
        Ok(out) if out.status.success() => {
            tracing::info!("requested key-bound MDA attestation (option-B) from coordinator");
            true
        }
        Ok(out) => {
            tracing::warn!(
                status = %out.status,
                "request-attestation call returned non-zero; staying self-attested this boot"
            );
            false
        }
        Err(e) => {
            tracing::warn!(error = %e, "request-attestation curl failed; staying self-attested");
            false
        }
    }
}

// ---------------------------------------------------------------------------
// Auto option-B (production): derive serial/UDID + URLs and acquire the chain
// with zero hand-set env vars. Kicks in only when (a) no explicit COCORE_MDA_*
// env is configured and (b) the machine is actually MDM-enrolled. Honors the
// 7-day Apple rate limit by only requesting a fresh attestation when no bound
// chain is captured yet, throttled by a local cooldown.
// ---------------------------------------------------------------------------

/// Min interval between auto request-attestation calls. We only request when no
/// chain is captured yet; this just avoids hammering the coordinator (and the
/// device) while a capture is in flight or the device isn't fully enrolled.
const AUTO_REQUEST_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(6 * 3600);

/// True iff the operator pinned any explicit MDA acquisition env var. When set,
/// the explicit `try_load` / env `request_attestation` path owns the flow and
/// the auto path stays out of the way.
pub fn any_explicit_mda_env() -> bool {
    std::env::var(ENV_CHAIN_PATH).is_ok()
        || std::env::var(ENV_CHAIN_URL).is_ok()
        || std::env::var(ENV_ATTEST_BINARY).is_ok()
        || std::env::var(ENV_REQUEST_URL).is_ok()
}

/// Auto-acquire the MDA chain for a serving agent: derive the serial, Hardware
/// UUID, and coordinator URLs from `console_base`, and (only when this machine
/// is MDM-enrolled) load the captured chain, requesting a fresh, key-bound
/// attestation if none exists yet. Returns the chain (possibly empty this boot;
/// a freshly-requested one lands asynchronously and is picked up on the next
/// attestation refresh). Always fail-soft.
pub fn acquire_auto(console_base: &str, api_key: &str, public_key_b64: &str) -> Vec<Vec<u8>> {
    if !mdm_enrolled() {
        return Vec::new();
    }
    let Some(serial) = device_serial() else {
        tracing::warn!("MDA auto: enrolled but could not read device serial; skipping");
        return Vec::new();
    };
    let base = console_base.trim_end_matches('/');
    let chain_url = format!(
        "{base}/api/agent/mdm/attestation-chain?serial={}",
        urlencode(&serial)
    );
    tracing::info!(
        serial = %serial,
        base = %base,
        api_key_len = api_key.len(),
        "MDA auto: fetching captured chain"
    );
    // Try the already-captured chain first (reused across refreshes; rate-limit
    // friendly — we never re-request once we have a bound chain). The endpoint
    // is bearer-gated, so we MUST present the api_key (a keyless GET 401s).
    if let Ok(chain) = load_from_url_with_key(&chain_url, api_key) {
        if !chain.is_empty() {
            // Only trust a chain that actually binds THIS signing key. After a
            // key rotation (fresh install → new Secure Enclave key) the
            // coordinator may still hold a chain bound to the OLD key; embedding
            // it would never verify, and — worse — would mask the need to
            // re-request. A non-binding chain is treated as "no chain".
            if chain_binds_key(&chain, public_key_b64) {
                tracing::info!(
                    certs = chain.len(),
                    "MDA auto: loaded captured chain (binds key)"
                );
                return chain;
            }
            tracing::warn!(
                "MDA auto: captured chain does not bind the current signing key (rotated?); re-requesting"
            );
        }
    }
    // No chain yet → request one (cooldown-gated), then return empty for now.
    let Some(udid) = device_hardware_uuid() else {
        tracing::warn!("MDA auto: could not read Hardware UUID; cannot request attestation");
        return Vec::new();
    };
    if auto_request_cooldown_elapsed() {
        let request_url = format!("{base}/api/agent/mdm/request-attestation");
        if post_request_attestation(&request_url, api_key, &serial, &udid, public_key_b64) {
            mark_auto_requested();
            tracing::info!("MDA auto: requested attestation; chain will land on a later refresh");
        }
    } else {
        tracing::debug!("MDA auto: within request cooldown; not re-requesting this boot");
    }
    Vec::new()
}

/// True iff `chain` (DER, leaf-first) verifies and is bound to the
/// base64-encoded P-256 signing key `public_key_b64` — by the leaf key itself
/// or by the freshness nonce (`sha256(pubkey)`), per `MdaResult::binds_key`.
/// Fail-closed: any decode/verify error → false (treat as not bound).
fn chain_binds_key(chain: &[Vec<u8>], public_key_b64: &str) -> bool {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    let Ok(raw) = B64.decode(public_key_b64) else {
        return false;
    };
    crate::mda::verify_chain(chain)
        .map(|r| r.binds_key(&raw))
        .unwrap_or(false)
}

/// Is this Mac currently MDM-enrolled? Reads `profiles status -type enrollment`
/// ("MDM enrollment: Yes"). Any failure / non-macOS → false (skip option-B).
pub fn mdm_enrolled() -> bool {
    run_capture("profiles", &["status", "-type", "enrollment"])
        .map(|out| {
            out.lines().any(|l| {
                let l = l.trim();
                l.starts_with("MDM enrollment:") && l.contains("Yes")
            })
        })
        .unwrap_or(false)
}

/// Device serial (env override `COCORE_MDA_DEVICE_SERIAL`, else IOPlatformSerialNumber).
pub fn device_serial() -> Option<String> {
    if let Ok(s) = std::env::var(ENV_DEVICE_SERIAL) {
        if !s.is_empty() {
            return Some(s);
        }
    }
    ioreg_value("IOPlatformSerialNumber")
}

/// The MDM enrollment id macOS reports for a Mac = the Hardware UUID
/// (env override `COCORE_MDA_DEVICE_UDID`, else IOPlatformUUID).
pub fn device_hardware_uuid() -> Option<String> {
    if let Ok(s) = std::env::var(ENV_DEVICE_UDID) {
        if !s.is_empty() {
            return Some(s);
        }
    }
    ioreg_value("IOPlatformUUID")
}

/// Pull a string property off the IOPlatformExpertDevice node via `ioreg`.
fn ioreg_value(key: &str) -> Option<String> {
    let out = run_capture("ioreg", &["-rd1", "-c", "IOPlatformExpertDevice"])?;
    for line in out.lines() {
        if line.contains(&format!("\"{key}\"")) {
            // line looks like:  "IOPlatformUUID" = "376AF848-..."
            if let Some(v) = line.split('=').nth(1) {
                let v = v.trim().trim_matches('"').trim();
                if !v.is_empty() {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}

/// Run a command and capture stdout as a String; None on failure / non-zero.
fn run_capture(cmd: &str, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new(cmd).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn auto_request_marker_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".cocore").join(".mda-last-request"))
}

/// True if it's been longer than the cooldown since the last auto request (or
/// there's no record yet). Best-effort: any IO error → allow the request.
fn auto_request_cooldown_elapsed() -> bool {
    let Some(path) = auto_request_marker_path() else {
        return true;
    };
    let Ok(meta) = std::fs::metadata(&path) else {
        return true;
    };
    match meta.modified().ok().and_then(|m| m.elapsed().ok()) {
        Some(elapsed) => elapsed >= AUTO_REQUEST_COOLDOWN,
        None => true,
    }
}

fn mark_auto_requested() {
    if let Some(path) = auto_request_marker_path() {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(&path, b"");
    }
}

/// Clear the auto-request cooldown marker so the next attestation refresh
/// re-requests a hardware attestation immediately instead of waiting out the
/// remaining cooldown. Used by `cocore agent attestation --retry` for an
/// enrolled Mac that's impatient for its key-bound chain. Returns `Ok(true)`
/// when a marker existed and was removed, `Ok(false)` when there was nothing to
/// clear, and `Err` only on an unexpected IO error.
pub fn clear_auto_request_cooldown() -> std::io::Result<bool> {
    let Some(path) = auto_request_marker_path() else {
        return Ok(false);
    };
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

/// Minimal query-component percent-encoding (serials/UUIDs are alphanumeric +
/// `-`, but encode defensively so a stray char can't break the URL).
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Read a PEM file and return one DER blob per CERTIFICATE block,
/// in file order.
pub fn load_from_file(path: &Path) -> Result<Vec<Vec<u8>>> {
    let pem =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    parse_pem_chain(&pem)
}

/// Invoke `binary` with no arguments + an empty stdin; treat its
/// stdout as a PEM chain.
pub fn load_from_binary(binary: &Path) -> Result<Vec<Vec<u8>>> {
    use std::io::Read;
    use std::process::{Command, Stdio};
    use std::time::Instant;

    let mut child = Command::new(binary)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawning {}", binary.display()))?;

    // Poll for exit with a hard deadline. We deliberately don't
    // collect the binary's stderr — Apple's framework prints
    // device-identifying metadata to stderr on error paths and
    // routing that through our logger would create the kind of
    // leak the content audit (PR #134) explicitly closed.
    let deadline = Instant::now() + ATTEST_BINARY_TIMEOUT;
    loop {
        if let Some(status) = child.try_wait()? {
            if !status.success() {
                bail!("attest binary exited with {status}");
            }
            break;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            bail!(
                "attest binary did not exit within {}s; killed",
                ATTEST_BINARY_TIMEOUT.as_secs()
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    let mut stdout_buf = Vec::new();
    if let Some(mut s) = child.stdout.take() {
        s.read_to_end(&mut stdout_buf)
            .context("reading attest binary stdout")?;
    }
    let pem = std::str::from_utf8(&stdout_buf).context("attest binary stdout is not UTF-8")?;
    parse_pem_chain(pem)
}

/// `curl` the coordinator chain URL and parse the response. We shell out
/// to curl (rather than pulling in a blocking HTTP client) because
/// `try_load` runs synchronously at boot and the agent's `reqwest` is
/// async-only; this mirrors the attest-binary strategy's subprocess shape.
pub fn load_from_url(url: &str) -> Result<Vec<Vec<u8>>> {
    load_from_url_with_key(url, "")
}

/// Like `load_from_url`, but presents the agent's bearer key. The
/// `/api/agent/mdm/attestation-chain` endpoint is `authenticateAgent`-gated, so
/// a keyless GET 401s (curl `-f` → exit 56) — which is why the auto path could
/// request an attestation but never read the captured chain back. `acquire_auto`
/// always has the key, so it must use this.
pub fn load_from_url_with_key(url: &str, api_key: &str) -> Result<Vec<Vec<u8>>> {
    use std::process::Command;

    // Deliberately NOT `-f`: on a non-2xx we want to SEE the status + body, not
    // have curl collapse it into a bare non-zero exit. `-w` appends the HTTP
    // status after the body behind a marker so we can split it back out. This
    // is the diagnostic that pins why the in-process worker's chain GET can
    // come back empty while an identical manual GET returns the chain.
    const MARKER: &str = "\n__COCORE_HTTP__";
    let wfmt = format!("{MARKER}%{{http_code}}");
    let auth = if api_key.is_empty() {
        String::new()
    } else {
        format!("authorization: Bearer {api_key}")
    };
    let mut args: Vec<&str> = vec!["-sSL", "--max-time", "20", "-w", &wfmt];
    if !auth.is_empty() {
        args.push("-H");
        args.push(&auth);
    }
    args.push(url);
    let out = Command::new("curl")
        .args(&args)
        .output()
        .with_context(|| format!("invoking curl for {url}"))?;
    if !out.status.success() {
        bail!("curl for MDA chain URL failed to run: {}", out.status);
    }
    let raw = String::from_utf8(out.stdout).context("MDA chain URL response is not UTF-8")?;
    let (body, status) = raw.rsplit_once(MARKER).unwrap_or((raw.as_str(), "?"));
    let status = status.trim();
    if status != "200" {
        tracing::warn!(
            http_status = status,
            authed = !auth.is_empty(),
            body = %body.chars().take(200).collect::<String>(),
            "MDA chain GET returned non-200; treating as no chain this refresh"
        );
        return Ok(Vec::new());
    }
    let chain = parse_chain_response(body)?;
    if chain.is_empty() {
        tracing::info!(
            authed = !auth.is_empty(),
            "MDA chain GET 200 but no chain captured yet"
        );
    }
    Ok(chain)
}

/// Accept either a raw PEM chain or the console's JSON shape
/// `{"chain": ["<pem>", …] | null, …}`. A null/absent `chain` means the
/// coordinator hasn't captured this device's attestation yet → empty.
pub fn parse_chain_response(body: &str) -> Result<Vec<Vec<u8>>> {
    let trimmed = body.trim_start();
    if trimmed.starts_with('{') {
        let v: serde_json::Value = serde_json::from_str(trimmed)
            .context("MDA chain response looked like JSON but didn't parse")?;
        match v.get("chain") {
            Some(serde_json::Value::Array(arr)) => {
                let joined = arr
                    .iter()
                    .filter_map(|x| x.as_str())
                    .collect::<Vec<_>>()
                    .join("\n");
                return parse_pem_chain(&joined);
            }
            // `chain: null` (not captured yet) or missing → empty, not an error.
            _ => return Ok(Vec::new()),
        }
    }
    // Raw PEM body.
    parse_pem_chain(body)
}

/// Parse one or more PEM CERTIFICATE blocks into their DER bytes.
/// Whitespace between blocks is ignored; any non-CERTIFICATE block
/// (e.g. PRIVATE KEY) is rejected to avoid silent misuse.
pub fn parse_pem_chain(pem: &str) -> Result<Vec<Vec<u8>>> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};

    let mut out = Vec::new();
    let mut in_block = false;
    let mut current = String::new();
    for line in pem.lines() {
        let trimmed = line.trim();
        if let Some(label) = trimmed
            .strip_prefix("-----BEGIN ")
            .and_then(|s| s.strip_suffix("-----"))
        {
            if label != "CERTIFICATE" {
                bail!("PEM block label must be CERTIFICATE, got {label:?}");
            }
            in_block = true;
            current.clear();
            continue;
        }
        if trimmed.starts_with("-----END ") {
            if !in_block {
                bail!("END line without matching BEGIN");
            }
            in_block = false;
            let der = B64
                .decode(&current)
                .map_err(|e| anyhow!("base64 decode failed: {e}"))?;
            out.push(der);
            current.clear();
            continue;
        }
        if in_block {
            current.push_str(trimmed);
        }
    }
    if in_block {
        bail!("unterminated CERTIFICATE block (missing END line)");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Round-trip a single self-signed cert through parse_pem_chain.
    /// We don't care about cryptographic content here — just that
    /// the base64 inside the BEGIN/END markers round-trips through
    /// the parser.
    fn synthetic_pem(der_bodies: &[&[u8]]) -> String {
        use base64::{engine::general_purpose::STANDARD as B64, Engine};
        let mut out = String::new();
        for body in der_bodies {
            out.push_str("-----BEGIN CERTIFICATE-----\n");
            out.push_str(&B64.encode(body));
            out.push('\n');
            out.push_str("-----END CERTIFICATE-----\n");
        }
        out
    }

    #[test]
    fn parse_pem_chain_round_trips_one_cert() {
        let bodies: &[&[u8]] = &[b"hello DER world"];
        let pem = synthetic_pem(bodies);
        let parsed = parse_pem_chain(&pem).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0], bodies[0]);
    }

    #[test]
    fn parse_pem_chain_round_trips_multiple_certs_in_order() {
        let bodies: &[&[u8]] = &[b"leaf bytes", b"intermediate bytes", b"root-ish bytes"];
        let pem = synthetic_pem(bodies);
        let parsed = parse_pem_chain(&pem).unwrap();
        assert_eq!(parsed.len(), 3);
        for (i, body) in bodies.iter().enumerate() {
            assert_eq!(&parsed[i], body, "chain entry {i} mismatched");
        }
    }

    #[test]
    fn parse_pem_chain_returns_empty_for_no_blocks() {
        let pem = "\n# just a comment\n";
        let parsed = parse_pem_chain(pem).unwrap();
        assert!(parsed.is_empty());
    }

    #[test]
    fn parse_chain_response_accepts_json_chain_array() {
        let bodies: &[&[u8]] = &[b"leaf bytes", b"intermediate bytes"];
        let pems: Vec<String> = bodies.iter().map(|b| synthetic_pem(&[b])).collect();
        let json = serde_json::json!({ "status": "ok", "chain": pems }).to_string();
        let parsed = parse_chain_response(&json).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0], bodies[0]);
        assert_eq!(parsed[1], bodies[1]);
    }

    #[test]
    fn parse_chain_response_treats_null_chain_as_empty() {
        let json = r#"{"status":"pending","chain":null}"#;
        assert!(parse_chain_response(json).unwrap().is_empty());
        // missing field too
        assert!(parse_chain_response(r#"{"status":"pending"}"#)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn parse_chain_response_falls_back_to_raw_pem() {
        let bodies: &[&[u8]] = &[b"raw-pem-leaf"];
        let pem = synthetic_pem(bodies);
        let parsed = parse_chain_response(&pem).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0], bodies[0]);
    }

    #[test]
    fn parse_pem_chain_rejects_non_certificate_blocks() {
        let pem = "-----BEGIN PRIVATE KEY-----\nAAA=\n-----END PRIVATE KEY-----\n";
        let err = parse_pem_chain(pem).unwrap_err();
        assert!(format!("{err}").contains("CERTIFICATE"));
    }

    #[test]
    fn parse_pem_chain_rejects_unterminated_block() {
        let pem = "-----BEGIN CERTIFICATE-----\nAAA=\n";
        let err = parse_pem_chain(pem).unwrap_err();
        assert!(format!("{err}").contains("unterminated"));
    }

    #[test]
    fn load_from_file_reads_pem_chain() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let bodies: &[&[u8]] = &[b"alpha", b"beta"];
        let pem = synthetic_pem(bodies);
        {
            let mut f = tmp.reopen().unwrap();
            f.write_all(pem.as_bytes()).unwrap();
        }
        let chain = load_from_file(tmp.path()).unwrap();
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0], bodies[0]);
        assert_eq!(chain[1], bodies[1]);
    }

    #[test]
    fn load_from_file_errors_on_missing_path() {
        let err = load_from_file(Path::new("/nonexistent/path/xyz.pem")).unwrap_err();
        assert!(format!("{err}").contains("reading"));
    }

    #[test]
    fn urlencode_passes_serials_and_encodes_specials() {
        // Serials / UUIDs (alnum + dash) pass through unchanged.
        assert_eq!(urlencode("H2WHW38LQ6NV"), "H2WHW38LQ6NV");
        assert_eq!(
            urlencode("376AF848-8EC9-5336-AB51-0801857F726D"),
            "376AF848-8EC9-5336-AB51-0801857F726D"
        );
        // Anything else is percent-encoded so it can't break the query string.
        assert_eq!(urlencode("a b&c=d?e"), "a%20b%26c%3Dd%3Fe");
    }

    #[test]
    fn request_body_is_well_formed_json() {
        let body = build_request_body("H2WHW38LQ6NV", "A1B2-UDID", "cHVia2V5");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["serial"], "H2WHW38LQ6NV");
        assert_eq!(v["udid"], "A1B2-UDID");
        assert_eq!(v["publicKey"], "cHVia2V5");
    }

    /// Make sure `try_load` returns empty (not an error) when no
    /// env var is set. We can't reliably manipulate process env
    /// inside a parallel-test framework without races, so this
    /// test runs only when neither env var is set — most common
    /// case in CI.
    #[test]
    fn try_load_returns_empty_with_no_env_configuration() {
        // Best-effort guard. We don't assert if these are set,
        // because some operator-style tests intentionally set
        // them.
        if std::env::var(ENV_CHAIN_PATH).is_ok() || std::env::var(ENV_ATTEST_BINARY).is_ok() {
            return;
        }
        assert!(try_load().is_empty());
    }

    /// load_from_binary spawns a real child process. We use
    /// `/bin/sh -c '...'` to emit a synthetic chain on stdout; no
    /// Apple framework required. Skipped on platforms without
    /// /bin/sh.
    #[test]
    fn load_from_binary_captures_stdout_pem() {
        if !Path::new("/bin/sh").exists() {
            return;
        }
        let bodies: &[&[u8]] = &[b"binary-test-leaf"];
        let pem = synthetic_pem(bodies);

        // Write a small shell script that echoes the PEM, then
        // CLOSE every writable fd to the file before exec'ing it.
        // On Linux, exec() of a file that has any open write fd
        // returns ETXTBSY ("Text file busy", os error 26).
        // NamedTempFile's internal File handle stays open with
        // write access for the lifetime of the binding, so we
        // convert into a TempPath here — that drops the File but
        // keeps the path (auto-deleted on drop, same as before).
        let script = tempfile::Builder::new()
            .prefix("cocore-mda-stub-")
            .suffix(".sh")
            .tempfile()
            .unwrap();
        {
            let mut f = script.reopen().unwrap();
            writeln!(f, "#!/bin/sh").unwrap();
            // Use printf to avoid `echo` line-buffering oddities.
            for line in pem.lines() {
                writeln!(f, "printf '%s\\n' {}", shell_escape(line)).unwrap();
            }
            // Flush + fsync so the bytes are on disk and this write fd is fully
            // released before we exec — shrinks the ETXTBSY window on Linux.
            f.sync_all().unwrap();
        }
        let script_path = script.into_temp_path();

        // chmod +x
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&script_path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script_path, perms).unwrap();

        // Linux can transiently return ETXTBSY ("Text file busy") when exec'ing
        // a file whose write fd the kernel only just released — even after the
        // sync + drop above. `load_from_binary` surfaces that as an `Err` (from
        // `Command::spawn`), so retry a few times to keep the test hermetic on
        // CI. Normally succeeds on the first attempt; the loop only spins on the
        // rare race (≤ ~0.5s worst case).
        let chain = {
            let mut got = None;
            let mut last_err = None;
            for _ in 0..25 {
                match load_from_binary(&script_path) {
                    Ok(c) => {
                        got = Some(c);
                        break;
                    }
                    Err(e) => {
                        last_err = Some(e);
                        std::thread::sleep(std::time::Duration::from_millis(20));
                    }
                }
            }
            got.unwrap_or_else(|| {
                panic!(
                    "load_from_binary failed after retries: {:#}",
                    last_err.unwrap()
                )
            })
        };
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0], bodies[0]);
    }

    /// load_from_binary surfaces non-zero exit as an error, not
    /// silently as an empty chain. Operator-visibility matters
    /// when the attestation tool exists but fails.
    #[test]
    fn load_from_binary_errors_on_nonzero_exit() {
        if !Path::new("/bin/false").exists() {
            return;
        }
        let err = load_from_binary(Path::new("/bin/false")).unwrap_err();
        assert!(format!("{err}").contains("exited with"));
    }

    fn shell_escape(s: &str) -> String {
        // POSIX single-quote with embedded-quote escape.
        let mut out = String::from("'");
        for c in s.chars() {
            if c == '\'' {
                out.push_str("'\\''");
            } else {
                out.push(c);
            }
        }
        out.push('\'');
        out
    }
}
