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
//!      `/agent/mdm/attestation-chain` endpoint returns once step-ca
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
//! ## BINDING CONTRACT (load-bearing)
//!
//! Whichever flow produces the chain, its **leaf MUST certify this
//! agent's receipt-signing P-256 key** (the `SigningIdentity` public
//! key — the same value published as the attestation's `publicKey`). The
//! ACME `device-attest-01` path lets the device choose the attested key,
//! so the provisioning tool submits the signing key's public key. A
//! verifier BINDS the chain to the signer by requiring
//! `leaf.publicKey == attestation.publicKey`; a chain whose leaf attests
//! some OTHER key earns nothing (it could be a valid Apple chain for an
//! unrelated device, stapled onto this signer). `attestation::build`
//! enforces the same on the way out — it drops any chain that doesn't
//! verify Apple-rooted AND bind to the signing key, staying
//! self-attested rather than publishing an unbacked hardware claim.
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
    use std::process::Command;

    let out = Command::new("curl")
        .args(["-fsSL", "--max-time", "20", url])
        .output()
        .with_context(|| format!("invoking curl for {url}"))?;
    if !out.status.success() {
        bail!("curl for MDA chain URL exited with {}", out.status);
    }
    let body = String::from_utf8(out.stdout).context("MDA chain URL response is not UTF-8")?;
    parse_chain_response(&body)
}

/// Accept either a raw PEM chain or the console's JSON shape
/// `{"chain": ["<pem>", …] | null, …}`. A null/absent `chain` means the
/// coordinator hasn't captured this device's attestation yet → empty.
pub fn parse_chain_response(body: &str) -> Result<Vec<Vec<u8>>> {
    let trimmed = body.trim_start();
    if trimmed.starts_with('{') {
        let v: serde_json::Value =
            serde_json::from_str(trimmed).context("MDA chain response looked like JSON but didn't parse")?;
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
        let pems: Vec<String> = bodies
            .iter()
            .map(|b| synthetic_pem(&[b]))
            .collect();
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
        assert!(parse_chain_response(r#"{"status":"pending"}"#).unwrap().is_empty());
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
        }
        let script_path = script.into_temp_path();

        // chmod +x
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&script_path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script_path, perms).unwrap();

        let chain = load_from_binary(&script_path).unwrap();
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
