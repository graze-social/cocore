//! `cocore agent doctor` — health-check + (with `--fix`) safe repair.
//!
//! Why this exists: when something goes wrong with an installed agent,
//! the failure modes are silent (publishes 401 at WARN level, daemon
//! quietly retries forever, machine never appears on /machines, user
//! has no diagnostic path). The doctor produces one punch-list output
//! that covers every failure mode we know about today and prints
//! exact commands for whatever the user has to do themselves.
//!
//! Checks (each runs independently; one failure doesn't stop the
//! others — the goal is a complete picture, not a fail-fast):
//!
//!   1. session.json present + parseable
//!   2. LaunchAgent loaded (macOS only)
//!   3. Console reachable + version comparison vs. installed
//!   4. API key valid via /api/agent/whoami (smoke-tests the same
//!      auth path the proxy createRecord uses; a 401 here means the
//!      next provider/attestation publish would fail)
//!   5. Cross-system view via /api/agent/health: advisor sees us,
//!      PDS has a fresh provider record. Diagnosis from the server
//!      drives the user-facing hint string.
//!
//! `--fix` does the safe repairs only:
//!   * Bounce the LaunchAgent (covers the "session.json is fresher
//!     than the running daemon" case after `cocore agent pair`).
//!
//! Things `--fix` does NOT do:
//!   * Re-pair (browser-mediated; can't be silent).
//!   * Replace the binary (use `cocore agent update`).
//!   * Republish records (would require running cmd_serve's full
//!     init; bouncing the LaunchAgent achieves the same thing
//!     under normal conditions).

use anyhow::{Context, Result};
use serde::Deserialize;

use cocore_provider::oauth;

const REQUEST_TIMEOUT_SECS: u64 = 6;

#[derive(Debug, Deserialize)]
struct WhoamiResponse {
    did: String,
    valid: bool,
    #[serde(default)]
    #[allow(dead_code)]
    key_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case)]
struct HealthResponse {
    diagnosis: String,
    hint: String,
    advisor: HealthAdvisor,
    pds: HealthPds,
}

#[derive(Debug, Deserialize)]
struct HealthAdvisor {
    online: bool,
    #[serde(rename = "lastSeen")]
    last_seen: Option<String>,
    #[serde(rename = "machineLabel")]
    machine_label: Option<String>,
}

#[derive(Debug, Deserialize)]
struct HealthPds {
    #[serde(rename = "providerRecord")]
    provider_record: Option<HealthProviderRecord>,
}

#[derive(Debug, Deserialize)]
struct HealthProviderRecord {
    uri: String,
    #[serde(rename = "createdAt")]
    created_at: String,
}

/// One row in the punch-list output. `ok=true` is the green tick;
/// `ok=false` is a red x with a note. Notes are human-readable
/// sentences, not key-value pairs.
struct Check {
    name: &'static str,
    ok: bool,
    note: String,
}

pub async fn run(console: &str, fix: bool) -> Result<()> {
    let console = console.trim_end_matches('/');
    println!("==> cocore agent doctor");
    println!("  console: {console}");
    println!(
        "  binary:  {} (cocore {})",
        current_exe()?,
        env!("CARGO_PKG_VERSION")
    );
    println!();

    let mut checks: Vec<Check> = Vec::new();

    // 1. session.json
    let session = oauth::load_session().context("read session.json")?;
    let session_check = match &session {
        Some(s) => Check {
            name: "session.json",
            ok: true,
            note: format!("paired as {} ({})", s.handle, s.did),
        },
        None => Check {
            name: "session.json",
            ok: false,
            note: format!(
                "missing or unreadable. Run `cocore agent pair --console {console}` to mint one."
            ),
        },
    };
    print_check(&session_check);
    checks.push(session_check);

    // 2. LaunchAgent (macOS only)
    let launchagent_state = launchagent_status();
    print_check(&launchagent_state);
    checks.push(launchagent_state);

    // 3. Latest release vs installed
    let version_check = compare_to_latest(console).await;
    print_check(&version_check);
    checks.push(version_check);

    // 4 + 5 — both require a session.
    let Some(s) = session else {
        println!();
        println!(
            "Skipping API-key + cross-system checks: no session. Pair first, then re-run doctor."
        );
        if fix {
            println!("--fix: nothing to fix without a session.");
        }
        return Ok(());
    };
    let api_key = s.api_key.clone();
    let bearer = format!("Bearer {api_key}");

    let whoami = check_whoami(console, &bearer).await;
    print_check(&whoami);
    let key_valid = whoami.ok;
    checks.push(whoami);

    // Health is only meaningful if the key is valid; otherwise the
    // call would 401 and the diagnosis would be "you don't have a
    // valid key" — which we already know.
    if key_valid {
        let health = check_health(console, &bearer).await;
        print_check(&health);
        checks.push(health);
    } else {
        let dummy = Check {
            name: "cross-system health",
            ok: false,
            note: "skipped because the API key is invalid; re-pair first.".to_string(),
        };
        print_check(&dummy);
        checks.push(dummy);
    }

    // Summary
    let failed: Vec<&Check> = checks.iter().filter(|c| !c.ok).collect();
    println!();
    if failed.is_empty() {
        println!("==> all checks passed.");
        return Ok(());
    }
    println!("==> {} check(s) failed:", failed.len());
    for c in &failed {
        println!("  - {}: {}", c.name, c.note);
    }

    if !fix {
        println!();
        println!(
            "Re-run with `--fix` to apply the safe automatic repairs (bouncing the LaunchAgent)."
        );
        println!("Anything that needs a browser (re-pair) or replaces the binary (update) prints as a command above.");
        return Ok(());
    }

    // --fix: do the safe repairs.
    println!();
    println!("==> --fix: applying safe repairs");
    apply_fixes();
    println!(
        "Fixes applied. Re-run `cocore agent doctor` in ~10s to confirm everything is healthy."
    );
    Ok(())
}

fn print_check(c: &Check) {
    let mark = if c.ok { "✓" } else { "✗" };
    println!("  [{mark}] {} — {}", c.name, c.note);
}

fn current_exe() -> Result<String> {
    Ok(std::env::current_exe()
        .context("current_exe")?
        .display()
        .to_string())
}

async fn compare_to_latest(console: &str) -> Check {
    let url = format!("{console}/agent/version");
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return Check {
                name: "latest release",
                ok: false,
                note: format!("could not build HTTP client: {e}"),
            };
        }
    };
    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => {
            return Check {
                name: "latest release",
                ok: false,
                note: format!("GET {url} failed: {e}"),
            };
        }
    };
    if !resp.status().is_success() {
        return Check {
            name: "latest release",
            ok: false,
            note: format!("GET {url} returned {}", resp.status()),
        };
    }
    let tag = match resp.text().await {
        Ok(t) => t.trim().to_string(),
        Err(e) => {
            return Check {
                name: "latest release",
                ok: false,
                note: format!("read {url}: {e}"),
            };
        }
    };
    let installed = format!("v{}", env!("CARGO_PKG_VERSION"));
    if tag == installed {
        Check {
            name: "latest release",
            ok: true,
            note: format!("you're on {} (latest)", installed),
        }
    } else {
        Check {
            name: "latest release",
            ok: false,
            note: format!(
                "newer release available: {} (you have {}). Run `cocore agent update`.",
                tag, installed
            ),
        }
    }
}

async fn check_whoami(console: &str, bearer: &str) -> Check {
    let url = format!("{console}/api/agent/whoami");
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return Check {
                name: "API key",
                ok: false,
                note: format!("could not build HTTP client: {e}"),
            };
        }
    };
    let resp = match client
        .get(&url)
        .header("Authorization", bearer)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            return Check {
                name: "API key",
                ok: false,
                note: format!("GET {url} failed: {e}"),
            };
        }
    };
    let status = resp.status();
    if status.as_u16() == 401 {
        return Check {
            name: "API key",
            ok: false,
            note: "401 from the console — the key in session.json is invalid. Run `cocore agent pair` to mint a fresh one (typical cause: a recent wipe-my-data dropped the key).".to_string(),
        };
    }
    if !status.is_success() {
        return Check {
            name: "API key",
            ok: false,
            note: format!("GET {url} returned {status}"),
        };
    }
    match resp.json::<WhoamiResponse>().await {
        Ok(w) if w.valid => Check {
            name: "API key",
            ok: true,
            note: format!("valid; resolves to {}", w.did),
        },
        Ok(_) => Check {
            name: "API key",
            ok: false,
            note: "console returned 200 but valid=false — investigate.".to_string(),
        },
        Err(e) => Check {
            name: "API key",
            ok: false,
            note: format!("parse whoami: {e}"),
        },
    }
}

async fn check_health(console: &str, bearer: &str) -> Check {
    let url = format!("{console}/api/agent/health");
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return Check {
                name: "cross-system health",
                ok: false,
                note: format!("could not build HTTP client: {e}"),
            };
        }
    };
    let resp = match client
        .get(&url)
        .header("Authorization", bearer)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            return Check {
                name: "cross-system health",
                ok: false,
                note: format!("GET {url} failed: {e}"),
            };
        }
    };
    if !resp.status().is_success() {
        return Check {
            name: "cross-system health",
            ok: false,
            note: format!("GET {url} returned {}", resp.status()),
        };
    }
    match resp.json::<HealthResponse>().await {
        Ok(h) => {
            let advisor_summary = if h.advisor.online {
                let label = h.advisor.machine_label.as_deref().unwrap_or("unknown");
                let last_seen = h.advisor.last_seen.as_deref().unwrap_or("?");
                format!("advisor sees us ({label}, last_seen={last_seen})")
            } else {
                "advisor offline".to_string()
            };
            let pds_summary = match &h.pds.provider_record {
                Some(p) => format!("provider record at {} (createdAt={})", p.uri, p.created_at),
                None => "no provider record on PDS".to_string(),
            };
            let healthy = h.diagnosis == "healthy";
            Check {
                name: "cross-system health",
                ok: healthy,
                note: format!(
                    "{} · {} · diagnosis={} — {}",
                    advisor_summary, pds_summary, h.diagnosis, h.hint
                ),
            }
        }
        Err(e) => Check {
            name: "cross-system health",
            ok: false,
            note: format!("parse health: {e}"),
        },
    }
}

#[cfg(target_os = "macos")]
fn launchagent_status() -> Check {
    use std::process::Command;
    let uid = unsafe { libc::getuid() };
    let target = format!("gui/{uid}/dev.cocore.provider");
    let out = match Command::new("launchctl").args(["print", &target]).output() {
        Ok(o) => o,
        Err(e) => {
            return Check {
                name: "LaunchAgent",
                ok: false,
                note: format!("could not run launchctl: {e}"),
            };
        }
    };
    if !out.status.success() {
        return Check {
            name: "LaunchAgent",
            ok: false,
            note: format!(
                "{target} not loaded. The installer didn't run, or the LaunchAgent was unloaded. Re-run the installer with `curl -fsSL cocore.dev/agent | sh`."
            ),
        };
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let state = stdout
        .lines()
        .find_map(|l| {
            let l = l.trim();
            l.strip_prefix("state = ").map(str::to_string)
        })
        .unwrap_or_else(|| "?".to_string());
    let pid = stdout
        .lines()
        .find_map(|l| {
            let l = l.trim();
            l.strip_prefix("pid = ").map(str::to_string)
        })
        .unwrap_or_else(|| "—".to_string());
    let ok = state == "running";
    Check {
        name: "LaunchAgent",
        ok,
        note: format!("{target}: state={state} pid={pid}"),
    }
}

#[cfg(target_os = "linux")]
fn launchagent_status() -> Check {
    // Linux parity for the macOS LaunchAgent check: inspect the systemd user
    // unit. `ok` only when it's active; when it isn't installed we report a
    // non-fatal note (the operator may run the agent another way) rather than
    // a free green tick.
    match crate::service::active_state() {
        Some((active, state)) => Check {
            name: "serve service",
            ok: active,
            note: format!("{}: {state}", crate::service::UNIT),
        },
        None => Check {
            name: "serve service",
            ok: true,
            note: format!(
                "{} not installed (running the agent another way is fine; \
                 re-run the installer to manage it via systemd)",
                crate::service::UNIT
            ),
        },
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn launchagent_status() -> Check {
    Check {
        name: "serve service",
        ok: true,
        note: "not applicable on this OS (manage your serve daemon with your platform's service manager)".to_string(),
    }
}

#[cfg(target_os = "macos")]
fn apply_fixes() {
    use std::process::Command;
    let uid = unsafe { libc::getuid() };
    let target = format!("gui/{uid}/dev.cocore.provider");
    let installed = Command::new("launchctl")
        .args(["print", &target])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !installed {
        println!("  - LaunchAgent not installed; skipping kickstart. Re-run `curl -fsSL cocore.dev/agent | sh` if you want it installed.");
        return;
    }
    let bounced = Command::new("launchctl")
        .args(["kickstart", "-k", &target])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if bounced {
        println!("  - Bounced LaunchAgent. Daemon will re-read session.json and republish provider record on next serve init.");
    } else {
        println!(
            "  - launchctl kickstart {target} failed. Run it manually: `launchctl kickstart -k {target}`."
        );
    }
}

#[cfg(target_os = "linux")]
fn apply_fixes() {
    // Linux parity for the macOS kickstart fix: restart the systemd user unit.
    if crate::service::restart_if_installed() {
        println!("  - Restarted {}. It will re-read session.json and republish its provider record on next serve init.", crate::service::UNIT);
    } else {
        println!(
            "  - {} not installed; nothing to restart. Re-run the installer if you want it managed via systemd.",
            crate::service::UNIT
        );
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn apply_fixes() {
    println!("  - no fixes to apply on this OS.");
}
