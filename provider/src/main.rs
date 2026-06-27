use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use cocore_provider::{
    advisor::AdvisorClient,
    attestation, oauth,
    pds::{
        AttestationFault, EngineFault, ModelPrice, PdsClient, ProBonoPolicy, ProviderRecord,
        TrustLevel,
    },
    pricing,
    protocol::Register,
    receipt::StrongRef,
    secure_enclave, security, system_profile,
};
use std::sync::Arc;
use tokio::sync::RwLock;

mod doctor;
mod models_cli;
mod update;

#[derive(Parser)]
#[command(
    name = "cocore",
    version,
    about = "cocore — decentralized compute, ATProto-native"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,

    #[arg(long, env = "COCORE_LOG", default_value = "info")]
    log: String,
}

#[derive(Subcommand)]
enum Cmd {
    /// Provider-agent commands. The agent is the long-running
    /// process that registers with the advisor, attests, and serves
    /// inference requests on a paired ATProto identity.
    #[command(subcommand)]
    Agent(AgentCmd),
}

#[derive(Subcommand)]
enum AgentCmd {
    /// Pair this machine with an ATProto identity. Prints a URL +
    /// 8-character code; opening the URL in any signed-in browser
    /// approves the pairing and delivers a session blob to this
    /// agent. Persists the session at `~/.cocore/session.json`.
    Pair {
        #[arg(long, env = "COCORE_CONSOLE", default_value = "https://cocore.dev")]
        console: String,
    },
    /// Run the agent: connect to the advisor, register, heartbeat,
    /// answer attestation challenges, and (eventually) serve
    /// encrypted inference requests.
    Serve {
        #[arg(
            long,
            env = "COCORE_ADVISOR",
            default_value = "wss://advisor.cocore.dev/v1/agent"
        )]
        advisor: String,
    },
    /// Print the active session's identity for debugging.
    Whoami,
    /// Print this machine's receipt-signing P-256 public key (base64 of the
    /// raw 64-byte X‖Y point — the value published as `attestation.publicKey`).
    /// The App Attest helper hashes this for its clientDataHash binding; the
    /// spike runner reads it via this command.
    Pubkey,
    /// Print this machine's owner-chosen trust tier from its PDS provider
    /// record: `attested-confidential` or `best-effort`. The macOS tray's
    /// agent supervisor runs this to decide which worker binary to spawn (the
    /// measured confidential push-receiver bundle vs. the default best-effort
    /// CLI). Prints `best-effort` when not paired / no record yet / on a read
    /// error — the safe default.
    Tier,
    /// Opt this machine IN to the attested-confidential tier (or out with
    /// `--off`). Writes the owner's `desiredTier` on the provider record —
    /// exactly what the console's "Upgrade to confidential" does — so the
    /// serving agent restarts and re-selects the confidential worker. The tray's
    /// Security section drives this; also runnable by hand.
    Confidential {
        /// Revert to best-effort instead of enabling confidential.
        #[arg(long)]
        off: bool,
    },
    /// Diagnose this install end-to-end: LaunchAgent state,
    /// session.json, API key validity, and the console's view of
    /// whether the advisor sees us + a fresh provider record is
    /// published to PDS. Output is a punch-list a user can paste
    /// into a GitHub issue.
    ///
    /// `--fix` does the safe automatic repairs (bouncing the
    /// LaunchAgent today). Re-pair / update prompts always print as
    /// commands the user runs themselves, since they require a
    /// browser or write to the binary on disk.
    Doctor {
        #[arg(long, env = "COCORE_CONSOLE", default_value = "https://cocore.dev")]
        console: String,
        /// Apply the safe fixes (kickstart the LaunchAgent if it's
        /// stopped or stale). Re-pair / update suggestions are
        /// always printed as commands; this flag never silently
        /// re-pairs or replaces the binary.
        #[arg(long)]
        fix: bool,
    },
    /// Replace this install's binary with the latest release pulled
    /// through the console's GitHub-releases proxy. With `--check`,
    /// only print the latest version + whether it's newer. Without
    /// `--check`, downloads + atomically replaces ~/.local/bin/cocore +
    /// kickstarts the LaunchAgent (macOS) so the daemon picks up the
    /// new binary.
    Update {
        #[arg(long, env = "COCORE_CONSOLE", default_value = "https://cocore.dev")]
        console: String,
        /// Print the latest version + comparison only; don't replace
        /// the installed binary.
        #[arg(long)]
        check: bool,
    },
    /// Manage which inference models this machine loads + advertises.
    ///
    /// Edits the LaunchAgent plist's `COCORE_INFERENCE_MODELS` env
    /// var and bounces the daemon. The bounced agent re-runs
    /// `build_engines()` against the new list, rebuilds the provider
    /// record from the actually-loaded engines, and re-publishes it
    /// to PDS — so the AppView's mirror (and therefore the advisor's
    /// matchmaking) sees the updated supportedModels within seconds.
    ///
    /// macOS-only; on Linux there's no LaunchAgent to bounce and the
    /// command prints what it would have done.
    #[command(subcommand)]
    Models(ModelsCmd),
    /// Pause serving on this machine. Sets the owner's `active` switch
    /// to false on this machine's provider record (the same switch the
    /// console's "Pause serving" flips) so the state is shared: the site
    /// reflects it and the menu-bar app stops the agent. Idempotent.
    Pause,
    /// Resume serving on this machine (sets `active` back to true). The
    /// menu-bar app restarts the agent and it rejoins the advisor.
    Resume,
    /// Print this machine's serve switch: `serving` or `paused`. The
    /// menu-bar app polls this to reconcile the agent process to the
    /// owner's choice no matter which side (site or tray) changed it.
    Active,
    /// Report this machine's attestation status: its trust level, whether the
    /// Mac is MDM-enrolled, whether an attestation record is published (and
    /// when it expires), and any attestation fault. Explains the common
    /// "enrolled but still self-attested" state. The "list via command" the
    /// settings UI mirrors.
    Attestation {
        /// Clear the MDA request cooldown so the next attestation refresh
        /// re-requests a hardware attestation immediately, instead of waiting
        /// out the remaining (up to 6h) cooldown. Use on an MDM-enrolled Mac
        /// that's still self-attested and you don't want to wait.
        #[arg(long)]
        retry: bool,
    },
    /// Write a content-safe diagnostic bundle (a `.tar.gz`) for a bug
    /// report and print its path. Contains crash + health telemetry only
    /// — logs (no prompt/token content by design), the last panic +
    /// backtrace, the crash counter, a redacted session (no API key, no
    /// signing key), the system profile, and macOS `.ips` crash reports.
    /// The tray's "Send bug report" button shells out to this.
    Diag {
        /// Where to write the bundle. Defaults to
        /// `~/.cocore/diagnostics-<timestamp>.tar.gz`.
        #[arg(long)]
        out: Option<std::path::PathBuf>,
    },
}

#[derive(Subcommand)]
enum ModelsCmd {
    /// Print the model NSIDs currently configured for this agent.
    List,
    /// Replace the model list with a comma-separated set. The new
    /// list takes effect after the bounce; the bounced agent's
    /// startup publish makes the change visible on PDS + AppView.
    Set {
        /// Comma-separated NSIDs, e.g.
        /// `mlx-community/Qwen2.5-3B-Instruct-4bit,mlx-community/gemma-3-4b-it-qat-4bit`
        models: String,
    },
    /// Append a model NSID to the existing list (idempotent — a
    /// duplicate add is a no-op). Run without an argument to pick from
    /// an interactive menu of catalog models that fit this machine's
    /// RAM — useful when you don't remember the exact HuggingFace NSID.
    Add { model: Option<String> },
    /// Remove a model NSID from the list (idempotent).
    Remove { model: String },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Hardening must come before *anything* else, including the
    // tracing subscriber (which allocates and may load dylibs).
    security::apply_all().context("hardening")?;

    // Capture panics durably (location + backtrace → ~/.cocore/last-panic.txt
    // + a content-free crash counter) BEFORE anything can panic, so the next
    // field failure names itself instead of vanishing with the unified log.
    cocore_provider::diagnostics::install_panic_hook();

    let cli = Cli::parse();
    init_tracing(&cli.log);

    match cli.cmd {
        Cmd::Agent(AgentCmd::Pair { console }) => cmd_pair(&console).await,
        Cmd::Agent(AgentCmd::Serve { advisor }) => cmd_serve_entry(advisor).await,
        Cmd::Agent(AgentCmd::Whoami) => cmd_whoami(),
        Cmd::Agent(AgentCmd::Pubkey) => cmd_pubkey(),
        Cmd::Agent(AgentCmd::Tier) => cmd_print_tier().await,
        Cmd::Agent(AgentCmd::Confidential { off }) => cmd_set_confidential(!off).await,
        Cmd::Agent(AgentCmd::Doctor { console, fix }) => doctor::run(&console, fix).await,
        Cmd::Agent(AgentCmd::Update { console, check }) => update::run(&console, check).await,
        Cmd::Agent(AgentCmd::Models(cmd)) => models_cli::run(cmd).await,
        Cmd::Agent(AgentCmd::Pause) => cmd_set_active(false).await,
        Cmd::Agent(AgentCmd::Resume) => cmd_set_active(true).await,
        Cmd::Agent(AgentCmd::Active) => cmd_print_active().await,
        Cmd::Agent(AgentCmd::Attestation { retry }) => cmd_attestation(retry).await,
        Cmd::Agent(AgentCmd::Diag { out }) => cmd_diag(out),
    }
}

/// Write a content-safe diagnostic bundle and print its path. Shelled
/// out to by the tray's "Send bug report" button; also runnable by hand.
fn cmd_diag(out: Option<std::path::PathBuf>) -> Result<()> {
    let profile = system_profile::collect();
    let profile_json = serde_json::to_string_pretty(&profile).unwrap_or_else(|_| "{}".to_string());
    let path = cocore_provider::diagnostics::make_diagnostic_bundle(out, &profile_json)?;
    println!("{}", path.display());
    Ok(())
}

/// Find this machine's provider record (matched by attestation pubkey, the
/// stable per-machine fingerprint) and return `(rkey, value, cid)`. The raw
/// JSON `value` + `cid` let a one-shot command flip a single field and write
/// it back with a compare-and-swap, preserving everything the serve loop
/// published — the same spread-and-override the console uses.
async fn find_my_provider_record(
    pds: &PdsClient,
    attestation_pub_key: &str,
) -> Result<(String, serde_json::Value, String)> {
    let listed = pds.list_my_records("dev.cocore.compute.provider").await?;
    let rec = listed
        .into_iter()
        .find(|r| {
            r.value.get("attestationPubKey").and_then(|v| v.as_str()) == Some(attestation_pub_key)
        })
        .context("no provider record for this machine yet — has it served at least once?")?;
    let rkey = rec
        .uri
        .rsplit('/')
        .next()
        .context("malformed record uri")?
        .to_string();
    Ok((rkey, rec.value, rec.cid))
}

/// Open this machine's session + identity for a one-shot record edit.
fn open_pds() -> Result<(PdsClient, String)> {
    let session = oauth::load_session()?.context("not paired — run `cocore agent pair` first")?;
    let pds = PdsClient::new(session);
    let signer = secure_enclave::load_or_create_identity()?;
    Ok((pds, signer.public_key_b64()))
}

/// `cocore agent pause` / `resume`: flip the shared `active` switch on this
/// machine's provider record. Source of truth is the owner's PDS, so this
/// is exactly what the console writes — both sides converge on one field.
async fn cmd_set_active(active: bool) -> Result<()> {
    let (pds, pubkey) = open_pds()?;
    // The write is a compare-and-swap on the record's CID. A still-serving
    // agent republishes its provider record (reconnect, attestation refresh)
    // and bumps the CID out from under us, so the swap can lose a race. Treat
    // that as transient: re-read the fresh record (and CID) and retry, rather
    // than surfacing a spurious failure the tray would otherwise swallow into
    // a stuck pause. Only the swap conflict is retried; other errors bubble up.
    const MAX_ATTEMPTS: u32 = 4;
    for attempt in 1..=MAX_ATTEMPTS {
        let find = find_my_provider_record(&pds, &pubkey).await;
        if find.is_err() && active {
            // First serve hasn't published a provider record yet. An absent
            // `active` field reads as true, so resume is already the desired
            // state — let `agent serve` create the record on startup.
            println!("serving (no change)");
            return Ok(());
        }
        let (rkey, mut value, cid) = find?;
        if value
            .get("active")
            .and_then(|v| v.as_bool())
            .unwrap_or(true)
            == active
        {
            println!("{} (no change)", if active { "serving" } else { "paused" });
            return Ok(());
        }
        value["active"] = serde_json::json!(active);
        match pds
            .put_record("dev.cocore.compute.provider", &rkey, &value, Some(&cid))
            .await
        {
            Ok(_) => {
                println!("{}", if active { "serving" } else { "paused" });
                return Ok(());
            }
            Err(e) if is_swap_conflict(&e) && attempt < MAX_ATTEMPTS => {
                tracing::warn!(
                    attempt,
                    "active-switch swap lost a race; re-reading and retrying"
                );
                continue;
            }
            Err(e) => return Err(e.into()),
        }
    }
    unreachable!("loop returns on success, on the final attempt, or on a non-swap error")
}

/// Apply the desired confidential tier to a provider-record JSON value in
/// place. `on` sets `desiredTier="attested-confidential"`; `off` removes the
/// field entirely (absent ≡ best-effort, matching the console's downgrade).
/// Returns true if the value actually changed.
fn apply_desired_tier(value: &mut serde_json::Value, on: bool) -> bool {
    let current = value.get("desiredTier").and_then(|v| v.as_str());
    let already_set = matches!(current, Some("attested-confidential"));
    if already_set == on {
        return false;
    }
    if let Some(obj) = value.as_object_mut() {
        if on {
            obj.insert(
                "desiredTier".to_string(),
                serde_json::json!("attested-confidential"),
            );
        } else {
            obj.remove("desiredTier");
        }
    }
    true
}

/// `cocore agent confidential [--off]`: opt this machine in/out of the
/// attested-confidential tier by writing the owner's `desiredTier` to its
/// provider record — the same field the console's "Upgrade to confidential"
/// sets. Source of truth is the owner's PDS, so the console + tray + CLI all
/// converge. The serving agent's reconciler sees the change and restarts, and
/// the supervisor re-selects the confidential worker. CAS on the CID with a
/// bounded retry, exactly like `cmd_set_active`.
async fn cmd_set_confidential(on: bool) -> Result<()> {
    let (pds, pubkey) = open_pds()?;
    let label = if on {
        "attested-confidential"
    } else {
        "best-effort"
    };
    const MAX_ATTEMPTS: u32 = 4;
    for attempt in 1..=MAX_ATTEMPTS {
        let find = find_my_provider_record(&pds, &pubkey).await;
        if find.is_err() && !on {
            // No provider record yet — an absent `desiredTier` already reads as
            // best-effort, so disabling is a no-op.
            println!("{label} (no change)");
            return Ok(());
        }
        let (rkey, mut value, cid) = find?;
        if !apply_desired_tier(&mut value, on) {
            println!("{label} (no change)");
            return Ok(());
        }
        match pds
            .put_record("dev.cocore.compute.provider", &rkey, &value, Some(&cid))
            .await
        {
            Ok(_) => {
                println!("{label}");
                return Ok(());
            }
            Err(e) if is_swap_conflict(&e) && attempt < MAX_ATTEMPTS => {
                tracing::warn!(
                    attempt,
                    "desiredTier swap lost a race; re-reading and retrying"
                );
                continue;
            }
            Err(e) => return Err(e.into()),
        }
    }
    unreachable!("loop returns on success, on the final attempt, or on a non-swap error")
}

/// `cocore agent models set/add/remove` percolation: write the owner's model
/// pick to `desiredModels` on this machine's provider record — the SAME field
/// the console's model picker writes. This is what makes a tray model change
/// percolate to the PDS source of truth (and from there to the AppView, the
/// confidential native engine, and any serving sibling that reconciles), rather
/// than only living in the local LaunchAgent plist. An empty list REMOVES the
/// field (revert to the machine's local default). Field-scoped CAS on the CID
/// with a bounded retry, exactly like `cmd_set_active`: it patches only
/// `desiredModels` and leaves every other (agent + owner) field untouched.
///
/// A missing record (the machine hasn't served yet, so nothing to patch onto)
/// is a no-op — the caller's local plist write still applies and first serve
/// publishes the full record. Returns whether a write actually happened.
async fn cmd_set_desired_models(models: Vec<String>) -> Result<bool> {
    let (pds, pubkey) = open_pds()?;
    const MAX_ATTEMPTS: u32 = 5;
    for attempt in 1..=MAX_ATTEMPTS {
        let find = find_my_provider_record(&pds, &pubkey).await;
        if find.is_err() {
            // No provider record yet — nothing to patch `desiredModels` onto.
            // The local plist still carries the set; first serve publishes it.
            tracing::info!(
                "no provider record yet; skipped desiredModels PDS write (local config carries the set until first serve)"
            );
            return Ok(false);
        }
        let (rkey, mut value, cid) = find?;
        let current: Option<Vec<String>> = value
            .get("desiredModels")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|m| m.as_str().map(str::to_string))
                    .collect()
            });
        let next: Option<Vec<String>> = if models.is_empty() {
            None
        } else {
            Some(models.clone())
        };
        if current == next {
            return Ok(false); // already in the desired state — no write.
        }
        // Patch ONLY desiredModels; everything else rides through untouched.
        if let Some(obj) = value.as_object_mut() {
            if models.is_empty() {
                obj.remove("desiredModels");
            } else {
                obj.insert("desiredModels".to_string(), serde_json::json!(models));
            }
        }
        match pds
            .put_record("dev.cocore.compute.provider", &rkey, &value, Some(&cid))
            .await
        {
            Ok(_) => {
                tracing::info!(
                    count = models.len(),
                    "wrote desiredModels to PDS (owner model pick)"
                );
                return Ok(true);
            }
            Err(e) if is_swap_conflict(&e) && attempt < MAX_ATTEMPTS => {
                tracing::warn!(
                    attempt,
                    "desiredModels swap lost a race; re-reading and retrying"
                );
                tokio::time::sleep(std::time::Duration::from_millis(50 * attempt as u64)).await;
                continue;
            }
            Err(e) => return Err(e.into()),
        }
    }
    unreachable!("loop returns on success, on the final attempt, or on a non-swap error")
}

/// True when a PDS error is an `InvalidSwap` compare-and-swap conflict — the
/// record's CID changed between our read and write, so a retry against the
/// fresh CID is the correct response.
fn is_swap_conflict(e: &cocore_provider::error::ProviderError) -> bool {
    matches!(e, cocore_provider::error::ProviderError::Pds(msg) if msg.contains("InvalidSwap"))
}

/// Read this machine's owner-chosen `desiredTier` from its PDS provider
/// record. Returns `None` when not paired, when this machine has no record yet
/// (never served), or on any read error — all of which the caller treats as
/// best-effort. Backs both the confidential entry gate and the `agent tier`
/// probe the macOS supervisor runs to pick a worker binary.
async fn read_my_desired_tier() -> Option<String> {
    let session = oauth::load_session().ok()??;
    let pds = PdsClient::new(session);
    let signer = secure_enclave::load_or_create_identity().ok()?;
    let pubkey = signer.public_key_b64();
    let (_rkey, value, _cid) = find_my_provider_record(&pds, &pubkey).await.ok()?;
    value
        .get("desiredTier")
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

/// `cocore agent tier`: print this machine's owner-chosen trust tier
/// (`attested-confidential` or `best-effort`). Normalises an absent/unknown
/// value to `best-effort` so the caller (the macOS supervisor) always gets one
/// of the two binary-selection answers.
async fn cmd_print_tier() -> Result<()> {
    let tier = match read_my_desired_tier().await.as_deref() {
        Some("attested-confidential") => "attested-confidential",
        _ => "best-effort",
    };
    println!("{tier}");
    Ok(())
}

/// `cocore agent active`: print `serving` or `paused` from the shared switch.
async fn cmd_print_active() -> Result<()> {
    let (pds, pubkey) = open_pds()?;
    let active = match find_my_provider_record(&pds, &pubkey).await {
        Ok((_, value, _)) => value
            .get("active")
            .and_then(|v| v.as_bool())
            .unwrap_or(true),
        // Never served — no record to read; default active is true.
        Err(_) => true,
    };
    println!("{}", if active { "serving" } else { "paused" });
    Ok(())
}

/// `cocore agent attestation [--retry]`: report this machine's attestation
/// posture. Reads the provider record (trustLevel + any attestationFault) and
/// the latest published attestation record (URI + expiry + whether it carries a
/// hardware MDA chain), plus the local MDM-enrollment state, and explains the
/// common "enrolled but still self-attested" case. `--retry` first clears the
/// MDA request cooldown so the next refresh re-requests a hardware attestation.
async fn cmd_attestation(retry: bool) -> Result<()> {
    if retry {
        match cocore_provider::mda_loader::clear_auto_request_cooldown() {
            Ok(true) => println!(
                "Cleared the MDA request cooldown — the next attestation refresh will re-request a hardware attestation."
            ),
            Ok(false) => println!("No MDA request cooldown was set (nothing to clear)."),
            Err(e) => println!("Could not clear the MDA request cooldown: {e}"),
        }
    }

    let (pds, pubkey) = open_pds()?;

    // Provider record: the ACHIEVED trustLevel + any attestation fault.
    let (trust_level, attestation_fault_msg) = match find_my_provider_record(&pds, &pubkey).await {
        Ok((_, value, _)) => {
            let tl = value
                .get("trustLevel")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            let fault = value
                .get("attestationFault")
                .and_then(|f| f.get("message"))
                .and_then(|m| m.as_str())
                .map(str::to_string);
            (tl, fault)
        }
        Err(_) => (
            "unknown (this machine has not served yet)".to_string(),
            None,
        ),
    };
    println!("trustLevel:    {trust_level}");

    // Local MDM enrollment (macOS system state; non-macOS reports `no`).
    let enrolled = cocore_provider::mda_loader::mdm_enrolled();
    println!("mdmEnrolled:   {}", if enrolled { "yes" } else { "no" });

    // Latest published attestation record on this machine's PDS.
    match latest_attestation_record(&pds).await {
        Ok(Some(att)) => {
            println!(
                "attestation:   {} (expires {})",
                att.uri,
                att.expires_at.as_deref().unwrap_or("?")
            );
            println!(
                "hardwareBound: {}",
                if att.mda_chain_present {
                    "yes"
                } else {
                    "no (self-attested)"
                }
            );
        }
        Ok(None) => {
            println!("attestation:   NONE published");
            if let Some(msg) = &attestation_fault_msg {
                println!("fault:         {msg}");
            }
        }
        Err(e) => println!("attestation:   (could not read from PDS: {e})"),
    }

    // The common point of confusion: enrolled, but still self-attested.
    if enrolled && trust_level != "hardware-attested" {
        println!();
        println!(
            "This Mac is MDM-enrolled but not yet hardware-attested. A key-bound \
             attestation chain was requested and lands on the next attestation \
             refresh (≤23h). To re-request sooner, run \
             `cocore agent attestation --retry`."
        );
    }
    Ok(())
}

/// A flattened view of this machine's most recent attestation record, for the
/// `attestation` status command.
struct AttestationView {
    uri: String,
    expires_at: Option<String>,
    mda_chain_present: bool,
}

/// Read this machine's latest `dev.cocore.compute.attestation` record from its
/// PDS, picking the one with the freshest `attestedAt`. `Ok(None)` when none is
/// published (the machine never attested, or publish failed).
async fn latest_attestation_record(pds: &PdsClient) -> Result<Option<AttestationView>> {
    let records = pds
        .list_my_records("dev.cocore.compute.attestation")
        .await?;
    let latest = records.into_iter().max_by(|a, b| {
        let key = |r: &cocore_provider::pds::ListedRecord| {
            r.value
                .get("attestedAt")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string()
        };
        key(a).cmp(&key(b))
    });
    Ok(latest.map(|r| AttestationView {
        uri: r.uri,
        expires_at: r
            .value
            .get("expiresAt")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        mda_chain_present: r
            .value
            .get("mdaCertChain")
            .and_then(|v| v.as_array())
            .is_some_and(|a| !a.is_empty()),
    }))
}

fn init_tracing(level: &str) {
    // Stderr (as before) PLUS a rolling, content-safe file log under
    // ~/.cocore/logs so a crash leaves a durable trail.
    cocore_provider::diagnostics::init_logging(level);
}

async fn cmd_pair(console: &str) -> Result<()> {
    let pair = oauth::start_pair(console).await;
    match pair {
        Ok(p) => {
            println!("Open this URL in any browser signed into the co/core console:");
            println!("  {}", p.verification_uri);
            println!("Code (auto-filled by the URL above): {}", p.user_code);
            let session = oauth::poll_pair(console, &p.device_id).await?;
            oauth::store_session(&session)?;
            println!("Paired as {} ({}).", session.handle, session.did);
            // Bounce the LaunchAgent (if installed) so the running
            // `cocore agent serve` daemon picks up the fresh
            // session.json without manual launchctl. Without this,
            // a re-pair after `wipe-my-data` (which deletes the
            // agent's API key) leaves the daemon running with a
            // stale-and-now-401'ing key — silently, until somebody
            // notices the machine never appeared on /machines.
            // Best-effort, macOS-only; logs what happened.
            kickstart_launchagent_if_installed();
        }
        Err(e) => {
            tracing::warn!(error = %e, "device pair flow not yet wired");
            println!("Device pair flow lands in M2. For now, drop a session JSON at ~/.cocore/session.json.");
        }
    }
    Ok(())
}

/// macOS: bounce the cocore LaunchAgent so a running `cocore agent
/// serve` re-reads ~/.cocore/session.json. No-op on other OSes (the
/// installer is macOS-only today). Tolerant of every failure mode —
/// the LaunchAgent might not be installed, the user might not have a
/// GUI session, etc. — because pairing is the user's primary action;
/// a failure here turns into a one-line note, not an error.
#[cfg(target_os = "macos")]
fn kickstart_launchagent_if_installed() {
    use std::process::Command;
    let uid = unsafe { libc::getuid() };
    let target = format!("gui/{uid}/dev.cocore.provider");
    // `launchctl print` errors out cleanly when the LaunchAgent is
    // not loaded, which is how we detect "no installer was run."
    let installed = Command::new("launchctl")
        .args(["print", &target])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !installed {
        println!(
            "Note: no LaunchAgent at {target}. If the daemon is running another way, restart it manually.",
        );
        return;
    }
    let bounced = Command::new("launchctl")
        .args(["kickstart", "-k", &target])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if bounced {
        println!("Bounced LaunchAgent — your machine should appear on /machines within ~10s.");
    } else {
        println!(
            "Warning: could not bounce {target}. Run `launchctl kickstart -k {target}` manually if /machines stays empty.",
        );
    }
}

#[cfg(not(target_os = "macos"))]
fn kickstart_launchagent_if_installed() {
    // No LaunchAgent on Linux / Windows; the agent is run as a
    // foreground process or via systemd / nssm and the operator is
    // expected to manage that lifecycle themselves. Pairing under
    // those setups still writes session.json correctly; the daemon
    // either picks it up at next start or needs a manual restart.
}

// Owner-intent field preservation is no longer a hand-rolled allowlist
// (`preserve_console_fields`). Every agent re-publish now goes through
// `dedup_and_publish_provider`, which merges the agent's authored fields onto
// the LATEST record via `cocore_provider::pds::merge_agent_provider_fields` —
// owner-intent fields AND any unknown/future field are preserved by default, so
// a new owner setting can't be silently clobbered by an agent write.

/// Find this machine's existing provider record (if any) on the
/// user's PDS by matching `attestationPubKey`, delete any other
/// records that share the same key (they're stale duplicates), and
/// then upsert the new record at the kept rkey. If no match exists,
/// fall back to createRecord with a fresh TID. Returns
/// `(published, kept_existing, deleted_count)`.
///
/// Why this lives here and not on the console: any machine can run
/// this loop on its own without the user clicking anything. The
/// equivalent helper at `packages/console/src/lib/provider-record-pds.server.ts`
/// (`dedupMyProviderRecords`) is for after-the-fact UI cleanup; this
/// is the prevention story.
async fn dedup_and_publish_provider(
    pds: &cocore_provider::pds::PdsClient,
    attestation_pub_key: &str,
    record: &ProviderRecord,
) -> anyhow::Result<(cocore_provider::pds::PublishedRecord, bool, usize)> {
    // The single agent write path for this machine's provider record: a
    // compare-and-swap read-modify-write that reads the LATEST record, merges
    // the agent's authored fields onto it (owner-intent + unknown fields
    // preserved — see `merge_agent_provider_fields`), and putRecords under a
    // swap guard, retrying on `InvalidSwap` by re-reading. A read failure
    // aborts — we never publish a fabricated body on a blind read. It also
    // dedups: a DID that holds several records with our attestationPubKey
    // (stale reinstall dupes) keeps the newest and deletes the rest.
    const MAX_ATTEMPTS: u32 = 6;
    let collection = "dev.cocore.compute.provider";
    let mut deleted = 0usize;
    let mut last_conflict: Option<cocore_provider::error::ProviderError> = None;
    for attempt in 1..=MAX_ATTEMPTS {
        // Read latest. A transport/auth failure propagates and ABORTS — the
        // republish never invents a record on top of an unreadable PDS.
        let listed = pds.list_my_records(collection).await?;
        let mut matching: Vec<(String, String, String, serde_json::Value)> = Vec::new();
        let mut other_pubkey_count = 0usize;
        for r in &listed {
            let rkey = r.uri.rsplit('/').next().unwrap_or("").to_string();
            let key = r.value.get("attestationPubKey").and_then(|v| v.as_str());
            let created_at = r
                .value
                .get("createdAt")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            match key {
                Some(k) if k == attestation_pub_key => {
                    matching.push((rkey, r.cid.clone(), created_at, r.value.clone()));
                }
                Some(_) => other_pubkey_count += 1,
                // No attestationPubKey — pre-2026-05 record; leave alone.
                None => {}
            }
        }
        if attempt == 1 && other_pubkey_count > 0 {
            tracing::info!(
                other_pubkey_count,
                "saw provider records on this DID with a different attestationPubKey — those describe other machines; leaving alone"
            );
        }
        // Sort newest-first by createdAt; the head is canonical.
        matching.sort_by(|a, b| b.2.cmp(&a.2));

        let Some((rkey, cid, _, existing_value)) = matching.first().cloned() else {
            // First publish: no record yet. The agent authors everything; owner
            // fields are absent (correct for a brand-new machine).
            let published = pds.publish_provider(record).await?;
            return Ok((published, false, deleted));
        };

        // Delete duplicate losers (best-effort; only need to run once).
        for (loser_rkey, loser_cid, _, _) in matching.iter().skip(1) {
            match pds
                .delete_record(collection, loser_rkey, Some(loser_cid))
                .await
            {
                Ok(()) => {
                    deleted += 1;
                    tracing::info!(rkey = %loser_rkey, "deleted duplicate provider record");
                }
                Err(e) => {
                    tracing::warn!(error = %e, rkey = %loser_rkey, "failed to delete duplicate provider record")
                }
            }
        }

        // Merge the agent's fields onto the LATEST body and CAS-put.
        let merged = cocore_provider::pds::merge_agent_provider_fields(&existing_value, record);
        match pds.put_record(collection, &rkey, &merged, Some(&cid)).await {
            Ok(published) => return Ok((published, true, deleted)),
            Err(e) if is_swap_conflict(&e) && attempt < MAX_ATTEMPTS => {
                // Someone (a console edit, a sibling write) committed between our
                // read and put. Re-read the now-current record and replay.
                tracing::warn!(
                    attempt,
                    "provider record swap conflict; re-reading and retrying"
                );
                last_conflict = Some(e);
                tokio::time::sleep(std::time::Duration::from_millis(50 * attempt as u64)).await;
                continue;
            }
            Err(e) => return Err(e.into()),
        }
    }
    Err(last_conflict
        .map(anyhow::Error::from)
        .unwrap_or_else(|| anyhow::anyhow!("provider record publish exhausted retries")))
}

/// `~/.cocore/serving-paused` — present while the owner has this machine
/// stopped from the console. The menu-bar app polls for it to show the
/// machine as paused (vs. the local "serving" state, which only tracks
/// whether the agent PROCESS is up). The agent writes it while disconnected
/// for a remote stop and removes it the moment it reconnects to serve.
fn serving_paused_path() -> Option<std::path::PathBuf> {
    dirs::home_dir().map(|h| h.join(".cocore").join("serving-paused"))
}
fn write_serving_paused() {
    if let Some(p) = serving_paused_path() {
        let _ = std::fs::write(p, chrono::Utc::now().to_rfc3339());
    }
}
fn clear_serving_paused() {
    if let Some(p) = serving_paused_path() {
        let _ = std::fs::remove_file(p);
    }
}

/// Block until the owner's `active` switch on our provider record is true,
/// polling every 20s. Returns immediately when active (or when we have no
/// rkey to check). While stopped, writes the `serving-paused` marker so the
/// tray reflects it; clears it once we're active again. This is what makes
/// a console "Stop serving" actually pause the machine: the agent stays out
/// of the advisor's registry (no jobs) until the owner starts it.
/// Whether the serve gate should connect now or keep waiting.
#[derive(Debug, PartialEq, Eq)]
enum ActiveGate {
    Serve,
    Wait,
}

/// Pure decision for {@link wait_until_active}: given this poll's `active` read
/// — `None` means the read couldn't be RESOLVED (a transient blip), `Some(b)`
/// is a confirmed value — and whether we've previously confirmed a pause,
/// decide whether to serve or keep waiting, latching `confirmed_paused`.
///
/// The invariant this encodes: a read blip must NEVER flip the decision. Once
/// we've confirmed the owner paused us, an unresolved read keeps us paused (it
/// can't un-pause us). Until we've ever confirmed a pause, an unresolved read
/// serves optimistically so a PDS outage doesn't strand a healthy machine — the
/// advisor's own control poll re-checks and disconnects if we were wrong.
fn active_gate_decision(read: Option<bool>, confirmed_paused: &mut bool) -> ActiveGate {
    match read {
        Some(true) => ActiveGate::Serve,
        Some(false) => {
            *confirmed_paused = true;
            ActiveGate::Wait
        }
        None => {
            if *confirmed_paused {
                ActiveGate::Wait
            } else {
                ActiveGate::Serve
            }
        }
    }
}

async fn wait_until_active(pds: &cocore_provider::pds::PdsClient, rkey: Option<&str>) {
    let Some(rk) = rkey else {
        clear_serving_paused();
        return;
    };
    let mut announced = false;
    // Whether we've CONFIRMED (via a successful read) that the owner paused us.
    let mut confirmed_paused = false;
    loop {
        // `get_provider_control` returns `None` ONLY when the read couldn't be
        // resolved (a transient PDS / console-proxy blip), distinct from a
        // confirmed `Some(active)`. Acting on that blip as if it were a real
        // value is the conflation that let a paused machine un-pause itself.
        let read = pds
            .get_provider_control(rk)
            .await
            .map(|(active, _, _)| active);
        if active_gate_decision(read, &mut confirmed_paused) == ActiveGate::Serve {
            clear_serving_paused();
            return;
        }
        if !announced {
            tracing::info!(
                "owner stopped this machine from the console — staying disconnected until they start it"
            );
            announced = true;
        }
        write_serving_paused();
        tokio::time::sleep(std::time::Duration::from_secs(20)).await;
    }
}

/// Serve entrypoint. On the confidential (`apns`) build it hands the process
/// **main thread** to the AppKit APNs push host while the tokio serve loop runs
/// on a dedicated thread's runtime: AppKit's run loop must own the main thread,
/// and the measured worker binary (this process — it holds `K` and the SE key)
/// must be the push receiver, so the code-identity challenge can only be
/// answered with this split. On every other build it's a thin async
/// passthrough with no push receiver.
#[cfg(all(target_os = "macos", feature = "apns"))]
async fn cmd_serve_entry(advisor: String) -> Result<()> {
    use tokio::sync::mpsc::unbounded_channel;
    // Runtime tier gate (fleet-safety keystone). This apns worker binary holds
    // the AppKit push host + the in-process MLX engine, but it must only take
    // the confidential process shape when the owner actually opted THIS machine
    // in (desiredTier=attested-confidential). On every other machine it behaves
    // byte-for-byte like the default best-effort build: serve directly on the
    // main runtime, no push receiver, no AppKit, subprocess engine, same model.
    // (The macOS supervisor normally only spawns this binary for confidential
    // machines via `agent tier`; this in-process gate is the backstop so a
    // stale/raced spawn can never silently flip a machine's behaviour.)
    let desired_tier = read_my_desired_tier().await;
    let confidential = desired_tier.as_deref() == Some("attested-confidential");
    if !confidential {
        tracing::info!(
            "desiredTier is not attested-confidential — serving best-effort (no push host, subprocess engine)"
        );
        return cmd_serve(&advisor, None).await;
    }
    tracing::info!(
        "desiredTier=attested-confidential — confidential path (push host + in-process MLX engine)"
    );
    // Make sure the confidential model's weights are present and point the
    // native engine at the resolved Hugging Face snapshot dir BEFORE the serve
    // thread builds engines. Non-fatal: on failure `build_engines` publishes an
    // honest engineFault and the machine serves `stub` until the owner picks a
    // confidential-compatible model from the console.
    prepare_native_confidential_model().await;

    // The push host (main thread) forwards `E_K(nonce)` challenges on this
    // channel; the serve loop (worker thread) drains it. Unbounded so the
    // Cocoa-thread callback never blocks.
    let (push_tx, push_rx) = unbounded_channel::<String>();
    // Drive the async serve loop on its own multi-threaded runtime, leaving the
    // main OS thread free for `NSApplication.run`.
    std::thread::Builder::new()
        .name("cocore-serve".into())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    tracing::error!(error = %e, "failed to build serve runtime");
                    std::process::exit(1);
                }
            };
            if let Err(e) = rt.block_on(cmd_serve(&advisor, Some(push_rx))) {
                tracing::error!(error = %e, "serve loop exited with error");
            }
            // The serve loop only returns on a fatal / owner-stop path; the push
            // host owns main and never returns, so exit and let the supervisor
            // restart us cleanly rather than leaving a half-dead process.
            std::process::exit(0);
        })
        .map_err(|e| anyhow::anyhow!("spawn serve thread: {e}"))?;
    // Hand the main thread to the push host. Never returns.
    cocore_provider::push_host::run_blocking(push_tx)
}

/// Confidential tier (apns build): make sure the in-process MLX engine's model
/// is downloaded and pointed at its local Hugging Face snapshot before engines
/// are built. Public model weights aren't security-sensitive — only *serving*
/// must stay inside the measured binary — so we reuse the venv's
/// `huggingface_hub` as a download-only step, then resolve the snapshot dir it
/// returns and export the two env vars `build_engines` reads
/// (`COCORE_NATIVE_MLX_MODEL` + `COCORE_NATIVE_MLX_MODEL_DIR`). The native
/// engine serves exactly ONE model — the owner's first non-`stub`
/// `desiredModels`, else a small default. An incompatible pick (a non
/// Qwen2/Llama/Gemma/Phi arch, e.g. `qwen3_5`) downloads fine but fails native
/// load, which `build_engines` turns into an honest engineFault.
#[cfg(all(target_os = "macos", feature = "apns"))]
async fn prepare_native_confidential_model() {
    const DEFAULT_MODEL: &str = "mlx-community/Qwen2.5-0.5B-Instruct-4bit";
    // Already wired by the environment (e.g. a LaunchAgent that pre-set both
    // vars, like the canary) — respect it and skip the download probe.
    if std::env::var_os("COCORE_NATIVE_MLX_MODEL").is_some()
        && std::env::var_os("COCORE_NATIVE_MLX_MODEL_DIR").is_some()
    {
        tracing::info!("native MLX model already configured via env; skipping download probe");
        return;
    }
    // Choose the model the native engine serves (it serves exactly one): the
    // owner's PDS `desiredModels` (website picker) first, then the local
    // `COCORE_INFERENCE_MODELS` the macOS tray / launchd plist set, then the
    // small default. The tray sets its model choice through the plist, NOT
    // `desiredModels`, so reading `desiredModels` alone made every tray-
    // configured confidential machine ignore the owner's pick and fall back to
    // the default. The singular `COCORE_INFERENCE_MODEL` is honoured for plist
    // back-compat, matching `build_engines`.
    let inference_models_env = std::env::var("COCORE_INFERENCE_MODELS")
        .or_else(|_| std::env::var("COCORE_INFERENCE_MODEL"))
        .ok();
    let model = pick_confidential_native_model(
        &read_my_desired_models().await,
        inference_models_env.as_deref(),
        DEFAULT_MODEL,
    );

    // Resolve the venv interpreter the install script bootstrapped.
    let venv_python = std::env::var("COCORE_PYTHON_VENV")
        .ok()
        .map(std::path::PathBuf::from)
        .or_else(|| dirs::home_dir().map(|h| h.join(".cocore/python")))
        .map(|venv| venv.join("bin/python"));
    let Some(venv_python) = venv_python.filter(|p| p.exists()) else {
        tracing::warn!(
            "no venv python to download the confidential model; build_engines will publish a fault"
        );
        // Flag the intended model (without a dir) so build_engines faults honestly.
        std::env::set_var("COCORE_NATIVE_MLX_MODEL", &model);
        return;
    };

    tracing::info!(
        model = %model,
        "downloading confidential model weights (download-only; serving stays in the measured binary)"
    );
    // Surface progress in the tray while the (potentially multi-GB, multi-minute)
    // download runs; the serve loop's own monitor takes over once engines build.
    write_provision_status(
        "provisioning",
        std::slice::from_ref(&model),
        model_download_bytes(std::slice::from_ref(&model)),
        // We're entering the download phase, so show a download bar, not the
        // "loading into memory…" state (loading=false). The serve loop's own
        // monitor recomputes this from `.incomplete` probes once engines build.
        false,
        None,
    );

    let dir = tokio::task::spawn_blocking({
        let model = model.clone();
        let venv_python = venv_python.clone();
        move || download_hf_snapshot(&venv_python, &model)
    })
    .await
    .ok()
    .flatten();

    std::env::set_var("COCORE_NATIVE_MLX_MODEL", &model);
    match dir {
        Some(dir) => {
            tracing::info!(model = %model, dir = %dir, "confidential model ready");
            std::env::set_var("COCORE_NATIVE_MLX_MODEL_DIR", dir);
        }
        None => tracing::warn!(
            model = %model,
            "confidential model download failed; build_engines will publish a fault"
        ),
    }
}

/// Run the venv's `huggingface_hub.snapshot_download` as a download-only step
/// and return the resolved local snapshot directory (which is exactly what the
/// native engine needs). Blocking — spawns the venv python and waits for the
/// weight download; a no-op when the weights are already cached. Call from
/// `spawn_blocking`.
#[cfg(all(target_os = "macos", feature = "apns"))]
fn download_hf_snapshot(venv_python: &std::path::Path, model: &str) -> Option<String> {
    // Pass the model id as argv (sys.argv[1]) instead of interpolating it into
    // the snippet — no quoting/injection edge cases, and the snippet stays a
    // plain string literal (which rustfmt never reflows).
    let code =
        "import sys; from huggingface_hub import snapshot_download; print(snapshot_download(sys.argv[1]))";
    let mut cmd = std::process::Command::new(venv_python);
    cmd.arg("-c")
        .arg(code)
        .arg(model)
        // Accelerated parallel download (hf_transfer is installed by
        // scripts/bootstrap-python-venv.sh alongside vllm-mlx).
        .env("HF_HUB_ENABLE_HF_TRANSFER", "1");
    // Same auth + plain-LFS download env the engine subprocess uses, so the
    // confidential pre-warm doesn't hit the unauthenticated 429 throttle (#117).
    cocore_provider::engines::subprocess::apply_hf_download_env(&mut cmd);
    let out = cmd.output().ok()?;
    if !out.status.success() {
        tracing::warn!(
            model = %model,
            stderr = %String::from_utf8_lossy(&out.stderr).lines().last().unwrap_or_default(),
            "huggingface snapshot_download failed"
        );
        return None;
    }
    let dir = String::from_utf8_lossy(&out.stdout)
        .lines()
        .last()
        .map(|l| l.trim().to_string())?;
    if dir.is_empty() {
        None
    } else {
        Some(dir)
    }
}

/// Read this machine's owner-chosen `desiredModels` from its PDS provider
/// record (empty when not paired / no record / read error). Used to pick the
/// confidential native model.
#[cfg(all(target_os = "macos", feature = "apns"))]
async fn read_my_desired_models() -> Vec<String> {
    let Some(session) = oauth::load_session().ok().flatten() else {
        return Vec::new();
    };
    let pds = PdsClient::new(session);
    let Ok(signer) = secure_enclave::load_or_create_identity() else {
        return Vec::new();
    };
    let pubkey = signer.public_key_b64();
    // The console proxy that fronts these PDS reads 502s transiently. A failed
    // read here used to fall straight through to the hardcoded default model —
    // silently overriding the owner's website model pick and serving (and
    // downloading) the WRONG model until the next restart happened to read
    // cleanly. Retry a few times with short backoff so a blip doesn't downgrade
    // the model; a record that genuinely lists no `desiredModels` still yields
    // an empty list on the first read (Ok path) with no retry.
    const ATTEMPTS: u32 = 3;
    for attempt in 1..=ATTEMPTS {
        match find_my_provider_record(&pds, &pubkey).await {
            Ok((_, value, _)) => {
                return value
                    .get("desiredModels")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|m| m.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
            }
            Err(e) if attempt < ATTEMPTS => {
                tracing::warn!(
                    error = %e,
                    attempt,
                    "couldn't read desiredModels (transient read / no record yet); retrying before any fallback to the default model"
                );
                tokio::time::sleep(std::time::Duration::from_secs(2 * attempt as u64)).await;
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "couldn't read desiredModels after retries; falling back to the default confidential model"
                );
                return Vec::new();
            }
        }
    }
    Vec::new()
}

/// Non-confidential builds: no push host, serve directly on the main runtime.
#[cfg(not(all(target_os = "macos", feature = "apns")))]
async fn cmd_serve_entry(advisor: String) -> Result<()> {
    cmd_serve(&advisor, None).await
}

async fn cmd_serve(
    advisor_url: &str,
    // APNs code-identity push receiver (confidential tier; `apns` build). The
    // process main thread runs the AppKit push host and forwards challenges
    // here; we thread it into every `AdvisorClient::run` so it survives
    // reconnects. `None` on non-apns builds / headless sessions.
    mut push_rx: Option<tokio::sync::mpsc::UnboundedReceiver<String>>,
) -> Result<()> {
    // No session yet → the user installed but hasn't paired. Sleep
    // forever in this process rather than exit-1 → launchd
    // restart → exit-1 → launchd restart… The KeepAlive loop fills
    // the logs with hundreds of "no session" errors and burns
    // CPU on respawn while the user reads the instructions to
    // run `cocore agent pair` in their other terminal. A quiet
    // wait is the right idle state: the LaunchAgent stays in
    // "running" so doctor can still introspect it; the message is
    // printed once; the process consumes ~zero resources.
    //
    // Once pair lands, `cmd_pair` calls `kickstart -k` which
    // bounces us — the new process boots, finds session.json,
    // and serves normally.
    let session = match oauth::load_session()? {
        Some(s) => s,
        None => {
            tracing::warn!(
                "no session.json at ~/.cocore/session.json — run `cocore agent pair` to finish setup. \
                 sleeping until the LaunchAgent is bounced after pairing."
            );
            // Long-sleep loop. We don't use tokio::time::sleep::MAX
            // because some launchds get unhappy with absurd
            // durations; a daily heartbeat is fine.
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(24 * 60 * 60)).await;
            }
        }
    };
    let pds = PdsClient::new(session.clone());
    tracing::info!(did = %pds.provider_did(), "serving");

    // Load the signing identity FIRST so the Register frame can carry
    // its public key — the advisor verifies our attestation responses
    // against that key, so leaving it empty (as the M1 walking
    // skeleton did) makes the very first AttestationChallenge round
    // close the connection with `attestation-bad-signature`.
    // Held as an `Arc` so the background re-attestation task can share the same
    // signing identity as the serve loop (the trait is `Send + Sync`).
    let signer: Arc<dyn secure_enclave::SigningIdentity> =
        secure_enclave::load_or_create_identity()?.into();

    // X25519 encryption keypair for sealed prompts. M2 will persist
    // this alongside the session; for now we generate fresh on every
    // serve and the advisor only stores it for forwarding.
    let enc = cocore_provider::crypto::ProviderKeypair::generate();

    // Publish a `dev.cocore.compute.provider` record so the user's
    // PDS (and the AppView indexing it) advertise this machine.
    // Hardware fields come from real system telemetry
    // (system_profile::collect) — chip, RAM, GPU cores, etc. —
    // rather than the v0.2.x stubs. Matchmakers use these to route
    // inference work to capable hardware.
    let profile = system_profile::collect();
    tracing::info!(
        chip = %profile.chip,
        ram_gb = profile.ram_gb,
        gpu_cores = ?profile.gpu_cores,
        memory_bandwidth_gbs = ?profile.memory_bandwidth_gbs,
        os = ?profile.os,
        "collected system profile"
    );
    let attestation_pub_key = signer.public_key_b64();

    // Publish a PROVISIONING provider record immediately — before the
    // (potentially slow) engine load below. A cold model load can take
    // tens of seconds to a few minutes; without this, the machine
    // wouldn't appear on the console until the engine was fully ready,
    // which feels like the "Start serving" click did nothing. We publish
    // a minimal record now (no models yet, `provisioning: true`) so the
    // row shows up right away as "provisioning", then re-publish the real
    // record (real supportedModels, `provisioning: false`) at the same
    // rkey once the engine is up — `dedup_and_publish_provider` upserts
    // the record it just wrote in place, so this never creates a dupe.
    {
        let provisioning_record = ProviderRecord {
            machineLabel: profile.machine_label.clone(),
            chip: profile.chip.clone(),
            ramGB: profile.ram_gb,
            gpuCores: profile.gpu_cores,
            memoryBandwidthGBs: profile.memory_bandwidth_gbs,
            cpuCores: profile.cpu_cores,
            pCores: profile.p_cores,
            eCores: profile.e_cores,
            modelIdentifier: profile.model_identifier.clone(),
            os: profile.os.clone(),
            supportedModels: vec![],
            priceList: vec![],
            encryptionPubKey: enc.public_key_b64(),
            attestationPubKey: attestation_pub_key.clone(),
            // Provisioning: engine not up yet, so honestly self-attested /
            // best-effort. The real publish below sets the earned values.
            trustLevel: TrustLevel::SelfAttested,
            tier: None,
            acceptedExchanges: vec![],
            contactEndpoint: None,
            binaryVersion: Some(env!("CARGO_PKG_VERSION").to_string()),
            payoutsEnabled: None,
            // Preserved from the existing record by dedup, like payoutsEnabled.
            active: None,
            desiredModels: None,
            desiredTier: None,
            // Owner's pro-bono election — preserved from the existing record
            // by dedup, like active/desiredModels/desiredTier.
            proBono: None,
            // Owner's location-sharing opt-in — preserved from the existing
            // record by dedup, like proBono. The provisioning publish never
            // stamps region (no network lookup before the engine is up).
            shareLocation: None,
            provisioning: Some(true),
            // NOT serving yet: this record is published immediately (so the
            // machine is visible) while the engine is still loading/downloading.
            // Claiming `serving: true` here is a lie — it makes the console +
            // tray say "serving and earning" before any model is loaded. The
            // real record below flips this to true once engines are up.
            serving: Some(false),
            engineFault: None,
            attestationFault: None,
            // Coarse location is resolved (best-effort, network) and stamped
            // only on the real record below — never worth delaying the
            // "machine is visible" provisioning publish on an IP lookup.
            region: None,
            regionSource: None,
            regionObservedAt: None,
            createdAt: chrono::Utc::now(),
        };
        match dedup_and_publish_provider(&pds, &attestation_pub_key, &provisioning_record).await {
            Ok((published, _, _)) => tracing::info!(
                uri = %published.uri,
                "published provisioning provider record — machine is visible while the engine loads"
            ),
            Err(e) => tracing::warn!(error = %e, "failed to publish provisioning provider record"),
        }
    }

    // Build the engine registry BEFORE the provider record so
    // supportedModels = registry.loaded_models(). Previously this was
    // derived from `pricing::models_for_machine(ram_gb)` which gave
    // the *RAM-derived upper bound* — what could plausibly fit — not
    // what actually loaded. The advisor would route jobs for any of
    // the advertised NSIDs and the agent would silently fall through
    // to stub for everything except the one model the env actually
    // pointed at. The registry's `loaded_models()` is now the single
    // source of truth.
    //
    // Honour the owner's remote model choice first: if they picked models on
    // the website (`desiredModels` on this machine's record, preserved onto
    // the provisioning record just published), load THAT set instead of the
    // local default. `build_engines` reads `COCORE_INFERENCE_MODELS`, so we
    // point it there before building. We remember the set we started from so
    // a later change (owner edits the list on the site) triggers a reload.
    // This serve's confidential standing. `push_rx.is_some()` is the
    // process-shape signal: only the confidential entry path (the apns worker)
    // hands us a push receiver, so it doubles as "this is the confidential
    // worker". On a confidential machine inference must stay inside the
    // measured binary — the native in-process MLX engine — so we DON'T point
    // the subprocess engine at the owner's models (that would serve them out
    // of an unmeasured Python child, defeating the tier). We still read
    // `desiredModels` below so a change still triggers a reload restart.
    let confidential = push_rx.is_some();
    let (desired_at_start, desired_tier_at_start, pro_bono_at_start, share_location_at_start): (
        Vec<String>,
        Option<String>,
        ProBonoPolicy,
        bool,
    ) = match find_my_provider_record(&pds, &attestation_pub_key).await {
        Ok((_, value, _)) => {
            let models = value
                .get("desiredModels")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|m| m.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            let tier = value
                .get("desiredTier")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            // The owner's location-sharing opt-in, read off our own record so
            // this serve decides whether to geolocate + stamp `region`. Absent
            // ≡ off (no country published).
            let share_location = value
                .get("shareLocation")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            // The owner's pro-bono election, read off our own record so each
            // served job can decide per-requester whether it's free. Absent /
            // malformed ≡ off (every job metered + billed).
            let pro_bono = ProBonoPolicy::from_record_value(&value).unwrap_or_default();
            (models, tier, pro_bono, share_location)
        }
        Err(_) => (Vec::new(), None, ProBonoPolicy::default(), false),
    };
    match inference_models_action(confidential, &desired_at_start) {
        InferenceModelsAction::Clear => {
            // Confidential = native-only. Inference MUST stay inside the
            // measured binary, so the subprocess engine serves nothing — clear
            // `COCORE_INFERENCE_MODELS` (both spellings) regardless of who set
            // it. The macOS tray injects it from its `inferenceModels`
            // preference and a launchd plist can set it too; without this clear,
            // a confidential machine would spawn a Python child for that model,
            // both leaking plaintext out of the measured binary and piling load
            // onto small machines (enough to starve the advisor WS loop so
            // code-attestation never sticks). `build_engines` then registers the
            // native engine + `stub` only.
            tracing::info!(
                "confidential tier — serving the in-process native engine only (cleared COCORE_INFERENCE_MODELS)"
            );
            std::env::remove_var("COCORE_INFERENCE_MODELS");
            std::env::remove_var("COCORE_INFERENCE_MODEL");
        }
        InferenceModelsAction::Set(models) => {
            tracing::info!(models = %models, "loading owner-selected models from the console");
            std::env::set_var("COCORE_INFERENCE_MODELS", models);
        }
        // No console selection on a best-effort machine: leave whatever the
        // environment / install default already provides, exactly as before.
        InferenceModelsAction::Leave => {}
    }

    // Per-model schedules + the full configured set they apply to. The serve
    // loop reloads (restarts) when a window boundary flips the active set;
    // `build_engines` narrows to the currently-active subset on each build.
    let model_schedules = cocore_provider::schedule::ModelSchedules::from_env();
    let configured_models: Vec<String> = std::env::var("COCORE_INFERENCE_MODELS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    // Provisioning observability (#2/#3/#5): tell the tray we're coming up
    // and stream download progress while `build_engines` (which can spend
    // many minutes downloading weights) runs. Cleared on success; replaced
    // with the fault on failure. A background thread polls the HF cache
    // size so the marker carries live "downloaded N bytes".
    let provisioning_models: Vec<String> = std::env::var("COCORE_INFERENCE_MODELS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && s != "stub")
        .collect();
    let monitor_stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let monitor = if provisioning_models.is_empty() {
        clear_provision_status();
        None
    } else {
        write_provision_status(
            "provisioning",
            &provisioning_models,
            model_download_bytes(&provisioning_models),
            !any_model_downloading(&provisioning_models),
            None,
        );
        let models = provisioning_models.clone();
        let stop = std::sync::Arc::clone(&monitor_stop);
        Some(std::thread::spawn(move || {
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                let bytes = model_download_bytes(&models);
                // No in-flight `.incomplete` blob → weights are on disk and a
                // model is loading into memory, not downloading.
                let loading = !any_model_downloading(&models);
                write_provision_status("provisioning", &models, bytes, loading, None);
                // ~2s between updates, but wake promptly to stop.
                for _ in 0..8 {
                    if stop.load(std::sync::atomic::Ordering::Relaxed) {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(250));
                }
            }
        }))
    };

    let (engines, engine_fault, tool_call_models) = build_engines(profile.ram_gb);

    // Stop the progress monitor and record the outcome for the tray: clear
    // the marker on success (tray shows normal serving), or write the fault
    // so the tray can surface "Provisioning failed: …".
    monitor_stop.store(true, std::sync::atomic::Ordering::Relaxed);
    if let Some(h) = monitor {
        let _ = h.join();
    }
    match &engine_fault {
        Some(f) => write_provision_status(
            "failed",
            &provisioning_models,
            model_download_bytes(&provisioning_models),
            false,
            Some(f),
        ),
        None => clear_provision_status(),
    }

    // Advertise the LIVE set, not every registered engine: `live_models()`
    // filters to engines whose `ready()` holds, so a child that failed to
    // come up (or has already died by the time we publish) never lands in
    // `supportedModels`. At boot this equals the registered set, but using
    // it here keeps the advertised set honest if an engine dies between
    // registration and publish — and is the same accessor the serve loop's
    // health check reconciles toward.
    let loaded_models = engines.live_models();
    tracing::info!(
        loaded = ?loaded_models,
        fault = ?engine_fault.as_ref().map(|f| &f.code),
        "engines loaded; provider record's supportedModels will reflect this"
    );
    // One priceList entry per *loaded* model. We deliberately price every
    // loaded id — including off-catalog custom MLX models a provider added
    // by hand — at the uniform exchange rate (see
    // `pricing::price_components_for`). The earlier `filter_map` over the
    // catalog silently DROPPED custom models from priceList, so they
    // appeared in `supportedModels` with no price and the requester-facing
    // model directory rendered them priceless. `modelId` is always the
    // real loaded id, never the catalog fallback's id.
    let price_list: Vec<ModelPrice> = loaded_models
        .iter()
        .map(|id| {
            let (input_per_mtok, output_per_mtok, currency) = pricing::price_components_for(id);
            ModelPrice {
                modelId: id.clone(),
                inputPricePerMTok: input_per_mtok,
                outputPricePerMTok: output_per_mtok,
                currency: currency.to_string(),
            }
        })
        .collect();

    // Build the signed attestation BEFORE the provider record so the record can
    // publish the ACHIEVED trustLevel/tier derived from its evidence — never a
    // self-declared value. trustLevel rises to hardware-attested only with a real
    // Apple MDA chain (COCORE_MDA_CERT_CHAIN_PATH / _CHAIN_URL / _ATTEST_BINARY)
    // bound to this machine's signing key; `tier` is the attestation's own
    // evidence-gated computation, which stays best-effort until the measured
    // native engine serves under a hardened-attested posture.
    // Snapshot the engine-derived attestation inputs once: the loaded engine
    // set is fixed for this serve, so the refresh task can carry this instead
    // of borrowing the (later-moved) engine registry.
    let engine_facts = EngineAttestationFacts::from_registry(&engines);
    // Build + publish the attestation now. This is the SAME path the refresh
    // task below re-runs every ~23h (attestations expire after 24h); doing it
    // here gives the provider record its ACHIEVED trustLevel/tier and the
    // Register frame its attestation URI / cdHash / tier.
    let boot_attestation = build_and_publish_attestation(
        &session,
        &*signer,
        &enc.public_key_b64(),
        &engine_facts,
        &pds,
    )
    .await;
    let achieved_trust_level = boot_attestation.trust_level;
    let achieved_tier = boot_attestation.tier.clone();

    // Coarse, opt-in location (refresh-on-serve). Only when the owner opted in
    // via the console's `shareLocation` switch (read off our record above) do we
    // resolve this machine's country from its public IP and stamp it onto the
    // record. ADVISORY/self-asserted (a VPN moves it) — published to the
    // provider's OWN PDS, never trusted as proof. A failed lookup leaves it
    // unset for this serve; sharing-off omits it entirely so the next
    // re-publish drops any prior value.
    let (region, region_source, region_observed_at) = if share_location_at_start {
        let http = reqwest::Client::new();
        match cocore_provider::geoip::resolve_country(&http).await {
            Some(cc) => {
                tracing::info!(country = %cc, "location sharing on — stamping provider record region");
                (
                    Some(cc),
                    Some(cocore_provider::geoip::REGION_SOURCE_IP_GEO.to_string()),
                    Some(chrono::Utc::now()),
                )
            }
            None => {
                tracing::warn!(
                    "location sharing on but country lookup failed — leaving region unset this serve"
                );
                (None, None, None)
            }
        }
    } else {
        (None, None, None)
    };

    let provider_record = ProviderRecord {
        machineLabel: profile.machine_label,
        chip: profile.chip,
        ramGB: profile.ram_gb,
        gpuCores: profile.gpu_cores,
        memoryBandwidthGBs: profile.memory_bandwidth_gbs,
        cpuCores: profile.cpu_cores,
        pCores: profile.p_cores,
        eCores: profile.e_cores,
        modelIdentifier: profile.model_identifier,
        os: profile.os.clone(),
        supportedModels: loaded_models.clone(),
        priceList: price_list,
        encryptionPubKey: enc.public_key_b64(),
        attestationPubKey: attestation_pub_key.clone(),
        // ACHIEVED trust, derived from the attestation evidence built above —
        // never self-declared. hardware-attested only with a bound Apple MDA
        // chain; tier is the attestation's own evidence-gated value.
        trustLevel: achieved_trust_level,
        tier: achieved_tier,
        acceptedExchanges: vec![],
        contactEndpoint: None,
        binaryVersion: Some(env!("CARGO_PKG_VERSION").to_string()),
        // Set to `None` here — `dedup_and_publish_provider` reads
        // the existing record's value and propagates it through.
        // The agent never writes `true` of its own initiative;
        // that's the console's job after a successful Stripe Connect
        // onboard.
        payoutsEnabled: None,
        // Same carry-through: the owner's start/stop switch lives on the
        // console-written record; dedup preserves it so a serve restart
        // never clobbers a "stopped" machine back to serving.
        active: None,
        desiredModels: None,
        // Owner's confidential opt-in — preserved by dedup like the others.
        desiredTier: None,
        // Owner's pro-bono election — preserved by dedup like the others.
        proBono: None,
        // Owner's location-sharing opt-in — preserved by dedup like proBono.
        // (The `region` below was already gated on its value, read at serve
        // start; this carries the switch itself through the re-publish.)
        shareLocation: None,
        // Engine is loaded by this point — clear the provisioning flag we
        // set on the early publish above, so the console flips the row
        // from "provisioning" to live.
        provisioning: Some(false),
        // Up and serving. We flip this to false from the SIGTERM handler
        // below on graceful shutdown, so the console shows "offline".
        serving: Some(true),
        // Surface the engine-load outcome. `None` on a healthy serve
        // clears any stale fault from a prior failed serve; `Some(..)`
        // tells the console this machine is up but only serving `stub`.
        engineFault: engine_fault,
        // Surface an attestation build/publish failure so the console shows the
        // machine can't produce receipts (and why) instead of a healthy-looking
        // idle machine. `None` clears any stale fault on a clean (re-)attestation.
        attestationFault: boot_attestation.fault.clone(),
        // Coarse, opt-in location resolved above (refresh-on-serve). Absent
        // when sharing is off or the lookup failed. Agent-authored, so the merge
        // overwrites it when present and CLEARS it when absent (it's in
        // `AGENT_OPTIONAL_KEYS`) — turning off sharing drops the stale region.
        region,
        regionSource: region_source,
        regionObservedAt: region_observed_at,
        createdAt: chrono::Utc::now(),
    };
    // Dedup-then-upsert: every machine has exactly one provider record
    // identified by its Secure-Enclave-bound `attestationPubKey`. On
    // every serve startup we list this DID's existing provider records,
    // pick the freshest record that already carries our pubkey, delete
    // the rest as duplicates, and putRecord at the kept rkey. If no
    // existing record matches, we createRecord with a fresh TID rkey.
    // Net result: the on-PDS view stays one record per physical Mac
    // even across reinstalls / upgrades / re-pairs.
    // Keep the rkey of the record we just upserted so the SIGTERM handler
    // can flip `serving` to false at the same rkey on graceful shutdown.
    let provider_rkey: Option<String> = match dedup_and_publish_provider(
        &pds,
        &attestation_pub_key,
        &provider_record,
    )
    .await
    {
        Ok((published, kept_existing, deleted)) => {
            tracing::info!(
                uri = %published.uri,
                kept_existing,
                deleted,
                "published provider record (dedup-and-upsert)"
            );
            published.uri.rsplit('/').next().map(|s| s.to_string())
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to publish provider record; machine will not appear on the console");
            None
        }
    };

    // The attestation was built + published by `build_and_publish_attestation`
    // above (its evidence already set the provider record's trustLevel/tier).
    // On build/publish failure the strong-ref is `None`: the InferenceRequest
    // stub still answers, receipts just aren't published, and the
    // `attestationFault` on the record above tells the console why. Echo the
    // measured identity + tier on the Register frame so the advisor can compute
    // confidential eligibility (the PDS attestation stays authoritative for
    // client verification).
    let register_cd_hash = boot_attestation.cd_hash.clone();
    let register_tier = boot_attestation.register_tier.clone();
    // The live, refreshable attestation cell. The refresh task swaps a fresh
    // strong-ref in here ~1h before the current one expires; the receipt path
    // reads it per job, so receipts always reference the current attestation.
    let attestation: Arc<RwLock<Option<StrongRef>>> =
        Arc::new(RwLock::new(boot_attestation.strong_ref.clone()));

    // The Register frame echoes the same telemetry the PDS record
    // carries so the advisor's /providers list matches what's on
    // PDS. Live updates (CPU load, models loaded) belong on
    // heartbeats, not here.
    let register = Register {
        provider_did: session.did.clone(),
        // This machine's provider-record rkey — the advisor's stable
        // per-machine id, so this machine and any sibling under the same DID
        // both stay connected instead of evicting each other.
        machine_id: provider_rkey.clone(),
        machine_label: provider_record.machineLabel.clone(),
        chip: provider_record.chip.clone(),
        ram_gb: provider_record.ramGB,
        supported_models: provider_record.supportedModels.clone(),
        encryption_pub_key: enc.public_key_b64(),
        attestation_pub_key: signer.public_key_b64(),
        attestation_uri: boot_attestation
            .strong_ref
            .as_ref()
            .map(|r| r.uri.clone())
            .unwrap_or_default(),
        // Tell the advisor (live, in addition to the PDS record) when the
        // engine failed to load, so the central matchmaker can note a
        // degraded machine instead of just seeing a short supportedModels.
        engine_fault: provider_record.engineFault.clone(),
        cd_hash: register_cd_hash,
        tier: register_tier,
        // Echo the coarse, opt-in country from the provider record so the
        // advisor can route by country without a PDS read. `None` when the
        // owner hasn't opted into location sharing.
        region: provider_record.region.clone(),
        // The measured agent's APNs device token, when the push host registered
        // one (confidential build + logged-in GUI session). Lets the advisor
        // send the code-identity challenge that proves this exact binary is
        // genuine. `None` everywhere else → those machines stay best-effort.
        #[cfg(all(target_os = "macos", feature = "apns"))]
        apns_device_token: cocore_provider::push_host::current_device_token(),
        #[cfg(not(all(target_os = "macos", feature = "apns")))]
        apns_device_token: None,
        // Tool calling: advertise verified support only. vLLM/vllm-mlx owns
        // parser/template semantics; each subprocess engine runs a forced-tool
        // startup canary before its model is listed here. The boolean stays for
        // legacy advisors/clients; `tool_call_models` is the per-model subset.
        supports_tool_calls: Some(!tool_call_models.is_empty()),
        tool_call_models: if tool_call_models.is_empty() {
            None
        } else {
            Some(tool_call_models.clone())
        },
        // Echo our binary version live so the advisor can route version-gated
        // jobs (e.g. image input requires a release that supports messages-v1).
        binary_version: Some(env!("CARGO_PKG_VERSION").to_string()),
    };

    // Periodic re-attestation. Attestations expire after 24h; without this the
    // attestation built at boot lapses, every receipt that strong-refs it
    // becomes invalid, and the machine silently drops out of its attested
    // posture (the "confidential mode flips on/off / can't re-attest" failure).
    // The task rebuilds + republishes on a fixed cadence (default ~23h, env
    // override for testing), re-running the MDA auto-acquire so a key-bound
    // chain that landed after boot is picked up, and swaps the fresh strong-ref
    // into the shared cell the receipt path reads. On failure it keeps the
    // previous ref until the next cycle and records an `attestationFault` on the
    // provider record so the console surfaces the degraded state.
    let refresh_handle = {
        let attestation = attestation.clone();
        let pds = pds.clone();
        let session = session.clone();
        let signer = signer.clone();
        let enc_pub = enc.public_key_b64();
        let engine_facts = engine_facts.clone();
        let attestation_pub_key = attestation_pub_key.clone();
        let base_record = provider_record.clone();
        tokio::spawn(async move {
            let interval = attestation_refresh_interval();
            loop {
                tokio::time::sleep(interval).await;
                let outcome = build_and_publish_attestation(
                    &session,
                    &*signer,
                    &enc_pub,
                    &engine_facts,
                    &pds,
                )
                .await;
                match &outcome.strong_ref {
                    Some(r) => {
                        *attestation.write().await = Some(r.clone());
                        tracing::info!(uri = %r.uri, "attestation refreshed");
                    }
                    None => {
                        tracing::warn!(
                            "attestation refresh failed; keeping previous ref until next cycle"
                        );
                    }
                }
                // Reflect the refresh outcome on the provider record so the
                // console clears or surfaces the fault. Best-effort: a failed
                // re-publish here doesn't affect the live attestation cell.
                republish_attestation_fault(
                    &pds,
                    &attestation_pub_key,
                    &base_record,
                    outcome.fault.clone(),
                )
                .await;
            }
        })
    };

    // The serve future below loops forever. Race it against a graceful
    // shutdown signal (SIGTERM from launchd / the macOS app supervisor on
    // quit / pause / bounce, or Ctrl-C in a terminal) so that when the
    // agent is told to stop we get a chance to flip the provider record's
    // `serving` flag to false — the console then shows the machine offline
    // the moment it stops serving instead of leaving it looking idle.
    let serve = async {
        match cocore_provider::schedule::ServeWindow::from_env() {
            None => {
                // No serve window → connect continuously, reconnecting on
                // drops with exponential backoff. Previously a single dropped
                // connection returned Err and exited the process, relying on
                // launchd KeepAlive to restart — but in the app-supervised
                // (download-only) case nothing restarts it, so one blip stopped
                // serving entirely. Reconnect in-process instead.
                let mut backoff = std::time::Duration::from_secs(1);
                // A connection that stayed up this long before dropping was
                // healthy — the drop is almost always Railway's edge recycling
                // the proxied WebSocket (a 1006 "reset without close" every
                // ~minute), NOT a real fault. Resetting the backoff after such
                // a connection keeps the machine rejoining promptly instead of
                // ratcheting toward the 30s cap and sitting out of the
                // advisor's registry a third of the time (which, across an
                // owner's machines, is what surfaces as intermittent "503 no
                // machines available"). Only a connection that fails QUICKLY,
                // repeatedly, still earns the growing backoff.
                const HEALTHY_UPTIME: std::time::Duration = std::time::Duration::from_secs(30);
                loop {
                    // Honour a remote stop: if the owner stopped this machine
                    // from the console, don't (re)connect — poll until they
                    // start it again, so we stay out of routing entirely.
                    wait_until_active(&pds, provider_rkey.as_deref()).await;
                    let connected_at = std::time::Instant::now();
                    let result = AdvisorClient::new(advisor_url)
                        .run(
                            register.clone(),
                            &*signer,
                            &enc,
                            &pds,
                            attestation.clone(),
                            &engines,
                            provider_rkey.as_deref(),
                            &desired_at_start,
                            desired_tier_at_start.as_deref(),
                            &model_schedules,
                            &configured_models,
                            push_rx.as_mut(),
                            &pro_bono_at_start,
                        )
                        .await;
                    let lived = connected_at.elapsed();
                    match result {
                        Ok(()) => {
                            // Advisor closed cleanly (e.g. deploy); rejoin shortly.
                            backoff = std::time::Duration::from_secs(1);
                            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                        }
                        Err(_) if lived >= HEALTHY_UPTIME => {
                            // Dropped after a healthy run — reconnect promptly
                            // and reset the backoff rather than penalising a
                            // connection that was working.
                            tracing::warn!(lived_s = lived.as_secs(), "advisor connection dropped after healthy uptime; reconnecting promptly");
                            backoff = std::time::Duration::from_secs(1);
                            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, lived_s = lived.as_secs(), backoff_s = backoff.as_secs(), "advisor connection dropped; reconnecting");
                            tokio::time::sleep(backoff).await;
                            backoff = (backoff * 2).min(std::time::Duration::from_secs(30));
                        }
                    }
                }
            }
            Some(window) => {
                tracing::info!(
                start = window.start,
                end = window.end,
                "serve window configured — connecting to the advisor only during [{}:00,{}:00) local time",
                window.start,
                window.end
            );
                // Reuse the engines already built (for the provider record)
                // on the first in-window run; free them while idle and
                // rebuild on the next open. `None` == freed/idle.
                let mut current = Some(engines);
                loop {
                    if window.contains_now() {
                        // Remote stop overrides the schedule window too.
                        wait_until_active(&pds, provider_rkey.as_deref()).await;
                        let eng = match current.take() {
                            Some(e) => e,
                            None => {
                                tracing::info!("serve window opened — loading inference engines");
                                // The fault (if any) was already published on the
                                // initial provider record; the in-window reload only
                                // needs the registry.
                                let (eng, _fault, _tool_call_models) =
                                    build_engines(provider_record.ramGB);
                                eng
                            }
                        };
                        let close_in = window.seconds_until_close().max(1);
                        tracing::info!(
                            closes_in_s = close_in,
                            "inside serve window — connecting to advisor"
                        );
                        let client = AdvisorClient::new(advisor_url);
                        tokio::select! {
                            res = client.run(register.clone(), &*signer, &enc, &pds, attestation.clone(), &eng, provider_rkey.as_deref(), &desired_at_start, desired_tier_at_start.as_deref(), &model_schedules, &configured_models, push_rx.as_mut(), &pro_bono_at_start) => {
                                if let Err(e) = res {
                                    tracing::warn!(error = %e, "advisor run ended; reconnecting within window in 5s");
                                }
                                // Connection ended on its own but the window
                                // is still open — keep engines, reconnect soon.
                                current = Some(eng);
                                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                            }
                            _ = tokio::time::sleep(std::time::Duration::from_secs(close_in)) => {
                                tracing::info!("serve window closed — disconnecting and freeing inference engines");
                                drop(eng); // SubprocessEngine::drop SIGTERMs the Python child
                            }
                        }
                    } else {
                        // Idle: make sure engines are freed, then sleep to open.
                        current = None;
                        let open_in = window.seconds_until_open().max(1);
                        tracing::info!(
                            opens_in_s = open_in,
                            "outside serve window — idle (disconnected, engines freed)"
                        );
                        tokio::time::sleep(std::time::Duration::from_secs(open_in)).await;
                    }
                }
            }
        }
    };

    tokio::select! {
        // `serve` never returns on its own; this arm exists only so the
        // future is polled.
        _ = serve => {}
        _ = wait_for_shutdown_signal() => {
            tracing::info!("graceful shutdown signal received — marking provider offline");
            // Don't leave a stale "provisioning"/"failed" marker behind for a
            // machine the owner just stopped.
            clear_provision_status();
            if provider_rkey.is_some() {
                // Flip `serving` to false WITHOUT clobbering the owner /
                // console-authored switches. Our in-memory `provider_record`
                // carries `active` / `payoutsEnabled` / `desiredModels` as
                // `None` (the agent never authors them), and those fields are
                // `#[serde(skip_serializing_if = "Option::is_none")]` — so a
                // blind `put_provider` of it OMITS them, and an absent `active`
                // reads back as the default `true`. That silently UN-PAUSES a
                // machine the owner just paused: the tray sets `active=false`,
                // then SIGTERMs the agent, and this shutdown marker would wipe
                // the switch, so the 30s reconciler reads "serving" and turns
                // serving right back on (the "pause won't stick" bug). Mirror
                // the dedup re-publish path: read the live record and preserve
                // those fields, CAS-ing on the CID we just read so we don't
                // race the pause's own write.
                let publish = async {
                    let mut offline = provider_record.clone();
                    offline.serving = Some(false);
                    offline.provisioning = Some(false);
                    // Don't carry a stale fault into the offline marker; the
                    // machine simply stopped serving.
                    offline.engineFault = None;
                    offline.createdAt = chrono::Utc::now();
                    // The single CAS write path merges this onto the LATEST
                    // record — preserving the owner's `active` (so a machine
                    // paused moments ago stays paused instead of being un-paused
                    // by this marker) and every other owner/unknown field — and
                    // retries on a swap conflict.
                    dedup_and_publish_provider(&pds, &attestation_pub_key, &offline).await
                };
                match tokio::time::timeout(std::time::Duration::from_secs(5), publish).await {
                    Ok(Ok((published, _, _))) => tracing::info!(uri = %published.uri, "published provider record with serving=false (owner switches preserved)"),
                    Ok(Err(e)) => tracing::warn!(error = %e, "failed to publish offline marker (active switch left intact)"),
                    Err(_) => tracing::warn!("offline-marker publish timed out after 5s"),
                }
            } else {
                tracing::warn!("no provider rkey captured; cannot publish offline marker");
            }
        }
    }
    // Stop the background re-attestation task on the way out (shutdown only —
    // `serve` itself never returns).
    refresh_handle.abort();
    Ok(())
}

/// Engine-derived attestation inputs, snapshotted once at serve start. The
/// loaded engine set is fixed for a serve lifetime, so the re-attestation task
/// carries this owned snapshot instead of borrowing the engine registry (which
/// the serve loop may move into its schedule branch).
#[derive(Clone, Default)]
struct EngineAttestationFacts {
    in_process_backend: bool,
    metallib_hash: Option<String>,
    engine_lib_hash: Option<String>,
}

impl EngineAttestationFacts {
    fn from_registry(engines: &cocore_provider::engines::EngineRegistry) -> Self {
        Self {
            in_process_backend: engines.entries().iter().any(|(_, e)| e.in_process()),
            metallib_hash: engines
                .entries()
                .iter()
                .find_map(|(_, e)| e.metallib_hash()),
            engine_lib_hash: engines
                .entries()
                .iter()
                .find_map(|(_, e)| e.engine_lib_hash()),
        }
    }
}

/// The result of building + publishing one attestation.
struct AttestationOutcome {
    /// Strong-ref to the published attestation record; `None` when build or
    /// publish failed (receipts skip publishing in that mode).
    strong_ref: Option<StrongRef>,
    /// ACHIEVED trust level, derived from what the attestation actually
    /// embedded — a bound MDA chain or App Attest object earns
    /// hardware-attested; otherwise self-attested.
    trust_level: TrustLevel,
    /// The attestation's evidence-gated tier, when built.
    tier: Option<String>,
    /// Measured cdHash to echo on the Register frame.
    cd_hash: Option<String>,
    /// Tier to echo on the Register frame.
    register_tier: Option<String>,
    /// Set when build or publish failed, for the provider record + console.
    fault: Option<AttestationFault>,
}

/// Assemble the attestation inputs from the current machine + key state, build
/// the signed record, and publish it to the provider's PDS. Used both at serve
/// start and by the periodic refresh task (attestations expire after 24h; see
/// `attestation.rs`). Re-runs the MDA auto-acquire so a key-bound chain that was
/// requested on an earlier cycle but landed later is picked up on refresh.
/// Fail-soft: any build/publish error returns `strong_ref: None` plus a
/// content-safe `fault`, never panics.
async fn build_and_publish_attestation(
    session: &oauth::Session,
    signer: &dyn secure_enclave::SigningIdentity,
    encryption_pub_key_b64: &str,
    engine_facts: &EngineAttestationFacts,
    pds: &PdsClient,
) -> AttestationOutcome {
    let mut attestation_inputs =
        attestation::build_stub_inputs(&session.did, encryption_pub_key_b64);
    // MDA option-B (the live macOS hardware-attested path). EXPLICIT env wins;
    // otherwise AUTO derives serial + Hardware UUID + coordinator URLs from the
    // session console base and, only when this Mac is MDM-enrolled, loads the
    // captured chain — requesting a fresh key-bound attestation if none is held
    // yet (it lands on a later refresh, which is exactly what this task drives).
    let pubkey_b64 = signer.public_key_b64();
    cocore_provider::mda_loader::request_attestation(&pubkey_b64);
    let mut mda_cert_chain = cocore_provider::mda_loader::try_load();
    if mda_cert_chain.is_empty() && !cocore_provider::mda_loader::any_explicit_mda_env() {
        mda_cert_chain = cocore_provider::mda_loader::acquire_auto(
            &session.api_base,
            &session.api_key,
            &pubkey_b64,
        );
    }
    attestation_inputs.mda_cert_chain = mda_cert_chain;
    // App Attest evidence — bound to this signing key; `build` re-verifies + only
    // embeds it if it binds. A no-op on macOS (iOS-only), retained for a future
    // iOS companion.
    attestation_inputs.app_attest =
        cocore_provider::mda_loader::load_appattest(&signer.public_key_b64());
    attestation_inputs.in_process_backend = engine_facts.in_process_backend;
    attestation_inputs.metallib_hash = engine_facts.metallib_hash.clone();
    attestation_inputs.engine_lib_hash = engine_facts.engine_lib_hash.clone();

    let built = attestation::build(attestation_inputs, signer);
    // Derive trust/tier from what the attestation ACTUALLY embedded, not from
    // what was loaded: `build` drops any MDA chain / App Attest that doesn't
    // verify Apple-rooted AND bind to our signing key.
    let (trust_level, tier) = match &built {
        Ok(rec) => (
            if !rec.mdaCertChain.is_empty() || rec.appAttest.is_some() {
                TrustLevel::HardwareAttested
            } else {
                TrustLevel::SelfAttested
            },
            Some(rec.tier.clone()),
        ),
        Err(_) => (TrustLevel::SelfAttested, None),
    };

    match built {
        Ok(record) => {
            let cd_hash = record.cdHash.clone();
            let register_tier = Some(record.tier.clone());
            match pds.publish_attestation(&record).await {
                Ok(published) => {
                    tracing::info!(uri = %published.uri, "published attestation");
                    AttestationOutcome {
                        strong_ref: Some(StrongRef {
                            uri: published.uri,
                            cid: published.cid,
                        }),
                        trust_level,
                        tier,
                        cd_hash,
                        register_tier,
                        fault: None,
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to publish attestation; receipts disabled");
                    AttestationOutcome {
                        strong_ref: None,
                        trust_level,
                        tier,
                        cd_hash,
                        register_tier,
                        fault: Some(AttestationFault {
                            code: "attestation-publish-failed".to_string(),
                            message: "This machine could not publish its attestation record \
                                to its PDS, so it cannot produce verifiable receipts and will \
                                complete no billable jobs. The machine is otherwise online. \
                                Fix: check this machine's network connection to its PDS and \
                                that the session is still valid (re-pair with \
                                `cocore agent pair` if needed); it retries automatically on \
                                the next attestation refresh."
                                .to_string(),
                            at: chrono::Utc::now(),
                        }),
                    }
                }
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to build attestation; receipts disabled");
            AttestationOutcome {
                strong_ref: None,
                trust_level,
                tier,
                cd_hash: None,
                register_tier: None,
                fault: Some(AttestationFault {
                    code: "attestation-build-failed".to_string(),
                    message: "This machine could not assemble its signed attestation, so it \
                        cannot produce verifiable receipts and will complete no billable jobs. \
                        This usually means the signing identity or a measured-binary input is \
                        unavailable. Fix: update to the latest co/core build and restart \
                        serving; if it persists, re-pair with `cocore agent pair`."
                        .to_string(),
                    at: chrono::Utc::now(),
                }),
            }
        }
    }
}

/// How long the re-attestation task waits between refreshes. Default ~23h (one
/// hour before the 24h expiry); `COCORE_ATTESTATION_REFRESH_SECS` overrides it
/// for testing (a positive integer number of seconds).
fn attestation_refresh_interval() -> std::time::Duration {
    std::env::var("COCORE_ATTESTATION_REFRESH_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|s| *s > 0)
        .map(std::time::Duration::from_secs)
        .unwrap_or_else(|| std::time::Duration::from_secs(23 * 3600))
}

/// Re-publish this machine's provider record to reflect the latest attestation
/// outcome (clear the fault on success, set it on failure) after a refresh
/// cycle. Mirrors the shutdown offline-marker path: read the live record, clone
/// our agent-built base, preserve the console-authored switches, and CAS on the
/// CID we just read so we don't clobber a concurrent console write. Best-effort
/// — a failure here never affects the live attestation cell.
async fn republish_attestation_fault(
    pds: &PdsClient,
    attestation_pub_key: &str,
    base_record: &ProviderRecord,
    fault: Option<AttestationFault>,
) {
    let publish = async {
        let mut rec = base_record.clone();
        rec.attestationFault = fault.clone();
        // Mid-serve: the machine is up and past provisioning.
        rec.serving = Some(true);
        rec.provisioning = Some(false);
        rec.createdAt = chrono::Utc::now();
        // Single CAS write path: merges onto the latest record (owner switches +
        // unknown fields preserved) and retries on conflict.
        dedup_and_publish_provider(pds, attestation_pub_key, &rec).await
    };
    match tokio::time::timeout(std::time::Duration::from_secs(10), publish).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "failed to re-publish provider record after attestation refresh")
        }
        Err(_) => {
            tracing::warn!("provider record re-publish after attestation refresh timed out")
        }
    }
}

/// Resolves when the process receives a graceful shutdown signal: SIGTERM
/// (sent by launchd / the macOS app supervisor on quit, pause, or bounce)
/// or Ctrl-C in an interactive terminal. Used to publish a `serving=false`
/// provider record so the console shows the machine offline immediately.
async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut sigterm) => {
                tokio::select! {
                    _ = sigterm.recv() => {}
                    _ = tokio::signal::ctrl_c() => {}
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "SIGTERM handler unavailable; falling back to Ctrl-C only");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

// ── Provisioning status marker (agent → tray) ──────────────────────
//
// `~/.cocore/provision-status.json` — written while the agent is
// bringing a model online (downloading weights + loading) so the
// menu-bar app can show a real "Provisioning…" state with download
// progress, and surface a fault if it fails, instead of claiming
// "Serving" the moment the process is alive. Best-effort + content-free
// (model ids + byte counts only). The tray polls it like bad-standing-at.

fn provision_status_path() -> Option<std::path::PathBuf> {
    let home = std::env::var("HOME").ok().filter(|h| !h.is_empty())?;
    Some(
        std::path::Path::new(&home)
            .join(".cocore")
            .join("provision-status.json"),
    )
}

/// Total bytes of the configured models' HuggingFace cache dirs (incl.
/// in-progress `.incomplete` blobs) — the download-progress signal.
fn model_download_bytes(models: &[String]) -> u64 {
    let Ok(home) = std::env::var("HOME") else {
        return 0;
    };
    if home.is_empty() {
        return 0;
    }
    let hub = std::path::Path::new(&home)
        .join(".cache")
        .join("huggingface")
        .join("hub");
    let mut total = 0u64;
    for m in models {
        let dir = hub.join(format!("models--{}", m.replace('/', "--")));
        total = total.saturating_add(provision_dir_size(&dir));
    }
    total
}

/// Recursively sum regular-file sizes under `dir` (best-effort). Uses
/// `symlink_metadata` so HF's `snapshots/*` symlinks aren't double-
/// counted — only the real `blobs/` files (completed + `.incomplete`).
fn provision_dir_size(dir: &std::path::Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    let mut total = 0u64;
    for entry in entries.flatten() {
        let path = entry.path();
        match std::fs::symlink_metadata(&path) {
            Ok(md) if md.is_dir() => total = total.saturating_add(provision_dir_size(&path)),
            Ok(md) if md.is_file() => total = total.saturating_add(md.len()),
            _ => {}
        }
    }
    total
}

/// Write the provisioning marker. `phase` is "provisioning" or "failed".
/// `loading` is true while provisioning when no weights are actively
/// downloading — i.e. the bytes are all on disk and the agent is mmapping a
/// model into Metal. The tray uses it to show "loading into memory…" rather
/// than a download bar (and, critically, NOT a bare "complete" state) during
/// the gap between/after downloads. Best-effort; content-free (ids + byte
/// counts + an optional fault code/message, all already public on the record).
fn write_provision_status(
    phase: &str,
    models: &[String],
    bytes: u64,
    loading: bool,
    fault: Option<&EngineFault>,
) {
    let Some(path) = provision_status_path() else {
        return;
    };
    let body = serde_json::json!({
        "phase": phase,
        "models": models,
        "bytesDownloaded": bytes,
        "loading": loading,
        "updatedAt": chrono::Utc::now().to_rfc3339(),
        "fault": fault.map(|f| serde_json::json!({ "code": f.code, "message": f.message })),
    });
    let _ = std::fs::write(path, body.to_string());
}

/// Whether any configured model has an in-flight HuggingFace download — a
/// `blobs/*.incomplete` file (HF writes each blob there and renames it on
/// completion). When false during provisioning, the weights are all on disk
/// and the remaining work is loading them into memory. Mirrors the tray's
/// own `.incomplete` probe so the two agree on download-vs-load.
fn any_model_downloading(models: &[String]) -> bool {
    let Ok(home) = std::env::var("HOME") else {
        return false;
    };
    if home.is_empty() {
        return false;
    }
    let hub = std::path::Path::new(&home)
        .join(".cache")
        .join("huggingface")
        .join("hub");
    models.iter().any(|m| {
        let blobs = hub
            .join(format!("models--{}", m.replace('/', "--")))
            .join("blobs");
        std::fs::read_dir(&blobs)
            .map(|rd| {
                rd.flatten()
                    .any(|e| e.file_name().to_string_lossy().ends_with(".incomplete"))
            })
            .unwrap_or(false)
    })
}

/// Remove the provisioning marker (engine is up + serving, or the
/// machine stopped) so the tray falls back to its normal serving state.
fn clear_provision_status() {
    if let Some(path) = provision_status_path() {
        let _ = std::fs::remove_file(path);
    }
}

/// What a serve should do with `COCORE_INFERENCE_MODELS` (the subprocess
/// engine's model set) before building engines.
#[derive(Debug, PartialEq, Eq)]
enum InferenceModelsAction {
    /// Clear the var (both spellings) — confidential = native-only, inference
    /// stays in the measured binary, so the subprocess engine serves nothing.
    Clear,
    /// Set it to this CSV — the owner picked models on the console (best-effort).
    Set(String),
    /// Leave the existing env / install default untouched — best-effort machine
    /// with no console selection.
    Leave,
}

/// Decide the `COCORE_INFERENCE_MODELS` action for a serve. A confidential
/// machine ALWAYS clears it (native-only — never a subprocess child, no matter
/// what the supervisor injected); a best-effort machine sets the owner's
/// `desiredModels` when present, else leaves whatever is already configured.
fn inference_models_action(confidential: bool, desired: &[String]) -> InferenceModelsAction {
    if confidential {
        InferenceModelsAction::Clear
    } else if desired.is_empty() {
        InferenceModelsAction::Leave
    } else {
        InferenceModelsAction::Set(desired.join(","))
    }
}

/// Pick the single model a confidential machine's native (in-process) MLX
/// engine should serve, from the owner's intent.
///
/// Mirrors the best-effort priority in {@link inference_models_action}: the PDS
/// `desiredModels` (the web-console model picker) wins, then the local
/// `COCORE_INFERENCE_MODELS` the macOS tray and launchd plist set, then a small
/// default. The native engine serves exactly ONE model, so we take the first
/// non-`stub` entry from whichever source is populated.
///
/// The two sources matter because the tray and the website set the owner's
/// choice through DIFFERENT channels: the website writes PDS `desiredModels`,
/// while the tray's "Add a model" runs `cocore agent models`, which edits the
/// LaunchAgent plist's `COCORE_INFERENCE_MODELS` and bounces the daemon (it does
/// NOT write `desiredModels`). The best-effort path already honours both — it
/// loads `desiredModels` when present and otherwise leaves the plist value in
/// place. Confidential native selection has to honour both too, or a machine
/// configured from the tray (the common case) silently ignores the owner's pick
/// and serves the default.
// Only called from the apns-gated confidential path, but kept un-gated so its
// unit tests build (and run) on every platform — like `inference_models_action`.
#[cfg_attr(not(all(target_os = "macos", feature = "apns")), allow(dead_code))]
fn pick_confidential_native_model(
    desired_models: &[String],
    inference_models_env: Option<&str>,
    default_model: &str,
) -> String {
    let first_servable = |raw: &str| {
        raw.split(',')
            .map(str::trim)
            .find(|m| !m.is_empty() && *m != "stub")
            .map(str::to_string)
    };
    desired_models
        .iter()
        .map(|s| s.trim())
        .find(|m| !m.is_empty() && *m != "stub")
        .map(str::to_string)
        .or_else(|| inference_models_env.and_then(first_servable))
        .unwrap_or_else(|| default_model.to_string())
}

/// Build the per-model engine registry for this serve invocation.
///
/// Every registry includes a `stub` entry — it's the no-cost
/// fallback for protocol-level smoke tests and the "this provider
/// exists but doesn't run real inference" signal.
///
/// For each id named in `COCORE_INFERENCE_MODELS` (comma-separated)
/// we spawn one `SubprocessEngine`. Each engine owns a Python child
/// process that hosts `vllm-mlx` on a Unix domain socket; the Rust
/// side proxies `/v1/chat/completions` over the socket. The legacy
/// singular `COCORE_INFERENCE_MODEL` env var is honored when the
/// plural is absent for v0.4.0 plist back-compat.
///
/// Each configured model is loaded with bounded recovery
/// ([`ENGINE_START_MAX_ATTEMPTS`] attempts with backoff) rather than a
/// single best-effort try. The dominant first-boot failures are
/// *transient*: the install script may still be `pip`-installing the
/// venv when `serve` races ahead, or the Hugging Face weight download
/// hasn't finished on a cold machine. A retry a few seconds later
/// usually succeeds where the first attempt couldn't — which is exactly
/// the "machine says it's running a model but never gets picked up"
/// trap (it registered `stub` because the one-shot load lost the race).
///
/// When every attempt for a model is exhausted we give up *for this
/// serve* and record the reason. The returned `Option<EngineFault>`
/// summarizes the failure (content-safe) so the caller can publish it
/// on the provider record and the console can show the operator a fault +
/// remediation instead of a green machine that silently only serves
/// `stub`. The `stub` engine always stays registered so protocol-level
/// smoke tests still work.
///
/// `ram_gb` is this machine's physical memory. Catalog models whose
/// conservative `min_ram_gb` floor exceeds it are skipped *before* we
/// pay for a spawn + cold weight download that would only OOM — there's
/// no point advertising (and then flapping on) a model the machine
/// can't hold. Off-catalog ids have no known footprint, so they're left
/// for `start()` to arbitrate. Set `COCORE_IGNORE_RAM_FLOOR=1` to bypass
/// the guard (e.g. a machine the operator knows can run a model the
/// conservative floor rejects).
fn build_engines(
    ram_gb: u32,
) -> (
    cocore_provider::engines::EngineRegistry,
    Option<EngineFault>,
    Vec<String>,
) {
    use cocore_provider::engines::stub::StubEngine;
    let mut registry = cocore_provider::engines::EngineRegistry::new();
    registry.register("stub", std::sync::Arc::new(StubEngine));

    // A confidential machine's native engine failed to come up. Surfaced as
    // the serve's engineFault so the console shows an honest "couldn't serve
    // confidentially" instead of a green machine that silently only runs
    // `stub`. Stays `None` on best-effort builds/machines (no native env set),
    // so their behaviour is unchanged.
    #[cfg_attr(not(feature = "native_mlx"), allow(unused_mut, unused_assignments))]
    let mut native_fault: Option<EngineFault> = None;

    // WS-ENGINE: the native in-process MLX engine (confidential tier). Opt-in
    // and feature-gated so it never disrupts the subprocess path. Configure a
    // model id + its local snapshot dir; the prompt is then served entirely
    // inside the measured binary (flips inProcessBackend + metallibHash true).
    #[cfg(feature = "native_mlx")]
    if let Ok(model) = std::env::var("COCORE_NATIVE_MLX_MODEL") {
        use cocore_provider::engines::native_mlx::NativeMlxEngine;
        use cocore_provider::engines::Engine;
        match std::env::var("COCORE_NATIVE_MLX_MODEL_DIR") {
            Ok(dir) => match NativeMlxEngine::load(std::path::PathBuf::from(dir), None) {
                Ok(engine) if engine.ready() => {
                    tracing::info!(model = %model, "loaded native in-process MLX engine (confidential-capable)");
                    registry.register(model, std::sync::Arc::new(engine));
                }
                Ok(_) => {
                    tracing::warn!(
                        model = %model,
                        "native MLX engine loaded but metallib not located; not registering (confidential tier unavailable)"
                    );
                    native_fault = Some(EngineFault {
                        code: "native-metallib-missing".to_string(),
                        message: format!(
                            "The confidential (in-process MLX) engine for `{model}` loaded but its \
                             signed Metal kernel library couldn't be located, so it won't serve. \
                             This is a packaging problem on this build, not your configuration. \
                             The machine is online but only serving the no-op `stub` engine."
                        ),
                        models: vec![model.clone()],
                        at: chrono::Utc::now(),
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, model = %model, "failed to load native MLX engine");
                    native_fault = Some(EngineFault {
                        code: "native-load-failed".to_string(),
                        message: format!(
                            "The confidential (in-process MLX) engine couldn't load `{model}`. The \
                             native engine supports Qwen2/Llama/Gemma/Phi-family MLX models; a \
                             different architecture (e.g. a Qwen3 model) won't load in-process. \
                             Pick a confidential-compatible model in the console. The machine is \
                             online but only serving the no-op `stub` engine. ({e})"
                        ),
                        models: vec![model.clone()],
                        at: chrono::Utc::now(),
                    });
                }
            },
            Err(_) => {
                tracing::warn!(
                    model = %model,
                    "confidential model selected but weights not downloaded yet; serving stub until provisioned"
                );
                native_fault = Some(EngineFault {
                    code: "native-model-missing".to_string(),
                    message: format!(
                        "The confidential model `{model}` isn't downloaded on this machine yet, so \
                         the in-process engine can't serve it. The machine is online but only \
                         serving the no-op `stub` engine; it will recover once the weights finish \
                         downloading and it restarts."
                    ),
                    models: vec![model.clone()],
                    at: chrono::Utc::now(),
                });
            }
        }
    }

    let raw = std::env::var("COCORE_INFERENCE_MODELS")
        .or_else(|_| std::env::var("COCORE_INFERENCE_MODEL"))
        .unwrap_or_default();
    if raw.trim().is_empty() {
        tracing::info!(
            "no inference models configured (set COCORE_INFERENCE_MODELS to enable real inference; this agent will serve `stub` only)"
        );
        // On a confidential machine the subprocess set is intentionally empty
        // (inference runs in-process), so a native failure is the fault to
        // surface here. On best-effort machines `native_fault` is `None`.
        return (registry, native_fault, vec![]);
    }

    // Resolve the venv interpreter once. The install script writes it
    // to `~/.cocore/python/bin/python` via `uv venv`.
    let Some(home) = dirs::home_dir() else {
        tracing::warn!("no $HOME; cannot locate venv python; serving stub only");
        let fault = EngineFault {
            code: "no-home".to_string(),
            message: "The agent could not locate your home directory, so it can't \
                      find the Python inference environment. The machine is online \
                      but only serving the no-op `stub` engine, so it won't be \
                      matched to real inference jobs."
                .to_string(),
            models: vec![],
            at: chrono::Utc::now(),
        };
        return (registry, Some(fault), vec![]);
    };
    let venv_python = home.join(".cocore/python/bin/python");

    let configured: Vec<String> = raw
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    // Per-model scheduling: narrow to the models whose time window is open
    // right now (a model with no per-model window stays on). Applied here —
    // the single point every build flows through (startup, whole-app window
    // re-open, health rebuild) — so the loaded set always matches the clock.
    let schedules = cocore_provider::schedule::ModelSchedules::from_env();
    let configured: Vec<String> = if schedules.is_empty() {
        configured
    } else {
        let active = schedules.active_now(&configured);
        tracing::info!(active = ?active, "per-model schedule: loading the models whose window is open now");
        active
    };

    // RAM-fit guard. Skip catalog models whose conservative `min_ram_gb`
    // floor exceeds this machine's memory before spending a spawn + cold
    // weight download on a load that can only OOM. We judge ONLY models
    // the catalog knows the footprint of; off-catalog custom ids have no
    // floor, so we let `start()` be the arbiter for those. The operator
    // can bypass with COCORE_IGNORE_RAM_FLOOR=1.
    let ignore_ram_floor = std::env::var("COCORE_IGNORE_RAM_FLOOR")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let mut too_large: Vec<String> = vec![];
    let configured: Vec<String> = if ignore_ram_floor {
        configured
    } else {
        configured
            .into_iter()
            .filter(|model| {
                let over_floor = cocore_provider::pricing::RATES
                    .iter()
                    .find(|r| r.model_id == model.as_str())
                    .is_some_and(|r| r.min_ram_gb > ram_gb);
                if over_floor {
                    tracing::warn!(
                        model = %model,
                        ram_gb,
                        "configured model needs more RAM than this machine has; not loading or advertising it (set COCORE_IGNORE_RAM_FLOOR=1 to override)"
                    );
                    too_large.push(model.clone());
                }
                !over_floor
            })
            .collect()
    };

    // Overprovisioning guard. Even when each model individually fits its
    // floor, the SUM of a concurrent set can exceed RAM — a 7B + 3B on a
    // 16 GB Mac, or two models a per-model schedule lands in the same hour.
    // Prune largest-first until the summed floors fit; pruned models are
    // surfaced like too-large ones. Bypassed by COCORE_IGNORE_RAM_FLOOR.
    let configured: Vec<String> = if ignore_ram_floor {
        configured
    } else {
        let (kept, over_budget) = cocore_provider::pricing::fit_within_budget(&configured, ram_gb);
        for m in &over_budget {
            tracing::warn!(
                model = %m,
                ram_gb,
                "skipping model to stay within the RAM budget — the concurrent set's summed floors exceed this machine's memory (set COCORE_IGNORE_RAM_FLOOR=1 to override)"
            );
        }
        too_large.extend(over_budget);
        kept
    };

    // Headroom advisory (does NOT drop anything — the hard guard above
    // already kept the set within total RAM). If the kept set leaves less
    // than the user reserve free, the Mac may get sluggish under the
    // owner's own work; surface that the same way the tray meter does.
    if !ignore_ram_floor {
        let report = cocore_provider::pricing::budget_report(&configured, ram_gb);
        if matches!(report.status, cocore_provider::pricing::BudgetStatus::Tight) {
            tracing::warn!(
                used_gb = report.used_gb,
                reserve_gb = report.reserve_gb,
                ram_gb = report.total_gb,
                "pinned models fit but leave little headroom for your own apps — this Mac may get sluggish while you use it. Drop one or stagger their hours."
            );
        }
    }

    // Vision / multimodal models ARE served now: vllm-mlx loads them through
    // its multimodal path (the subprocess engine passes `--vision`/force_mllm
    // for vision model ids), and the same /v1/chat/completions endpoint accepts
    // image_url content parts. So they're no longer skipped here — they load
    // and fail (or succeed) like any other model.

    let mut failed: Vec<String> = vec![];
    let mut saw_venv_missing = false;
    let mut last_err: Option<String> = None;

    let tool_config = cocore_provider::engines::subprocess::VllmToolConfig::from_env();
    if tool_config.enabled {
        tracing::info!(
            parser = tool_config.tool_call_parser.as_deref().unwrap_or("auto"),
            chat_template_kwargs = tool_config.default_chat_template_kwargs.is_some(),
            extra_args = tool_config.extra_args.len(),
            "tool calling requested; vLLM config will be passed through and verified with a startup canary"
        );
    }
    let mut tool_call_models: Vec<String> = vec![];

    for model in &configured {
        match start_engine_with_recovery(model, &venv_python, tool_config.clone()) {
            Ok(engine) => {
                tracing::info!(model = %model, "inference subprocess engine ready");
                if engine.verified_tool_calls() {
                    tool_call_models.push(model.clone());
                }
                registry.register(model.clone(), std::sync::Arc::new(engine));
            }
            Err(EngineStartFailure::VenvMissing) => {
                saw_venv_missing = true;
                // Per-model terminal line (content-safe, carries the
                // `model` field) so `cocore agent models` and the tray can
                // tail the log and report this model's outcome. Keep the
                // "inference engine load failed" phrase stable —
                // `models_cli::match_log_line` matches on it.
                tracing::warn!(model = %model, reason = "venv-missing", "inference engine load failed");
                failed.push(model.clone());
            }
            Err(EngineStartFailure::Failed(err)) => {
                last_err = Some(err);
                tracing::warn!(model = %model, "inference engine load failed");
                failed.push(model.clone());
            }
        }
    }

    if failed.is_empty() && too_large.is_empty() {
        return (registry, None, tool_call_models);
    }

    // The fault's `models` field lists every model that won't be served
    // this run — the ones that tried-and-failed and the ones we skipped as too
    // large for RAM — so the console shows the operator the full set missing
    // from `supportedModels`.
    let mut all_unserved = failed.clone();
    all_unserved.extend(too_large.iter().cloned());

    // Build a curated, content-safe fault for the console. Detailed
    // tracebacks already went to `tracing` inside the recovery loop;
    // we deliberately do NOT inline them here — the record is public
    // and a 600-char human summary triages better than a wall of
    // Python stderr.
    //
    // Priority when more than one category applies: a missing venv is
    // the most actionable global problem, then real load failures, then
    // RAM-floor skips. The chosen message's prose references its own
    // category's models; `models` always carries the full unserved set.
    let fault = if saw_venv_missing {
        EngineFault {
            code: "venv-missing".to_string(),
            message: format!(
                "The Python inference environment at {} is missing or incomplete, \
                 so the configured model(s) [{}] could not load even after retrying. \
                 The machine is online but only serving the no-op `stub` engine, so \
                 it won't be matched to real inference jobs. Fix: re-run the installer \
                 to (re)provision the environment — `curl -fsSL https://cocore.dev/agent | sh` \
                 — then start serving again.",
                venv_python.display(),
                failed.join(", "),
            ),
            models: all_unserved,
            at: chrono::Utc::now(),
        }
    } else if !failed.is_empty() && is_socket_path_too_long(last_err.as_deref()) {
        // The engine couldn't open its local Unix-domain socket because the
        // assembled path overflowed the OS `sun_path` limit (a long $HOME +
        // a long model id). The generic "not in MLX format" message below
        // would be actively wrong — the weights are fine; the socket path is
        // the problem. Current builds budget the path under the limit
        // (engines/subprocess.rs `socket_filename`), so this only bites
        // stragglers on an older binary.
        tracing::warn!(
            models = ?failed,
            last_error = %last_err.as_deref().unwrap_or("(none captured)"),
            "engine socket path exceeded the OS limit; serving stub only"
        );
        EngineFault {
            code: "engine-socket-path".to_string(),
            message: format!(
                "The inference engine for [{}] couldn't open its local socket: the \
                 socket path under your home directory is too long for the operating \
                 system (the `sun_path` limit). The weights are fine — this is a path \
                 length problem, not a model problem. The machine is online but only \
                 serving the no-op `stub` engine. Fix: update to the latest co/core \
                 build (which shortens the socket path) — \
                 `curl -fsSL https://cocore.dev/agent | sh` — then start serving again.",
                failed.join(", "),
            ),
            models: all_unserved,
            at: chrono::Utc::now(),
        }
    } else if !failed.is_empty() && is_vision_config_failure(last_err.as_deref()) {
        // A vision/multimodal model whose config the multimodal runtime
        // (mlx_vlm) couldn't parse — the "not in MLX format" message below would
        // be actively wrong here (the weights ARE MLX; the vision_config is the
        // problem). This is overwhelmingly a merged / re-quantized VLM whose
        // vision_config was stripped or left incomplete, so it can't load as a
        // vision model in any client. Point the operator at a known-good VLM.
        tracing::warn!(
            models = ?failed,
            last_error = %last_err.as_deref().unwrap_or("(none captured)"),
            "vision model failed to load — incomplete vision_config; serving stub only"
        );
        EngineFault {
            code: "model-vision-incompatible".to_string(),
            message: format!(
                "The vision/multimodal model(s) [{}] couldn't load: the runtime rejected \
                 their image config (an incomplete `vision_config`). The weights are MLX, \
                 but this is almost always a merged or re-quantized VLM whose vision config \
                 was dropped during conversion — so it can't be served as a vision model in \
                 any tool, not just co/core. The machine is online but only serving the \
                 no-op `stub` engine. Fix: pick a standard MLX vision model — e.g. \
                 `mlx-community/Qwen2.5-VL-7B-Instruct-4bit` or \
                 `mlx-community/Qwen2.5-VL-3B-Instruct-4bit` — then start serving again.",
                failed.join(", "),
            ),
            models: all_unserved,
            at: chrono::Utc::now(),
        }
    } else if !failed.is_empty() && is_multimodal_weight_map_failure(last_err.as_deref()) {
        // A merged / multimodal checkpoint whose weights are nested under
        // `language_model.*` (e.g. some Gemma multimodal exports) that the
        // runtime can't key-map onto its module tree. Distinct from the
        // vision_config failure above: there the image config was rejected;
        // here the weight NAMES don't line up. Either way "not in MLX format"
        // would be wrong — the weights ARE MLX, just laid out for a
        // multimodal model the text runtime can't load.
        tracing::warn!(
            models = ?failed,
            last_error = %last_err.as_deref().unwrap_or("(none captured)"),
            "multimodal checkpoint weights could not be mapped; serving stub only"
        );
        EngineFault {
            code: "model-multimodal-incompatible".to_string(),
            message: format!(
                "The model(s) [{}] couldn't load: this looks like a merged or \
                 multimodal checkpoint whose weights are nested (e.g. under \
                 `language_model.*`), which the runtime can't map onto a text model. \
                 The weights are MLX, but they're laid out for a multimodal model that \
                 can't be served as plain text. The machine is online but only serving \
                 the no-op `stub` engine. Fix: pick a standard MLX text model — e.g. \
                 `mlx-community/Qwen2.5-7B-Instruct-4bit` — or a standard MLX vision \
                 model, then start serving again.",
                failed.join(", "),
            ),
            models: all_unserved,
            at: chrono::Utc::now(),
        }
    } else if !failed.is_empty() && is_weight_download_incomplete(last_err.as_deref()) {
        // The weights never finished downloading — the readiness watchdog
        // killed a stalled/throttled download, or the engine logged HF
        // throttling (unauthenticated 429s). The generic "not MLX format"
        // message below would be actively wrong (the model id is fine; the
        // bytes just never landed) and sends the operator down the wrong path
        // verifying model packaging instead of the download. See issue #117.
        tracing::warn!(
            models = ?failed,
            last_error = %last_err.as_deref().unwrap_or("(none captured)"),
            "weight download did not complete (stalled/throttled/killed); serving stub only"
        );
        EngineFault {
            code: "model-download-incomplete".to_string(),
            message: format!(
                "The weight download for [{}] was throttled or killed before it \
                 finished, so the engine never came online — the model id and format \
                 are fine; the bytes never landed. The machine is online but only \
                 serving the no-op `stub` engine, so it won't be matched to real \
                 inference jobs. Most common cause: HuggingFace rate-limited an \
                 unauthenticated download. Fix: set a HuggingFace token before serving \
                 (export `HF_TOKEN=hf_...`, or `COCORE_HF_TOKEN`), ensure the machine \
                 can reach huggingface.co, then start serving again. The download \
                 resumes from where it left off, so retrying after authenticating \
                 usually succeeds.",
                failed.join(", "),
            ),
            models: all_unserved,
            at: chrono::Utc::now(),
        }
    } else if !failed.is_empty() {
        tracing::warn!(
            models = ?failed,
            attempts = ENGINE_START_MAX_ATTEMPTS,
            last_error = %last_err.as_deref().unwrap_or("(none captured)"),
            "giving up on inference engine load after exhausting recovery attempts; serving stub only"
        );
        EngineFault {
            code: "model-load-failed".to_string(),
            message: format!(
                "The inference engine for [{}] did not come online after {} attempts. \
                 The machine is online but only serving the no-op `stub` engine, so it \
                 won't be matched to real inference jobs. Most common cause: the model \
                 isn't in MLX format — cocore runs MLX weights (anything under \
                 `mlx-community/...`, or any repo carrying MLX 4-bit weights). A stock \
                 PyTorch / safetensors repo (e.g. `meta-llama/...`) will NOT load; look \
                 for an MLX conversion of it instead. Other causes: the model id is wrong \
                 or not on Hugging Face, the weight download failed, or the machine ran \
                 out of memory loading it. Fix: use an MLX-format model id, ensure the \
                 machine can reach Hugging Face, then start serving again. If it keeps \
                 failing, DM @cocore.dev on Bluesky with your machine label and we'll help.",
                failed.join(", "),
                ENGINE_START_MAX_ATTEMPTS,
            ),
            models: all_unserved,
            at: chrono::Utc::now(),
        }
    } else {
        // Only RAM-floor skips — nothing actually tried to load.
        tracing::warn!(
            models = ?too_large,
            ram_gb,
            "configured model(s) need more RAM than this machine has; serving stub only"
        );
        EngineFault {
            code: "model-too-large".to_string(),
            message: format!(
                "The configured model(s) [{}] need more memory than this machine's {}GB \
                 of RAM, so they were not loaded. The machine is online but only serving \
                 the no-op `stub` engine, so it won't be matched to real inference jobs. \
                 Fix: pick a smaller model that fits this machine (the model picker only \
                 offers models that fit), or run cocore on a machine with more RAM. If you \
                 know this model fits, set COCORE_IGNORE_RAM_FLOOR=1 and start serving again.",
                too_large.join(", "),
                ram_gb,
            ),
            models: all_unserved,
            at: chrono::Utc::now(),
        }
    };

    (registry, Some(fault), tool_call_models)
}

/// How a single model's load ultimately failed, after recovery.
enum EngineStartFailure {
    /// The venv interpreter never appeared across all attempts.
    VenvMissing,
    /// The subprocess was spawned but never became ready. Carries the
    /// last attempt's content-safe error string for local logging.
    Failed(String),
}

/// Max attempts to bring one model's inference subprocess online before
/// giving up. Each attempt itself allows a full cold weight download
/// (the subprocess `start()` has its own multi-minute readiness
/// ceiling), so 3 attempts covers "the installer was still provisioning
/// the venv" and "the first cold download hiccuped" without blocking
/// provisioning indefinitely.
const ENGINE_START_MAX_ATTEMPTS: u32 = 3;

/// Base backoff between attempts; scaled by the attempt number so we
/// wait a little longer each time for a concurrent venv install / weight
/// download to make progress.
const ENGINE_START_BACKOFF: std::time::Duration = std::time::Duration::from_secs(8);

/// Whether an engine-start error is the "this VLM's image config is broken"
/// failure — the multimodal loader (mlx_vlm) choking on an incomplete
/// `vision_config`. Detected from the captured subprocess stderr, which the
/// startup bail embeds verbatim. Drives a precise operator message instead of
/// the generic "not in MLX format" one (which is wrong: the weights ARE MLX).
fn is_vision_config_failure(last_err: Option<&str>) -> bool {
    let Some(e) = last_err else { return false };
    // `VisionConfig` is the mlx_vlm class in the traceback; `vision_config` is
    // the config key it failed to build. Either is a strong, content-safe
    // signal (the ring buffer carries only library tracebacks at startup).
    e.contains("VisionConfig") || e.contains("vision_config")
}

/// Whether an engine-start error is the "the local socket path is too long"
/// failure — the OS rejecting an AF_UNIX `bind()` whose path exceeds the
/// `sun_path` limit. Current builds budget the path so this can't happen
/// (engines/subprocess.rs `socket_filename`), but an older binary on a long
/// $HOME still hits it; classifying it gives a precise message instead of the
/// wrong "not in MLX format" one. Content-safe (OS error text only).
fn is_socket_path_too_long(last_err: Option<&str>) -> bool {
    let Some(e) = last_err else { return false };
    e.contains("ENAMETOOLONG")
        || e.contains("path too long")
        || (e.contains("AF_UNIX") && e.contains("too long"))
}

/// Whether an engine-start error is the "multimodal checkpoint weights can't be
/// mapped" failure — a merged/multimodal export whose tensors are nested under
/// `language_model.*` (or similar) that the text runtime can't key onto its
/// module tree. Distinct from [`is_vision_config_failure`]: here the weight
/// NAMES don't line up rather than the image config being rejected.
/// Content-safe (library traceback text only).
fn is_multimodal_weight_map_failure(last_err: Option<&str>) -> bool {
    let Some(e) = last_err else { return false };
    e.contains("language_model.")
        || (e.contains("Missing key") && e.contains("language_model."))
        || (e.contains("KeyError") && e.contains("language_model."))
}

/// Whether an engine-start error is the "the weight download never finished"
/// failure — the readiness watchdog SIGKILLing a stalled/throttled download, or
/// the engine logging HuggingFace throttling (unauthenticated 429s) before being
/// killed. Detected from the watchdog's own bail text ("made no progress …",
/// "never became ready") and the throttle signals the child writes to stderr.
/// Drives a precise "download was throttled/killed" message instead of the
/// generic "not MLX format" one, which is wrong here — the weights ARE the right
/// format; the bytes just never landed. Content-safe (watchdog + library
/// traceback text only). See issue #117.
fn is_weight_download_incomplete(last_err: Option<&str>) -> bool {
    let Some(e) = last_err else { return false };
    e.contains("made no progress for")
        || e.contains("never became ready")
        || e.contains("unauthenticated requests to the HF Hub")
        || e.contains("Too Many Requests")
}

/// Try to start one model's inference subprocess, retrying transient
/// failures with backoff. Re-checks for the venv interpreter on every
/// attempt because the install script may still be provisioning it when
/// `serve` first runs.
fn start_engine_with_recovery(
    model: &str,
    venv_python: &std::path::Path,
    tool_config: cocore_provider::engines::subprocess::VllmToolConfig,
) -> std::result::Result<cocore_provider::engines::subprocess::SubprocessEngine, EngineStartFailure>
{
    use cocore_provider::engines::subprocess::SubprocessEngine;
    let mut last_err: Option<String> = None;
    for attempt in 1..=ENGINE_START_MAX_ATTEMPTS {
        if !venv_python.exists() {
            last_err = Some(format!("venv python missing at {}", venv_python.display()));
            tracing::warn!(
                model = %model,
                attempt,
                python = %venv_python.display(),
                "venv python missing; the installer may still be provisioning it — will retry after backoff"
            );
        } else {
            match SubprocessEngine::new(model, venv_python.to_path_buf(), tool_config.clone()) {
                Ok(engine) => match engine.start() {
                    Ok(()) => return Ok(engine),
                    Err(e) => {
                        let err = format!("{e:#}");
                        tracing::warn!(model = %model, attempt, error = %err, "inference subprocess failed to start; will retry");
                        last_err = Some(err);
                    }
                },
                Err(e) => {
                    let err = format!("{e:#}");
                    tracing::warn!(model = %model, attempt, error = %err, "could not construct subprocess engine; will retry");
                    last_err = Some(err);
                }
            }
        }
        if attempt < ENGINE_START_MAX_ATTEMPTS {
            let backoff = ENGINE_START_BACKOFF * attempt;
            tracing::info!(
                model = %model,
                attempt,
                backoff_s = backoff.as_secs(),
                "retrying inference engine load after backoff"
            );
            std::thread::sleep(backoff);
        }
    }
    if !venv_python.exists() {
        Err(EngineStartFailure::VenvMissing)
    } else {
        Err(EngineStartFailure::Failed(
            last_err.unwrap_or_else(|| "unknown error".to_string()),
        ))
    }
}

fn cmd_whoami() -> Result<()> {
    match oauth::load_session()? {
        Some(s) => {
            println!("did:    {}", s.did);
            println!("handle: {}", s.handle);
            println!("api:    {}", s.api_base);
        }
        None => println!("not paired; run `cocore agent pair`"),
    }
    Ok(())
}

/// `cocore agent pubkey`: print the base64 receipt-signing public key. Loads
/// (or creates) the Secure Enclave identity, same as the serve loop, so the
/// printed key matches what attestations publish.
fn cmd_pubkey() -> Result<()> {
    let signer = secure_enclave::load_or_create_identity()?;
    println!("{}", signer.public_key_b64());
    Ok(())
}

#[cfg(test)]
mod inference_models_action_tests {
    use super::*;

    fn v(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn confidential_always_clears_regardless_of_desired() {
        // Native-only: even with owner-selected models (or an injected env), a
        // confidential serve must never run the subprocess engine.
        assert_eq!(
            inference_models_action(true, &[]),
            InferenceModelsAction::Clear
        );
        assert_eq!(
            inference_models_action(true, &v(&["mlx-community/Qwen3.5-0.8B-MLX-4bit"])),
            InferenceModelsAction::Clear
        );
        assert_eq!(
            inference_models_action(true, &v(&["a", "b"])),
            InferenceModelsAction::Clear
        );
    }

    #[test]
    fn best_effort_sets_desired_or_leaves_default() {
        // Owner picked models → set them (joined CSV, order preserved).
        assert_eq!(
            inference_models_action(false, &v(&["a", "b"])),
            InferenceModelsAction::Set("a,b".to_string())
        );
        // No console selection → leave whatever the env/default provides.
        assert_eq!(
            inference_models_action(false, &[]),
            InferenceModelsAction::Leave
        );
    }

    const DEFAULT: &str = "mlx-community/Qwen2.5-0.5B-Instruct-4bit";

    #[test]
    fn confidential_native_prefers_pds_desired_models() {
        // The website picker (PDS `desiredModels`) wins, even when the tray
        // plist also set something. First non-`stub` entry, order preserved.
        assert_eq!(
            pick_confidential_native_model(
                &v(&["stub", "mlx-community/gemma-3-4b-it-qat-4bit"]),
                Some("mlx-community/Qwen2.5-7B-Instruct-4bit"),
                DEFAULT,
            ),
            "mlx-community/gemma-3-4b-it-qat-4bit"
        );
    }

    #[test]
    fn confidential_native_falls_back_to_tray_plist_env() {
        // The common case: configured from the tray, which sets the plist's
        // `COCORE_INFERENCE_MODELS` and never writes `desiredModels`. Without
        // this fallback the machine ignored the owner's pick (the bug).
        assert_eq!(
            pick_confidential_native_model(
                &[],
                Some("mlx-community/gemma-3-4b-it-qat-4bit,stub"),
                DEFAULT,
            ),
            "mlx-community/gemma-3-4b-it-qat-4bit"
        );
        // `stub` is never a servable native pick — skip it in the env list too.
        assert_eq!(
            pick_confidential_native_model(
                &v(&["stub"]),
                Some("stub , mlx-community/gemma-3-4b-it-qat-4bit"),
                DEFAULT,
            ),
            "mlx-community/gemma-3-4b-it-qat-4bit"
        );
    }

    #[test]
    fn confidential_native_defaults_when_no_owner_choice() {
        // Neither source has a servable model → the small default.
        assert_eq!(pick_confidential_native_model(&[], None, DEFAULT), DEFAULT);
        assert_eq!(
            pick_confidential_native_model(&v(&["stub"]), Some("stub"), DEFAULT),
            DEFAULT
        );
        assert_eq!(
            pick_confidential_native_model(&[], Some(""), DEFAULT),
            DEFAULT
        );
    }
}

#[cfg(test)]
mod apply_desired_tier_tests {
    use super::*;

    #[test]
    fn enabling_sets_field_and_reports_change() {
        let mut v = serde_json::json!({ "machineLabel": "Mac" });
        assert!(apply_desired_tier(&mut v, true));
        assert_eq!(v["desiredTier"], serde_json::json!("attested-confidential"));
        // Idempotent: already on → no change.
        assert!(!apply_desired_tier(&mut v, true));
    }

    #[test]
    fn disabling_removes_field_and_reports_change() {
        let mut v = serde_json::json!({ "desiredTier": "attested-confidential", "x": 1 });
        assert!(apply_desired_tier(&mut v, false));
        assert!(v.get("desiredTier").is_none());
        assert_eq!(v["x"], serde_json::json!(1)); // other fields preserved
                                                  // Idempotent: already off (absent) → no change.
        assert!(!apply_desired_tier(&mut v, false));
    }

    #[test]
    fn absent_field_is_best_effort() {
        let mut v = serde_json::json!({});
        assert!(!apply_desired_tier(&mut v, false)); // absent == off already
        assert!(apply_desired_tier(&mut v, true)); // off -> on
    }
}

#[cfg(test)]
mod vision_fault_tests {
    use super::is_vision_config_failure;

    #[test]
    fn detects_mlx_vlm_visionconfig_failure() {
        let err = "inference subprocess for X exited during startup with exit status: 1\n  [stderr] TypeError: VisionConfig.__init__() missing 6 required positional arguments";
        assert!(is_vision_config_failure(Some(err)));
    }

    #[test]
    fn detects_vision_config_key_failure() {
        assert!(is_vision_config_failure(Some("KeyError: 'vision_config'")));
    }

    #[test]
    fn ignores_unrelated_failures_and_none() {
        assert!(!is_vision_config_failure(Some(
            "OSError: out of memory loading weights"
        )));
        assert!(!is_vision_config_failure(Some(
            "ModuleNotFoundError: vllm_mlx"
        )));
        assert!(!is_vision_config_failure(None));
    }

    use super::{is_multimodal_weight_map_failure, is_socket_path_too_long};

    #[test]
    fn detects_socket_path_too_long() {
        assert!(is_socket_path_too_long(Some(
            "OSError: AF_UNIX path too long"
        )));
        assert!(is_socket_path_too_long(Some(
            "[stderr] bind: [Errno 63] ENAMETOOLONG"
        )));
        assert!(!is_socket_path_too_long(Some("KeyError: 'vision_config'")));
        assert!(!is_socket_path_too_long(None));
    }

    #[test]
    fn detects_multimodal_weight_map_failure() {
        assert!(is_multimodal_weight_map_failure(Some(
            "ValueError: could not map weights: language_model.layers.0.self_attn.q_proj"
        )));
        assert!(is_multimodal_weight_map_failure(Some(
            "Missing key in checkpoint: language_model.embed_tokens.weight"
        )));
        // A text model with a corrupted/version-mismatched checkpoint produces
        // a bare `Missing key … model.…` (no `language_model.`): this must NOT
        // be classified as multimodal, or the user gets the wrong remediation.
        assert!(!is_multimodal_weight_map_failure(Some(
            "Missing key in checkpoint: model.layers.0.self_attn.q_proj.weight"
        )));
        assert!(!is_multimodal_weight_map_failure(Some(
            "OSError: out of memory loading weights"
        )));
        assert!(!is_multimodal_weight_map_failure(None));
    }

    /// A vision_config failure must be classified by the vision branch, not
    /// the multimodal-weight-map one — the fault chain checks vision first,
    /// and these stderrs don't overlap.
    #[test]
    fn vision_config_not_misread_as_weight_map() {
        let err = "TypeError: VisionConfig.__init__() missing 6 required positional arguments";
        assert!(is_vision_config_failure(Some(err)));
        assert!(!is_multimodal_weight_map_failure(Some(err)));
    }

    use super::is_weight_download_incomplete;

    #[test]
    fn detects_watchdog_no_progress_kill() {
        // The exact bail text the readiness watchdog emits when it SIGKILLs a
        // stalled/throttled download (subprocess.rs).
        let err = "inference subprocess for mlx-community/Qwen3.5-4B-MLX-4bit made no progress for 300s (26 MB downloaded so far) and never became ready.";
        assert!(is_weight_download_incomplete(Some(err)));
    }

    #[test]
    fn detects_hf_throttle_signals() {
        assert!(is_weight_download_incomplete(Some(
            "Warning: You are sending unauthenticated requests to the HF Hub. Please set a HF_TOKEN"
        )));
        assert!(is_weight_download_incomplete(Some(
            "[stderr] HTTP Error 429: Too Many Requests"
        )));
    }

    #[test]
    fn download_incomplete_ignores_unrelated_and_none() {
        // A real not-MLX / OOM / import failure must NOT be misclassified as a
        // download problem, or the operator gets the wrong remediation.
        assert!(!is_weight_download_incomplete(Some(
            "OSError: out of memory loading weights"
        )));
        assert!(!is_weight_download_incomplete(Some(
            "TypeError: VisionConfig.__init__() missing 6 required positional arguments"
        )));
        assert!(!is_weight_download_incomplete(None));
    }
}

#[cfg(test)]
mod active_gate_tests {
    use super::*;

    #[test]
    fn confirmed_active_serves_and_confirmed_pause_waits() {
        let mut paused = false;
        assert_eq!(
            active_gate_decision(Some(true), &mut paused),
            ActiveGate::Serve
        );
        assert!(!paused);
        assert_eq!(
            active_gate_decision(Some(false), &mut paused),
            ActiveGate::Wait
        );
        assert!(paused, "a confirmed pause latches");
    }

    #[test]
    fn a_read_blip_after_a_confirmed_pause_stays_paused() {
        // The regression: owner pauses (Some(false)); then the next read blips
        // (None). The machine must STAY paused — a blip can't un-pause it.
        let mut paused = false;
        assert_eq!(
            active_gate_decision(Some(false), &mut paused),
            ActiveGate::Wait
        );
        assert_eq!(
            active_gate_decision(None, &mut paused),
            ActiveGate::Wait,
            "an unresolved read must never un-pause a confirmed-paused machine"
        );
        // …and once the owner resumes (Some(true)), it serves.
        assert_eq!(
            active_gate_decision(Some(true), &mut paused),
            ActiveGate::Serve
        );
    }

    #[test]
    fn a_read_blip_with_no_prior_pause_serves_optimistically() {
        // A PDS outage at startup (never confirmed a pause) must not strand a
        // healthy machine offline — serve, and let the advisor's control poll
        // catch a pause if there is one.
        let mut paused = false;
        assert_eq!(active_gate_decision(None, &mut paused), ActiveGate::Serve);
        assert!(!paused);
    }
}

#[cfg(test)]
mod offline_marker_tests {
    use super::*;
    use cocore_provider::pds::{ProviderRecord, TrustLevel};

    /// A provider record as the AGENT builds it in-memory: the
    /// console-authored switches are all `None` (the agent never authors
    /// them). This is exactly what the shutdown offline marker clones.
    fn agent_built_record() -> ProviderRecord {
        ProviderRecord {
            machineLabel: "Mac Mini".into(),
            chip: "Apple M1".into(),
            ramGB: 8,
            gpuCores: Some(8),
            memoryBandwidthGBs: Some(68),
            cpuCores: Some(8),
            pCores: Some(4),
            eCores: Some(4),
            modelIdentifier: Some("Macmini9,1".into()),
            os: Some("macOS 26.4.1".into()),
            supportedModels: vec!["stub".into()],
            priceList: vec![],
            encryptionPubKey: "enc".into(),
            attestationPubKey: "att".into(),
            trustLevel: TrustLevel::SelfAttested,
            tier: None,
            acceptedExchanges: vec![],
            contactEndpoint: None,
            binaryVersion: Some("0.9.13".into()),
            payoutsEnabled: None,
            active: None,
            desiredModels: None,
            desiredTier: None,
            proBono: None,
            shareLocation: None,
            provisioning: Some(false),
            serving: Some(true),
            engineFault: None,
            attestationFault: None,
            region: None,
            regionSource: None,
            regionObservedAt: None,
            createdAt: chrono::Utc::now(),
        }
    }

    use cocore_provider::pds::merge_agent_provider_fields;

    /// The regression: a machine the owner just PAUSED (`active=false` on the
    /// live PDS record) must stay paused after the agent writes its shutdown
    /// offline marker. The marker is the agent-built record (`active=None`);
    /// merging it onto the live record must keep the live `active=false`.
    #[test]
    fn offline_marker_keeps_a_paused_machine_paused() {
        let mut offline = agent_built_record();
        offline.serving = Some(false);
        let live = serde_json::json!({ "active": false, "serving": true });

        let merged = merge_agent_provider_fields(&live, &offline);

        assert_eq!(
            merged.get("active"),
            Some(&serde_json::json!(false)),
            "pause preserved"
        );
        assert_eq!(
            merged.get("serving"),
            Some(&serde_json::json!(false)),
            "agent serving=false applied"
        );
    }

    /// The reverse must also hold: quitting a SERVING machine must not
    /// accidentally pause it. `active=true` on the live record is preserved.
    #[test]
    fn offline_marker_keeps_a_serving_machine_serving() {
        let mut offline = agent_built_record();
        offline.serving = Some(false);
        let live = serde_json::json!({ "active": true });

        let merged = merge_agent_provider_fields(&live, &offline);

        assert_eq!(merged.get("active"), Some(&serde_json::json!(true)));
    }

    /// Every owner-intent field on the live record rides through an agent
    /// re-publish untouched — the agent never authors them, so the merge keeps
    /// the live values verbatim.
    #[test]
    fn merge_preserves_all_owner_intent_fields() {
        let offline = agent_built_record();
        let live = serde_json::json!({
            "active": false,
            "payoutsEnabled": true,
            "desiredModels": ["mlx-community/Qwen2.5-3B-Instruct-4bit", "stub"],
            "desiredTier": "attested-confidential",
            "proBono": { "mode": "direct", "dids": ["did:plc:friend"] },
            "shareLocation": true
        });

        let merged = merge_agent_provider_fields(&live, &offline);

        assert_eq!(merged.get("active"), Some(&serde_json::json!(false)));
        assert_eq!(merged.get("payoutsEnabled"), Some(&serde_json::json!(true)));
        assert_eq!(
            merged.get("desiredModels"),
            Some(&serde_json::json!([
                "mlx-community/Qwen2.5-3B-Instruct-4bit",
                "stub"
            ]))
        );
        assert_eq!(
            merged.get("desiredTier"),
            Some(&serde_json::json!("attested-confidential"))
        );
        assert_eq!(
            merged.get("proBono"),
            Some(&serde_json::json!({ "mode": "direct", "dids": ["did:plc:friend"] }))
        );
        assert_eq!(merged.get("shareLocation"), Some(&serde_json::json!(true)));
    }

    /// THE property that kills the whole bug class: a field this agent build has
    /// never heard of (a future owner setting) is preserved by default. The old
    /// allowlist would have dropped it.
    #[test]
    fn merge_preserves_an_unknown_future_field() {
        let offline = agent_built_record();
        let live = serde_json::json!({
            "active": true,
            "someFutureOwnerToggle": { "nested": [1, 2, 3] }
        });

        let merged = merge_agent_provider_fields(&live, &offline);

        assert_eq!(
            merged.get("someFutureOwnerToggle"),
            Some(&serde_json::json!({ "nested": [1, 2, 3] })),
            "an unknown field must survive an agent re-publish"
        );
    }

    /// The agent OWNS its fields: it overwrites present ones and CLEARS the
    /// optional ones it no longer emits (a stale tier / engineFault / region).
    #[test]
    fn merge_overwrites_agent_fields_and_clears_absent_ones() {
        let mut rebuilt = agent_built_record();
        rebuilt.supportedModels =
            vec!["mlx-community/gemma-3-4b-it-qat-4bit".into(), "stub".into()];
        // Healthy this serve: no fault, not confidential, not sharing location.
        rebuilt.engineFault = None;
        rebuilt.tier = None;
        rebuilt.region = None;
        let live = serde_json::json!({
            "supportedModels": ["old-model"],
            "engineFault": { "code": "stale", "message": "old", "models": [], "at": "2020-01-01T00:00:00Z" },
            "tier": "attested-confidential",
            "region": "US",
            "active": true
        });

        let merged = merge_agent_provider_fields(&live, &rebuilt);

        // Always-present agent field overwritten.
        assert_eq!(
            merged.get("supportedModels"),
            Some(&serde_json::json!([
                "mlx-community/gemma-3-4b-it-qat-4bit",
                "stub"
            ]))
        );
        // Stale agent-authored optional fields cleared.
        assert_eq!(merged.get("engineFault"), None, "cleared fault");
        assert_eq!(merged.get("tier"), None, "cleared achieved tier");
        assert_eq!(merged.get("region"), None, "cleared region");
        // Owner field still preserved.
        assert_eq!(merged.get("active"), Some(&serde_json::json!(true)));
    }

    /// Defence in depth: even if a bug populated an owner-intent field on the
    /// agent record, the merge must NOT write it — the live value wins.
    #[test]
    fn merge_never_lets_the_agent_write_an_owner_field() {
        let mut rebuilt = agent_built_record();
        rebuilt.active = Some(true); // agent erroneously authoring an owner field
        rebuilt.desiredModels = Some(vec!["agent-should-not-set-this".into()]);
        let live = serde_json::json!({ "active": false, "desiredModels": ["owner-choice"] });

        let merged = merge_agent_provider_fields(&live, &rebuilt);

        assert_eq!(
            merged.get("active"),
            Some(&serde_json::json!(false)),
            "owner value wins"
        );
        assert_eq!(
            merged.get("desiredModels"),
            Some(&serde_json::json!(["owner-choice"])),
            "agent can never overwrite the owner's model pick"
        );
    }

    /// First publish (empty base): the agent authors everything; owner-intent
    /// fields are simply absent, which is correct for a brand-new machine.
    #[test]
    fn merge_onto_empty_base_yields_agent_fields_only() {
        let rebuilt = agent_built_record();
        let merged = merge_agent_provider_fields(&serde_json::json!({}), &rebuilt);

        assert_eq!(merged.get("chip"), Some(&serde_json::json!("Apple M1")));
        assert_eq!(
            merged.get("supportedModels"),
            Some(&serde_json::json!(["stub"]))
        );
        assert_eq!(merged.get("active"), None);
        assert_eq!(merged.get("desiredModels"), None);
    }
}
