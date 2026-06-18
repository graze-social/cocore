use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use cocore_provider::{
    advisor::AdvisorClient,
    attestation, oauth,
    pds::{EngineFault, ModelPrice, PdsClient, ProviderRecord, TrustLevel},
    pricing,
    protocol::Register,
    receipt::StrongRef,
    secure_enclave, security, system_profile,
};

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
        #[arg(
            long,
            env = "COCORE_CONSOLE",
            default_value = "https://console.cocore.dev"
        )]
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
        #[arg(
            long,
            env = "COCORE_CONSOLE",
            default_value = "https://console.cocore.dev"
        )]
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
        #[arg(
            long,
            env = "COCORE_CONSOLE",
            default_value = "https://console.cocore.dev"
        )]
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
        Cmd::Agent(AgentCmd::Serve { advisor }) => cmd_serve(&advisor).await,
        Cmd::Agent(AgentCmd::Whoami) => cmd_whoami(),
        Cmd::Agent(AgentCmd::Doctor { console, fix }) => doctor::run(&console, fix).await,
        Cmd::Agent(AgentCmd::Update { console, check }) => update::run(&console, check).await,
        Cmd::Agent(AgentCmd::Models(cmd)) => models_cli::run(cmd),
        Cmd::Agent(AgentCmd::Pause) => cmd_set_active(false).await,
        Cmd::Agent(AgentCmd::Resume) => cmd_set_active(true).await,
        Cmd::Agent(AgentCmd::Active) => cmd_print_active().await,
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
        let (rkey, mut value, cid) = find_my_provider_record(&pds, &pubkey).await?;
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

/// True when a PDS error is an `InvalidSwap` compare-and-swap conflict — the
/// record's CID changed between our read and write, so a retry against the
/// fresh CID is the correct response.
fn is_swap_conflict(e: &cocore_provider::error::ProviderError) -> bool {
    matches!(e, cocore_provider::error::ProviderError::Pds(msg) if msg.contains("InvalidSwap"))
}

/// `cocore agent active`: print `serving` or `paused` from the shared switch.
async fn cmd_print_active() -> Result<()> {
    let (pds, pubkey) = open_pds()?;
    let (_, value, _) = find_my_provider_record(&pds, &pubkey).await?;
    let active = value
        .get("active")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    println!("{}", if active { "serving" } else { "paused" });
    Ok(())
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
            println!("Open this URL in any browser signed into the cocore console:");
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

/// Overlay the owner/console-authored fields (`active`, `payoutsEnabled`,
/// `desiredModels`) from an existing PDS record onto a record the agent is
/// about to (re-)publish.
///
/// The agent NEVER authors these — the console writes them (the start/stop
/// switch, Stripe-Connect payouts eligibility, the model picker). They are
/// all `#[serde(skip_serializing_if = "Option::is_none")]`, and the agent
/// builds its in-memory record with them as `None`, so any write that doesn't
/// carry them forward OMITS them from the record. That's silently destructive:
/// an absent `active` reads back as the default `true`, so a write that drops
/// it UN-PAUSES a machine the owner just paused. Both the startup dedup
/// re-publish and the graceful-shutdown offline marker funnel through here so
/// neither can clobber the switches.
fn preserve_console_fields(record: &mut ProviderRecord, existing: &serde_json::Value) {
    record.active = existing.get("active").and_then(|v| v.as_bool());
    record.payoutsEnabled = existing.get("payoutsEnabled").and_then(|v| v.as_bool());
    record.desiredModels = existing
        .get("desiredModels")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|m| m.as_str().map(str::to_string))
                .collect::<Vec<_>>()
        });
}

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
    let collection = "dev.cocore.compute.provider";
    let listed = pds.list_my_records(collection).await?;
    // Group by attestationPubKey; keep records that match ours.
    // Each matching tuple carries the existing record's body so we
    // can preserve fields the agent doesn't manage (notably
    // `payoutsEnabled`, set by the console's Stripe-Connect reconcile)
    // when we re-publish on startup.
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
            Some(_) => {
                other_pubkey_count += 1;
            }
            None => {
                // No attestationPubKey — pre-2026-05 record from before
                // the field was required; leave alone.
            }
        }
    }
    if other_pubkey_count > 0 {
        tracing::info!(
            other_pubkey_count,
            "saw provider records on this DID with a different attestationPubKey — those describe other machines; leaving alone"
        );
    }
    // Sort newest-first by createdAt; the head wins.
    matching.sort_by(|a, b| b.2.cmp(&a.2));
    let mut kept_existing = false;
    let mut deleted = 0usize;
    let chosen_rkey = if let Some((rkey, _, _, _)) = matching.first() {
        kept_existing = true;
        // Delete losers.
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
                    // Non-fatal: surface and move on. The dedup is
                    // best-effort; partial cleanup is better than
                    // none, and the user can re-run on next serve.
                    tracing::warn!(error = %e, rkey = %loser_rkey, "failed to delete duplicate provider record");
                }
            }
        }
        Some(rkey.clone())
    } else {
        None
    };

    let published = match chosen_rkey {
        Some(rkey) => {
            // Refresh the swapRecord (CID) right before the put — the
            // delete loop above might've changed nothing, but a
            // future caller could have written between our list and
            // our put. Re-getRecord is overkill; pass the CID we saw
            // at list time. If a swap conflict happens, the user
            // re-running serve will re-list and recover.
            let (swap, existing_value) = matching
                .first()
                .map(|(_, cid, _, val)| (cid.clone(), val.clone()))
                .unwrap_or_default();
            // Preserve the owner/console-authored switches from the kept
            // record (see `preserve_console_fields`): the agent never authors
            // them, and re-publishing without them resets the DID's
            // payouts-eligibility and restarts a machine the owner stopped.
            let mut merged = record.clone();
            preserve_console_fields(&mut merged, &existing_value);
            pds.put_provider(
                &rkey,
                &merged,
                if swap.is_empty() { None } else { Some(&swap) },
            )
            .await?
        }
        None => pds.publish_provider(record).await?,
    };
    Ok((published, kept_existing, deleted))
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
async fn wait_until_active(pds: &cocore_provider::pds::PdsClient, rkey: Option<&str>) {
    let Some(rk) = rkey else {
        clear_serving_paused();
        return;
    };
    let mut announced = false;
    loop {
        if pds.get_provider_active(rk).await.unwrap_or(true) {
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

async fn cmd_serve(advisor_url: &str) -> Result<()> {
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
    let signer = secure_enclave::load_or_create_identity()?;

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
            trustLevel: TrustLevel::SelfAttested,
            acceptedExchanges: vec![],
            contactEndpoint: None,
            binaryVersion: Some(env!("CARGO_PKG_VERSION").to_string()),
            payoutsEnabled: None,
            // Preserved from the existing record by dedup, like payoutsEnabled.
            active: None,
            desiredModels: None,
            provisioning: Some(true),
            // NOT serving yet: this record is published immediately (so the
            // machine is visible) while the engine is still loading/downloading.
            // Claiming `serving: true` here is a lie — it makes the console +
            // tray say "serving and earning" before any model is loaded. The
            // real record below flips this to true once engines are up.
            serving: Some(false),
            engineFault: None,
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
    let desired_at_start: Vec<String> =
        match find_my_provider_record(&pds, &attestation_pub_key).await {
            Ok((_, value, _)) => value
                .get("desiredModels")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|m| m.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default(),
            Err(_) => Vec::new(),
        };
    if !desired_at_start.is_empty() {
        tracing::info!(models = ?desired_at_start, "loading owner-selected models from the console");
        std::env::set_var("COCORE_INFERENCE_MODELS", desired_at_start.join(","));
    }

    let (engines, engine_fault) = build_engines(profile.ram_gb);
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
        trustLevel: TrustLevel::SelfAttested,
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

    // Publish a fresh self-attested attestation so receipts emitted
    // during this `serve` lifetime have a real strong-ref. If the
    // PDS publish fails (network, auth, schema), continue with no
    // attestation: the InferenceRequest stub still answers; receipts
    // just won't be published.
    //
    // If COCORE_MDA_CERT_CHAIN_PATH or COCORE_MDA_ATTEST_BINARY is
    // set and resolves to a valid PEM chain, the resulting record
    // carries `mdaCertChain` and the AppView's verifier promotes
    // receipts to `trustLevel: hardware-attested`. Failure here
    // returns an empty chain (NOT an error) — see the loader's
    // module doc for the rationale.
    let mut attestation_inputs =
        attestation::build_stub_inputs(&session.did, &enc.public_key_b64());
    attestation_inputs.mda_cert_chain = cocore_provider::mda_loader::try_load();
    let attestation_ref: Option<StrongRef> = match attestation::build(attestation_inputs, &*signer)
    {
        Ok(record) => match pds.publish_attestation(&record).await {
            Ok(published) => {
                tracing::info!(uri = %published.uri, "published attestation");
                Some(StrongRef {
                    uri: published.uri,
                    cid: published.cid,
                })
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to publish attestation; receipts disabled");
                None
            }
        },
        Err(e) => {
            tracing::warn!(error = %e, "failed to build attestation; receipts disabled");
            None
        }
    };

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
        attestation_uri: attestation_ref
            .as_ref()
            .map(|r| r.uri.clone())
            .unwrap_or_default(),
        // Tell the advisor (live, in addition to the PDS record) when the
        // engine failed to load, so the central matchmaker can note a
        // degraded machine instead of just seeing a short supportedModels.
        engine_fault: provider_record.engineFault.clone(),
    };
    let attestation = attestation_ref.as_ref();

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
                            attestation,
                            &engines,
                            provider_rkey.as_deref(),
                            &desired_at_start,
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
                                let (eng, _fault) = build_engines(provider_record.ramGB);
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
                            res = client.run(register.clone(), &*signer, &enc, &pds, attestation, &eng, provider_rkey.as_deref(), &desired_at_start) => {
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
                    let (rk, value, cid) =
                        find_my_provider_record(&pds, &attestation_pub_key).await?;
                    let mut offline = provider_record.clone();
                    offline.serving = Some(false);
                    offline.provisioning = Some(false);
                    // Don't carry a stale fault into the offline marker; the
                    // machine simply stopped serving.
                    offline.engineFault = None;
                    offline.createdAt = chrono::Utc::now();
                    // Preserve the owner/console-authored switches verbatim —
                    // crucially `active`, so a machine paused moments ago stays
                    // paused instead of being un-paused by this write.
                    preserve_console_fields(&mut offline, &value);
                    pds.put_provider(&rk, &offline, Some(&cid)).await
                };
                match tokio::time::timeout(std::time::Duration::from_secs(5), publish).await {
                    Ok(Ok(published)) => tracing::info!(uri = %published.uri, "published provider record with serving=false (active/payouts/desiredModels preserved)"),
                    Ok(Err(e)) => tracing::warn!(error = %e, "failed to publish offline marker (active switch left intact)"),
                    Err(_) => tracing::warn!("offline-marker publish timed out after 5s"),
                }
            } else {
                tracing::warn!("no provider rkey captured; cannot publish offline marker");
            }
        }
    }
    Ok(())
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
) {
    use cocore_provider::engines::stub::StubEngine;
    let mut registry = cocore_provider::engines::EngineRegistry::new();
    registry.register("stub", std::sync::Arc::new(StubEngine));

    let raw = std::env::var("COCORE_INFERENCE_MODELS")
        .or_else(|_| std::env::var("COCORE_INFERENCE_MODEL"))
        .unwrap_or_default();
    if raw.trim().is_empty() {
        tracing::info!(
            "no inference models configured (set COCORE_INFERENCE_MODELS to enable real inference; this agent will serve `stub` only)"
        );
        return (registry, None);
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
        return (registry, Some(fault));
    };
    let venv_python = home.join(".cocore/python/bin/python");

    let configured: Vec<String> = raw
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

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

    let mut failed: Vec<String> = vec![];
    let mut saw_venv_missing = false;
    let mut last_err: Option<String> = None;

    for model in &configured {
        match start_engine_with_recovery(model, &venv_python) {
            Ok(engine) => {
                tracing::info!(model = %model, "inference subprocess engine ready");
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
        return (registry, None);
    }

    // The fault's `models` field lists every model that won't be served
    // this run — both the ones that tried-and-failed and the ones we
    // skipped as too large for RAM — so the console shows the operator
    // the full set that's missing from `supportedModels`.
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
                 to (re)provision the environment — `curl -fsSL https://console.cocore.dev/agent | sh` \
                 — then start serving again.",
                venv_python.display(),
                failed.join(", "),
            ),
            models: all_unserved,
            at: chrono::Utc::now(),
        }
    } else if failed.is_empty() {
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
    } else {
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
    };

    (registry, Some(fault))
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

/// Try to start one model's inference subprocess, retrying transient
/// failures with backoff. Re-checks for the venv interpreter on every
/// attempt because the install script may still be provisioning it when
/// `serve` first runs.
fn start_engine_with_recovery(
    model: &str,
    venv_python: &std::path::Path,
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
            match SubprocessEngine::new(model, venv_python.to_path_buf()) {
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
            acceptedExchanges: vec![],
            contactEndpoint: None,
            binaryVersion: Some("0.9.13".into()),
            payoutsEnabled: None,
            active: None,
            desiredModels: None,
            provisioning: Some(false),
            serving: Some(true),
            engineFault: None,
            createdAt: chrono::Utc::now(),
        }
    }

    /// The regression: a machine the owner just PAUSED (`active=false` on the
    /// live PDS record) must stay paused after the agent writes its
    /// shutdown offline marker. Before the fix the marker was the
    /// agent-built record (active=None) written blind, which omitted
    /// `active` and let it read back as the default `true` — un-pausing the
    /// machine so the tray reconciler restarted it.
    #[test]
    fn offline_marker_keeps_a_paused_machine_paused() {
        let mut offline = agent_built_record();
        offline.serving = Some(false);
        let live = serde_json::json!({ "active": false, "serving": true });

        preserve_console_fields(&mut offline, &live);

        assert_eq!(offline.active, Some(false), "pause must be preserved");
        // And it must SERIALIZE with active:false present — the whole bug was
        // the field being omitted, so an absent field reading back as `true`.
        let json = serde_json::to_value(&offline).unwrap();
        assert_eq!(json.get("active"), Some(&serde_json::json!(false)));
        assert_eq!(json.get("serving"), Some(&serde_json::json!(false)));
    }

    /// The reverse must also hold: quitting a SERVING machine must not
    /// accidentally pause it. `active=true` on the live record is preserved.
    #[test]
    fn offline_marker_keeps_a_serving_machine_serving() {
        let mut offline = agent_built_record();
        offline.serving = Some(false);
        let live = serde_json::json!({ "active": true });

        preserve_console_fields(&mut offline, &live);

        assert_eq!(offline.active, Some(true));
    }

    /// `payoutsEnabled` and `desiredModels` ride the same path and must be
    /// carried through too (regression guard for the broader clobber).
    #[test]
    fn offline_marker_preserves_payouts_and_desired_models() {
        let mut offline = agent_built_record();
        let live = serde_json::json!({
            "active": false,
            "payoutsEnabled": true,
            "desiredModels": ["mlx-community/Qwen2.5-3B-Instruct-4bit", "stub"]
        });

        preserve_console_fields(&mut offline, &live);

        assert_eq!(offline.payoutsEnabled, Some(true));
        assert_eq!(
            offline.desiredModels,
            Some(vec![
                "mlx-community/Qwen2.5-3B-Instruct-4bit".to_string(),
                "stub".to_string()
            ])
        );
    }

    /// When the live record has no switches set (a brand-new machine), the
    /// fields stay `None` — we don't fabricate values.
    #[test]
    fn offline_marker_leaves_absent_switches_absent() {
        let mut offline = agent_built_record();
        let live = serde_json::json!({ "serving": true });

        preserve_console_fields(&mut offline, &live);

        assert_eq!(offline.active, None);
        assert_eq!(offline.payoutsEnabled, None);
        assert_eq!(offline.desiredModels, None);
    }
}
