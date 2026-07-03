//! `cocore agent models` — manage the inference-model list without
//! editing the plist by hand.
//!
//! ## What this does
//!
//! Every cocore agent loads `stub` plus whatever it finds in
//! `COCORE_INFERENCE_MODELS` (comma-separated NSIDs). That env var
//! lives in `~/Library/LaunchAgents/dev.cocore.provider.plist`. This
//! module is the user-facing surface for editing it:
//!
//! * `cocore agent models list`       — print the current set.
//! * `cocore agent models set a,b,c`  — replace the set.
//! * `cocore agent models add a`      — append.
//! * `cocore agent models remove a`   — drop.
//!
//! After any mutating command we kickstart the LaunchAgent. The
//! bounced daemon re-runs `cmd_serve`, rebuilds the engine registry
//! against the new list, and publishes a fresh provider record to
//! PDS — so the AppView's mirror (and therefore the advisor's
//! eligibility filter) sees the new `supportedModels` within seconds.
//! There's no separate "tell the AppView" step; the serve startup is
//! the propagation path.
//!
//! ## Why PlistBuddy
//!
//! macOS ships `/usr/libexec/PlistBuddy` which understands the binary
//! and XML plist formats and supports nested-key writes. Adding a
//! plist crate to Cargo.toml would work too, but the agent already
//! shells out to `launchctl`, `xcode-select`, etc.; one more
//! macOS-native helper keeps the dependency surface small.
//!
//! ## Linux fallback
//!
//! On non-macOS hosts there's no LaunchAgent, so we print what we
//! *would* have done plus a one-liner about how to set the env var
//! manually under whatever supervisor the user is running.

#[cfg(target_os = "macos")]
use anyhow::Context;
use anyhow::Result;
// `Path` is referenced on macOS-only functions (read/write/delete
// env_var, report_outcomes) AND on `await_engine_load_results`,
// which is gated `cfg(any(target_os = "macos", test))`. On Linux
// in `cargo test --locked` the test build pulls in the latter, so
// the import has to be at least as permissive as the broadest
// consumer — `any(target_os = "macos", test)` covers both.
#[cfg(any(target_os = "macos", test))]
use std::path::Path;
use std::path::PathBuf;
#[cfg(target_os = "macos")]
use std::process::Command;
// `Duration` is referenced inside `#[cfg(target_os = "macos")] {}`
// blocks in `commit()`, in `await_engine_load_results`
// (cfg(any(target_os = "macos", test))), and in the tests. Linux
// non-test builds strip all three, leaving the import dead.
#[cfg(any(target_os = "macos", test))]
use std::time::Duration;

use crate::ModelsCmd;
use cocore_provider::pricing;
use cocore_provider::system_profile;

#[cfg(target_os = "macos")]
const ENV_KEY: &str = "EnvironmentVariables:COCORE_INFERENCE_MODELS";
/// Legacy singular form from v0.4.0 plists. The agent honors it as a
/// fallback (build_engines reads the plural first, falls back to the
/// singular). We read it here so `list` shows a consistent view, and
/// we delete it on `set`/`add`/`remove` so there's exactly one source
/// of truth going forward.
#[cfg(target_os = "macos")]
const LEGACY_ENV_KEY: &str = "EnvironmentVariables:COCORE_INFERENCE_MODEL";

pub async fn run(cmd: ModelsCmd) -> Result<()> {
    match cmd {
        ModelsCmd::List => list(),
        ModelsCmd::Set { models } => {
            let next = normalize(&models);
            let prev = read_current().unwrap_or_default();
            let added: Vec<String> = next.iter().filter(|m| !prev.contains(m)).cloned().collect();
            commit(&next, "set", &added).await
        }
        ModelsCmd::Add { model } => {
            // Resolve the model id: either the explicit positional or
            // an interactive pick from the catalog (filtered to this
            // machine's RAM). The picker lets a new user discover what
            // they can run without having to memorize the exact
            // HuggingFace NSID — historically the most error-prone
            // step of getting a real model serving.
            let m = match model {
                Some(s) => {
                    let trimmed = s.trim().to_string();
                    if trimmed.is_empty() {
                        anyhow::bail!("refusing to add an empty model NSID");
                    }
                    trimmed
                }
                None => prompt_for_catalog_model()?,
            };
            // Refuse before we touch the plist if this machine doesn't
            // have the venv `uv` provisions during install. Without
            // the venv, the bounced daemon's build_engines() can't
            // spawn the subprocess for this model, the model gets
            // silently dropped from supportedModels, and the user's
            // machine disappears from the model page with no error
            // anywhere. `stub` is always addable; everything else
            // needs the venv.
            check_model_addable(&m, venv_python_present())?;
            let mut current = read_current()?;
            if current.contains(&m) {
                println!("'{m}' is already in the list; no change.");
                return Ok(());
            }
            current.push(m.clone());
            commit(&current, "add", std::slice::from_ref(&m)).await
        }
        ModelsCmd::Remove { model } => {
            let m = model.trim();
            let mut current = read_current()?;
            let before = current.len();
            current.retain(|x| x != m);
            if current.len() == before {
                println!("'{m}' was not in the list; no change.");
                return Ok(());
            }
            commit(&current, "remove", &[]).await
        }
    }
}

fn list() -> Result<()> {
    let current = read_current()?;
    if current.is_empty() {
        println!(
            "No models configured (COCORE_INFERENCE_MODELS empty or unset). The agent will load only the stub engine."
        );
        return Ok(());
    }
    for m in &current {
        println!("{m}");
    }
    // Resource-budget summary — the CLI mirror of the tray meter, derived
    // from the same pricing::budget_report so the green/yellow/red verdict
    // is identical everywhere.
    let ram_gb = system_profile::collect().ram_gb;
    if ram_gb > 0 {
        let report = pricing::budget_report(&current, ram_gb);
        println!(
            "\nPinned ~{}GB · reserved for you ~{}GB · this Mac {}GB",
            report.used_gb, report.reserve_gb, report.total_gb
        );
        match report.status {
            pricing::BudgetStatus::Comfortable => {
                println!("OK: comfortable — plenty of headroom for your own apps.");
            }
            pricing::BudgetStatus::Tight => {
                println!(
                    "WARN: tight — these fit, but leave little for you; this Mac may get sluggish while you work. Drop one or stagger their hours."
                );
            }
            pricing::BudgetStatus::Oversubscribed => {
                println!(
                    "WARN: oversubscribed — the agent will drop the largest to fit at startup: {}",
                    report.dropped.join(", ")
                );
            }
        }
    }
    Ok(())
}

/// Normalize a comma-separated input: trim each piece, drop empties,
/// dedupe while preserving order.
fn normalize(raw: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for piece in raw.split(',') {
        let p = piece.trim();
        if p.is_empty() {
            continue;
        }
        let s = p.to_string();
        if !out.contains(&s) {
            out.push(s);
        }
    }
    out
}

async fn commit(models: &[String], verb: &str, await_models: &[String]) -> Result<()> {
    let joined = models.join(",");

    // Percolate the owner's model pick to the PDS source of truth FIRST, on
    // every platform: write `desiredModels` (the same field the website's model
    // picker sets) so the choice propagates to the AppView, the confidential
    // native engine, and any serving sibling that reconciles — not just the
    // local plist. On macOS this complements the plist+bounce below; on a
    // never-served machine it's a no-op (the plist carries the set until first
    // serve). A failure here is non-fatal on macOS (the local plist write still
    // drives this machine, and the next serve republish reconciles), but we
    // surface it so the user knows cross-device sync is delayed.
    let pds_wrote = match crate::cmd_set_desired_models(models.to_vec()).await {
        Ok(wrote) => wrote,
        Err(e) => {
            tracing::warn!(error = %e, "couldn't write desiredModels to PDS");
            eprintln!(
                "warning: couldn't sync your model choice to your account ({e}). \
                 Applied locally; it will sync on the next serve."
            );
            false
        }
    };

    #[cfg(target_os = "macos")]
    {
        let _ = pds_wrote;
        let plist = plist_path()?;
        write_env_var(&plist, ENV_KEY, &joined)
            .with_context(|| format!("updating {ENV_KEY} in {}", plist.display()))?;
        // Clear the legacy singular so the plist has exactly one source
        // of truth for which models the agent loads. Best-effort —
        // missing key is fine.
        let _ = delete_env_var(&plist, LEGACY_ENV_KEY);
        println!(
            "{verb}: wrote COCORE_INFERENCE_MODELS=\"{joined}\" to {}",
            plist.display()
        );

        // Pull the agent's StandardOutPath from the plist now so we
        // can tail it for engine-load results after the bounce. We
        // read the path from the plist (rather than hardcoding
        // ~/.cocore/logs/stdout.log) so a user who customized
        // StandardOutPath still gets the confirmation behavior.
        // tracing_subscriber::fmt() writes to stdout by default — see
        // init_tracing() in main.rs — so success/failure lines land
        // in StandardOutPath, not StandardErrorPath.
        let log_path = read_env_var(&plist, "StandardOutPath")
            .ok()
            .map(PathBuf::from);
        // Snapshot the current file length so we tail forward from
        // here rather than re-reading historical log contents. If the
        // file doesn't exist yet (clean install), we start at 0.
        let start_offset = log_path
            .as_ref()
            .and_then(|p| std::fs::metadata(p).ok())
            .map(|m| m.len())
            .unwrap_or(0);

        bounce_launch_agent()?;

        match log_path.as_deref() {
            Some(p) if !await_models.is_empty() => {
                let outcomes = await_engine_load_results(
                    p,
                    start_offset,
                    await_models,
                    Duration::from_secs(10),
                );
                report_outcomes(&outcomes, p);
            }
            _ => {
                println!(
                    "Bounced the LaunchAgent. The agent will re-publish its provider record with the new\n\
                     supportedModels within a few seconds. Tail ~/.cocore/logs/stdout.log to watch the\n\
                     engine-load + register-with-advisor sequence."
                );
            }
        }
        Ok(())
    }
    #[cfg(target_os = "linux")]
    {
        let _ = (verb, await_models, joined);
        // Linux parity for the macOS plist-edit + bounce. Unlike macOS, there
        // is NO local model list to edit: the PDS `desiredModels` write above
        // is the source of truth, and the serve loop reconciles it into
        // COCORE_INFERENCE_MODELS at startup (inference_models_action). So the
        // action is the PDS write + an immediate service restart to apply it
        // now rather than waiting for the advisor's ~30s reconcile.
        if pds_wrote {
            let restarted = crate::service::restart_if_installed();
            if restarted {
                println!(
                    "Wrote your model selection ({} model(s)) to your account and restarted {}. \
                     Watch `journalctl --user -u {} -f` for the engine-load + register sequence.",
                    models.len(),
                    crate::service::UNIT,
                    crate::service::UNIT,
                );
            } else {
                println!(
                    "Wrote your model selection ({} model(s)) to your account. A running agent will \
                     reconcile within ~30s; no {} found to restart immediately (restart your serve \
                     daemon to apply now).",
                    models.len(),
                    crate::service::UNIT,
                );
            }
            Ok(())
        } else {
            anyhow::bail!(
                "Couldn't sync the model selection — this machine has no provider record yet \
                 (has it served at least once?)."
            )
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (verb, await_models, joined);
        if pds_wrote {
            println!(
                "Wrote your model selection ({} model(s)) to your account. A running agent will \
                 reconcile within ~30s and reload; restart the service to apply immediately.",
                models.len()
            );
            Ok(())
        } else {
            anyhow::bail!(
                "Couldn't sync the model selection — this machine has no provider record yet \
                 (has it served at least once?)."
            )
        }
    }
}

#[cfg(target_os = "macos")]
fn plist_path() -> Result<PathBuf> {
    let home = dirs::home_dir().context("could not resolve $HOME for plist path")?;
    let p = home
        .join("Library")
        .join("LaunchAgents")
        .join("dev.cocore.provider.plist");
    if !p.exists() {
        anyhow::bail!(
            "no LaunchAgent plist at {}. Install the agent (curl … | sh) first.",
            p.display()
        );
    }
    Ok(p)
}

#[cfg(not(target_os = "macos"))]
#[allow(dead_code)]
fn plist_path() -> Result<PathBuf> {
    anyhow::bail!("plist editing is macOS-only")
}

/// `pub(crate)` so the menu-bar companion (menubar.rs) can render the
/// configured set as checkbox state without re-implementing the
/// plist-with-legacy-fallback read.
pub(crate) fn read_current() -> Result<Vec<String>> {
    #[cfg(target_os = "macos")]
    {
        let plist = plist_path()?;
        if let Ok(s) = read_env_var(&plist, ENV_KEY) {
            let v = normalize(&s);
            if !v.is_empty() {
                return Ok(v);
            }
        }
        // Fall back to the legacy singular for v0.4.0 plists.
        if let Ok(s) = read_env_var(&plist, LEGACY_ENV_KEY) {
            return Ok(normalize(&s));
        }
        Ok(Vec::new())
    }
    #[cfg(not(target_os = "macos"))]
    {
        if let Ok(s) = std::env::var("COCORE_INFERENCE_MODELS") {
            let v = normalize(&s);
            if !v.is_empty() {
                return Ok(v);
            }
        }
        match std::env::var("COCORE_INFERENCE_MODEL") {
            Ok(s) => Ok(normalize(&s)),
            Err(_) => Ok(Vec::new()),
        }
    }
}

#[cfg(target_os = "macos")]
fn read_env_var(plist: &Path, key: &str) -> Result<String> {
    let out = Command::new("/usr/libexec/PlistBuddy")
        .args(["-c", &format!("Print :{key}"), plist.to_str().unwrap()])
        .output()
        .context("invoking /usr/libexec/PlistBuddy Print")?;
    if !out.status.success() {
        anyhow::bail!(
            "PlistBuddy could not read :{key} from {}: {}",
            plist.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

#[cfg(target_os = "macos")]
fn write_env_var(plist: &Path, key: &str, value: &str) -> Result<()> {
    // PlistBuddy returns non-zero when Set targets a missing key, so
    // try Set first; on failure fall back to Add (which creates the
    // key + value as a string). This handles both fresh-install
    // plists (key may not exist yet on v0.4.0 stub installs) and the
    // common case where the key already exists.
    let set = Command::new("/usr/libexec/PlistBuddy")
        .args([
            "-c",
            &format!("Set :{key} {value}"),
            plist.to_str().unwrap(),
        ])
        .status()
        .context("invoking /usr/libexec/PlistBuddy Set")?;
    if set.success() {
        return Ok(());
    }
    let add = Command::new("/usr/libexec/PlistBuddy")
        .args([
            "-c",
            &format!("Add :{key} string {value}"),
            plist.to_str().unwrap(),
        ])
        .status()
        .context("invoking /usr/libexec/PlistBuddy Add")?;
    if !add.success() {
        anyhow::bail!(
            "PlistBuddy failed to Set or Add :{key} in {}",
            plist.display()
        );
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn delete_env_var(plist: &Path, key: &str) -> Result<()> {
    let out = Command::new("/usr/libexec/PlistBuddy")
        .args(["-c", &format!("Delete :{key}"), plist.to_str().unwrap()])
        .output()
        .context("invoking /usr/libexec/PlistBuddy Delete")?;
    if !out.status.success() {
        // Missing key returns non-zero; that's fine.
        return Ok(());
    }
    Ok(())
}

/// Refuse `models add` for non-stub model ids when this machine has
/// no Python venv to run them in. v0.6.0 unified the previously-
/// dual-variant builds into a single binary that ALWAYS supports
/// real inference — but only if `~/.cocore/python/bin/python` exists
/// (the venv `uv` provisions during install). Without that, calling
/// `models add gemma-3-4b` would write the id to the plist, the
/// bounced daemon's `build_engines()` would skip the spawn because
/// the venv is missing, and the user's machine would publish
/// `supportedModels: ["stub"]` — exactly the silent-no-op failure
/// the inference-feature-flag check used to guard against, just
/// triggered by a different missing dependency.
///
/// The `stub` engine doesn't need the venv; it's always addable.
fn check_model_addable(model: &str, venv_present: bool) -> Result<()> {
    if model == "stub" || venv_present {
        return Ok(());
    }
    anyhow::bail!(
        "cocore agent models add requires a Python venv at ~/.cocore/python.\n\
         The venv is what hosts vllm-mlx — without it the bounced agent\n\
         can't load `{model}` and will publish supportedModels=[\"stub\"].\n\
         \n\
         Provision the venv with:\n  \
         curl -fsSL cocore.dev/agent | sh\n\
         \n\
         (Re-running the installer is idempotent — it won't redo work\n\
         that's already done.)"
    )
}

/// True when the venv `uv` provisions during install exists and looks
/// usable. Used to decide whether `models add <real-model>` should
/// proceed or refuse with a clear "provision the venv first" message.
fn venv_python_present() -> bool {
    let Some(home) = dirs::home_dir() else {
        return false;
    };
    let py = home.join(".cocore/python/bin/python");
    py.exists()
}

/// Interactive picker shown when `cocore agent models add` is called
/// without a positional. Detects this machine's RAM, filters the
/// catalog at `pricing::RATES` to entries that fit, prints a numbered
/// menu with each model's one-line description, and reads the user's
/// choice from stdin.
///
/// Why a hand-rolled prompt and not `dialoguer`/`inquire`: the agent
/// already keeps its dependency surface tight (the only TUI thing in
/// the binary today is `println!`), and the menu we want is fixed-
/// width text — a numbered list with one-line descriptions. A
/// dependency for that would dwarf the implementation.
///
/// The user can type either the menu number (`3`) or the full NSID
/// (`mlx-community/...`) — typing the NSID lets power users use the
/// picker to confirm the spelling without leaving the prompt.
///
/// Failure modes:
///   * stdin closed (e.g. piped, no TTY) → bail with a clear error
///     pointing at the positional form.
///   * empty input → re-prompt up to 3 times before bailing.
///   * unknown number / NSID → re-prompt, same retry budget.
///
/// Returns the chosen NSID on success.
fn prompt_for_catalog_model() -> Result<String> {
    use std::io::{BufRead, Write};

    let profile = system_profile::collect();
    let pickable = pricing::pickable_for_machine(profile.ram_gb);

    if pickable.is_empty() {
        anyhow::bail!(
            "no catalog models fit this machine ({}GB RAM detected). The smallest catalog \
             entry needs 4GB. If you know the model id, pass it as an argument: \
             `cocore agent models add <model-id>`.",
            profile.ram_gb
        );
    }

    println!();
    println!("This machine: {} · {}GB RAM", profile.chip, profile.ram_gb);
    println!("Catalog models that fit (small → large):");
    println!();
    for (i, m) in pickable.iter().enumerate() {
        println!("  {}) {}\n     {}", i + 1, m.model_id, m.description);
    }
    println!();
    println!(
        "Pick a number (1-{}) or paste any MLX-format HuggingFace NSID\n\
         (anything under mlx-community/, or another repo with MLX 4-bit\n\
         weights — stock PyTorch repos won't load). Empty to abort.",
        pickable.len()
    );

    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut tries = 0;
    let max_tries = 3;
    loop {
        tries += 1;
        if tries > max_tries {
            anyhow::bail!("too many invalid attempts; aborting picker.");
        }

        print!("> ");
        stdout.flush().ok();
        let mut line = String::new();
        let read = stdin.lock().read_line(&mut line);
        match read {
            Ok(0) => {
                anyhow::bail!(
                    "stdin closed before a model was picked. If you're piping or running \
                     without a TTY, pass the model id directly: \
                     `cocore agent models add <model-id>`."
                );
            }
            Err(e) => anyhow::bail!("reading stdin: {e}"),
            Ok(_) => {}
        }
        let input = line.trim();
        if input.is_empty() {
            println!("Empty input; aborting.");
            anyhow::bail!("no model selected.");
        }

        // Numeric? Then resolve against the menu position.
        if let Ok(n) = input.parse::<usize>() {
            if n >= 1 && n <= pickable.len() {
                return Ok(pickable[n - 1].model_id.to_string());
            }
            println!(
                "'{input}' is out of range (1-{}). Try again.",
                pickable.len()
            );
            continue;
        }

        // Otherwise treat as a free-form NSID. We accept any non-empty
        // `org/model` here — the catalog is curated suggestions, not an
        // allowlist; a provider can serve any MLX-format model. We don't
        // hard-reject non-`mlx-community/` ids (valid MLX conversions live
        // under many orgs), so the only requirement is the `org/model`
        // shape. If the model turns out not to be MLX-format, the bounce +
        // log-tail below surfaces the load failure and the provider record
        // publishes an engineFault explaining the MLX requirement.
        if input.contains('/') {
            return Ok(input.to_string());
        }

        println!(
            "'{input}' doesn't look like a menu number or a HuggingFace NSID \
             (expected `org/model`). Try again."
        );
    }
}

/// Outcome of polling the agent log for a single model after a
/// LaunchAgent bounce. `Pending` means we never saw a definitive
/// line about that model within the timeout — either the engine
/// genuinely takes longer (cold weight download) or something
/// failed before tracing got a chance to emit.
#[cfg(any(target_os = "macos", test))]
#[derive(Debug, PartialEq, Eq, Clone)]
enum LoadOutcome {
    Ready,
    Failed,
    Pending,
}

/// Classify a single log line against the requested model list.
///
/// The provider's `build_engines()` emits exactly one terminal event
/// per model — either `inference subprocess engine ready` (info) or
/// `inference engine load failed` (warn) — each with a `model=<id>`
/// tracing field. We match by substring on both the message text and
/// the model id, which keeps us robust to tracing format tweaks (the
/// default formatter quotes string fields that contain slashes, e.g.
/// `model="org/name"`). Keep these phrases in sync with the
/// `tracing::{info,warn}!` calls in `main.rs::build_engines`.
#[cfg(any(target_os = "macos", test))]
fn match_log_line(line: &str, models: &[String]) -> Option<(String, LoadOutcome)> {
    let ready = line.contains("inference subprocess engine ready");
    let failed = line.contains("inference engine load failed");
    if !ready && !failed {
        return None;
    }
    let m = models.iter().find(|m| line.contains(m.as_str()))?;
    let outcome = if ready {
        LoadOutcome::Ready
    } else {
        LoadOutcome::Failed
    };
    Some((m.clone(), outcome))
}

/// Tail `log_path` starting at `start_offset`, classifying each new
/// line via `match_log_line`. Returns once every model has a
/// definitive outcome OR `timeout` elapses (in which case still-
/// unresolved models come back as `Pending`).
///
/// Tolerates two real-world quirks of LaunchAgent log files:
///   * the file might not exist yet when we start polling (clean
///     install, agent's first stdout flush hasn't happened);
///   * the file can be rotated or truncated under us — if its length
///     drops below our recorded offset, we reset to 0.
#[cfg(any(target_os = "macos", test))]
fn await_engine_load_results(
    log_path: &Path,
    start_offset: u64,
    models: &[String],
    timeout: Duration,
) -> Vec<(String, LoadOutcome)> {
    use std::collections::HashMap;
    use std::io::{BufRead, BufReader, Seek, SeekFrom};
    use std::time::Instant;

    let mut outcomes: HashMap<String, LoadOutcome> = models
        .iter()
        .map(|m| (m.clone(), LoadOutcome::Pending))
        .collect();

    let deadline = Instant::now() + timeout;
    let mut offset = start_offset;
    let poll_interval = Duration::from_millis(200);

    loop {
        if let Ok(mut f) = std::fs::File::open(log_path) {
            let len = f.metadata().map(|m| m.len()).unwrap_or(0);
            if len < offset {
                offset = 0;
            }
            if f.seek(SeekFrom::Start(offset)).is_ok() {
                let mut reader = BufReader::new(f);
                let mut line = String::new();
                loop {
                    line.clear();
                    match reader.read_line(&mut line) {
                        Ok(0) => break,
                        Ok(n) => {
                            offset += n as u64;
                            if let Some((m, o)) = match_log_line(&line, models) {
                                outcomes.insert(m, o);
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
        }

        let all_resolved = outcomes
            .values()
            .all(|o| !matches!(o, LoadOutcome::Pending));
        if all_resolved || Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(poll_interval);
    }

    models
        .iter()
        .map(|m| {
            (
                m.clone(),
                outcomes.remove(m).unwrap_or(LoadOutcome::Pending),
            )
        })
        .collect()
}

/// Print the per-model outcome from `await_engine_load_results` and,
/// if anything went wrong, a recovery hint pointing at the log.
#[cfg(target_os = "macos")]
fn report_outcomes(outcomes: &[(String, LoadOutcome)], log_path: &Path) {
    let mut any_failed = false;
    let mut any_pending = false;
    for (m, o) in outcomes {
        match o {
            LoadOutcome::Ready => println!("  \u{2713} {m} loaded"),
            LoadOutcome::Failed => {
                any_failed = true;
                eprintln!("  \u{2717} {m} failed to load");
            }
            LoadOutcome::Pending => {
                any_pending = true;
            }
        }
    }

    if any_failed {
        let pending_models: Vec<&str> = outcomes
            .iter()
            .filter(|(_, o)| matches!(o, LoadOutcome::Failed))
            .map(|(m, _)| m.as_str())
            .collect();
        let names = pending_models.join(", ");
        eprintln!(
            "\nwarn: model(s) [{names}] did not finish loading within 10s.\n\
             \x20     Check {} for the python traceback.\n\n\
             \x20     Common causes:\n\
             \x20       * Python venv at ~/.cocore/python is broken — reinstall via\n\
             \x20         `curl -fsSL cocore.dev/agent/inference | sh`\n\
             \x20       * Model id is wrong or not on HuggingFace\n\
             \x20       * Out-of-memory during load (check Activity Monitor)\n\n\
             \x20     The plist was still updated; if you fix the underlying issue,\n\
             \x20     `launchctl kickstart -k gui/$UID/dev.cocore.provider` will retry.",
            log_path.display()
        );
    } else if any_pending {
        let pending_models: Vec<&str> = outcomes
            .iter()
            .filter(|(_, o)| matches!(o, LoadOutcome::Pending))
            .map(|(m, _)| m.as_str())
            .collect();
        let names = pending_models.join(", ");
        eprintln!(
            "\nnote: couldn't confirm load of [{names}] within 10s — first-time model\n\
             \x20     downloads from HuggingFace can take longer. Tail {} to\n\
             \x20     watch progress.",
            log_path.display()
        );
    }
}

#[cfg(target_os = "macos")]
fn bounce_launch_agent() -> Result<()> {
    let uid = unsafe { libc::getuid() };
    let target = format!("gui/{uid}/dev.cocore.provider");
    let plist = plist_path()?;
    // `launchctl kickstart -k` alone restarts the running program
    // but does NOT re-read the plist — launchd hands the new process
    // the env it cached at the most recent `bootstrap`. So an
    // `EnvironmentVariables` change like the one this CLI just made
    // would never reach the agent. To pick up plist edits we always
    // bootout + bootstrap, then kickstart for good measure. Each
    // step is best-effort: bootout fails if not loaded (fine),
    // bootstrap fails if already loaded (also fine — the bootout
    // above made that unlikely), enable + kickstart should both
    // succeed once the service is loaded.
    let _ = Command::new("launchctl")
        .args(["bootout", &target])
        .status();
    let _ = Command::new("launchctl")
        .args(["bootstrap", &format!("gui/{uid}"), plist.to_str().unwrap()])
        .status();
    let _ = Command::new("launchctl").args(["enable", &target]).status();
    let kick = Command::new("launchctl")
        .args(["kickstart", "-k", &target])
        .status()
        .context("invoking launchctl kickstart")?;
    if !kick.success() {
        anyhow::bail!(
            "launchctl could not (re)load {target}. Run `cocore agent doctor` for a diagnostic."
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn model(s: &str) -> String {
        s.to_string()
    }

    /// The default tracing formatter renders fields after the message;
    /// string fields containing slashes get quoted. Both shapes are
    /// realistic samples taken from a manual run of the agent.
    fn ready_line(m: &str) -> String {
        format!(
            "2026-05-13T12:00:00.000000Z  INFO cocore::main: inference subprocess engine ready model=\"{m}\"\n"
        )
    }
    fn failed_line(m: &str) -> String {
        format!(
            "2026-05-13T12:00:00.000000Z  WARN cocore::main: inference engine load failed model=\"{m}\"\n"
        )
    }

    #[test]
    fn match_log_line_recognizes_ready() {
        let models = vec![model("mlx-community/foo")];
        let line = ready_line("mlx-community/foo");
        let (m, o) = match_log_line(&line, &models).expect("matched");
        assert_eq!(m, "mlx-community/foo");
        assert_eq!(o, LoadOutcome::Ready);
    }

    #[test]
    fn match_log_line_recognizes_failed() {
        let models = vec![model("mlx-community/foo")];
        let line = failed_line("mlx-community/foo");
        let (m, o) = match_log_line(&line, &models).expect("matched");
        assert_eq!(m, "mlx-community/foo");
        assert_eq!(o, LoadOutcome::Failed);
    }

    #[test]
    fn match_log_line_ignores_unrelated_lines() {
        let models = vec![model("mlx-community/foo")];
        let line = "2026-05-13T12:00:00.000000Z  INFO cocore::main: bound to console\n";
        assert!(match_log_line(line, &models).is_none());
    }

    #[test]
    fn match_log_line_ignores_other_models() {
        let models = vec![model("mlx-community/foo")];
        let line = ready_line("mlx-community/bar");
        assert!(match_log_line(&line, &models).is_none());
    }

    /// All requested models report `vllm-mlx engine ready`: each
    /// resolves to `Ready` and the poller returns early (well under
    /// the timeout).
    #[test]
    fn await_returns_ready_when_success_line_appears() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("stdout.log");
        let mut f = std::fs::File::create(&log).unwrap();
        f.write_all(ready_line("mlx-community/foo").as_bytes())
            .unwrap();
        f.write_all(ready_line("mlx-community/bar").as_bytes())
            .unwrap();
        f.flush().unwrap();

        let models = vec![model("mlx-community/foo"), model("mlx-community/bar")];
        let start = std::time::Instant::now();
        let outcomes = await_engine_load_results(&log, 0, &models, Duration::from_secs(5));
        // Early-exit: should be far under the 5s timeout.
        assert!(start.elapsed() < Duration::from_secs(2));

        assert_eq!(
            outcomes,
            vec![
                (model("mlx-community/foo"), LoadOutcome::Ready),
                (model("mlx-community/bar"), LoadOutcome::Ready),
            ]
        );
    }

    /// A `failed to load vllm-mlx engine` line should resolve the
    /// model to `Failed`, not leave it `Pending`.
    #[test]
    fn await_returns_failed_when_failure_line_appears() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("stdout.log");
        let mut f = std::fs::File::create(&log).unwrap();
        f.write_all(failed_line("mlx-community/foo").as_bytes())
            .unwrap();
        f.flush().unwrap();

        let models = vec![model("mlx-community/foo")];
        let outcomes = await_engine_load_results(&log, 0, &models, Duration::from_secs(5));
        assert_eq!(
            outcomes,
            vec![(model("mlx-community/foo"), LoadOutcome::Failed)]
        );
    }

    /// Neither line ever appears in the polling window. The poller
    /// must NOT block forever; it returns `Pending` so the caller can
    /// print a soft "couldn't confirm" message and exit zero.
    #[test]
    fn await_returns_pending_on_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("stdout.log");
        std::fs::File::create(&log)
            .unwrap()
            .write_all(b"2026-05-13T12:00:00.000000Z  INFO unrelated\n")
            .unwrap();

        let models = vec![model("mlx-community/foo")];
        let start = std::time::Instant::now();
        let outcomes = await_engine_load_results(&log, 0, &models, Duration::from_millis(400));
        // Timeout is honored — we don't sit forever.
        assert!(start.elapsed() < Duration::from_secs(2));
        assert_eq!(
            outcomes,
            vec![(model("mlx-community/foo"), LoadOutcome::Pending)]
        );
    }

    /// `start_offset` skips historical content: a prior "ready" line
    /// from a previous bounce should NOT mark a model ready for this
    /// bounce's poll. Otherwise restarts that fail would look like
    /// they succeeded.
    #[test]
    fn await_skips_lines_before_start_offset() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("stdout.log");
        let historical = ready_line("mlx-community/foo");
        let mut f = std::fs::File::create(&log).unwrap();
        f.write_all(historical.as_bytes()).unwrap();
        f.flush().unwrap();
        let after = std::fs::metadata(&log).unwrap().len();

        let models = vec![model("mlx-community/foo")];
        let outcomes = await_engine_load_results(&log, after, &models, Duration::from_millis(400));
        assert_eq!(
            outcomes,
            vec![(model("mlx-community/foo"), LoadOutcome::Pending)]
        );
    }

    #[test]
    fn stub_addable_without_venv() {
        check_model_addable("stub", false).expect(
            "the stub engine is in-process and venv-independent; adding it must always succeed",
        );
    }

    #[test]
    fn stub_addable_with_venv() {
        check_model_addable("stub", true).expect("stub must remain addable when the venv exists");
    }

    #[test]
    fn real_model_allowed_with_venv() {
        check_model_addable("mlx-community/Qwen2.5-3B-Instruct-4bit", true)
            .expect("with the venv present, real models are addable");
    }

    #[test]
    fn real_model_refused_without_venv() {
        let err = check_model_addable("mlx-community/Qwen2.5-3B-Instruct-4bit", false)
            .expect_err("with no venv, non-stub model ids must be refused");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("~/.cocore/python"),
            "error must point at the missing venv path: {msg}"
        );
        assert!(
            msg.contains("cocore.dev/agent"),
            "error must give the recovery one-liner: {msg}"
        );
    }
}
