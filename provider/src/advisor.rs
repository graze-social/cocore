//! Advisor client: outbound WebSocket from the provider to a federated
//! matchmaking service. The advisor wraps requester prompts to the
//! provider's X25519 key and forwards them; the advisor never sees
//! plaintext, never holds a receipt, and never gets to invalidate one.
//!
//! Phase 2.5+: handles InferenceRequest end-to-end — decrypts the
//! sealed prompt, streams token deltas back to the requester as they
//! are produced, publishes a `dev.cocore.compute.receipt` to our PDS
//! when we have enough strong-refs, and emits InferenceComplete whose
//! `receipt_uri` carries the published `at://`.

// Hot serve path: a panic here can poison shared state or (before the
// per-job catch_unwind boundary) take the whole agent down — the exact
// escalation that took machines offline. Deny the panic-on-the-happy-path
// footguns in production builds; the `#[cfg(test)]` module below is exempt
// (tests legitimately use `unwrap`/`expect`/`panic!`).
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

use crate::canonical::to_canonical_bytes;
use crate::crypto::ProviderKeypair;
use crate::engines::{DeltaChannel, Engine, EngineRegistry};
use crate::error::{ProviderError, Result};
use crate::hypervisor;
use crate::pds::{PdsClient, ProBonoPolicy};
use crate::pricing;
use crate::protocol::{
    AdvisorMessage, AttestationChallenge, AttestationResponse, ChunkChannel,
    CodeAttestationResponse, HealthStanding, Heartbeat, InferenceChunk, InferenceComplete,
    InferenceKeepalive, InferenceRequest, Pong, Register, SessionKey,
};
use crate::receipt::{self, Money, ReceiptInputs, StrongRef};
use crate::secure_enclave::SigningIdentity;
use chrono::Utc;
use futures_util::stream::FuturesUnordered;
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use zeroize::Zeroizing;

pub struct AdvisorClient {
    pub url: String,
}

/// Owns a [`GenerateRequest`] for the duration of a `spawn_blocking`
/// engine call and zeroizes its message contents on drop. The
/// decrypted prompt is copied into `request.messages[*].content`; this
/// guard guarantees those copies are wiped once generation finishes —
/// crucially on the panic-unwind path too, where an explicit
/// post-await zeroize line would be skipped because `spawn_blocking`
/// catches the panic and turns it into a `JoinError`.
struct ZeroizeOnDrop(crate::engines::GenerateRequest);

impl Drop for ZeroizeOnDrop {
    fn drop(&mut self) {
        for m in &mut self.0.messages {
            m.zeroize_content();
        }
    }
}

/// Bundles the long-lived state that
/// [`handle_inference_request`] needs to publish a receipt: the PDS
/// client (signs its own DPoP), the active attestation strong-ref, and
/// the signer + X25519 keypair already passed for chunk/complete
/// construction.
///
/// The attestation is a shared, refreshable cell rather than a plain
/// reference: a background task in `cmd_serve` re-publishes the attestation
/// ~1h before it expires (24h lifetime) and swaps the new strong-ref in here,
/// so jobs always reference the CURRENT attestation. It reads `None` when
/// attestation publish failed (at boot or on a refresh) — receipts skip
/// publishing in that mode — and a job reads the freshest value at the moment
/// it publishes its receipt.
struct ServeContext<'a> {
    signer: &'a dyn SigningIdentity,
    encryption: &'a ProviderKeypair,
    pds: &'a PdsClient,
    attestation: Arc<RwLock<Option<StrongRef>>>,
    /// Per-model engine registry. `cmd_serve` constructs the
    /// registry from `COCORE_INFERENCE_MODELS` (or the singular
    /// legacy form), with a `stub` entry always included for the
    /// protocol-smoke-test path. `handle_inference_request` looks
    /// up the request's `model` field here; a miss surfaces as a
    /// sealed error chunk to the requester rather than silently
    /// falling back to the stub (which would let the stub-engine's
    /// echo masquerade as a real model's reply).
    engines: &'a EngineRegistry,
    /// The owner's pro-bono election, read from this machine's provider
    /// record at serve start. A request from a requester this policy
    /// matches is served free: the receipt carries `proBono: true` with a
    /// zero price and zero token counts, and the exchange takes no cut.
    /// An off / non-matching policy serves the job as a normal paid job.
    pro_bono: &'a ProBonoPolicy,
}

impl AdvisorClient {
    pub fn new(url: impl Into<String>) -> Self {
        Self { url: url.into() }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn run(
        &self,
        mut register: Register,
        signer: &dyn SigningIdentity,
        encryption: &ProviderKeypair,
        pds: &PdsClient,
        // Shared, refreshable attestation cell (see `ServeContext`). Cloned
        // from `cmd_serve`, which also hands a clone to the refresh task; on
        // reconnect `run` re-reads the same cell, so it always picks up any
        // attestation refreshed mid-connection.
        attestation: Arc<RwLock<Option<StrongRef>>>,
        engines: &EngineRegistry,
        // rkey of this machine's provider record, so we can read the owner's
        // `active` start/stop switch off our own PDS. `None` skips the check
        // (we assume serving).
        provider_rkey: Option<&str>,
        // The `desiredModels` set this serve loaded against. If the owner
        // edits it on the website we detect the change here and restart to
        // reload — compared to THIS set (not what loaded) so a model that
        // won't fit RAM doesn't look like a perpetual change.
        desired_at_start: &[String],
        // The `desiredTier` this serve loaded against (`None` == best-effort).
        // If the owner flips it on the console (opt in to / out of
        // attested-confidential) we detect the change here and restart, so the
        // supervisor re-selects the right worker binary on the next spawn (the
        // confidential push-receiver bundle vs. the default best-effort CLI).
        desired_tier_at_start: Option<&str>,
        // Per-model schedules + the full configured set they apply to. The
        // serve loop watches for a window boundary (a model's active state
        // flipping) and restarts to reload the new active set.
        model_schedules: &crate::schedule::ModelSchedules,
        configured_models: &[String],
        // APNs code-identity push receiver (confidential tier; `apns` build).
        // The process main thread runs the AppKit push host (see
        // `push_host::run_blocking`) and forwards each received `E_K(nonce)`
        // challenge here. `None` on non-apns builds and on headless sessions
        // that never registered for push — the corresponding `select!` arm is
        // then inert and the loop behaves exactly as before.
        mut push_rx: Option<&mut mpsc::UnboundedReceiver<String>>,
        // The owner's pro-bono election, read from this machine's provider
        // record at serve start. Threaded into `ServeContext` so each job
        // can decide, per requester, whether to serve free + unmetered.
        pro_bono: &ProBonoPolicy,
        // The owner's `toolCalls` opt-in this serve loaded against. If the
        // owner flips it on the console we detect the change in the control
        // re-read below and restart to rebuild engines — the same reload path
        // as a `desiredModels` edit (engines are built once per serve, and the
        // per-model tool-call parser is chosen at build time).
        tool_calls_at_start: bool,
    ) -> Result<()> {
        // Reject a plaintext advisor URL before we connect. A `ws://` link lets
        // a network attacker read/inject job dispatch and control frames
        // (spoofed InferenceRequests, forged ControlChanged/RecoverRequest) —
        // the default is `wss://`, so a non-TLS URL is either a misconfig or an
        // active downgrade. Allow it ONLY when the operator explicitly opts in
        // via `COCORE_ALLOW_INSECURE_ADVISOR=1`, for local dev against a
        // plaintext advisor.
        require_secure_advisor_url(&self.url)?;

        tracing::info!(url = %self.url, "connecting to advisor");
        // Connect failures return the classified `AdvisorConnect` variant —
        // the Register frame never reached the advisor, so the serve loop can
        // count consecutive occurrences and publish an `advisorFault` on the
        // provider record (the only remotely-visible trace of a machine that
        // serves locally but never joins the network).
        let (ws, _resp) =
            match tokio::time::timeout(CONNECT_TIMEOUT, connect_async(&self.url)).await {
                Ok(r) => r.map_err(|e| ProviderError::AdvisorConnect {
                    code: classify_ws_connect_error(&e),
                    detail: e.to_string(),
                })?,
                Err(_) => {
                    return Err(ProviderError::AdvisorConnect {
                        code: "connect-timeout".to_string(),
                        detail: format!(
                            "advisor connect timed out after {}s",
                            CONNECT_TIMEOUT.as_secs()
                        ),
                    });
                }
            };
        let (mut write, mut read) = ws.split();

        // Stamp our stable per-machine id (this machine's provider-record
        // rkey) so the advisor can hold us AND a sibling machine under the
        // same DID instead of one evicting the other. Leave any explicit
        // value already set; otherwise derive it from provider_rkey.
        if register.machine_id.is_none() {
            register.machine_id = provider_rkey.map(str::to_string);
        }

        // Our measured cdHash, captured before `register` is moved into the
        // frame — bound into every code-attestation response (0.9.23) so the
        // code-identity proof is tied to this specific binary.
        let my_cd_hash: Option<String> = register.cd_hash.clone();

        // Mint a fresh atproto service-auth JWT for THIS registration, so the
        // advisor can bind `provider_did` to real DID control (a machine can't
        // register under a DID it doesn't hold). The token is minted by the
        // provider's PDS (`com.atproto.server.getServiceAuth`) with
        // `aud` = the advisor's DID and `lxm` = "dev.cocore.compute.register".
        // It's short-lived, so we re-mint on every (re)connect. A mint failure
        // is non-fatal: log it and register WITHOUT the jwt — the advisor's
        // enforcement flag decides whether an unauthenticated Register is
        // rejected, and we'd rather send an unsigned frame than crash the serve
        // loop over a transient PDS / console-proxy blip.
        let advisor_did = advisor_did();
        match pds.mint_service_auth(&advisor_did, REGISTER_LXM).await {
            Ok(jwt) => register.auth_jwt = Some(jwt),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    aud = %advisor_did,
                    lxm = REGISTER_LXM,
                    "could not mint service-auth JWT for advisor registration; registering without it"
                );
                register.auth_jwt = None;
            }
        }

        // Register
        let payload = serde_json::to_string(&AdvisorMessage::Register(register))
            .map_err(|e| ProviderError::Advisor(e.to_string()))?;
        write
            .send(Message::Text(payload.into()))
            .await
            .map_err(|e| ProviderError::Advisor(e.to_string()))?;
        tracing::info!("registered with advisor");
        // A fresh, successful registration is a clean slate — clear any
        // stale "bad standing" marker from a previous serve so the tray's
        // red ping doesn't linger after the machine has recovered.
        clear_bad_standing();
        // Registration is the moment this machine can actually take jobs, so
        // it's what closes the boot-time "starting" window the serve path
        // marked after engines loaded (see main's provision-status marker).
        // Only now does the tray flip from "connecting…" to "Serving".
        clear_starting_provision_marker();
        // It also proves the advisor path works end-to-end — remove any
        // `advisorFault` published on the provider record (by this process
        // after repeated connect failures, or left behind by a previous one)
        // so the console stops showing "can't reach the network". Runs
        // off-loop: a PDS round-trip must never stall ping handling. The
        // maybe-published marker makes this a no-op — not even a read — on
        // the common reconnect (the advisor's edge recycles the socket every
        // ~14 minutes), and a failed clear leaves the marker set so the next
        // registration retries.
        if crate::pds::advisor_fault_maybe_published() {
            if let Some(rk) = provider_rkey {
                let pds_clear = pds.clone();
                let rk = rk.to_string();
                tokio::spawn(async move {
                    match pds_clear.patch_provider_advisor_fault(&rk, None).await {
                        Ok(true) => tracing::info!(
                            "cleared advisorFault on provider record after successful registration"
                        ),
                        Ok(false) => {}
                        Err(e) => tracing::warn!(
                            error = %e,
                            "could not clear advisorFault after registration; will retry on the next one"
                        ),
                    }
                });
            }
        }

        let ctx = ServeContext {
            signer,
            encryption,
            pds,
            attestation,
            engines,
            pro_bono,
        };
        // A shared reference the per-job futures copy in (each `async move`
        // would otherwise move `ctx` itself, leaving none for the next job).
        let ctx = &ctx;

        // Heartbeat ticker + read loop.
        let mut hb = tokio::time::interval(std::time::Duration::from_secs(30));

        // The owner's start/stop switch, read from our own PDS record. We
        // report it in every heartbeat so the advisor routes us no jobs
        // when the owner stops the machine from the console. Re-read on a
        // slow poll (the fallback) and immediately on a `control_changed`
        // nudge (the fast path) — both via `active_reads` so the network
        // read NEVER blocks the hot loop's ping handling. Absent /
        // unreadable == serving.
        let active = match provider_rkey {
            Some(rk) => pds.get_provider_active(rk).await.unwrap_or(true),
            None => true,
        };
        // The owner stopped us between the outer gate and now — disconnect
        // immediately. The outer `cmd_serve` loop sees us return and waits
        // (polling our PDS switch) until they start us again, so we drop out
        // of the advisor's registry entirely rather than lingering as a
        // connected-but-idle machine.
        if !active {
            tracing::info!("owner has this machine stopped; not serving");
            return Ok(());
        }
        // The per-model active set this serve loaded against. A schedule
        // window opening/closing changes it; we restart to reload (below).
        let active_at_start = model_schedules.active_now(configured_models);
        let mut active_reads = FuturesUnordered::new();
        let mut active_poll = tokio::time::interval(std::time::Duration::from_secs(30));
        active_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // First interval tick fires immediately; consume it (we just read).
        active_poll.tick().await;

        // Engine health watchdog. A subprocess engine's Python child can
        // die mid-serve (OOM on a small Mac, a crash); registration isn't
        // retracted on death, so without this the agent keeps advertising
        // the dead model and the advisor keeps routing jobs that get
        // dropped here — no receipt, no credit, while the network counts
        // them dispatched. Periodically check each engine OFF the hot loop
        // (the check + any restart blocks) and either restart it in place
        // or, if it can't be recovered, restart the agent so the next boot
        // re-registers without it.
        let mut health_checks = FuturesUnordered::new();
        // Self-right checks triggered on demand by a `RecoverRequest` (the
        // advisor flagged us unhealthy, or the owner clicked "Try to recover"
        // in the console). Runs the same engine health-check + bounded restart
        // as the periodic watchdog, but OFF the scheduled cadence and reports
        // the outcome back to the advisor via `RecoverResult`.
        let mut recover_checks: FuturesUnordered<tokio::task::JoinHandle<Vec<String>>> =
            FuturesUnordered::new();
        let mut health_poll = tokio::time::interval(ENGINE_HEALTH_INTERVAL);
        health_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Consume the immediate first tick — engines were just verified at
        // boot (build_engines only registers ones that became ready).
        health_poll.tick().await;

        // In-flight job futures. Each inbound frame we act on becomes a
        // `handle_inbound` future parked here instead of being awaited
        // inline. That is what keeps the keepalive alive during a long
        // inference: `handle_inbound` hands the blocking `engine.generate`
        // call to `spawn_blocking` and `.await`s the join handle, so while
        // a completion runs for minutes on a blocking thread this `select!`
        // keeps cycling and answers the advisor's pings/heartbeats. Awaiting
        // `handle_inbound` inline (the previous shape) would instead pin the
        // whole loop on that one await and miss every ping until it
        // returned — the advisor would reset us mid-job.
        //
        // `FuturesUnordered` holds a single anonymous future type (the one
        // `async move` block below, at one source location), so no boxing is
        // needed. The advisor has no per-provider single-flight gate, so if
        // it routes a second job while the first is in flight both run
        // concurrently (each on its own blocking thread) rather than the
        // second waiting behind the first.
        let mut inflight = FuturesUnordered::new();
        // Inference jobs emit chunks while generation is still running;
        // the blocking engine thread forwards plaintext deltas here and
        // the async side seals + writes them to the advisor immediately.
        let (outbound_tx, mut outbound_rx) = mpsc::unbounded_channel::<String>();
        // When this connection began. After a sustained clean uptime we
        // clear the crash counter (below) so a future "N crashes recently"
        // distinguishes a flapping machine from one that hiccuped once long
        // ago. Until then every heartbeat carries the counter, so the
        // advisor sees a crash-looping machine even though the current
        // process is up.
        let loop_started = std::time::Instant::now();
        let mut crash_count_reset = false;
        // Read-idle watchdog state: when did we last hear ANYTHING from the
        // advisor (a keepalive ping, a job, a control frame)? If that goes
        // stale the link is dead even though `read.next()` hasn't returned —
        // see RECV_IDLE_TIMEOUT.
        let mut last_recv = std::time::Instant::now();
        let mut idle_check = tokio::time::interval(IDLE_CHECK_INTERVAL);
        idle_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        idle_check.tick().await; // consume the immediate first tick
        loop {
            tokio::select! {
                _ = idle_check.tick() => {
                    if last_recv.elapsed() >= RECV_IDLE_TIMEOUT {
                        tracing::warn!(
                            idle_s = last_recv.elapsed().as_secs(),
                            "no frames from advisor within the idle window — link presumed dead (network drop / sleep); reconnecting"
                        );
                        return Err(ProviderError::Advisor("advisor read-idle timeout".into()));
                    }
                }
                _ = hb.tick() => {
                    if !crash_count_reset && loop_started.elapsed() >= CRASH_COUNT_RESET_AFTER {
                        crate::diagnostics::reset_crash_count();
                        crash_count_reset = true;
                    }
                    let m = AdvisorMessage::Heartbeat(Heartbeat {
                        load: 0.0,
                        queue_depth: inflight.len() as u32,
                        at: Utc::now(),
                        active: Some(active),
                        crash: crate::diagnostics::crash_signature(),
                    });
                    let s = serde_json::to_string(&m).map_err(|e| ProviderError::Advisor(e.to_string()))?;
                    write.send(Message::Text(s.into()))
                        .await
                        .map_err(|e| ProviderError::Advisor(e.to_string()))?;
                }
                // Slow poll: re-read the owner's start/stop switch off our
                // PDS as the fallback for a missed nudge. The read runs in
                // `active_reads` (below), never inline, so it can't stall
                // ping handling.
                _ = active_poll.tick() => {
                    // Per-model schedule boundary: if a window opened or closed
                    // since this serve started, the active set changed — reload
                    // by restarting (engines are built once per serve). Local +
                    // cheap, and independent of the PDS read, so it works even
                    // without a provider_rkey. Skipped entirely when no per-model
                    // schedules are set (the common case).
                    if !model_schedules.is_empty() {
                        let active_now = model_schedules.active_now(configured_models);
                        if models_changed(&active_now, &active_at_start) {
                            tracing::info!(
                                from = ?active_at_start, to = ?active_now,
                                "a model's schedule window changed the active set; restarting to reload engines"
                            );
                            // process::exit runs no destructors, so reap the
                            // engine subprocesses here — otherwise their Drop
                            // never fires and the Python children orphan.
                            ctx.engines.terminate_all();
                            std::process::exit(3);
                        }
                    }
                    if active_reads.is_empty() {
                        if let Some(rk) = provider_rkey {
                            active_reads.push(read_provider_control(pds, rk));
                        }
                    }
                }
                // A control re-read finished. Honour two owner changes: a
                // stop (disconnect) and a model-set edit (restart to reload).
                Some(maybe_control) = active_reads.next(), if !active_reads.is_empty() => {
                    // A `None` here means the control read couldn't be resolved
                    // this cycle (the console proxy fronting the PDS read 502'd,
                    // or the record momentarily didn't list) — owner intent is
                    // UNKNOWN, so skip reconciliation entirely. Acting on the old
                    // read-error defaults (best-effort tier + empty models) is
                    // what made a transient blip look like the owner opting out
                    // of confidential / clearing their models and trip a spurious
                    // restart loop. Wait for the next poll / nudge instead.
                    let Some((next_active, desired, desired_tier, tool_calls)) = maybe_control else {
                        tracing::debug!("provider-control read unresolved this cycle; skipping reconciliation");
                        continue;
                    };
                    if !next_active {
                        // Owner stopped us — disconnect and let the outer loop
                        // hold us out of the registry until they start us again.
                        tracing::info!("owner stopped this machine from the console; disconnecting");
                        return Ok(());
                    }
                    if tier_changed(desired_tier.as_deref(), desired_tier_at_start) {
                        // Owner changed this machine's trust tier on the console
                        // (opted in to / out of attested-confidential). The
                        // confidential path needs a different process shape — the
                        // measured push-receiver bundle vs. the default CLI — which
                        // only the supervisor can select at spawn. Exit non-zero so
                        // launchd / the app supervisor respawns; the fresh boot reads
                        // the new tier and the supervisor picks the right binary.
                        tracing::info!(
                            from = ?desired_tier_at_start, to = ?desired_tier,
                            "owner changed this machine's trust tier from the console; restarting to re-select the worker"
                        );
                        // Reap engine subprocesses before the destructor-
                        // skipping exit — confidential serves in-process, so
                        // a leaked best-effort child would linger with no
                        // owner. (See terminate_all.)
                        ctx.engines.terminate_all();
                        std::process::exit(3);
                    }
                    if models_changed(&desired, desired_at_start) {
                        // Owner edited the model set on the website. Engines
                        // are built once per serve, so reload by restarting:
                        // exit non-zero (launchd KeepAlive is SuccessfulExit
                        // =false; the app supervisor respawns any unintended
                        // exit) and the fresh serve loads the new set.
                        tracing::info!(
                            from = ?desired_at_start, to = ?desired,
                            "owner changed this machine's models from the console; restarting to reload engines"
                        );
                        // Reap engine subprocesses before the destructor-
                        // skipping exit so the old model's child doesn't
                        // orphan while the fresh serve loads the new set.
                        ctx.engines.terminate_all();
                        std::process::exit(3);
                    }
                    if tool_calls != tool_calls_at_start {
                        // Owner flipped the tool-calling switch on the console.
                        // The per-model tool-call parser is chosen at engine
                        // build time, so reload the same way a model-set edit
                        // does: reap children and exit non-zero for the
                        // supervisor to respawn into a fresh serve that reads
                        // the new intent.
                        tracing::info!(
                            from = tool_calls_at_start, to = tool_calls,
                            "owner changed this machine's tool-calling setting from the console; restarting to rebuild engines"
                        );
                        ctx.engines.terminate_all();
                        std::process::exit(3);
                    }
                }
                // Engine health watchdog tick: kick off a check unless one
                // is already in flight. The check + any restart runs on a
                // blocking thread so this loop keeps answering pings.
                _ = health_poll.tick() => {
                    if health_checks.is_empty() {
                        let entries = ctx.engines.entries();
                        // Only subprocess engines can die; if there's nothing
                        // but the always-ready stub, skip the spawn entirely.
                        if entries.iter().any(|(m, _)| m.as_str() != "stub") {
                            health_checks.push(tokio::task::spawn_blocking(move || {
                                check_and_restart_engines(entries)
                            }));
                        }
                    }
                }
                // A health check finished. If any engine is dead-and-
                // unrecoverable, restart the agent: the fresh serve runs
                // build_engines() again, rebuilds supportedModels from the
                // live set, and re-publishes the provider record (with an
                // engineFault) + Register — the authoritative path the
                // advisor's matchmaking reads, so it stops routing the dead
                // model. A recovered engine just keeps serving (no exit).
                Some(res) = health_checks.next(), if !health_checks.is_empty() => {
                    // A panicked/cancelled health task (JoinError) must not
                    // take down serving — treat it as "nothing dead".
                    let dead = res.unwrap_or_default();
                    if !dead.is_empty() {
                        tracing::error!(
                            models = ?dead,
                            "inference engine(s) died and could not be restarted; restarting agent to re-register without them"
                        );
                        // Exit non-zero so launchd KeepAlive (SuccessfulExit
                        // =false) / the app supervisor respawn us. A distinct
                        // code from the model-change reload (exit 3) keeps the
                        // two causes apart in logs. Reap first: the engines
                        // that AREN'T dead would otherwise orphan past this
                        // destructor-skipping exit (terminate is a no-op on
                        // the already-dead ones).
                        ctx.engines.terminate_all();
                        std::process::exit(7);
                    }
                }
                // An on-demand self-right finished. Report the outcome to the
                // advisor and update the local bad-standing marker the tray +
                // console read. If engines came back (or there were none to
                // recover — a transiently-wedged loop that's now pumping),
                // recovered=true and we clear the marker; if an engine is
                // dead-and-unrecoverable, recovered=false with remediation
                // detail, then we restart the agent so a fresh serve
                // re-registers without the dead model (the same escalation the
                // periodic watchdog uses).
                Some(res) = recover_checks.next(), if !recover_checks.is_empty() => {
                    let dead = res.unwrap_or_default();
                    let (recovered, detail) = if dead.is_empty() {
                        clear_bad_standing();
                        (true, None)
                    } else {
                        let detail = format!(
                            "inference engine(s) {dead:?} could not be restarted; the machine is restarting to recover"
                        );
                        write_bad_standing(Some(&detail));
                        (false, Some(detail))
                    };
                    let m = AdvisorMessage::RecoverResult(crate::protocol::RecoverResult {
                        recovered,
                        detail: detail.clone(),
                    });
                    let s = serde_json::to_string(&m)
                        .map_err(|e| ProviderError::Advisor(e.to_string()))?;
                    write.send(Message::Text(s.into()))
                        .await
                        .map_err(|e| ProviderError::Advisor(e.to_string()))?;
                    if !recovered {
                        tracing::error!(
                            models = ?dead,
                            "self-right could not restart engine(s); restarting agent to re-register without them"
                        );
                        // Reap surviving engines before the destructor-
                        // skipping exit (no-op on the dead ones).
                        ctx.engines.terminate_all();
                        std::process::exit(7);
                    }
                    tracing::info!("self-right succeeded; cleared bad-standing");
                }
                Some(payload) = outbound_rx.recv() => {
                    write.send(Message::Text(payload.into()))
                        .await
                        .map_err(|e| ProviderError::Advisor(e.to_string()))?;
                }
                // APNs code-identity challenge (confidential tier). The push
                // host on the main thread forwarded an `E_K(nonce)` payload:
                // open it with `K`, SE-sign the recovered nonce, and emit a
                // `CodeAttestationResponse` over the existing outbound channel
                // so the advisor can mark this measured binary `codeAttested`.
                // Inert when `push_rx` is None (non-apns / headless).
                Some(payload) = next_push(&mut push_rx) => {
                    // Bind our measured cdHash (the value we registered) into the
                    // signed code-attestation, so the proof is tied to this binary.
                    match handle_code_challenge_payload(encryption, signer, &payload, my_cd_hash.as_deref()) {
                        Ok(Some(resp)) => {
                            match serde_json::to_string(&AdvisorMessage::CodeAttestationResponse(resp)) {
                                Ok(s) => {
                                    // Route through outbound_tx so the single
                                    // `write` half stays uncontended.
                                    let _ = outbound_tx.send(s);
                                    tracing::info!("answered APNs code-identity challenge");
                                }
                                Err(e) => tracing::warn!(error = %e, "serialize code-attestation response failed"),
                            }
                        }
                        Ok(None) => tracing::warn!("code-identity push payload was not a parseable challenge"),
                        Err(e) => tracing::warn!(error = %e, "failed to answer code-identity challenge"),
                    }
                }
                // An in-flight job finished — flush its replies. Guarded so
                // the branch is disabled (rather than spinning on a `None`)
                // when nothing is in flight.
                Some(replies) = inflight.next(), if !inflight.is_empty() => {
                    for reply in replies? {
                        let s = serde_json::to_string(&reply)
                            .map_err(|e| ProviderError::Advisor(e.to_string()))?;
                        write.send(Message::Text(s.into()))
                            .await
                            .map_err(|e| ProviderError::Advisor(e.to_string()))?;
                    }
                }
                msg = read.next() => {
                    match msg {
                        None => {
                            tracing::warn!("advisor closed connection");
                            return Ok(());
                        }
                        Some(Err(e)) => return Err(ProviderError::Advisor(e.to_string())),
                        Some(Ok(Message::Text(t))) => {
                            last_recv = std::time::Instant::now();
                            // Peek for control frames the advisor expects an
                            // INSTANT answer to. These must be handled right
                            // here on the serve loop — NOT parked in `inflight`
                            // — so a `pong` proves this loop is pumping even
                            // while a long inference runs on a blocking thread.
                            match serde_json::from_str::<AdvisorMessage>(&t) {
                                Ok(AdvisorMessage::Ping(p)) => {
                                    // Liveness preflight: answer immediately.
                                    let pong = AdvisorMessage::Pong(Pong { nonce: p.nonce });
                                    let s = serde_json::to_string(&pong)
                                        .map_err(|e| ProviderError::Advisor(e.to_string()))?;
                                    write.send(Message::Text(s.into()))
                                        .await
                                        .map_err(|e| ProviderError::Advisor(e.to_string()))?;
                                }
                                Ok(AdvisorMessage::HealthNotice(h)) => {
                                    // The advisor changed our standing — surface
                                    // it (or clear it) for the menu-bar app.
                                    match h.standing {
                                        HealthStanding::Bad => write_bad_standing(h.reason.as_deref()),
                                        HealthStanding::Ok => clear_bad_standing(),
                                    }
                                }
                                Ok(AdvisorMessage::ControlChanged(_)) => {
                                    // The owner changed something on the console
                                    // (start/stop switch or model set) — re-read
                                    // now (off-loop) so it takes effect in ~a
                                    // second instead of at the next 30s poll.
                                    if let Some(rk) = provider_rkey {
                                        active_reads.push(read_provider_control(pds, rk));
                                    }
                                }
                                Ok(AdvisorMessage::RecoverRequest(rr)) => {
                                    // We've been flagged unhealthy — try to
                                    // self-right NOW rather than waiting for the
                                    // next 30s health tick. Run the engine
                                    // health-check + bounded restart off-loop;
                                    // the result branch reports the outcome.
                                    tracing::warn!(
                                        reason = ?rr.reason,
                                        "advisor requested self-right; running engine recovery"
                                    );
                                    if recover_checks.is_empty() {
                                        let entries = ctx.engines.entries();
                                        recover_checks.push(tokio::task::spawn_blocking(move || {
                                            check_and_restart_engines(entries)
                                        }));
                                    }
                                }
                                // Everything else (inference, attestation, …) is
                                // parked in `inflight` at a single source location
                                // so `FuturesUnordered` sees one future type.
                                _ => {
                                    let live = outbound_tx.clone();
                                    inflight.push(async move {
                                        // Isolate each job behind a catch_unwind
                                        // boundary: a panic in one handler (a bad
                                        // frame, an engine edge case) is recorded
                                        // by the panic hook (last-panic.txt + the
                                        // crash signature) but MUST NOT unwind into
                                        // the serve loop and take the whole agent
                                        // down. One bad job ≠ a dead machine.
                                        use futures_util::FutureExt;
                                        let job = async move {
                                            match serde_json::from_str::<AdvisorMessage>(&t) {
                                                Ok(AdvisorMessage::InferenceRequest(req)) => {
                                                    Ok(handle_inference_request_live(req, ctx, live).await)
                                                }
                                                _ => handle_inbound(&t, ctx).await,
                                            }
                                        };
                                        match std::panic::AssertUnwindSafe(job).catch_unwind().await {
                                            Ok(replies) => replies,
                                            Err(_) => {
                                                tracing::error!(
                                                    "a job handler panicked; isolated it (see ~/.cocore/last-panic.txt) — connection stays up"
                                                );
                                                Ok(Vec::new())
                                            }
                                        }
                                    });
                                }
                            }
                        }
                        Some(Ok(Message::Ping(payload))) => {
                            last_recv = std::time::Instant::now();
                            // Answer the advisor's keepalive ping IMMEDIATELY.
                            // The advisor pings every 30s and terminates any
                            // socket that misses a pong for one interval. A
                            // tokio-tungstenite split stream only flushes its
                            // auto-pong on our next write (the 30s heartbeat),
                            // so the pong races the advisor's deadline and
                            // often loses — the advisor then resets us and we
                            // reconnect, over and over (the flapping). Sending
                            // the pong here, from the read half, flushes it now.
                            //
                            // This now holds even MID-INFERENCE: the engine
                            // call runs on a `spawn_blocking` thread parked in
                            // `inflight`, so this loop is free to receive the
                            // ping and flush the pong while generation runs.
                            write.send(Message::Pong(payload))
                                .await
                                .map_err(|e| ProviderError::Advisor(e.to_string()))?;
                        }
                        Some(Ok(Message::Close(_))) => return Ok(()),
                        _ => {}
                    }
                }
            }
        }
    }
}

/// Read the owner's controls (start/stop switch + desired model set) off our
/// PDS. A free fn (rather than two inline `async` blocks) so both
/// `active_reads.push` sites produce the SAME future type — `FuturesUnordered`
/// holds one anonymous type. `None` means the read couldn't be resolved (a
/// transient blip); the caller skips reconciliation rather than acting on
/// read-error defaults.
async fn read_provider_control(
    pds: &PdsClient,
    rkey: &str,
) -> Option<(bool, Vec<String>, Option<String>, bool)> {
    pds.get_provider_control(rkey).await
}

/// Whether two `desiredTier` values differ, normalising `None` to the
/// best-effort default so an absent field and an explicit `"best-effort"` are
/// the same thing (no spurious restart). A real change — e.g. the owner opting
/// into `attested-confidential` from the console, or back out — returns true,
/// which restarts the agent so the supervisor re-selects the right binary.
fn tier_changed(a: Option<&str>, b: Option<&str>) -> bool {
    let norm = |t: Option<&str>| match t {
        Some("attested-confidential") => "attested-confidential",
        _ => "best-effort",
    };
    norm(a) != norm(b)
}

/// Whether two model sets differ, ignoring order and duplicates — so a
/// reorder or a dupe in the owner's list isn't mistaken for a real change.
fn models_changed(a: &[String], b: &[String]) -> bool {
    let norm = |v: &[String]| {
        let mut s: Vec<&str> = v.iter().map(String::as_str).collect();
        s.sort_unstable();
        s.dedup();
        s.into_iter().map(str::to_string).collect::<Vec<_>>()
    };
    norm(a) != norm(b)
}

/// Environment escape hatch that permits a plaintext (`ws://`) advisor URL.
/// Set to `1`/`true` only for local development against a non-TLS advisor.
const ALLOW_INSECURE_ADVISOR_ENV: &str = "COCORE_ALLOW_INSECURE_ADVISOR";

/// Env var overriding the advisor's DID (the `aud` of the service-auth JWT we
/// mint for registration). Defaults to the production advisor's `did:web`.
const ADVISOR_DID_ENV: &str = "COCORE_ADVISOR_DID";

/// Default advisor DID when `COCORE_ADVISOR_DID` is unset.
const DEFAULT_ADVISOR_DID: &str = "did:web:advisor.cocore.dev";

/// The `lxm` (lexicon method) the registration service-auth JWT is scoped to.
/// The advisor checks the token was minted for exactly this method.
const REGISTER_LXM: &str = "dev.cocore.compute.register";

/// The advisor's DID used as the service-auth `aud`, from `COCORE_ADVISOR_DID`
/// or the production default. An empty/whitespace override falls back to the
/// default rather than minting a token bound to an empty audience.
fn advisor_did() -> String {
    match std::env::var(ADVISOR_DID_ENV) {
        Ok(v) if !v.trim().is_empty() => v.trim().to_string(),
        _ => DEFAULT_ADVISOR_DID.to_string(),
    }
}

/// Reject a non-`wss://` advisor URL unless the operator has explicitly opted
/// into insecure transport. Without TLS the advisor connection is trivially
/// MITM-able: an attacker on the path can inject `InferenceRequest`s (making
/// this machine serve arbitrary work) or forge control frames
/// (`ControlChanged`, `RecoverRequest`, `HealthNotice`). The default advisor
/// URL is `wss://`, so a `ws://` (or any other scheme) is a downgrade we refuse
/// unless `COCORE_ALLOW_INSECURE_ADVISOR` is truthy.
fn require_secure_advisor_url(url: &str) -> Result<()> {
    let scheme = url.split("://").next().unwrap_or("").to_ascii_lowercase();
    if scheme == "wss" {
        return Ok(());
    }
    let allow_insecure = std::env::var(ALLOW_INSECURE_ADVISOR_ENV)
        .map(|v| matches!(v.trim(), "1" | "true" | "TRUE" | "yes"))
        .unwrap_or(false);
    if scheme == "ws" && allow_insecure {
        tracing::warn!(
            url = %url,
            "connecting to advisor over PLAINTEXT ws:// because {ALLOW_INSECURE_ADVISOR_ENV} is set — \
             the connection is not encrypted and can be MITM'd; use this only for local development"
        );
        return Ok(());
    }
    Err(ProviderError::Advisor(format!(
        "refusing to connect to advisor over insecure transport: {url:?} (scheme {scheme:?}). \
         Use a wss:// URL, or set {ALLOW_INSECURE_ADVISOR_ENV}=1 to allow ws:// for local dev."
    )))
}

/// Classify a WebSocket connect failure into the machine-readable class the
/// `advisorFault` lexicon field carries. Only ever called for CONNECT-phase
/// errors (the handshake never completed), so every class here means "the
/// Register frame never reached the advisor". Deliberately coarse: the class
/// is published on a world-readable record, so it names the error KIND and
/// nothing else (no addresses, no raw error text).
fn classify_ws_connect_error(e: &tokio_tungstenite::tungstenite::Error) -> String {
    use tokio_tungstenite::tungstenite::Error as WsError;
    match e {
        // The upgrade got a plain HTTP answer instead of 101 — the advisor
        // host (or something in front of it) answered HTTP but refused the
        // WebSocket handshake.
        WsError::Http(resp) => format!("http-{}", resp.status().as_u16()),
        WsError::Io(io) => classify_connect_io_error(io),
        WsError::Url(_) => "bad-url".to_string(),
        // Everything else (TLS, protocol violations, …) — tungstenite's TLS
        // variant is feature-gated, so sniff the rendered error rather than
        // matching it structurally.
        other => {
            let s = other.to_string().to_ascii_lowercase();
            if s.contains("tls") || s.contains("certificate") || s.contains("ssl") {
                "tls-failure".to_string()
            } else {
                "ws-handshake-failed".to_string()
            }
        }
    }
}

/// Classify the io::Error under a failed WebSocket connect. DNS failures have
/// no dedicated `ErrorKind` on the platforms we ship (they surface as an
/// uncategorized getaddrinfo error), so those fall back to message sniffing.
fn classify_connect_io_error(io: &std::io::Error) -> String {
    use std::io::ErrorKind;
    match io.kind() {
        ErrorKind::TimedOut => "connect-timeout".to_string(),
        ErrorKind::ConnectionRefused => "connect-refused".to_string(),
        ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted | ErrorKind::BrokenPipe => {
            "connection-reset".to_string()
        }
        _ => {
            let s = io.to_string().to_ascii_lowercase();
            if s.contains("lookup")
                || s.contains("resolve")
                || s.contains("nodename")
                || s.contains("name or service")
                || s.contains("dns")
            {
                "dns-failure".to_string()
            } else if s.contains("network is unreachable")
                || s.contains("no route to host")
                || s.contains("host is down")
            {
                "network-unreachable".to_string()
            } else if s.contains("tls") || s.contains("certificate") || s.contains("ssl") {
                "tls-failure".to_string()
            } else {
                "io-error".to_string()
            }
        }
    }
}

/// Best-effort probe of the advisor's plain-HTTPS surface (`GET /ttft`, its
/// cheap public endpoint), used when the WebSocket connect keeps failing.
/// ANY HTTP response counts as reachable — it proves DNS + TCP + TLS + HTTP
/// to the advisor host all work, which is exactly the signal that separates
/// "this network filters WebSocket upgrades" (a middlebox) from "this
/// machine can't reach the advisor at all".
pub async fn probe_advisor_https(advisor_url: &str) -> bool {
    let Some(url) = advisor_https_probe_url(advisor_url) else {
        return false;
    };
    let Ok(client) = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(15))
        .build()
    else {
        return false;
    };
    match client.get(&url).send().await {
        Ok(resp) => {
            tracing::debug!(status = %resp.status(), "advisor HTTPS probe answered");
            true
        }
        Err(e) => {
            tracing::debug!(error = %e, "advisor HTTPS probe failed");
            false
        }
    }
}

/// `wss://host[:port]/…` → `https://host[:port]/ttft` (and `ws://` →
/// `http://` for local dev). `None` when the advisor URL has no
/// recognizable scheme/authority.
fn advisor_https_probe_url(advisor_url: &str) -> Option<String> {
    let (scheme, rest) = advisor_url.split_once("://")?;
    let authority = rest.split('/').next()?;
    if authority.is_empty() {
        return None;
    }
    let http_scheme = match scheme.to_ascii_lowercase().as_str() {
        "wss" | "https" => "https",
        "ws" | "http" => "http",
        _ => return None,
    };
    Some(format!("{http_scheme}://{authority}/ttft"))
}

/// Build the `advisorFault` body from a classified connect-failure code and
/// the outcome of the plain-HTTPS probe. The probe result FOLDS INTO the
/// classification: ambiguous network-ish failures with working HTTPS become
/// `upgrade-blocked` (a middlebox is filtering WebSockets specifically),
/// while a failed probe keeps the base code and says the advisor is
/// unreachable outright. Every message is a fixed, content-safe template —
/// remediation guidance only, never raw error text, URLs, or credentials.
pub fn build_advisor_fault(base_code: &str, https_reachable: bool) -> crate::pds::AdvisorFault {
    const RETRYING: &str = "The machine keeps serving locally and retries automatically; \
        it will rejoin the network on its own the moment a connection succeeds.";
    let (code, message): (String, String) = if https_reachable {
        match base_code {
            // A real HTTP answer to the upgrade: the advisor host is
            // reachable; the WebSocket endpoint itself said no.
            c if c.starts_with("http-") => (
                c.to_string(),
                format!(
                    "The co/core network service is reachable, but it answered this machine's \
                     WebSocket handshake with a plain HTTP error instead of accepting it. This \
                     is usually transient (a deploy or an edge hiccup). {RETRYING} If it \
                     persists for hours, check status with the co/core team."
                ),
            ),
            "tls-failure" => (
                "tls-failure".to_string(),
                format!(
                    "Secure-connection (TLS) setup for this machine's WebSocket to the co/core \
                     network failed even though plain HTTPS works — a TLS-intercepting proxy or \
                     security appliance on this network is the usual cause. {RETRYING} Try a \
                     network without TLS inspection, or exempt WebSocket traffic from it."
                ),
            ),
            // Timeouts, resets, refusals, protocol failures with HTTPS fine:
            // something on the path accepts HTTPS but kills WebSockets.
            _ => (
                "upgrade-blocked".to_string(),
                format!(
                    "This machine reaches the co/core network service over plain HTTPS, but its \
                     WebSocket connection — the channel jobs are dispatched over — cannot be \
                     established. A firewall, VPN, or proxy on this network is likely filtering \
                     WebSocket connections. {RETRYING} Try a different network, disable the \
                     VPN/proxy, or allow outbound secure WebSocket (wss) traffic."
                ),
            ),
        }
    } else {
        match base_code {
            "dns-failure" => (
                "dns-failure".to_string(),
                format!(
                    "This machine could not look up the co/core network service's address (DNS \
                     resolution failed). {RETRYING} Check this machine's internet connection, \
                     DNS settings, or any VPN/firewall software."
                ),
            ),
            "connect-timeout" => (
                "connect-timeout".to_string(),
                format!(
                    "Connection attempts to the co/core network service time out — neither its \
                     WebSocket nor plain HTTPS answered. {RETRYING} Check this machine's \
                     internet connection and any VPN/firewall software."
                ),
            ),
            "connect-refused" => (
                "connect-refused".to_string(),
                format!(
                    "The co/core network service actively refused this machine's connection, \
                     and plain HTTPS did not answer either — a local proxy or firewall is \
                     likely intercepting outbound traffic. {RETRYING} Check any VPN/proxy/\
                     firewall software on this machine or network."
                ),
            ),
            "tls-failure" => (
                "tls-failure".to_string(),
                format!(
                    "Secure-connection (TLS) setup to the co/core network service failed. \
                     {RETRYING} Check this machine's date & time, and any VPN or security \
                     software that inspects network traffic."
                ),
            ),
            "network-unreachable" => (
                "network-unreachable".to_string(),
                format!(
                    "This machine has no network route to the co/core network service. \
                     {RETRYING} Check this machine's internet connection."
                ),
            ),
            other => (
                other.to_string(),
                format!(
                    "This machine cannot establish its connection to the co/core network \
                     service (checked both WebSocket and plain HTTPS). {RETRYING} Check this \
                     machine's internet connection and any VPN/firewall software."
                ),
            ),
        }
    };
    crate::pds::AdvisorFault {
        code,
        message,
        observedAt: Utc::now(),
    }
}

/// How often the serve loop checks that every previously-ready engine's
/// subprocess is still alive. The check itself is a cheap non-blocking
/// `try_wait` per engine, so a tight-ish interval is fine; 30s bounds how
/// long a dead engine can keep being advertised before we restart it or
/// restart the agent to re-register without it.
const ENGINE_HEALTH_INTERVAL: Duration = Duration::from_secs(30);

/// Bound on a single advisor connect attempt. A reconnect made while the
/// network is only half-up (just came back, captive portal, DNS slow) can
/// otherwise hang with no error and strand the machine offline; on timeout
/// we bail to the reconnect loop and try again.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// How often the read-idle watchdog checks the link.
const IDLE_CHECK_INTERVAL: Duration = Duration::from_secs(15);

/// No frame from the advisor within this window ⇒ the link is silently dead
/// (network drop, laptop sleep/wake, Wi-Fi change) and we reconnect. The
/// advisor keepalive-pings every ~25s, so this is ~3 missed pings — long
/// enough to ride out jitter, short enough that a half-open socket doesn't
/// keep the machine "serving" against a dead connection (offline, silently)
/// for the minutes a TCP write can take to finally error.
const RECV_IDLE_TIMEOUT: Duration = Duration::from_secs(70);

/// While streaming a long generation, send an `InferenceKeepalive` to the
/// advisor at most this often during gaps with no user-visible token (slow
/// prefill / slow decode), so the advisor doesn't mistake a slow-but-alive
/// job for a silent machine. Comfortably under the advisor's session idle
/// budget, so several may be missed before any timeout.
const STREAM_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);

/// How long a connection must stay up before we clear the durable crash
/// counter. Long enough that a machine which reconnects only to crash
/// again still reports its prior crashes to the advisor (so flapping is
/// visible), short enough that a genuinely-recovered machine stops
/// reporting stale crashes within a few minutes.
const CRASH_COUNT_RESET_AFTER: Duration = Duration::from_secs(300);

/// Attempts to respawn a single dead engine's child before giving up on
/// it. A restart reuses already-downloaded weights, so it's fast when it
/// works; when it can't (e.g. the machine is out of memory) the child
/// exits during startup and `start()` bails quickly, so a small bound is
/// enough to ride out a transient blip without dragging out an
/// unrecoverable one.
const ENGINE_RESTART_MAX_ATTEMPTS: u32 = 2;

/// Backoff between restart attempts for one engine.
const ENGINE_RESTART_BACKOFF: Duration = Duration::from_secs(3);

/// Check every engine and restart any whose child has died. Runs on a
/// blocking thread — [`Engine::restart`] spawns a subprocess and blocks
/// on its readiness probe — so the caller hands this to `spawn_blocking`
/// and parks the join handle off the hot serve loop.
///
/// Returns the model ids that are dead AND could not be brought back
/// within [`ENGINE_RESTART_MAX_ATTEMPTS`]. The caller treats a non-empty
/// list as "this connection is advertising a model it can no longer
/// serve" and restarts the agent so the next boot re-registers (and
/// re-publishes the provider record) without the dead model.
fn check_and_restart_engines(entries: Vec<(String, Arc<dyn Engine>)>) -> Vec<String> {
    let mut unrecoverable = Vec::new();
    for (model, engine) in entries {
        if engine.ready() {
            continue;
        }
        tracing::warn!(
            model = %model,
            engine = engine.name(),
            "inference engine no longer ready (subprocess died); attempting bounded restart"
        );
        let mut recovered = false;
        for attempt in 1..=ENGINE_RESTART_MAX_ATTEMPTS {
            match engine.restart() {
                Ok(()) if engine.ready() => {
                    tracing::info!(model = %model, attempt, "inference engine restarted");
                    recovered = true;
                    break;
                }
                Ok(()) => {
                    tracing::warn!(
                        model = %model,
                        attempt,
                        "inference engine restart returned but engine still not ready"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        model = %model,
                        attempt,
                        error = %format!("{e:#}"),
                        "inference engine restart failed"
                    );
                }
            }
            if attempt < ENGINE_RESTART_MAX_ATTEMPTS {
                std::thread::sleep(ENGINE_RESTART_BACKOFF);
            }
        }
        if !recovered {
            unrecoverable.push(model);
        }
    }
    unrecoverable
}

/// Parse one inbound advisor frame and produce the replies, if any.
/// Some frames (e.g. AttestationChallenge) elicit one reply; others
/// (InferenceRequest) elicit two — a chunk plus a completion.
async fn handle_inbound(text: &str, ctx: &ServeContext<'_>) -> Result<Vec<AdvisorMessage>> {
    let parsed: AdvisorMessage = match serde_json::from_str(text) {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(error = %e, frame = %text, "ignoring unparseable advisor frame");
            return Ok(Vec::new());
        }
    };
    match parsed {
        AdvisorMessage::AttestationChallenge(c) => {
            let resp = build_challenge_response(&c, ctx.signer)?;
            tracing::debug!(nonce = %c.nonce, "answered attestation challenge");
            Ok(vec![AdvisorMessage::AttestationResponse(resp)])
        }
        AdvisorMessage::InferenceRequest(req) => Ok(handle_inference_request(req, ctx).await),
        // Ping / HealthNotice / ControlChanged / RecoverRequest are
        // intercepted on the serve loop (see `run`) and never reach here;
        // Pong/Register/RecoverResult/etc. are frames we emit or never
        // receive. All no-ops at the handler level.
        AdvisorMessage::Register(_)
        | AdvisorMessage::Heartbeat(_)
        | AdvisorMessage::InferenceChunk(_)
        | AdvisorMessage::InferenceKeepalive(_)
        | AdvisorMessage::InferenceComplete(_)
        | AdvisorMessage::AttestationResponse(_)
        | AdvisorMessage::Ping(_)
        | AdvisorMessage::Pong(_)
        | AdvisorMessage::HealthNotice(_)
        | AdvisorMessage::ControlChanged(_)
        | AdvisorMessage::RecoverRequest(_)
        | AdvisorMessage::RecoverResult(_)
        // SessionKey is a frame the provider EMITS for the confidential tier,
        // never one it receives.
        | AdvisorMessage::SessionKey(_)
        // CodeAttestationResponse is likewise provider→advisor only; the APNs
        // challenge arrives out-of-band over the push channel (see push_host),
        // not on this socket.
        | AdvisorMessage::CodeAttestationResponse(_) => {
            tracing::debug!("advisor sent a message we don't act on");
            Ok(Vec::new())
        }
    }
}

/// Serialize an advisor frame and push it onto the live outbound
/// channel when streaming, or collect it for tests / offline replay.
fn push_frame(
    live_tx: Option<&mpsc::UnboundedSender<String>>,
    collected: &mut Vec<AdvisorMessage>,
    msg: AdvisorMessage,
) {
    if let Some(tx) = live_tx {
        if let Ok(payload) = serde_json::to_string(&msg) {
            let _ = tx.send(payload);
        }
    } else {
        collected.push(msg);
    }
}

/// Production path: stream chunks to the advisor while generation runs.
async fn handle_inference_request_live(
    req: InferenceRequest,
    ctx: &ServeContext<'_>,
    live_tx: mpsc::UnboundedSender<String>,
) -> Vec<AdvisorMessage> {
    handle_inference_request_inner(req, ctx, Some(live_tx)).await
}

async fn handle_inference_request(
    req: InferenceRequest,
    ctx: &ServeContext<'_>,
) -> Vec<AdvisorMessage> {
    handle_inference_request_inner(req, ctx, None).await
}

async fn handle_inference_request_inner(
    req: InferenceRequest,
    ctx: &ServeContext<'_>,
    live_tx: Option<mpsc::UnboundedSender<String>>,
) -> Vec<AdvisorMessage> {
    let session_id = req.session_id.clone();
    let started_at = Utc::now();

    // Belt-and-suspenders model gate. The advisor's matchmaking
    // already filters by `supportedModels` from our Register frame,
    // so an honest advisor never routes us a request for a model we
    // didn't advertise — but the agent shouldn't trust the network
    // for that. Reject mismatches with a sealed error chunk so the
    // requester sees a real signal instead of the stub engine
    // pretending to be whatever they asked for.
    // Model-fit check moves inline into the engine lookup below —
    // `ctx.engines.for_model(req.model)` returns `None` for any
    // model the registry didn't load, and we reject with a sealed
    // error chunk there. Single source of truth.

    // Decrypted prompt bytes. Wrapped in `Zeroizing` so the heap
    // memory is wiped on drop instead of merely freed — defense in
    // depth against the agent process being core-dumped or having
    // its pages swapped to disk after a panic. The advisor itself
    // never sees these bytes; this is the first and only place in
    // the agent where the plaintext exists.
    let plaintext: Zeroizing<Vec<u8>> = match ctx
        .encryption
        .open_from(&req.requester_pub_key, &req.ciphertext)
    {
        Ok(pt) => Zeroizing::new(pt),
        Err(e) => {
            tracing::warn!(error = %e, session_id = %session_id, "failed to open inference ciphertext");
            return Vec::new();
        }
    };

    // Best-effort mlock: ask the kernel not to swap the pages
    // backing the plaintext buffer. Failure is non-fatal — on Macs
    // with the default `memorystatus`-controlled rlimits an mlock
    // call may be denied, in which case we keep going (the
    // Zeroizing wrapper still wipes on drop).
    mlock_buffer(&plaintext);

    // Build a chat-completions-shaped messages list from the
    // plaintext. The byte layout is described by `input_format`:
    //   * absent / "text" (legacy): the bytes are a raw flattened prompt
    //     string; re-wrap the whole thing as a single user message.
    //   * "messages-v1": the bytes are the canonical multimodal envelope
    //     (text + inline images); parse them into structured messages so
    //     vision models get their image parts.
    // The commitment is taken over `plaintext` below regardless of format,
    // so a parse failure here only means we can't serve — never that the
    // receipt's inputCommitment changes.
    let messages = match req.input_format.as_deref() {
        Some("messages-v1") => match crate::engines::parse_messages_v1(&plaintext) {
            Ok(msgs) => msgs,
            Err(e) => {
                tracing::warn!(error = %e, session_id = %session_id, "failed to parse messages-v1 envelope");
                let err =
                    "[cocore provider] could not parse the multimodal input envelope".to_string();
                let err_ct = match ctx
                    .encryption
                    .seal_to(&req.requester_pub_key, err.as_bytes())
                {
                    Ok(ct) => ct,
                    Err(e) => {
                        tracing::warn!(error = %e, session_id = %session_id, "failed to seal envelope-parse error");
                        return Vec::new();
                    }
                };
                let mut collected = Vec::new();
                push_frame(
                    live_tx.as_ref(),
                    &mut collected,
                    AdvisorMessage::InferenceChunk(InferenceChunk {
                        session_id: session_id.clone(),
                        seq: 0,
                        channel: ChunkChannel::Content,
                        ciphertext: err_ct,
                    }),
                );
                push_frame(
                    live_tx.as_ref(),
                    &mut collected,
                    AdvisorMessage::InferenceComplete(InferenceComplete {
                        session_id,
                        tokens_in: 0,
                        tokens_out: 0,
                        receipt_uri: String::new(),
                        receipt_commit_rev: None,
                        receipt_commit_cid: None,
                    }),
                );
                return if live_tx.is_some() {
                    Vec::new()
                } else {
                    collected
                };
            }
        },
        // None or "text": legacy raw-prompt path. `String::from_utf8_lossy`
        // owns its own allocation; the Message parts are zeroized by the
        // request's drop guard after the engine call returns.
        _ => vec![crate::engines::Message::text(
            "user",
            String::from_utf8_lossy(&plaintext).to_string(),
        )],
    };
    let request = crate::engines::GenerateRequest {
        model: req.model.clone(),
        messages,
        max_tokens: req.max_tokens_out,
        temperature: None,
        top_p: None,
        guided_json: req.output_schema.clone(),
        tools: req.tools.clone(),
        tool_choice: match (&req.tool_choice, &req.tool_choice_function) {
            // When tool_choice is "required" and a function name is specified,
            // reconstruct the OpenAI object form { type: "function", function: { name } }.
            (Some(choice), Some(func_name)) if choice.as_str() == Some("required") => {
                Some(serde_json::json!({
                    "type": "function",
                    "function": { "name": func_name }
                }))
            }
            // Otherwise pass through tool_choice as-is.
            _ => req.tool_choice.clone(),
        },
    };

    // Look up the engine for the requested model. A miss means the
    // requester named a model this provider didn't actually load —
    // the advisor's matchmaking should have prevented this, but a
    // belt-and-suspenders check here surfaces the failure as a
    // clear sealed error chunk instead of letting the stub engine
    // silently masquerade as the requested model's reply.
    let engine = match ctx.engines.for_model(&req.model) {
        Some(e) => e,
        None => {
            tracing::warn!(
                model = %req.model,
                loaded = ?ctx.engines.loaded_models(),
                session_id = %session_id,
                "provider does not have an engine loaded for the requested model",
            );
            let err = format!(
                "[cocore provider] this provider has no engine loaded for model '{}'. Loaded models: {}.",
                req.model,
                ctx.engines.loaded_models().join(", "),
            );
            let err_ct = match ctx
                .encryption
                .seal_to(&req.requester_pub_key, err.as_bytes())
            {
                Ok(ct) => ct,
                Err(e) => {
                    tracing::warn!(error = %e, session_id = %session_id, "failed to seal model-miss error");
                    return Vec::new();
                }
            };
            let mut collected = Vec::new();
            push_frame(
                live_tx.as_ref(),
                &mut collected,
                AdvisorMessage::InferenceChunk(InferenceChunk {
                    session_id: session_id.clone(),
                    seq: 0,
                    channel: ChunkChannel::Content,
                    ciphertext: err_ct,
                }),
            );
            push_frame(
                live_tx.as_ref(),
                &mut collected,
                AdvisorMessage::InferenceComplete(InferenceComplete {
                    session_id,
                    tokens_in: 0,
                    tokens_out: 0,
                    receipt_uri: String::new(),
                    receipt_commit_rev: None,
                    receipt_commit_cid: None,
                }),
            );
            return if live_tx.is_some() {
                Vec::new()
            } else {
                collected
            };
        }
    };

    let mut collected = Vec::new();

    // Hand off to the matched engine. `generate_stream` is
    // synchronous and blocking — the subprocess engine reads an SSE
    // body over a blocking `UnixStream`. We run it on a dedicated
    // thread and bridge plaintext deltas back to this async task,
    // which seals each delta and forwards it to the advisor
    // immediately (live path) or collects frames for tests.
    let (plain_tx, mut plain_rx) = mpsc::unbounded_channel::<(DeltaChannel, String)>();
    let engine_for_blocking = engine.clone();
    let engine_handle = tokio::task::spawn_blocking(move || {
        let guard = ZeroizeOnDrop(request);
        engine_for_blocking.generate_stream(&guard.0, &mut |channel, delta| {
            plain_tx
                .send((channel, delta.to_string()))
                .map_err(|_| anyhow::anyhow!("stream bridge closed"))?;
            Ok(())
        })
    });

    // The answer and the reasoning ("thinking") trace are sealed into the same
    // ordered ciphertext stream (so outputCipherCommitment still covers every
    // delivered byte) but accumulated separately so each gets its own plaintext
    // commitment, and each chunk is tagged with its channel for the requester.
    let mut reply = Zeroizing::new(String::new());
    let mut reasoning = Zeroizing::new(String::new());
    let mut all_ciphertext = Vec::new();
    let mut seq = 0u32;

    // Keepalive ticker: on the live path, if a whole interval passes with no
    // token sent (slow prefill / slow decode), nudge the advisor so it knows
    // we're alive and doesn't kill the job as silent. Skip catch-up ticks so
    // a stall doesn't burst keepalives; consume the immediate t=0 tick.
    let mut keepalive = tokio::time::interval(STREAM_KEEPALIVE_INTERVAL);
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    keepalive.tick().await;
    let mut token_since_tick = false;

    loop {
        tokio::select! {
            maybe = plain_rx.recv() => {
                let Some((channel, delta)) = maybe else { break };
                match channel {
                    DeltaChannel::Content => reply.push_str(&delta),
                    DeltaChannel::Reasoning => reasoning.push_str(&delta),
                    DeltaChannel::ToolCall => { /* tool call deltas are forwarded but not accumulated into reply/reasoning */ }
                }
                let ct = match ctx
                    .encryption
                    .seal_to(&req.requester_pub_key, delta.as_bytes())
                {
                    Ok(ct) => ct,
                    Err(e) => {
                        tracing::warn!(error = %e, session_id = %session_id, "failed to seal stream chunk");
                        return if live_tx.is_some() {
                            Vec::new()
                        } else {
                            collected
                        };
                    }
                };
                all_ciphertext.extend_from_slice(&ct);
                let chunk_channel = match channel {
                    DeltaChannel::Content => ChunkChannel::Content,
                    DeltaChannel::Reasoning => ChunkChannel::Reasoning,
                    DeltaChannel::ToolCall => ChunkChannel::ToolCall,
                };
                push_frame(
                    live_tx.as_ref(),
                    &mut collected,
                    AdvisorMessage::InferenceChunk(InferenceChunk {
                        session_id: session_id.clone(),
                        seq,
                        channel: chunk_channel,
                        ciphertext: ct,
                    }),
                );
                seq += 1;
                token_since_tick = true;
            }
            _ = keepalive.tick(), if live_tx.is_some() => {
                // Only when we've been quiet this interval — never interleave
                // keepalives into a healthy token stream.
                if !token_since_tick {
                    push_frame(
                        live_tx.as_ref(),
                        &mut collected,
                        AdvisorMessage::InferenceKeepalive(InferenceKeepalive {
                            session_id: session_id.clone(),
                        }),
                    );
                }
                token_since_tick = false;
            }
        }
    }

    let engine_result = match engine_handle.await {
        Ok(r) => r,
        Err(join_err) => Err(anyhow::anyhow!("inference task failed: {join_err}")),
    };
    let (engine_tokens_in, engine_tokens_out) = match engine_result {
        Ok(resp) => (resp.tokens_in, resp.tokens_out),
        Err(e) => {
            tracing::warn!(
                error = %e,
                engine = engine.name(),
                session_id = %session_id,
                "engine.generate_stream failed; falling back to a short error message",
            );
            let err = format!("[cocore provider] engine error: {e}");
            if seq == 0 {
                reply = Zeroizing::new(err);
                if let Ok(ct) = ctx
                    .encryption
                    .seal_to(&req.requester_pub_key, reply.as_bytes())
                {
                    all_ciphertext.extend_from_slice(&ct);
                    push_frame(
                        live_tx.as_ref(),
                        &mut collected,
                        AdvisorMessage::InferenceChunk(InferenceChunk {
                            session_id: session_id.clone(),
                            seq: 0,
                            channel: ChunkChannel::Content,
                            ciphertext: ct,
                        }),
                    );
                }
            }
            (0u64, 0u64)
        }
    };

    let completed_at = Utc::now();
    let input_commitment = sha256_hex(&plaintext);
    let output_commitment = sha256_hex(reply.as_bytes());
    // The reasoning trace gets its own commitment, present only when the model
    // actually produced reasoning — keeps the answer's commitment independent
    // of thinking output.
    let reasoning_commitment = (!reasoning.is_empty()).then(|| sha256_hex(reasoning.as_bytes()));
    // Commit to the concatenation of every sealed chunk we handed
    // back, in order, so the requester can prove the ciphertext they
    // received matches the receipt.
    let output_cipher_commitment = sha256_hex(&all_ciphertext);
    // Cryptographically commit to the output schema the provider used,
    // so the receipt proves which constrained-generation shape was in
    // effect. We hash the canonical JSON encoding so semantically
    // equivalent schemas produce identical hashes.
    let output_schema_hash = req.output_schema.as_ref().and_then(|schema| {
        to_canonical_bytes(schema)
            .ok()
            .map(|bytes| sha256_hex(&bytes))
    });
    // Commit to the tool definitions the provider used, so the receipt
    // proves which functions were available to the model.
    let tool_schema_hash = req.tools.as_ref().and_then(|tools| {
        to_canonical_bytes(tools)
            .ok()
            .map(|bytes| sha256_hex(&bytes))
    });

    let params = receipt::GenerationParams {
        maxTokens: Some(req.max_tokens_out as u64),
        seed: None,
        temperatureMilli: None,
        topPMilli: None,
        outputSchemaHash: output_schema_hash,
        toolSchemaHash: tool_schema_hash,
    };

    // Pro bono decision: if the owner has elected to serve this requester
    // for free, the job is explicitly NOT counted — we publish a receipt
    // (the provider's PDS stays the source of truth for work done) but with
    // zero tokens and a zero price, and flag it so the exchange takes no cut.
    // A non-matching / off policy falls through to normal metering below.
    let pro_bono = ctx.pro_bono.applies_to(&req.requester_did);

    let rate = pricing::rate_for(&req.model);
    let (tokens_in, tokens_out, price_minor) = if pro_bono {
        tracing::info!(
            session_id = %session_id,
            requester = %req.requester_did,
            mode = %ctx.pro_bono.mode,
            "serving job pro bono — unmetered, zero price, no exchange cut",
        );
        (0u64, 0u64, 0u64)
    } else {
        let tokens_in = if engine_tokens_in > 0 {
            engine_tokens_in
        } else {
            pricing::estimate_tokens(&plaintext)
        };
        let tokens_out = if engine_tokens_out > 0 {
            engine_tokens_out
        } else {
            pricing::estimate_tokens(reply.as_bytes())
        };
        let price_minor = pricing::price_minor(rate, tokens_in, tokens_out);
        (tokens_in, tokens_out, price_minor)
    };

    // Snapshot the current attestation for this job. The refresh task may swap
    // a newer one in between jobs; reading here means every receipt references
    // whatever attestation is live at publish time.
    let attestation_snapshot = ctx.attestation.read().await.clone();
    let (receipt_uri, receipt_commit) = match (req.job_cid.as_ref(), attestation_snapshot.as_ref())
    {
        (Some(job_cid), Some(attestation)) => publish_stub_receipt(
            ctx,
            &req,
            job_cid,
            attestation,
            input_commitment,
            output_commitment,
            Some(output_cipher_commitment),
            reasoning_commitment,
            Some(params),
            started_at,
            completed_at,
            tokens_in,
            tokens_out,
            Money {
                amount: price_minor,
                currency: rate.currency.into(),
            },
            pro_bono,
        )
        .await
        .unwrap_or_default(),
        (None, _) => {
            tracing::debug!(
                session_id = %session_id,
                "no job_cid in InferenceRequest; skipping receipt publish"
            );
            (String::new(), None)
        }
        (_, None) => {
            tracing::debug!(
                session_id = %session_id,
                "no active attestation; skipping receipt publish"
            );
            (String::new(), None)
        }
    };
    let (receipt_commit_rev, receipt_commit_cid) = match receipt_commit {
        Some(c) => (Some(c.rev), Some(c.cid)),
        None => (None, None),
    };

    push_frame(
        live_tx.as_ref(),
        &mut collected,
        AdvisorMessage::InferenceComplete(InferenceComplete {
            session_id,
            tokens_in: tokens_in.try_into().unwrap_or(u32::MAX),
            tokens_out: tokens_out.try_into().unwrap_or(u32::MAX),
            receipt_uri,
            receipt_commit_rev,
            receipt_commit_cid,
        }),
    );
    mark_served();
    if live_tx.is_some() {
        Vec::new()
    } else {
        collected
    }
}

/// Touch `~/.cocore/last-served-at` with the current time. The menu-bar
/// app polls this file's mtime and flashes a green heartbeat on its icon
/// for a few seconds after each served response. Content-free (only a
/// timestamp) and best-effort — it never blocks or fails the serve path.
fn mark_served() {
    let Some(home) = dirs::home_dir() else { return };
    let path = home.join(".cocore").join("last-served-at");
    let _ = std::fs::write(path, Utc::now().to_rfc3339());
}

/// `~/.cocore/bad-standing-at` — present iff the advisor has told this
/// machine it's in bad standing (it stopped routing jobs here because the
/// machine failed a preflight ping or went silent mid-job). The menu-bar
/// app polls for this file and shows a red "needs attention" ping while it
/// exists; the agent removes it on a clean re-register / `HealthNotice::Ok`.
fn bad_standing_path() -> Option<std::path::PathBuf> {
    dirs::home_dir().map(|h| h.join(".cocore").join("bad-standing-at"))
}

/// Record that the advisor put us in bad standing. Content-free (a
/// timestamp + a short machine-readable reason) and best-effort.
fn write_bad_standing(reason: Option<&str>) {
    let Some(path) = bad_standing_path() else {
        return;
    };
    let body = format!("{}\n{}", Utc::now().to_rfc3339(), reason.unwrap_or(""));
    let _ = std::fs::write(path, body);
    tracing::warn!(
        reason = reason.unwrap_or("unspecified"),
        "advisor marked this machine in bad standing — it stopped routing jobs here"
    );
}

/// Clear the bad-standing marker (recovered / freshly re-registered).
fn clear_bad_standing() {
    let Some(path) = bad_standing_path() else {
        return;
    };
    if std::fs::remove_file(&path).is_ok() {
        tracing::info!("cleared bad-standing marker");
    }
}

/// Remove `~/.cocore/provision-status.json` iff it's in the "starting"
/// phase — the boot-time marker the serve path leaves after engines load so
/// the tray shows "connecting to the network" until this first successful
/// advisor registration. Phase-guarded so a "failed" marker (engine fault,
/// machine registers stub-only) keeps surfacing its fault in the tray, and
/// best-effort like the bad-standing marker above.
fn clear_starting_provision_marker() {
    let Some(path) = dirs::home_dir().map(|h| h.join(".cocore").join("provision-status.json"))
    else {
        return;
    };
    let is_starting = std::fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .is_some_and(|v| v.get("phase").and_then(|p| p.as_str()) == Some("starting"));
    if is_starting && std::fs::remove_file(&path).is_ok() {
        tracing::info!("registered — cleared the boot-time provisioning marker");
    }
}

#[allow(clippy::too_many_arguments)]
async fn publish_stub_receipt(
    ctx: &ServeContext<'_>,
    req: &InferenceRequest,
    job_cid: &str,
    attestation: &StrongRef,
    input_commitment: String,
    output_commitment: String,
    output_cipher_commitment: Option<String>,
    reasoning_commitment: Option<String>,
    params: Option<receipt::GenerationParams>,
    started_at: chrono::DateTime<Utc>,
    completed_at: chrono::DateTime<Utc>,
    tokens_in: u64,
    tokens_out: u64,
    price: Money,
    pro_bono: bool,
) -> std::result::Result<(String, Option<crate::pds::RepoCommit>), ()> {
    let inputs = ReceiptInputs {
        job: StrongRef {
            uri: req.job_uri.clone(),
            cid: job_cid.to_string(),
        },
        requester: req.requester_did.clone(),
        model: req.model.clone(),
        input_commitment,
        output_commitment,
        output_cipher_commitment,
        reasoning_commitment,
        params,
        output_cipher_url: None,
        tokens_in,
        tokens_out,
        started_at,
        completed_at,
        price,
        attestation: attestation.clone(),
        pro_bono,
        // ADR-0004: carry the brokerage's dispatch countersignature onto the
        // receipt verbatim (wire snake_case → lexicon camelCase). Excluded from
        // the enclaveSignature in receipt::build.
        brokerage_countersignature: req.brokerage_countersignature.as_ref().map(|c| {
            receipt::BrokerageCountersignature {
                authority: c.authority.clone(),
                machineId: c.machine_id.clone(),
                nonce: c.nonce.clone(),
                sig: c.sig.clone(),
            }
        }),
    };
    let (record, _canonical) = match receipt::build(inputs, ctx.signer) {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, session_id = %req.session_id, "receipt build failed");
            return Err(());
        }
    };
    match ctx.pds.publish_receipt(&record).await {
        Ok(published) => {
            tracing::info!(uri = %published.uri, session_id = %req.session_id, "published receipt");
            Ok((published.uri, published.commit))
        }
        Err(e) => {
            tracing::warn!(error = %e, session_id = %req.session_id, "receipt publish failed");
            Err(())
        }
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// Best-effort `mlock(2)` over the pages backing `bytes`. Prevents
/// the kernel from paging the plaintext to swap (and thus from
/// persisting it to disk where a postmortem would recover it).
///
/// Failure modes we deliberately swallow:
///
/// - `EPERM` / `ENOMEM` — the process's RLIMIT_MEMLOCK is too low
///   to lock another page. On macOS the default per-process cap is
///   64KB and we have a venv's worth of allocations competing for
///   it; an mlock denial is expected and non-fatal. The `Zeroizing`
///   wrapper still wipes the bytes on drop, so the worst case is
///   "if the system swaps, the wiped-after-drop bytes might briefly
///   exist on disk before being overwritten."
/// - Non-Unix platforms — the agent only ships on macOS today, but
///   the `cfg(unix)` gate keeps the code portable if that ever
///   changes.
///
/// We intentionally do NOT `munlock` on drop. `mlock` is a page-
/// granularity hint; once Zeroizing has scrubbed the buffer, the
/// pages contain zeros and there's nothing left to protect.
fn mlock_buffer(bytes: &[u8]) {
    #[cfg(unix)]
    {
        if bytes.is_empty() {
            return;
        }
        // SAFETY: we pass a valid pointer + length to mlock; the
        // call has no aliasing requirements and returns -1 on
        // failure (which we ignore).
        let _ = unsafe { libc::mlock(bytes.as_ptr() as *const libc::c_void, bytes.len()) };
    }
}

/// Build the signed [`AttestationResponse`] for a challenge.
///
/// The signature covers a sorted-key canonical JSON of
/// `{ nonce, sipEnabled, timestamp }` (and `hypervisorPresent` when
/// available). Canonicalisation rule: sort by JSON key, integer-only,
/// no whitespace. Binary / model / runtime hashes are added in a
/// later milestone alongside the inference engine.
pub fn build_challenge_response(
    challenge: &AttestationChallenge,
    signer: &dyn SigningIdentity,
) -> Result<AttestationResponse> {
    let sip_enabled = current_sip_enabled();
    let hyp = hypervisor::detect();

    // Canonicalise the signed payload. We rebuild the value here
    // instead of relying on serde_json struct emission so the byte
    // layout is independent of declaration order.
    let mut payload = json!({
        "nonce": challenge.nonce,
        "sipEnabled": sip_enabled,
        "timestamp": challenge.timestamp.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    });
    if let Some(present) = hyp {
        // `payload` was just built from a `json!({...})` object literal, so
        // `as_object_mut` is always `Some` — but we don't `.unwrap()` on the
        // serve path even when "can't happen": a deny(clippy::unwrap_used)
        // guards this module, and an `if let` is free.
        if let Some(obj) = payload.as_object_mut() {
            obj.insert("hypervisorPresent".into(), json!(present));
        }
    }
    let canonical = to_canonical_bytes(&payload)
        .map_err(|e| ProviderError::Advisor(format!("canonical: {e}")))?;
    let sig = signer
        .sign(&canonical)
        .map_err(|e| ProviderError::Advisor(format!("sign: {e}")))?;

    Ok(AttestationResponse {
        nonce: challenge.nonce.clone(),
        timestamp: challenge.timestamp,
        sip_enabled,
        hypervisor_present: hyp,
        signature: sig,
    })
}

/// Mint a per-request ephemeral X25519 key and SE-sign it for the confidential
/// tier (WS-EPHEMERAL). The signature covers the canonical bytes of
/// `{attestationCid, ephemeralPubKey, nonce}` — byte-identical to the SDK's
/// `sessionKeyMessage` — so a confidential requester can verify (against
/// `attestation.publicKey`) that the key it seals to is controlled by the
/// attested enclave and was produced fresh for THIS request. Returns the
/// ephemeral keypair (which the serve loop uses to `open_from`/`seal_to`) and
/// the wire frame to relay to the requester.
pub fn build_session_key(
    signer: &dyn SigningIdentity,
    session_id: &str,
    attestation_cid: &str,
    nonce: &str,
) -> Result<(ProviderKeypair, SessionKey)> {
    let ephemeral = ProviderKeypair::generate();
    let ephemeral_pub = ephemeral.public_key_b64();
    let payload = json!({
        "attestationCid": attestation_cid,
        "ephemeralPubKey": ephemeral_pub,
        "nonce": nonce,
    });
    let canonical = to_canonical_bytes(&payload)
        .map_err(|e| ProviderError::Advisor(format!("canonical: {e}")))?;
    let sig = signer
        .sign(&canonical)
        .map_err(|e| ProviderError::Advisor(format!("sign: {e}")))?;
    Ok((
        ephemeral,
        SessionKey {
            session_id: session_id.into(),
            ephemeral_pub_key: ephemeral_pub,
            nonce: nonce.into(),
            attestation_cid: attestation_cid.into(),
            signature: sig,
        },
    ))
}

/// Recover an APNs code-identity challenge and produce the signed response.
///
/// The advisor seals a fresh nonce to the provider's X25519 key `K` with an
/// ephemeral key (`nacl.box` / `crypto_box`) and ships `{ sealed, eph_pub }`
/// in the push payload. Only the genuine binary can (a) receive that push at
/// all — AMFI gates the topic to our code signature — and (b) open the
/// envelope with `K`, which lives in this process's protected memory. We then
/// SE-sign the recovered nonce so the advisor can tie the push receipt to the
/// attested signing key. A failure here (wrong key, corrupt envelope, non-UTF-8
/// nonce) is silent at the security layer: no response means no code-attested
/// standing, which is the fail-closed default.
pub fn recover_code_challenge(
    encryption: &ProviderKeypair,
    signer: &dyn SigningIdentity,
    advisor_eph_pub_b64: &str,
    sealed_b64: &str,
    cd_hash: Option<&str>,
) -> Result<CodeAttestationResponse> {
    use base64::Engine as _;
    let sealed = base64::engine::general_purpose::STANDARD
        .decode(sealed_b64)
        .map_err(|e| ProviderError::Advisor(format!("code challenge b64: {e}")))?;
    let nonce_bytes = encryption
        .open_from(advisor_eph_pub_b64, &sealed)
        .map_err(|e| ProviderError::Advisor(format!("code challenge open: {e}")))?;
    let nonce = String::from_utf8(nonce_bytes)
        .map_err(|e| ProviderError::Advisor(format!("code challenge nonce utf8: {e}")))?;
    build_code_attestation_response(signer, &nonce, cd_hash)
}

/// Extract the code-identity challenge from an APNs push payload (the raw JSON
/// the push host hands us). The advisor packs the challenge under a top-level
/// `cc` object: `{ "cc": { "epk": <b64 advisor ephemeral X25519 pub>, "n":
/// <b64 nonce sealed to K> }, "aps": { "content-available": 1 } }`. Returns
/// `(eph_pub_b64, sealed_b64)`, or `None` if this push isn't a code challenge.
pub fn parse_code_challenge_payload(json_str: &str) -> Option<(String, String)> {
    let v: serde_json::Value = serde_json::from_str(json_str).ok()?;
    let cc = v.get("cc")?;
    let epk = cc.get("epk")?.as_str()?.to_string();
    let n = cc.get("n")?.as_str()?.to_string();
    Some((epk, n))
}

/// Convenience: parse an APNs payload and, if it carries a code challenge,
/// recover the nonce and produce the signed response. `Ok(None)` means the
/// push wasn't a code challenge (ignore it); `Err` means it was but couldn't
/// be opened (fail-closed — no response goes out).
/// Await the next APNs push payload from an optional receiver. When the
/// receiver is absent (non-apns build, or a headless session that never got a
/// push host), this future never resolves, so the `select!` arm that uses it
/// stays permanently inert — the serve loop behaves exactly as it did before
/// code identity existed.
async fn next_push(rx: &mut Option<&mut mpsc::UnboundedReceiver<String>>) -> Option<String> {
    match rx {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

pub fn handle_code_challenge_payload(
    encryption: &ProviderKeypair,
    signer: &dyn SigningIdentity,
    json_str: &str,
    cd_hash: Option<&str>,
) -> Result<Option<CodeAttestationResponse>> {
    match parse_code_challenge_payload(json_str) {
        Some((epk, sealed)) => {
            recover_code_challenge(encryption, signer, &epk, &sealed, cd_hash).map(Some)
        }
        None => Ok(None),
    }
}

/// Build the signed [`CodeAttestationResponse`] for an APNs code-identity
/// challenge. `recovered_nonce` is the plaintext the agent obtained by
/// decrypting the pushed challenge with its X25519 key `K`; we SE-sign the
/// canonical bytes of `{ nonce }` (sorted-key, integer-only, no whitespace —
/// the same rule `build_challenge_response` uses) so the advisor can verify
/// the signature against the registered `attestationPubKey`. The fact that the
/// agent could recover `recovered_nonce` at all is the load-bearing proof: the
/// push was AMFI-gated to our code signature and sealed to `K`.
pub fn build_code_attestation_response(
    signer: &dyn SigningIdentity,
    recovered_nonce: &str,
    cd_hash: Option<&str>,
) -> Result<CodeAttestationResponse> {
    // 0.9.23: BIND the measured cdHash into the signed payload so the proof of
    // code identity is tied to a specific binary, not just "answered the push".
    // We sign over our OWN measured cdHash (the same value we put in Register);
    // the advisor reconstructs with the cdHash we registered, so a mismatch
    // between the registered and signed cdHash fails verification. Canonical
    // sort-key order puts `cdHash` before `nonce`; the advisor's
    // `canonicalize({ cdHash, nonce })` matches byte-for-byte. Falls back to
    // `{ nonce }` only when no cdHash is available (a confidential machine
    // always has one).
    let payload = match cd_hash {
        Some(cd) => json!({ "cdHash": cd, "nonce": recovered_nonce }),
        None => json!({ "nonce": recovered_nonce }),
    };
    let canonical = to_canonical_bytes(&payload)
        .map_err(|e| ProviderError::Advisor(format!("canonical: {e}")))?;
    let sig = signer
        .sign(&canonical)
        .map_err(|e| ProviderError::Advisor(format!("sign: {e}")))?;
    Ok(CodeAttestationResponse {
        nonce: recovered_nonce.into(),
        signature: sig,
    })
}

/// Best-effort current SIP status. On non-macOS this is always
/// `true` because there's no equivalent kill-switch; on macOS we
/// optimistically return `true` because if SIP weren't enabled the
/// startup `require_sip_enabled` check would have refused to boot
/// the agent. (A real implementation re-runs csrutil here in case
/// Apple ever lands a runtime toggle.)
fn current_sip_enabled() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wss_advisor_url_is_always_accepted() {
        assert!(require_secure_advisor_url("wss://advisor.cocore.dev/v1/agent").is_ok());
        // Scheme match is case-insensitive.
        assert!(require_secure_advisor_url("WSS://advisor.cocore.dev/v1/agent").is_ok());
    }

    #[test]
    fn insecure_advisor_url_is_rejected_without_the_flag() {
        // The env var governs the ws:// escape hatch; make sure it's off here so
        // the test is deterministic regardless of the ambient environment.
        std::env::remove_var(ALLOW_INSECURE_ADVISOR_ENV);
        assert!(require_secure_advisor_url("ws://localhost:8080/v1/agent").is_err());
        // A bogus scheme is refused too.
        assert!(require_secure_advisor_url("http://advisor.cocore.dev").is_err());
    }

    #[test]
    fn insecure_advisor_url_allowed_only_with_explicit_opt_in() {
        std::env::set_var(ALLOW_INSECURE_ADVISOR_ENV, "1");
        assert!(require_secure_advisor_url("ws://localhost:8080/v1/agent").is_ok());
        // Even with the opt-in, a non-ws/wss scheme is still refused.
        assert!(require_secure_advisor_url("http://localhost:8080").is_err());
        std::env::remove_var(ALLOW_INSECURE_ADVISOR_ENV);
    }

    #[test]
    fn advisor_https_probe_url_maps_ws_scheme_and_path() {
        assert_eq!(
            advisor_https_probe_url("wss://advisor.cocore.dev/v1/agent").as_deref(),
            Some("https://advisor.cocore.dev/ttft")
        );
        assert_eq!(
            advisor_https_probe_url("ws://localhost:8080/v1/agent").as_deref(),
            Some("http://localhost:8080/ttft")
        );
        // Port is carried through; a bare authority (no path) works too.
        assert_eq!(
            advisor_https_probe_url("wss://advisor.cocore.dev:8443").as_deref(),
            Some("https://advisor.cocore.dev:8443/ttft")
        );
        // Unrecognizable inputs probe nothing rather than a fabricated URL.
        assert_eq!(advisor_https_probe_url("advisor.cocore.dev"), None);
        assert_eq!(advisor_https_probe_url("ftp://x"), None);
        assert_eq!(advisor_https_probe_url("wss:///path-only"), None);
    }

    #[test]
    fn classify_connect_io_error_covers_the_field_failures() {
        use std::io::{Error, ErrorKind};
        assert_eq!(
            classify_connect_io_error(&Error::new(ErrorKind::TimedOut, "t")),
            "connect-timeout"
        );
        assert_eq!(
            classify_connect_io_error(&Error::new(ErrorKind::ConnectionRefused, "r")),
            "connect-refused"
        );
        // macOS getaddrinfo failure has no dedicated kind — sniffed from the
        // message ("nodename nor servname provided, or not known").
        assert_eq!(
            classify_connect_io_error(&Error::other(
                "failed to lookup address information: nodename nor servname provided"
            )),
            "dns-failure"
        );
        assert_eq!(
            classify_connect_io_error(&Error::other("Network is unreachable (os error 51)")),
            "network-unreachable"
        );
        assert_eq!(
            classify_connect_io_error(&Error::other("something else entirely")),
            "io-error"
        );
    }

    #[test]
    fn build_advisor_fault_folds_the_https_probe_into_the_code() {
        // HTTPS works but the WS connect keeps timing out / being reset →
        // a middlebox is filtering WebSockets specifically.
        for base in ["connect-timeout", "connection-reset", "ws-handshake-failed"] {
            let f = build_advisor_fault(base, true);
            assert_eq!(f.code, "upgrade-blocked", "base {base}");
            assert!(f.message.contains("WebSocket"));
        }
        // A real HTTP answer to the upgrade keeps its status-carrying code.
        assert_eq!(build_advisor_fault("http-503", true).code, "http-503");
        // TLS failure stays TLS regardless of the probe (interception vs. broken).
        assert_eq!(build_advisor_fault("tls-failure", true).code, "tls-failure");
        assert_eq!(
            build_advisor_fault("tls-failure", false).code,
            "tls-failure"
        );
        // Probe also failing keeps the network-level base classification.
        assert_eq!(
            build_advisor_fault("dns-failure", false).code,
            "dns-failure"
        );
        assert_eq!(
            build_advisor_fault("connect-timeout", false).code,
            "connect-timeout"
        );
        // Unknown base codes pass through (fail open to a generic message).
        assert_eq!(build_advisor_fault("io-error", false).code, "io-error");
        // Content safety: no message ever carries a URL or raw error text.
        for (base, probe) in [("connect-timeout", true), ("dns-failure", false)] {
            let f = build_advisor_fault(base, probe);
            assert!(
                !f.message.contains("://"),
                "message leaks a URL: {}",
                f.message
            );
        }
    }

    #[test]
    fn models_changed_ignores_order_and_dupes_but_catches_edits() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        // Same set, different order / duplicated → not a change (no restart).
        assert!(!models_changed(&a(&["x", "y"]), &a(&["y", "x"])));
        assert!(!models_changed(&a(&["x", "x", "y"]), &a(&["y", "x"])));
        assert!(!models_changed(&[], &[]));
        // A real edit in either direction → a change (restart to reload).
        assert!(models_changed(&a(&["x"]), &a(&["x", "y"]))); // added
        assert!(models_changed(&a(&["x", "y"]), &a(&["x"]))); // removed
        assert!(models_changed(&a(&["x"]), &[])); // cleared → local default
        assert!(models_changed(&[], &a(&["x"]))); // newly pinned
    }

    #[test]
    fn tier_changed_normalises_default_and_catches_opt_in_out() {
        // Absent and explicit best-effort are the same → no restart.
        assert!(!tier_changed(None, None));
        assert!(!tier_changed(None, Some("best-effort")));
        assert!(!tier_changed(Some("best-effort"), None));
        assert!(!tier_changed(Some("best-effort"), Some("best-effort")));
        // An unknown/garbage tier normalises to best-effort, not a restart loop.
        assert!(!tier_changed(Some("wat"), None));
        // Staying confidential → no restart.
        assert!(!tier_changed(
            Some("attested-confidential"),
            Some("attested-confidential")
        ));
        // Opting in and opting back out → a real change (restart to re-select).
        assert!(tier_changed(Some("attested-confidential"), None));
        assert!(tier_changed(None, Some("attested-confidential")));
        assert!(tier_changed(
            Some("attested-confidential"),
            Some("best-effort")
        ));
    }

    use crate::engines::stub::StubEngine;
    use crate::oauth::Session;
    use crate::secure_enclave::{identity_lock, load_or_create_identity};
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    use p256::EncodedPoint;

    /// One-stub-engine registry for tests. Every InferenceRequest in
    /// the suite passes `model: "stub"`, so registering StubEngine
    /// under that NSID keeps the entire suite passing without
    /// constructing the bigger inference-feature engine.
    fn stub_registry() -> EngineRegistry {
        let mut r = EngineRegistry::new();
        r.register("stub", std::sync::Arc::new(StubEngine));
        r
    }

    fn fresh_keypair() -> ProviderKeypair {
        ProviderKeypair::generate()
    }

    /// PdsClient targeting localhost — handlers in these tests
    /// either short-circuit before they call PDS, or accept that
    /// the PDS call will fail (publish_stub_receipt's failure path
    /// is deliberately covered).
    fn fake_pds() -> PdsClient {
        PdsClient::new(Session {
            did: "did:plc:test".into(),
            handle: "test.example".into(),
            api_key: "cocore-fake".into(),
            api_base: "http://127.0.0.1:1".into(),
        })
    }

    /// An "off" pro-bono policy shared by the test contexts below — no
    /// requester is served pro bono, so these tests exercise the normal
    /// metered path. Returned as `'static` so `ctx` can hand `ServeContext`
    /// a reference without each call site owning a binding.
    fn off_pro_bono() -> &'static ProBonoPolicy {
        static P: std::sync::OnceLock<ProBonoPolicy> = std::sync::OnceLock::new();
        P.get_or_init(ProBonoPolicy::default)
    }

    fn ctx<'a>(
        signer: &'a dyn SigningIdentity,
        kp: &'a ProviderKeypair,
        pds: &'a PdsClient,
        attestation: Option<&StrongRef>,
        engines: &'a EngineRegistry,
    ) -> ServeContext<'a> {
        ServeContext {
            signer,
            encryption: kp,
            pds,
            attestation: Arc::new(RwLock::new(attestation.cloned())),
            engines,
            pro_bono: off_pro_bono(),
        }
    }

    #[test]
    fn challenge_response_signature_verifies() {
        let signer = load_or_create_identity().unwrap();
        let challenge = AttestationChallenge {
            nonce: "abc-123".into(),
            timestamp: chrono::Utc::now(),
        };
        let resp = build_challenge_response(&challenge, &*signer).unwrap();

        // Reconstruct what the verifier would canonicalise.
        let mut payload = json!({
            "nonce": resp.nonce,
            "sipEnabled": resp.sip_enabled,
            "timestamp": resp.timestamp.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        });
        if let Some(p) = resp.hypervisor_present {
            payload
                .as_object_mut()
                .unwrap()
                .insert("hypervisorPresent".into(), json!(p));
        }
        let canonical = to_canonical_bytes(&payload).unwrap();

        // Verify against the public key the registration message
        // would publish.
        let pub_raw = B64.decode(signer.public_key_b64()).unwrap();
        let mut uncompressed = [0u8; 65];
        uncompressed[0] = 0x04;
        uncompressed[1..].copy_from_slice(&pub_raw);
        let point = EncodedPoint::from_bytes(uncompressed).unwrap();
        let vk = VerifyingKey::from_encoded_point(&point).unwrap();
        let sig = Signature::from_der(&resp.signature).unwrap();
        vk.verify(&canonical, &sig)
            .expect("challenge response must verify");
    }

    #[test]
    fn code_attestation_response_binds_cdhash() {
        // 0.9.23: the SE signature is over {cdHash, nonce}, BOUND to the measured
        // binary — it must verify over those canonical bytes AND must NOT verify
        // over {nonce} alone (proving the cdHash is actually in the signed payload).
        let _g = identity_lock();
        let signer = load_or_create_identity().unwrap();
        let cd = "57bd6dfa8daf45c187249a4c70a2b6c396ab9fc0";
        let resp = build_code_attestation_response(&*signer, "deadbeefcafe", Some(cd)).unwrap();
        assert_eq!(resp.nonce, "deadbeefcafe");

        let pub_raw = B64.decode(signer.public_key_b64()).unwrap();
        let mut uncompressed = [0u8; 65];
        uncompressed[0] = 0x04;
        uncompressed[1..].copy_from_slice(&pub_raw);
        let point = EncodedPoint::from_bytes(uncompressed).unwrap();
        let vk = VerifyingKey::from_encoded_point(&point).unwrap();
        let sig = Signature::from_der(&resp.signature).unwrap();

        // Verifies over {cdHash, nonce} (advisor reconstructs this with the
        // registered cdHash).
        let bound = to_canonical_bytes(&json!({ "cdHash": cd, "nonce": resp.nonce })).unwrap();
        vk.verify(&bound, &sig)
            .expect("code attestation must verify over {cdHash, nonce}");
        // Does NOT verify over {nonce} alone — the binding is real.
        let unbound = to_canonical_bytes(&json!({ "nonce": resp.nonce })).unwrap();
        assert!(
            vk.verify(&unbound, &sig).is_err(),
            "a cdHash-bound proof must not verify as nonce-only"
        );
        // Nor over a DIFFERENT cdHash (a fork that registers a blessed cdHash but
        // signs its own would fail the advisor's reconstruction).
        let other =
            to_canonical_bytes(&json!({ "cdHash": "deadbeef", "nonce": resp.nonce })).unwrap();
        assert!(
            vk.verify(&other, &sig).is_err(),
            "proof must not verify against a different cdHash"
        );
    }

    #[test]
    fn code_challenge_round_trip_recovers_nonce_and_signs() {
        // Simulate the advisor exactly: seal a fresh nonce to the provider's
        // X25519 key `K` with an ephemeral key (the E_K(nonce) the push
        // carries), then prove the agent recovers it and signs a response that
        // verifies against its attestation key.
        let _g = identity_lock();
        let signer = load_or_create_identity().unwrap();
        let k = fresh_keypair(); // the provider's registered encryption key
        let advisor_eph = fresh_keypair();
        let nonce = "a1b2c3d4e5f6a7b8"; // hex nonce, like makeChallenge()

        let sealed = advisor_eph
            .seal_to(&k.public_key_b64(), nonce.as_bytes())
            .unwrap();
        let sealed_b64 = B64.encode(&sealed);

        let cd = "abc123def456";
        let resp = recover_code_challenge(
            &k,
            &*signer,
            &advisor_eph.public_key_b64(),
            &sealed_b64,
            Some(cd),
        )
        .unwrap();
        assert_eq!(resp.nonce, nonce);

        // Signature verifies against the attestation public key over {cdHash, nonce}.
        let canonical = to_canonical_bytes(&json!({ "cdHash": cd, "nonce": resp.nonce })).unwrap();
        let pub_raw = B64.decode(signer.public_key_b64()).unwrap();
        let mut uncompressed = [0u8; 65];
        uncompressed[0] = 0x04;
        uncompressed[1..].copy_from_slice(&pub_raw);
        let point = EncodedPoint::from_bytes(uncompressed).unwrap();
        let vk = VerifyingKey::from_encoded_point(&point).unwrap();
        let sig = Signature::from_der(&resp.signature).unwrap();
        vk.verify(&canonical, &sig).expect("response must verify");
    }

    #[test]
    fn parse_and_handle_code_challenge_payload_end_to_end() {
        // The full agent path: a realistic APNs payload (aps + cc) → parse →
        // recover → signed response that verifies.
        let _g = identity_lock();
        let signer = load_or_create_identity().unwrap();
        let k = fresh_keypair();
        let advisor_eph = fresh_keypair();
        let nonce = "00112233445566778899aabbccddeeff";
        let sealed = advisor_eph
            .seal_to(&k.public_key_b64(), nonce.as_bytes())
            .unwrap();
        let payload = json!({
            "aps": { "content-available": 1 },
            "cc": { "epk": advisor_eph.public_key_b64(), "n": B64.encode(&sealed) },
        })
        .to_string();

        assert!(parse_code_challenge_payload(&payload).is_some());
        let resp = handle_code_challenge_payload(&k, &*signer, &payload, Some("cd0011"))
            .unwrap()
            .expect("payload carries a code challenge");
        assert_eq!(resp.nonce, nonce);

        // A non-challenge push (plain aps) is ignored, not an error.
        let plain = json!({ "aps": { "content-available": 1 } }).to_string();
        assert!(parse_code_challenge_payload(&plain).is_none());
        assert!(
            handle_code_challenge_payload(&k, &*signer, &plain, Some("cd0011"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn code_challenge_wrong_recipient_key_fails() {
        // A fork that doesn't hold the registered `K` cannot open the envelope,
        // so it can never produce a response — fail-closed.
        let _g = identity_lock();
        let signer = load_or_create_identity().unwrap();
        let k = fresh_keypair();
        let not_k = fresh_keypair(); // the fork's own, different key
        let advisor_eph = fresh_keypair();
        let sealed = advisor_eph
            .seal_to(&k.public_key_b64(), b"deadbeef")
            .unwrap();
        let sealed_b64 = B64.encode(&sealed);
        let err = recover_code_challenge(
            &not_k,
            &*signer,
            &advisor_eph.public_key_b64(),
            &sealed_b64,
            Some("cd00"),
        );
        assert!(err.is_err(), "opening with the wrong K must fail");
    }

    #[test]
    fn session_key_signature_verifies_and_binds_inputs() {
        // WS-EPHEMERAL: the SE signature over {attestationCid, ephemeralPubKey,
        // nonce} must verify against the signer's public key over the SAME
        // canonical bytes the SDK's `sessionKeyMessage` reconstructs.
        let signer = load_or_create_identity().unwrap();
        let (eph, sk) =
            build_session_key(&*signer, "sess-1", "bafycid-xyz", "noncedeadbeef").unwrap();

        assert_eq!(sk.session_id, "sess-1");
        assert_eq!(sk.attestation_cid, "bafycid-xyz");
        assert_eq!(sk.nonce, "noncedeadbeef");
        assert_eq!(sk.ephemeral_pub_key, eph.public_key_b64());
        // ephemeral pub is a 32-byte X25519 key.
        assert_eq!(B64.decode(&sk.ephemeral_pub_key).unwrap().len(), 32);

        let canonical = to_canonical_bytes(&json!({
            "attestationCid": sk.attestation_cid,
            "ephemeralPubKey": sk.ephemeral_pub_key,
            "nonce": sk.nonce,
        }))
        .unwrap();

        let pub_raw = B64.decode(signer.public_key_b64()).unwrap();
        let mut uncompressed = [0u8; 65];
        uncompressed[0] = 0x04;
        uncompressed[1..].copy_from_slice(&pub_raw);
        let point = EncodedPoint::from_bytes(uncompressed).unwrap();
        let vk = VerifyingKey::from_encoded_point(&point).unwrap();
        let sig = Signature::from_der(&sk.signature).unwrap();
        vk.verify(&canonical, &sig)
            .expect("session key signature must verify");
    }

    #[test]
    fn challenge_response_echoes_nonce_and_timestamp() {
        let signer = load_or_create_identity().unwrap();
        let ts = chrono::Utc::now();
        let challenge = AttestationChallenge {
            nonce: "echo-test".into(),
            timestamp: ts,
        };
        let resp = build_challenge_response(&challenge, &*signer).unwrap();
        assert_eq!(resp.nonce, "echo-test");
        assert_eq!(resp.timestamp, ts);
    }

    #[tokio::test]
    async fn handle_inbound_returns_response_for_challenge() {
        let signer = load_or_create_identity().unwrap();
        let kp = fresh_keypair();
        let pds = fake_pds();
        let engines = stub_registry();
        let cx = ctx(&*signer, &kp, &pds, None, &engines);
        let challenge = AttestationChallenge {
            nonce: "frame-test".into(),
            timestamp: chrono::Utc::now(),
        };
        let frame =
            serde_json::to_string(&AdvisorMessage::AttestationChallenge(challenge)).unwrap();
        let replies = handle_inbound(&frame, &cx).await.unwrap();
        assert_eq!(replies.len(), 1);
        match &replies[0] {
            AdvisorMessage::AttestationResponse(r) => assert_eq!(r.nonce, "frame-test"),
            other => panic!("expected AttestationResponse, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn handle_inbound_ignores_unparseable() {
        let signer = load_or_create_identity().unwrap();
        let kp = fresh_keypair();
        let pds = fake_pds();
        let engines = stub_registry();
        let cx = ctx(&*signer, &kp, &pds, None, &engines);
        let replies = handle_inbound("not json", &cx).await.unwrap();
        assert!(replies.is_empty());
    }

    /// Fault injection: the serve loop wraps each job future in
    /// `AssertUnwindSafe(..).catch_unwind()` so a panic in one handler is
    /// contained, recorded, and the connection survives. This asserts the
    /// mechanism we rely on actually converts a panic into a recoverable
    /// `Err` instead of unwinding into the loop and aborting the agent —
    /// the exact escalation that took machines offline in the field.
    #[tokio::test]
    async fn a_panicking_job_is_isolated_not_fatal() {
        use futures_util::FutureExt;
        let job = async {
            panic!("boom inside a job handler");
            #[allow(unreachable_code)]
            Ok::<Vec<AdvisorMessage>, ProviderError>(Vec::new())
        };
        let outcome = std::panic::AssertUnwindSafe(job).catch_unwind().await;
        assert!(
            outcome.is_err(),
            "a job panic must be caught by the boundary, never propagated to the serve loop"
        );
        // The recovery path the loop takes: treat a caught panic as "no
        // replies" and keep serving.
        let recovered: Result<Vec<AdvisorMessage>> = match outcome {
            Ok(r) => r,
            Err(_) => Ok(Vec::new()),
        };
        assert!(recovered.unwrap().is_empty());
    }

    #[tokio::test]
    async fn handle_inference_request_emits_chunk_and_complete_no_receipt_when_missing_inputs() {
        let signer = load_or_create_identity().unwrap();
        let provider_kp = fresh_keypair();
        let requester_kp = fresh_keypair();
        let pds = fake_pds();
        let engines = stub_registry();
        let cx = ctx(&*signer, &provider_kp, &pds, None, &engines);
        let plaintext = b"Phase 2.5 round-trip plaintext.";
        let ct = requester_kp
            .seal_to(&provider_kp.public_key_b64(), plaintext)
            .unwrap();
        let req = InferenceRequest {
            job_uri: "at://did:plc:requester/dev.cocore.compute.job/abc".into(),
            // No job_cid, no attestation -> should skip receipt publish.
            job_cid: None,
            requester_did: "did:plc:requester".into(),
            requester_pub_key: requester_kp.public_key_b64(),
            model: "stub".into(),
            max_tokens_out: 16,
            ciphertext: ct,
            input_format: None,
            session_id: "session-1".into(),
            nonce: None,
            attestation_cid: None,
            output_schema: None,
            tools: None,
            tool_choice: None,
            tool_choice_function: None,
            brokerage_countersignature: None,
        };
        let replies = handle_inference_request(req, &cx).await;
        let chunks: Vec<&InferenceChunk> = replies
            .iter()
            .filter_map(|m| match m {
                AdvisorMessage::InferenceChunk(c) => Some(c),
                _ => None,
            })
            .collect();
        assert!(
            chunks.len() > 1,
            "stub stream should emit multiple chunks, got {}",
            chunks.len()
        );
        let mut opened = String::new();
        for c in &chunks {
            assert_eq!(c.session_id, "session-1");
            let piece = requester_kp
                .open_from(&provider_kp.public_key_b64(), &c.ciphertext)
                .expect("requester opens chunk");
            opened.push_str(&String::from_utf8(piece).unwrap());
        }
        assert!(opened.contains("cocore stub provider"));
        assert!(opened.contains("Phase 2.5 round-trip plaintext"));
        match replies.last() {
            Some(AdvisorMessage::InferenceComplete(c)) => {
                assert_eq!(c.session_id, "session-1");
                assert!(c.receipt_uri.is_empty(), "no inputs => no receipt URI");
            }
            other => panic!("expected InferenceComplete last, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn handle_inference_request_drops_undecryptable_ciphertext() {
        let signer = load_or_create_identity().unwrap();
        let provider_kp = fresh_keypair();
        let requester_kp = fresh_keypair();
        let pds = fake_pds();
        let engines = stub_registry();
        let cx = ctx(&*signer, &provider_kp, &pds, None, &engines);
        let req = InferenceRequest {
            job_uri: "at://x".into(),
            job_cid: None,
            requester_did: "did:plc:r".into(),
            requester_pub_key: requester_kp.public_key_b64(),
            model: "stub".into(),
            max_tokens_out: 1,
            // Garbage bytes — won't decrypt.
            ciphertext: vec![0u8; 64],
            input_format: None,
            session_id: "bad".into(),
            nonce: None,
            attestation_cid: None,
            output_schema: None,
            tools: None,
            tool_choice: None,
            tool_choice_function: None,
            brokerage_countersignature: None,
        };
        let replies = handle_inference_request(req, &cx).await;
        assert!(replies.is_empty());
    }

    #[tokio::test]
    async fn handle_inference_request_emits_empty_receipt_when_publish_fails() {
        // Has both job_cid AND attestation, so the publish path
        // runs — but the PdsClient targets a closed port, so the
        // HTTP call fails and `receipt_uri` ends up empty without
        // panicking.
        let signer = load_or_create_identity().unwrap();
        let provider_kp = fresh_keypair();
        let requester_kp = fresh_keypair();
        let pds = fake_pds();
        let attestation = StrongRef {
            uri: "at://did:plc:test/dev.cocore.compute.attestation/aaa".into(),
            cid: "bafyatt".into(),
        };
        let engines = stub_registry();
        let cx = ctx(&*signer, &provider_kp, &pds, Some(&attestation), &engines);
        let plaintext = b"hello";
        let ct = requester_kp
            .seal_to(&provider_kp.public_key_b64(), plaintext)
            .unwrap();
        let req = InferenceRequest {
            job_uri: "at://did:plc:requester/dev.cocore.compute.job/jjj".into(),
            job_cid: Some("bafyjob".into()),
            requester_did: "did:plc:requester".into(),
            requester_pub_key: requester_kp.public_key_b64(),
            model: "stub".into(),
            max_tokens_out: 4,
            ciphertext: ct,
            input_format: None,
            session_id: "publish-fails".into(),
            nonce: None,
            attestation_cid: None,
            output_schema: None,
            tools: None,
            tool_choice: None,
            tool_choice_function: None,
            brokerage_countersignature: None,
        };
        let replies = handle_inference_request(req, &cx).await;
        match replies.last() {
            Some(AdvisorMessage::InferenceComplete(c)) => {
                assert!(c.receipt_uri.is_empty(), "publish failure => empty URI");
            }
            other => panic!("expected InferenceComplete, got {other:?}"),
        }
    }
}
