//! PDS write surface for the provider.
//!
//! The provider publishes three record types:
//!
//!   * `dev.cocore.compute.provider`        — once per `serve` start
//!   * `dev.cocore.compute.attestation`     — once per `serve` start
//!   * `dev.cocore.compute.receipt`         — once per completed job
//!
//! v0.3.0 swapped the architecture: the agent **does not** call bsky
//! directly. It POSTs each record to the cocore console's proxy
//! (`POST /api/pds/createRecord`) using the API
//! key from its paired session. The console resolves the key to a
//! DID, restores the user's DPoP-aware OAuth session, and forwards
//! the create to bsky on the agent's behalf.
//!
//! Why: real bsky PDSes require DPoP-bound tokens (ES256-signed
//! per-request proofs). The agent doesn't sign DPoP today; the
//! console's JS OAuth client does. Routing every write through the
//! console keeps DPoP in one place and lets us iterate on signing
//! semantics without re-shipping a Rust binary.
//!
//! Token lifecycle: API keys are stable until revoked. There is no
//! refresh path here — if the key is rejected, the agent fails the
//! publish and surfaces the error. The user revokes/re-mints in the
//! console at /api-keys.

use crate::error::{ProviderError, Result};
use crate::oauth::Session;
use serde::{Deserialize, Serialize};

/// Connect timeout for every PDS / console-proxy HTTP call. A hostile or
/// half-open peer must not be able to hang the connect indefinitely.
pub(crate) const HTTP_CONNECT_TIMEOUT_SECS: u64 = 10;
/// Total request timeout for PDS / console-proxy calls. Record writes and the
/// small reads here have no long streaming body, so a modest ceiling is safe.
pub(crate) const HTTP_REQUEST_TIMEOUT_SECS: u64 = 30;

/// Inputs needed to publish a `dev.cocore.compute.provider` record.
#[allow(non_snake_case)]
#[derive(Debug, Serialize, Clone)]
pub struct ProviderRecord {
    pub machineLabel: String,
    pub chip: String,
    pub ramGB: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gpuCores: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memoryBandwidthGBs: Option<u32>,
    /// New in v0.3.1 — total CPU cores.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpuCores: Option<u32>,
    /// New in v0.3.1 — Apple Silicon performance-core split.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pCores: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eCores: Option<u32>,
    /// New in v0.3.1 — Apple model code (e.g. "Macmini9,1").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modelIdentifier: Option<String>,
    /// New in v0.3.1 — operating system + version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    pub supportedModels: Vec<String>,
    pub priceList: Vec<ModelPrice>,
    pub encryptionPubKey: String,
    pub attestationPubKey: String,
    /// Stable per-machine identity that survives signing-key rotation (a hash of
    /// the hardware serial, salted by DID). Unlike `attestationPubKey`, this does
    /// NOT change when the signing key rotates (software -> Secure Enclave on the
    /// 0.9.43 upgrade), so the agent can recognize an existing record as its own
    /// prior incarnation and adopt it (carrying `desiredTier`/`active`/... forward)
    /// instead of orphaning it. Absent on records written before 0.9.44 and on
    /// hosts where the serial can't be read; identity then falls back to
    /// `attestationPubKey` + hardware profile. Additive.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub machineFingerprint: Option<String>,
    pub trustLevel: TrustLevel,
    /// Agent-published ACHIEVED confidentiality tier (`attested-confidential` |
    /// `best-effort`), derived from the signed attestation's evidence — NEVER
    /// self-declared. Absent ≡ best-effort. The agent only publishes
    /// `attested-confidential` once the measured native engine is serving under
    /// a hardware-attested posture. See `desiredTier` for the owner's intent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub acceptedExchanges: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contactEndpoint: Option<String>,
    /// Version of the agent binary that wrote this record (e.g.
    /// `0.3.4`). Stamped on every `cocore agent serve` startup so
    /// dashboards can tell at a glance which machines need an
    /// update. Optional in the lexicon (additive); always set in
    /// records this binary writes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binaryVersion: Option<String>,
    /// Whether this DID has a payout method on file. The agent
    /// itself doesn't know — it's set by the console's reconcile
    /// flow after Stripe Connect onboarding. We carry the field
    /// here so the agent's startup `put_provider` can PRESERVE the
    /// value when it re-publishes the record (otherwise every
    /// serve restart would clobber the field back to absent). The
    /// agent never writes `true` on its own; it only echoes back
    /// whatever it found on the existing record.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payoutsEnabled: Option<bool>,
    /// Owner-controlled serve switch. `Some(false)` means the owner has
    /// stopped this machine from the console (it should be routed no jobs);
    /// `Some(true)` / `None` means it serves. The agent NEVER sets this
    /// itself — the console writes it to the owner's PDS — so the agent
    /// must PRESERVE whatever it finds on the existing record when it
    /// re-publishes (exactly like `payoutsEnabled`), and it reports the
    /// value to the advisor so routing can skip a stopped machine.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
    /// Model identifiers the OWNER wants this machine to load, written from
    /// a management UI (the console's per-machine model picker). The agent
    /// reconciles toward it (loads it at serve start; restarts to reload
    /// when it changes) but never AUTHORS it — like `active`/`payoutsEnabled`
    /// it's console-written and the agent must PRESERVE it on every
    /// re-publish, or each serve would clobber the owner's choice.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub desiredModels: Option<Vec<String>>,
    /// The confidentiality tier the OWNER opted this machine into (the console /
    /// tray "Upgrade security" action), `attested-confidential` | `best-effort`.
    /// Owner-written INTENT, like `desiredModels`/`active`: the agent reconciles
    /// toward it (switches to the measured native engine, earns the posture) but
    /// NEVER authors it, so it must PRESERVE whatever it finds on every
    /// re-publish. Setting it never fakes the achieved `tier`/`trustLevel` —
    /// those only rise once actually earned; a machine that can't (e.g. a
    /// non-native build) stays best-effort. Absent / `best-effort` = not opted
    /// in, serves exactly as before.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub desiredTier: Option<String>,
    /// The owner's pro-bono election: serve matching jobs free, unmetered,
    /// no exchange cut. Owner-written INTENT, like `desiredModels`/`active`/
    /// `desiredTier`: the agent reconciles toward it (a matching job gets a
    /// `proBono: true`, zero-price, zero-token receipt) but NEVER authors it,
    /// so it must PRESERVE whatever it finds on every re-publish. Absent ≡
    /// off (every job is metered and billed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proBono: Option<ProBonoPolicy>,
    /// The owner's opt-in to publishing this machine's coarse country. Owner-
    /// written INTENT, like `desiredModels`/`active`/`desiredTier`/`proBono`:
    /// the agent reconciles toward it (when true it geolocates the public IP at
    /// serve start and stamps `region`/`regionSource`/`regionObservedAt`) but
    /// NEVER authors it, so it must PRESERVE whatever it finds on every
    /// re-publish. Absent ≡ not sharing; the agent then omits the region
    /// fields so opting out clears any previously-shared value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shareLocation: Option<bool>,
    /// The owner's opt-in to serving tool/function calls. Owner-written INTENT,
    /// like `desiredModels`/`active`/`desiredTier`/`proBono`/`shareLocation`:
    /// the agent reconciles toward it (when true it enables vLLM automatic tool
    /// choice for the curated top models and verifies each with a forced-tool
    /// startup canary before advertising it) but NEVER authors it, so it must
    /// PRESERVE whatever it finds on every re-publish. Absent ≡ off (no engine
    /// advertises tool calls; the machine serves exactly as before).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub toolCalls: Option<bool>,
    /// True while the agent is still loading its inference engine. Set on
    /// the early "provisioning" publish at serve start so the machine
    /// appears on the console immediately; cleared (set false) on the
    /// re-publish once the engine is ready. See `cmd_serve`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provisioning: Option<bool>,
    /// Liveness flag. `Some(true)` while the serve loop is up; the agent
    /// publishes `Some(false)` on graceful shutdown (SIGTERM) so the
    /// console can show the machine offline the moment it stops serving.
    /// `None` on records from binaries that predate the field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serving: Option<bool>,
    /// Set when `serve` could not bring the configured inference engine
    /// online after exhausting its startup recovery attempts. The agent
    /// clears this (writes `None`) on every healthy serve, so its
    /// presence always reflects the *current* serve lifetime, not a
    /// stale failure. See `build_engines`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engineFault: Option<EngineFault>,
    /// Set when `serve` could not build or publish this machine's
    /// `dev.cocore.compute.attestation` record. Without a published
    /// attestation the machine cannot produce verifiable receipts (every
    /// receipt strong-refs one), so it stays effectively self-attested and
    /// silently completes no billable work. The agent clears this (writes
    /// `None`) on every successful (re-)attestation, so its presence reflects
    /// the current state, not a stale failure. See `build_and_publish_attestation`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestationFault: Option<AttestationFault>,
    /// Coarse, opt-in country of this machine, ISO 3166-1 alpha-2 (e.g.
    /// "US"). AGENT-authored and ADVISORY: a self-asserted claim from a
    /// best-effort IP→country lookup at serve start, NOT a proof of location
    /// (a VPN moves it; verifiers MUST NOT trust it — same posture as
    /// `tier`). Set fresh on every serve when the owner has opted in via the
    /// console's `shareLocation` switch on this record; `None` when sharing is
    /// off, so a re-publish drops any previously-shared value (opt-out clears
    /// the data). Unlike the console-authored switches it is NOT carried
    /// through `preserve_console_fields` — the agent re-derives it each serve
    /// from `shareLocation`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// How `region` was derived (e.g. `ip-geo`). Present iff `region` is.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub regionSource: Option<String>,
    /// When `region` was observed this serve. Present iff `region` is; lets
    /// consumers judge the freshness of the refresh-on-serve stamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub regionObservedAt: Option<chrono::DateTime<chrono::Utc>>,
    pub createdAt: chrono::DateTime<chrono::Utc>,
}

/// Owner-INTENT fields on the provider record. The console (web UI and, via the
/// proxy, the tray) is the ONLY writer of these; the agent reconciles its
/// runtime toward them but must NEVER author them. They are the contested
/// settings, so the merge below treats the latest PDS value as authoritative
/// and the agent's republish leaves them exactly as-is.
///
/// This is the one list that must stay in sync with the lexicon's owner-intent
/// fields. Adding a new owner setting? Add its key here (and the console writes
/// it). Forgetting to is the failure we are designing OUT — see
/// {@link merge_agent_provider_fields}, which preserves unknown keys by default,
/// so even an owner field missing from this list is carried through rather than
/// clobbered. The list exists only so the agent can defensively refuse to write
/// these even if a bug populated them.
pub const OWNER_INTENT_KEYS: &[&str] = &[
    "active",
    "payoutsEnabled",
    "desiredModels",
    "desiredTier",
    "proBono",
    "shareLocation",
    "toolCalls",
];

/// Agent-authored OPTIONAL fields — present some serves, absent others (a tier
/// the machine earned then lost, an engineFault that cleared, region when the
/// owner turns location sharing off). The agent owns these, so when it does NOT
/// emit one this serve the merge must DELETE it from the published record, or a
/// stale value would linger. Always-present agent fields (chip, ram,
/// supportedModels, keys, …) don't need listing — the overlay overwrites them
/// every serve regardless.
///
/// A new agent optional field forgotten here just goes stale (the old value
/// lingers until the next field-setting serve) — benign, and never touches
/// owner data. Contrast the old `preserve_console_fields` allowlist, whose
/// omission silently DESTROYED an owner setting.
const AGENT_OPTIONAL_KEYS: &[&str] = &[
    "gpuCores",
    "memoryBandwidthGBs",
    "cpuCores",
    "pCores",
    "eCores",
    "modelIdentifier",
    "os",
    "tier",
    "acceptedExchanges",
    "contactEndpoint",
    "binaryVersion",
    "provisioning",
    "serving",
    "engineFault",
    "attestationFault",
    "region",
    "regionSource",
    "regionObservedAt",
];

/// Produce the JSON body the agent should publish for its provider record, by
/// applying its freshly-built `agent_record` onto the LATEST record body read
/// from the PDS (`base`). This is the field-ownership merge that replaces the
/// old "rebuild the record and copy an allowlist of the owner's fields onto it"
/// (`preserve_console_fields`) — inverted so the safe default is PRESERVE:
///
///   1. Start from `base` (the latest PDS body) — so every key, including
///      owner-intent fields AND any field this build has never heard of, is
///      carried through by default. A new owner setting can never be clobbered.
///   2. Overlay every key the agent authored this serve (present in the
///      serialized `agent_record`), except — defensively — any owner-intent key
///      (the agent must never write those; it builds them as `None` so they're
///      already absent, but we strip them belt-and-suspenders).
///   3. Delete any agent-authored OPTIONAL key the agent did NOT emit this
///      serve, so a tier/fault/region the machine no longer has doesn't linger.
///
/// The result is then written under compare-and-swap by the caller, so a
/// concurrent owner edit either is already in `base` (and preserved) or wins
/// the swap and forces a re-read.
pub fn merge_agent_provider_fields(
    base: &serde_json::Value,
    agent_record: &ProviderRecord,
) -> serde_json::Value {
    let mut out = base.as_object().cloned().unwrap_or_default();
    let patch = serde_json::to_value(agent_record).unwrap_or(serde_json::Value::Null);
    let patch_obj = patch.as_object();
    // (3) Clear agent-authored optional fields the agent isn't emitting now.
    for key in AGENT_OPTIONAL_KEYS {
        let emitted_now = patch_obj.map(|o| o.contains_key(*key)).unwrap_or(false);
        if !emitted_now {
            out.remove(*key);
        }
    }
    // (2) Overlay the agent's authored fields, never an owner-intent field.
    if let Some(obj) = patch_obj {
        for (k, v) in obj {
            if OWNER_INTENT_KEYS.contains(&k.as_str()) {
                continue;
            }
            out.insert(k.clone(), v.clone());
        }
    }
    serde_json::Value::Object(out)
}

/// Stable per-machine fingerprint = `sha256(serial | did)`, hex. Salted by the
/// owner DID so the value can't correlate a machine across different owners.
/// Survives signing-key rotation because the hardware serial doesn't change.
/// Mirrors the attestation's `serialNumberHash` salt scheme so the two agree.
pub fn machine_fingerprint(serial: &str, did: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(serial.as_bytes());
    h.update(b"|");
    h.update(did.as_bytes());
    hex::encode(h.finalize())
}

/// One `dev.cocore.compute.provider` record on the DID, reduced to the fields
/// record-identity reconciliation needs. Built from a PDS list result.
#[derive(Debug, Clone)]
pub struct ListedProviderRecord {
    pub rkey: String,
    pub cid: String,
    pub created_at: String,
    pub attestation_pub_key: Option<String>,
    pub machine_fingerprint: Option<String>,
    pub machine_label: Option<String>,
    pub model_identifier: Option<String>,
    pub chip: Option<String>,
    pub value: serde_json::Value,
}

impl ListedProviderRecord {
    /// Extract the identity fields from a raw PDS record body.
    pub fn from_value(rkey: String, cid: String, value: serde_json::Value) -> Self {
        let s = |k: &str| value.get(k).and_then(|v| v.as_str()).map(str::to_string);
        Self {
            rkey,
            cid,
            created_at: s("createdAt").unwrap_or_default(),
            attestation_pub_key: s("attestationPubKey"),
            machine_fingerprint: s("machineFingerprint"),
            machine_label: s("machineLabel"),
            model_identifier: s("modelIdentifier"),
            chip: s("chip"),
            value,
        }
    }
}

/// This machine's identity, for matching its own records across a key rotation.
#[derive(Debug, Clone)]
pub struct MachineIdentity<'a> {
    pub attestation_pub_key: &'a str,
    /// `None` when the hardware serial couldn't be read.
    pub machine_fingerprint: Option<&'a str>,
    pub machine_label: &'a str,
    pub model_identifier: Option<&'a str>,
    pub chip: &'a str,
    /// The rkey this agent last published to (from `provider-rkey.json`), if any.
    pub cached_rkey: Option<&'a str>,
}

/// How a listed record relates to this machine.
#[derive(Debug, PartialEq, Eq)]
enum Kinship {
    /// Definitely this machine (current key, matching fingerprint, or our cached rkey).
    Mine,
    /// A legacy record (no `machineFingerprint`) whose hardware profile matches —
    /// probably ours from before the fix, but only adopted if it's the UNIQUE such
    /// candidate (guards against two identically-named machines under one DID).
    LegacyCandidate,
    /// Someone else's machine (a different fingerprint, or an unrelated record).
    Other,
}

fn classify(rec: &ListedProviderRecord, me: &MachineIdentity) -> Kinship {
    // A present fingerprint is DEFINITIVE: equal => mine, unequal => not mine.
    // This protects sibling machines from ever being adopted/deleted by heuristic.
    if let (Some(rf), Some(mf)) = (rec.machine_fingerprint.as_deref(), me.machine_fingerprint) {
        return if rf == mf {
            Kinship::Mine
        } else {
            Kinship::Other
        };
    }
    // A record carrying a fingerprint we don't share (we couldn't read our serial)
    // is not something we can claim — leave it alone.
    if rec.machine_fingerprint.is_some() {
        return Kinship::Other;
    }
    // Current signing key matches (the common, un-rotated case).
    if rec.attestation_pub_key.as_deref() == Some(me.attestation_pub_key) {
        return Kinship::Mine;
    }
    // Our own record per the local rkey cache (survives a key rotation because the
    // cache is keyed by DID, not pubkey).
    if me.cached_rkey.is_some()
        && rec.attestation_pub_key.is_some()
        && rec.rkey == me.cached_rkey.unwrap()
    {
        return Kinship::Mine;
    }
    // Legacy record without a fingerprint: match on the stable hardware profile.
    let profile_matches = rec.machine_label.as_deref() == Some(me.machine_label)
        && rec.model_identifier.as_deref() == me.model_identifier
        && rec.chip.as_deref() == Some(me.chip);
    if profile_matches {
        Kinship::LegacyCandidate
    } else {
        Kinship::Other
    }
}

/// The outcome of reconciling this machine's provider records: which record to
/// adopt (keep its rkey), the base body to publish onto (with the owner's intent
/// harvested from any orphaned prior record), and which stale duplicates to delete.
#[derive(Debug)]
pub struct ProviderReconciliation {
    pub canonical_rkey: String,
    pub canonical_cid: String,
    /// The canonical record body with owner-intent fields harvested from all of
    /// this machine's records (so a `desiredTier` stranded on a pre-rotation
    /// record is carried forward). Merge the agent's fields onto THIS.
    pub base: serde_json::Value,
    /// `(rkey, cid)` of stale duplicate records for THIS machine to delete.
    pub delete: Vec<(String, String)>,
    /// Count of legacy candidates left alone because the match was ambiguous
    /// (more than one profile-matching record) — surfaced for logging.
    pub ambiguous_legacy: usize,
}

/// Decide which of this machine's provider records to adopt and which to delete,
/// carrying the owner's intent forward across a signing-key rotation. Returns
/// `None` when no record belongs to this machine (caller creates a fresh one).
///
/// PURE (no I/O) so it's unit-testable; `dedup_and_publish_provider` supplies the
/// listed records and performs the resulting put/delete under compare-and-swap.
pub fn reconcile_provider_records(
    listed: &[ListedProviderRecord],
    me: &MachineIdentity,
) -> Option<ProviderReconciliation> {
    let mut mine: Vec<&ListedProviderRecord> = Vec::new();
    let mut legacy: Vec<&ListedProviderRecord> = Vec::new();
    for rec in listed {
        match classify(rec, me) {
            Kinship::Mine => mine.push(rec),
            Kinship::LegacyCandidate => legacy.push(rec),
            Kinship::Other => {}
        }
    }
    // A legacy profile match is adopted ONLY when unique — otherwise two
    // identically-named machines under one DID would cross-contaminate. When
    // ambiguous, leave the legacy records untouched (they'll age out / be handled
    // by the console cleanup), but still reconcile any definitively-mine records.
    let ambiguous_legacy = if legacy.len() > 1 { legacy.len() } else { 0 };
    if legacy.len() == 1 {
        mine.push(legacy[0]);
    }
    if mine.is_empty() {
        return None;
    }
    // Canonical = our cached rkey if it's among ours (keeps machineId stable),
    // else the newest by createdAt.
    mine.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    let canonical = me
        .cached_rkey
        .and_then(|rk| mine.iter().find(|r| r.rkey == rk).copied())
        .unwrap_or(mine[0]);

    // Harvest owner-intent: fill any owner key ABSENT on the canonical from the
    // most-recent OTHER record of ours that has it (mine is newest-first). This is
    // what carries a `desiredTier` stranded on a pre-rotation record forward.
    let mut base = canonical.value.clone();
    if let Some(obj) = base.as_object_mut() {
        for key in OWNER_INTENT_KEYS {
            let present = obj.get(*key).map(|v| !v.is_null()).unwrap_or(false);
            if present {
                continue;
            }
            if let Some(v) = mine
                .iter()
                .filter_map(|r| r.value.get(*key))
                .find(|v| !v.is_null())
            {
                obj.insert((*key).to_string(), v.clone());
            }
        }
    }

    let delete = mine
        .iter()
        .filter(|r| r.rkey != canonical.rkey)
        .map(|r| (r.rkey.clone(), r.cid.clone()))
        .collect();

    Some(ProviderReconciliation {
        canonical_rkey: canonical.rkey.clone(),
        canonical_cid: canonical.cid.clone(),
        base,
        delete,
        ambiguous_legacy,
    })
}

/// The owner's pro-bono election for a machine, mirroring the lexicon
/// `dev.cocore.compute.provider#proBonoPolicy`. Decides, per requester,
/// whether a job is served free + unmetered with no exchange cut.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ProBonoPolicy {
    /// `any` — every requester is served pro bono. `direct` — only the
    /// requesters in `dids` are. Any other / empty value is treated as
    /// off (paid), failing closed.
    pub mode: String,
    /// Requester DIDs served pro bono under `mode: direct`. Ignored when
    /// `mode` is `any`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dids: Vec<String>,
}

impl ProBonoPolicy {
    /// Does this policy serve `requester_did` pro bono? `any` ⇒ always;
    /// `direct` ⇒ only when the DID is listed; anything else ⇒ never.
    /// Fails closed (paid) on an unrecognized mode.
    pub fn applies_to(&self, requester_did: &str) -> bool {
        match self.mode.as_str() {
            "any" => true,
            "direct" => self.dids.iter().any(|d| d == requester_did),
            _ => false,
        }
    }

    /// Parse a policy from a raw provider-record JSON value (the shape
    /// `find_my_provider_record` returns). Returns `None` when the field
    /// is absent or malformed — both equivalent to "no pro bono".
    pub fn from_record_value(value: &serde_json::Value) -> Option<Self> {
        let obj = value.get("proBono")?;
        serde_json::from_value(obj.clone()).ok()
    }
}

/// A content-safe description of why the inference engine failed to
/// load. Published on the provider record so the console can show the
/// operator a fault + remediation instead of a silently-stubbed machine
/// that looks healthy but never gets routed real jobs. Recorded only
/// after `serve`'s bounded retry loop gives up; populated strictly from
/// startup diagnostics (no prompt/completion bytes ever reach it).
#[allow(non_snake_case)]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EngineFault {
    /// Machine-readable fault class: `model-load-failed`, `venv-missing`,
    /// or `no-home`.
    pub code: String,
    /// Human-readable summary with remediation guidance.
    pub message: String,
    /// The configured model ids that failed to load.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub models: Vec<String>,
    /// When the agent gave up and recorded the fault.
    pub at: chrono::DateTime<chrono::Utc>,
}

/// A content-safe description of why the attestation could not be built or
/// published. Published on the provider record (mirroring [`EngineFault`]) so
/// the console can show the operator that receipts are disabled and why,
/// instead of a machine that looks healthy but completes no billable jobs.
/// Cleared on every successful (re-)attestation. No prompt/completion bytes
/// ever reach it (attestation runs before any job).
#[allow(non_snake_case)]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AttestationFault {
    /// Machine-readable fault class: `attestation-publish-failed` (the record
    /// could not be written to the PDS) or `attestation-build-failed` (the
    /// signed record could not be assembled).
    pub code: String,
    /// Human-readable summary with remediation guidance.
    pub message: String,
    /// When the agent recorded the fault.
    pub at: chrono::DateTime<chrono::Utc>,
}

/// A content-safe description of why the advisor WebSocket cannot be
/// established. Published on the provider record (mirroring [`EngineFault`] /
/// [`AttestationFault`]) so the console can show "serving locally but can't
/// reach the network" instead of a healthy-looking machine that silently
/// never receives jobs. Written through the console's HTTPS proxy — exactly
/// the transport that still works in the failure this diagnoses — and
/// cleared on the next successful advisor registration.
///
/// Deliberately NOT a field on [`ProviderRecord`]: it changes mid-serve (set
/// after repeated connect failures, cleared on registration), so it is
/// written with the field-scoped [`PdsClient::patch_provider_advisor_fault`]
/// rather than the whole-record merge — a full re-publish (offline marker,
/// attestation refresh) carries it through untouched as an unknown key.
#[allow(non_snake_case)]
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct AdvisorFault {
    /// Machine-readable fault class: `dns-failure`, `tls-failure`,
    /// `connect-timeout`, `connect-refused`, `upgrade-blocked`,
    /// `http-<status>`, `network-unreachable`, … (see the lexicon).
    pub code: String,
    /// Human-readable summary with remediation guidance. Carries only the
    /// classified error kind — never raw error text, URLs, or credentials.
    pub message: String,
    /// When the agent recorded the fault.
    pub observedAt: chrono::DateTime<chrono::Utc>,
}

/// Whether this process may have an `advisorFault` published on its provider
/// record (or one left over from a previous process). Starts true so the
/// first successful registration after boot checks the record once and
/// removes any stale fault; [`PdsClient::patch_provider_advisor_fault`]
/// keeps it in sync afterwards, so subsequent reconnects skip the read
/// entirely instead of hitting the PDS every ~14-minute edge recycle.
static ADVISOR_FAULT_MAYBE_PUBLISHED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(true);

pub fn advisor_fault_maybe_published() -> bool {
    ADVISOR_FAULT_MAYBE_PUBLISHED.load(std::sync::atomic::Ordering::Relaxed)
}

#[allow(non_snake_case)]
#[derive(Debug, Serialize, Clone)]
pub struct ModelPrice {
    pub modelId: String,
    pub inputPricePerMTok: u64,
    pub outputPricePerMTok: u64,
    pub currency: String,
}

#[derive(Debug, Serialize, Clone, Copy)]
#[serde(rename_all = "kebab-case")]
pub enum TrustLevel {
    SelfAttested,
    HardwareAttested,
}

/// A published record's location, plus the signed repo commit it landed
/// in. `commit.rev` is an inclusion pointer into the provider's MST: the
/// repo revision at which this record became part of the signed tree.
#[derive(Debug, Clone, Deserialize)]
pub struct PublishedRecord {
    pub uri: String,
    pub cid: String,
    #[serde(default)]
    pub commit: Option<RepoCommit>,
}

/// The `commit` half of a `com.atproto.repo.createRecord` response.
#[derive(Debug, Clone, Deserialize)]
pub struct RepoCommit {
    pub cid: String,
    pub rev: String,
}

/// One row of `com.atproto.repo.listRecords` output, narrowed to what
/// the dedup path needs (everything else is ignored). The PDS exposes
/// listRecords without auth so we can hit it directly without going
/// through the console proxy.
#[derive(Debug, Clone, Deserialize)]
pub struct ListedRecord {
    pub uri: String,
    pub cid: String,
    pub value: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct ListRecordsResponse {
    records: Vec<ListedRecord>,
    #[serde(default)]
    cursor: Option<String>,
}

/// Response shape of `com.atproto.server.getServiceAuth` (as re-served by the
/// console proxy): a single short-lived JWT.
#[derive(Debug, Deserialize)]
struct ServiceAuthResponse {
    token: String,
}

/// HTTP client over the console's `/api/pds/createRecord`
/// endpoint. One instance per agent lifetime; the API key is
/// captured at construction and never rotated.
#[derive(Clone)]
pub struct PdsClient {
    did: String,
    api_base: String,
    api_key: String,
    http: reqwest::Client,
}

impl PdsClient {
    pub fn new(session: Session) -> Self {
        // Bound every PDS call: a slow or hostile PDS / console proxy must not
        // be able to wedge publish/read paths indefinitely. Mirrors the timeout
        // posture in `update.rs`.
        let http = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(HTTP_CONNECT_TIMEOUT_SECS))
            .timeout(std::time::Duration::from_secs(HTTP_REQUEST_TIMEOUT_SECS))
            .build()
            .expect("reqwest client construction is infallible");
        Self {
            did: session.did,
            api_base: session.api_base,
            api_key: session.api_key,
            http,
        }
    }

    pub fn provider_did(&self) -> &str {
        &self.did
    }

    pub async fn publish_provider(&self, record: &ProviderRecord) -> Result<PublishedRecord> {
        self.publish("dev.cocore.compute.provider", record).await
    }

    /// Idempotent upsert via the console's `proxy.putRecord` endpoint.
    /// Used by the dedup-and-republish path on every `serve` startup
    /// so this machine has exactly one provider record on PDS,
    /// stably-keyed by the rkey we computed at first publish.
    pub async fn put_provider(
        &self,
        rkey: &str,
        record: &ProviderRecord,
        swap_record: Option<&str>,
    ) -> Result<PublishedRecord> {
        self.put_record("dev.cocore.compute.provider", rkey, record, swap_record)
            .await
    }

    /// Generic putRecord proxy. Same auth + allowlist as
    /// `publish` (which is createRecord); the difference is the rkey
    /// is required and the operation is upsert-with-swap-guard.
    pub async fn put_record<R: Serialize>(
        &self,
        collection: &str,
        rkey: &str,
        record: &R,
        swap_record: Option<&str>,
    ) -> Result<PublishedRecord> {
        let url = format!("{}/api/pds/putRecord", self.api_base.trim_end_matches('/'));
        let body = match swap_record {
            Some(swap) => serde_json::json!({
                "collection": collection,
                "rkey": rkey,
                "record": record,
                "swapRecord": swap,
            }),
            None => serde_json::json!({
                "collection": collection,
                "rkey": rkey,
                "record": record,
            }),
        };
        tracing::debug!(collection, rkey, did = %self.did, "putRecord via console proxy");
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.api_key)
            .json(&body)
            .send()
            .await
            .map_err(|e| ProviderError::Pds(format!("transport: {e}")))?;
        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| ProviderError::Pds(format!("read body: {e}")))?;
        if !status.is_success() {
            return Err(ProviderError::Pds(format!(
                "console proxy putRecord {collection} returned {status}: {text}"
            )));
        }
        serde_json::from_str(&text).map_err(|e| {
            ProviderError::Pds(format!("decode {collection} response: {e} body={text}"))
        })
    }

    /// Delete a record on the user's PDS via the console proxy.
    /// Used to trim duplicate provider records on every `serve`
    /// startup. Treats 404 / "InvalidSwap" / "could not locate" as
    /// success — the goal is "the record is gone", and the proxy
    /// already mirrors the AppView clear regardless of PDS outcome.
    pub async fn delete_record(
        &self,
        collection: &str,
        rkey: &str,
        swap_record: Option<&str>,
    ) -> Result<()> {
        let url = format!(
            "{}/api/pds/deleteRecord",
            self.api_base.trim_end_matches('/')
        );
        let body = match swap_record {
            Some(swap) => serde_json::json!({
                "collection": collection,
                "rkey": rkey,
                "swapRecord": swap,
            }),
            None => serde_json::json!({
                "collection": collection,
                "rkey": rkey,
            }),
        };
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.api_key)
            .json(&body)
            .send()
            .await
            .map_err(|e| ProviderError::Pds(format!("transport: {e}")))?;
        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| ProviderError::Pds(format!("read body: {e}")))?;
        if !status.is_success() {
            return Err(ProviderError::Pds(format!(
                "console proxy deleteRecord {collection} returned {status}: {text}"
            )));
        }
        Ok(())
    }

    /// List all of this provider's own records under `collection` on
    /// its PDS. Reads through bsky's public read endpoint (no auth);
    /// the agent uses this to find duplicates by `attestationPubKey`
    /// before republishing. Pagination caps at 100 pages × 100 records
    /// per page (10000 total) — well above any realistic duplicate
    /// count.
    pub async fn list_my_records(&self, collection: &str) -> Result<Vec<ListedRecord>> {
        let pds_endpoint = self.resolve_pds_endpoint().await?;
        let mut out: Vec<ListedRecord> = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..100 {
            let mut url = format!(
                "{}/xrpc/com.atproto.repo.listRecords?repo={}&collection={}&limit=100",
                pds_endpoint.trim_end_matches('/'),
                self.did,
                collection,
            );
            if let Some(c) = &cursor {
                url.push_str(&format!("&cursor={c}"));
            }
            let resp = self
                .http
                .get(&url)
                .send()
                .await
                .map_err(|e| ProviderError::Pds(format!("listRecords transport: {e}")))?;
            if !resp.status().is_success() {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                return Err(ProviderError::Pds(format!(
                    "listRecords {collection} returned {status}: {text}"
                )));
            }
            let body: ListRecordsResponse = resp
                .json()
                .await
                .map_err(|e| ProviderError::Pds(format!("listRecords decode: {e}")))?;
            let got = body.records.len();
            out.extend(body.records);
            match body.cursor {
                Some(c) if got > 0 => cursor = Some(c),
                _ => break,
            }
        }
        Ok(out)
    }

    /// Read the owner-set `active` start/stop switch from this DID's
    /// provider record at `rkey`. Returns `Some(bool)` when the field is
    /// present, `None` when it's absent (the lexicon default — serving) or
    /// on any read error. Reuses `list_my_records` (the proxy exposes no
    /// getRecord); a DID typically owns one provider record, so this is a
    /// single cheap list. The agent polls this to honour a remote stop.
    pub async fn get_provider_active(&self, rkey: &str) -> Option<bool> {
        let listed = self
            .list_my_records("dev.cocore.compute.provider")
            .await
            .ok()?;
        let rec = listed
            .iter()
            .find(|r| r.uri.rsplit('/').next() == Some(rkey))?;
        rec.value.get("active").and_then(|v| v.as_bool())
    }

    /// Read the owner-set controls — the `active` start/stop switch, the
    /// `desiredModels` list, and the `desiredTier` intent — from this DID's
    /// provider record at `rkey` in one list. Within the record the per-field
    /// defaults are: `active` true (serving) when absent, `desired` empty when
    /// absent, `desiredTier` None when absent.
    ///
    /// Returns `None` when the controls couldn't be determined — the list read
    /// failed (the console proxy fronting these reads 502s transiently) OR no
    /// record currently matches `rkey`. The caller MUST treat `None` as "owner
    /// intent unknown THIS cycle" and skip reconciliation, NOT as a reset to
    /// defaults. A previous version returned `(true, [], None)` on a read
    /// error, which a transient blip made indistinguishable from the owner
    /// clearing their models AND opting out of the confidential tier
    /// (`desiredTier` None normalises to best-effort) — so every blip tripped a
    /// spurious "tier/models changed" restart and the machine churned. Reading
    /// `None` here is the only blip-safe contract. The agent polls this to
    /// honour remote pause + model changes; the serve loop also restarts on a
    /// `desiredTier` change so the supervisor can re-select the confidential
    /// worker binary.
    pub async fn get_provider_control(
        &self,
        rkey: &str,
    ) -> Option<(bool, Vec<String>, Option<String>, bool)> {
        let listed = self
            .list_my_records("dev.cocore.compute.provider")
            .await
            .ok()?;
        let rec = listed
            .iter()
            .find(|r| r.uri.rsplit('/').next() == Some(rkey))?;
        let active = rec
            .value
            .get("active")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        let desired = rec
            .value
            .get("desiredModels")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|m| m.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let desired_tier = rec
            .value
            .get("desiredTier")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        // The owner's tool-calling opt-in; absent ≡ off. The serve loop restarts
        // on a change so the fresh build rebuilds engines with the new setting.
        let tool_calls = rec
            .value
            .get("toolCalls")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        Some((active, desired, desired_tier, tool_calls))
    }

    /// Field-scoped patch of this machine's provider record: set (or, with
    /// `None`, remove) ONLY the `advisorFault` key, leaving every other field
    /// exactly as read. The record-transactor rule in miniature — read the
    /// LATEST record, patch one field, put under a compare-and-swap guard,
    /// re-read and replay on a swap conflict — so a concurrent owner edit or
    /// agent re-publish is never clobbered. Skips the write entirely (and
    /// returns `Ok(false)`) when the record already carries the desired
    /// state, so the serve loop's retries don't spam the PDS with no-op
    /// commits. Fails closed: an unreadable record aborts rather than
    /// fabricating a body.
    ///
    /// Returns whether a write actually happened. Keeps the process-wide
    /// [`advisor_fault_maybe_published`] marker in sync on success.
    pub async fn patch_provider_advisor_fault(
        &self,
        rkey: &str,
        fault: Option<&AdvisorFault>,
    ) -> Result<bool> {
        const MAX_ATTEMPTS: u32 = 4;
        let collection = "dev.cocore.compute.provider";
        for attempt in 1..=MAX_ATTEMPTS {
            let listed = self.list_my_records(collection).await?;
            let Some(rec) = listed
                .iter()
                .find(|r| r.uri.rsplit('/').next() == Some(rkey))
            else {
                return Err(ProviderError::Pds(format!(
                    "provider record {rkey} not found; cannot patch advisorFault"
                )));
            };
            let existing = rec.value.get("advisorFault");
            // Compare by code only: the message is deterministic per code and
            // observedAt changes every classification, so keying on it would
            // defeat the dedup and rewrite the record on every retry.
            let existing_code = existing
                .and_then(|f| f.get("code"))
                .and_then(|c| c.as_str());
            let unchanged = match fault {
                Some(f) => existing_code == Some(f.code.as_str()),
                None => existing.is_none(),
            };
            if unchanged {
                ADVISOR_FAULT_MAYBE_PUBLISHED
                    .store(fault.is_some(), std::sync::atomic::Ordering::Relaxed);
                return Ok(false);
            }
            let mut body = rec.value.as_object().cloned().unwrap_or_default();
            match fault {
                Some(f) => {
                    let v = serde_json::to_value(f)
                        .map_err(|e| ProviderError::Pds(format!("encode advisorFault: {e}")))?;
                    body.insert("advisorFault".to_string(), v);
                }
                None => {
                    body.remove("advisorFault");
                }
            }
            let patched = serde_json::Value::Object(body);
            match self
                .put_record(collection, rkey, &patched, Some(&rec.cid))
                .await
            {
                Ok(_) => {
                    ADVISOR_FAULT_MAYBE_PUBLISHED
                        .store(fault.is_some(), std::sync::atomic::Ordering::Relaxed);
                    return Ok(true);
                }
                Err(ProviderError::Pds(msg))
                    if msg.contains("InvalidSwap") && attempt < MAX_ATTEMPTS =>
                {
                    // Someone committed between our read and put — re-read the
                    // now-current record and replay the patch on top of it.
                    tracing::debug!(attempt, "advisorFault patch swap conflict; retrying");
                    tokio::time::sleep(std::time::Duration::from_millis(50 * attempt as u64)).await;
                }
                Err(e) => return Err(e),
            }
        }
        Err(ProviderError::Pds(
            "advisorFault patch exhausted swap retries".to_string(),
        ))
    }

    /// Walk the DID PLC directory to find this DID's PDS host. The
    /// agent only does this when it needs to read records directly
    /// (e.g. dedup); writes still go through the console proxy.
    async fn resolve_pds_endpoint(&self) -> Result<String> {
        if self.did.starts_with("did:plc:") {
            let url = format!("https://plc.directory/{}", self.did);
            let resp = self
                .http
                .get(&url)
                .send()
                .await
                .map_err(|e| ProviderError::Pds(format!("plc resolve transport: {e}")))?;
            if !resp.status().is_success() {
                return Err(ProviderError::Pds(format!(
                    "plc resolve {} returned {}",
                    self.did,
                    resp.status()
                )));
            }
            let doc: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| ProviderError::Pds(format!("plc resolve decode: {e}")))?;
            let services = doc.get("service").and_then(|s| s.as_array());
            if let Some(arr) = services {
                for svc in arr {
                    if svc.get("id").and_then(|v| v.as_str()) == Some("#atproto_pds") {
                        if let Some(ep) = svc.get("serviceEndpoint").and_then(|v| v.as_str()) {
                            return Ok(ep.to_string());
                        }
                    }
                }
            }
            return Err(ProviderError::Pds(format!(
                "no atproto_pds service in PLC doc for {}",
                self.did
            )));
        }
        // did:web — the doc lives at https://<host>/.well-known/did.json.
        // Honored for completeness; the agent's primary identity is
        // did:plc.
        if let Some(host) = self.did.strip_prefix("did:web:") {
            return Ok(format!("https://{host}"));
        }
        Err(ProviderError::Pds(format!(
            "unsupported DID method: {}",
            self.did
        )))
    }

    pub async fn publish_attestation<R: Serialize>(&self, record: &R) -> Result<PublishedRecord> {
        self.publish("dev.cocore.compute.attestation", record).await
    }

    pub async fn publish_receipt<R: Serialize>(&self, record: &R) -> Result<PublishedRecord> {
        self.publish("dev.cocore.compute.receipt", record).await
    }

    /// Mint a short-lived atproto service-auth JWT bound to `aud` (the
    /// intended service's DID) and `lxm` (the method NSID the token authorizes)
    /// via the caller's PDS `com.atproto.server.getServiceAuth`.
    ///
    /// The agent can't call getServiceAuth directly — like every other PDS
    /// call, it lacks the DPoP-bound OAuth session; the console holds it. So
    /// this goes through the console proxy (`POST /api/pds/getServiceAuth`,
    /// bearer-key auth, same as createRecord/putRecord), which restores the
    /// user's session, calls getServiceAuth on their PDS with `aud`/`lxm`, and
    /// returns `{ "token": "<jwt>" }`.
    ///
    /// Used to prove real DID control to the advisor at Register time: the
    /// advisor verifies the JWT's issuer == `provider_did` and its `lxm` ==
    /// `dev.cocore.compute.register`, binding the registration to a DID the
    /// caller actually controls (a machine can't register under someone else's
    /// DID). The token is short-lived, so the agent mints a fresh one on every
    /// (re)connect. Any failure is surfaced to the caller, which logs and
    /// registers WITHOUT the jwt rather than crashing — the advisor's own
    /// enforcement flag decides whether an unauthenticated Register is rejected.
    pub async fn mint_service_auth(&self, aud: &str, lxm: &str) -> Result<String> {
        let url = format!(
            "{}/api/pds/getServiceAuth",
            self.api_base.trim_end_matches('/')
        );
        let body = serde_json::json!({ "aud": aud, "lxm": lxm });
        tracing::debug!(aud, lxm, did = %self.did, "minting service-auth JWT via console proxy");

        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.api_key)
            .json(&body)
            .send()
            .await
            .map_err(|e| ProviderError::Pds(format!("transport: {e}")))?;
        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| ProviderError::Pds(format!("read body: {e}")))?;
        if !status.is_success() {
            return Err(ProviderError::Pds(format!(
                "console proxy getServiceAuth returned {status}: {text}"
            )));
        }
        let parsed: ServiceAuthResponse = serde_json::from_str(&text).map_err(|e| {
            ProviderError::Pds(format!("decode getServiceAuth response: {e} body={text}"))
        })?;
        Ok(parsed.token)
    }

    /// Generic publish for any cocore collection. The console proxy
    /// validates that `collection` starts with `dev.cocore.compute.`.
    pub async fn publish<R: Serialize>(
        &self,
        collection: &str,
        record: &R,
    ) -> Result<PublishedRecord> {
        let url = format!(
            "{}/api/pds/createRecord",
            self.api_base.trim_end_matches('/')
        );
        let body = serde_json::json!({
            "collection": collection,
            "record": record,
        });
        tracing::debug!(collection, did = %self.did, "publish via console proxy");

        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.api_key)
            .json(&body)
            .send()
            .await
            .map_err(|e| ProviderError::Pds(format!("transport: {e}")))?;
        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| ProviderError::Pds(format!("read body: {e}")))?;
        if !status.is_success() {
            return Err(ProviderError::Pds(format!(
                "console proxy createRecord {collection} returned {status}: {text}"
            )));
        }
        serde_json::from_str(&text).map_err(|e| {
            ProviderError::Pds(format!("decode {collection} response: {e} body={text}"))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(
        rkey: &str,
        created: &str,
        pubkey: Option<&str>,
        fp: Option<&str>,
        label: &str,
        model: &str,
        chip: &str,
        extra: serde_json::Value,
    ) -> ListedProviderRecord {
        let mut v = serde_json::json!({
            "machineLabel": label, "modelIdentifier": model, "chip": chip, "createdAt": created,
        });
        if let Some(k) = pubkey {
            v["attestationPubKey"] = serde_json::json!(k);
        }
        if let Some(f) = fp {
            v["machineFingerprint"] = serde_json::json!(f);
        }
        if let Some(o) = extra.as_object() {
            for (k, val) in o {
                v[k] = val.clone();
            }
        }
        ListedProviderRecord::from_value(rkey.into(), format!("cid-{rkey}"), v)
    }

    #[test]
    fn reconcile_current_key_single_record() {
        // The common case: one record, current key. Adopt it, nothing to delete.
        let listed = [rec(
            "r1",
            "t1",
            Some("KEY_A"),
            None,
            "Mac Mini 1",
            "Macmini9,1",
            "Apple M1",
            serde_json::json!({}),
        )];
        let me = MachineIdentity {
            attestation_pub_key: "KEY_A",
            machine_fingerprint: Some("FP1"),
            machine_label: "Mac Mini 1",
            model_identifier: Some("Macmini9,1"),
            chip: "Apple M1",
            cached_rkey: Some("r1"),
        };
        let r = reconcile_provider_records(&listed, &me).expect("mine");
        assert_eq!(r.canonical_rkey, "r1");
        assert!(r.delete.is_empty());
    }

    #[test]
    fn reconcile_key_rotation_adopts_legacy_and_harvests_desired_tier() {
        // THE bug: an old-key record (v0.9.42, no fingerprint) holds
        // desiredTier=attested-confidential; the new SE-key record has none. The
        // agent must adopt (keep the new/cached rkey), harvest desiredTier, and
        // delete the stale old record.
        let listed = [
            rec(
                "r_old",
                "t1",
                Some("KEY_OLD"),
                None,
                "Mac Mini 1",
                "Macmini9,1",
                "Apple M1",
                serde_json::json!({ "desiredTier": "attested-confidential", "active": true }),
            ),
            rec(
                "r_new",
                "t2",
                Some("KEY_NEW"),
                None,
                "Mac Mini 1",
                "Macmini9,1",
                "Apple M1",
                serde_json::json!({}),
            ),
        ];
        let me = MachineIdentity {
            attestation_pub_key: "KEY_NEW",
            machine_fingerprint: None, // this build read no fingerprint on the new record yet
            machine_label: "Mac Mini 1",
            model_identifier: Some("Macmini9,1"),
            chip: "Apple M1",
            cached_rkey: Some("r_new"),
        };
        let r = reconcile_provider_records(&listed, &me).expect("mine");
        assert_eq!(
            r.canonical_rkey, "r_new",
            "keeps the current rkey (machineId stable)"
        );
        assert_eq!(
            r.base.get("desiredTier").and_then(|v| v.as_str()),
            Some("attested-confidential"),
            "harvested owner intent"
        );
        assert_eq!(r.base.get("active").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(
            r.delete,
            vec![("r_old".into(), "cid-r_old".into())],
            "prunes the stale duplicate"
        );
    }

    #[test]
    fn reconcile_never_touches_a_sibling_with_a_different_fingerprint() {
        // A sibling machine (different fingerprint) under the same DID must be
        // left completely alone even if some fields collide.
        let listed = [
            rec(
                "r_me",
                "t2",
                Some("KEY_NEW"),
                Some("FP_ME"),
                "Mac Mini 1",
                "Macmini9,1",
                "Apple M1",
                serde_json::json!({}),
            ),
            rec(
                "r_sib",
                "t1",
                Some("KEY_SIB"),
                Some("FP_SIB"),
                "Mac Mini 1",
                "Macmini9,1",
                "Apple M1",
                serde_json::json!({ "desiredTier": "attested-confidential" }),
            ),
        ];
        let me = MachineIdentity {
            attestation_pub_key: "KEY_NEW",
            machine_fingerprint: Some("FP_ME"),
            machine_label: "Mac Mini 1",
            model_identifier: Some("Macmini9,1"),
            chip: "Apple M1",
            cached_rkey: Some("r_me"),
        };
        let r = reconcile_provider_records(&listed, &me).expect("mine");
        assert_eq!(r.canonical_rkey, "r_me");
        assert!(r.delete.is_empty(), "sibling never deleted");
        assert!(
            r.base.get("desiredTier").is_none(),
            "sibling's intent never harvested"
        );
    }

    #[test]
    fn reconcile_ambiguous_legacy_left_alone() {
        // Two legacy records with the SAME profile (identically-named machines):
        // don't guess — adopt neither, delete neither.
        let listed = [
            rec(
                "r1",
                "t1",
                Some("KEY_1"),
                None,
                "Mac",
                "Macmini9,1",
                "Apple M1",
                serde_json::json!({ "desiredTier": "attested-confidential" }),
            ),
            rec(
                "r2",
                "t2",
                Some("KEY_2"),
                None,
                "Mac",
                "Macmini9,1",
                "Apple M1",
                serde_json::json!({}),
            ),
        ];
        let me = MachineIdentity {
            attestation_pub_key: "KEY_3", // neither matches our current key
            machine_fingerprint: None,
            machine_label: "Mac",
            model_identifier: Some("Macmini9,1"),
            chip: "Apple M1",
            cached_rkey: None,
        };
        let r = reconcile_provider_records(&listed, &me);
        assert!(r.is_none(), "ambiguous legacy → mint fresh, touch nothing");
    }

    #[test]
    fn reconcile_fingerprint_match_survives_key_rotation() {
        // Post-fix: both records carry a fingerprint. A rotated key with the same
        // fingerprint is adopted; the older duplicate deleted.
        let listed = [
            rec(
                "r_old",
                "t1",
                Some("KEY_OLD"),
                Some("FP1"),
                "Mac Mini 1",
                "Macmini9,1",
                "Apple M1",
                serde_json::json!({ "desiredTier": "attested-confidential" }),
            ),
            rec(
                "r_new",
                "t2",
                Some("KEY_NEW"),
                Some("FP1"),
                "Mac Mini 1",
                "Macmini9,1",
                "Apple M1",
                serde_json::json!({}),
            ),
        ];
        let me = MachineIdentity {
            attestation_pub_key: "KEY_NEW",
            machine_fingerprint: Some("FP1"),
            machine_label: "Mac Mini 1",
            model_identifier: Some("Macmini9,1"),
            chip: "Apple M1",
            cached_rkey: Some("r_new"),
        };
        let r = reconcile_provider_records(&listed, &me).expect("mine");
        assert_eq!(r.canonical_rkey, "r_new");
        assert_eq!(
            r.base.get("desiredTier").and_then(|v| v.as_str()),
            Some("attested-confidential")
        );
        assert_eq!(r.delete, vec![("r_old".into(), "cid-r_old".into())]);
    }

    #[test]
    fn pro_bono_mode_any_serves_everyone() {
        let p = ProBonoPolicy {
            mode: "any".into(),
            dids: vec![],
        };
        assert!(p.applies_to("did:plc:anyone"));
        assert!(p.applies_to("did:plc:someone-else"));
    }

    #[test]
    fn pro_bono_mode_direct_serves_only_listed_dids() {
        let p = ProBonoPolicy {
            mode: "direct".into(),
            dids: vec!["did:plc:friend".into()],
        };
        assert!(p.applies_to("did:plc:friend"));
        // A non-listed requester is NOT pro bono — served as a normal paid job.
        assert!(!p.applies_to("did:plc:stranger"));
    }

    #[test]
    fn pro_bono_off_and_unknown_modes_fail_closed() {
        // Absent policy ≡ default ≡ off.
        assert!(!ProBonoPolicy::default().applies_to("did:plc:anyone"));
        // An unrecognized mode (e.g. a future value) fails closed to paid.
        let weird = ProBonoPolicy {
            mode: "future-mode".into(),
            dids: vec!["did:plc:friend".into()],
        };
        assert!(!weird.applies_to("did:plc:friend"));
    }

    #[test]
    fn pro_bono_from_record_value_parses_and_tolerates_absence() {
        let rec = serde_json::json!({
            "machineLabel": "m",
            "proBono": { "mode": "direct", "dids": ["did:plc:a", "did:plc:b"] }
        });
        let p = ProBonoPolicy::from_record_value(&rec).expect("policy present");
        assert_eq!(p.mode, "direct");
        assert!(p.applies_to("did:plc:b"));

        // No proBono field → None (off).
        let bare = serde_json::json!({ "machineLabel": "m" });
        assert!(ProBonoPolicy::from_record_value(&bare).is_none());
    }

    fn fake_session(api_base: &str) -> Session {
        Session {
            did: "did:plc:test".into(),
            handle: "test.example".into(),
            api_key: "cocore-fake-key".into(),
            api_base: api_base.into(),
        }
    }

    /// One-shot HTTP stub: handler returns Some((status, body)) for
    /// each accepted connection. Returns the bound port.
    async fn run_stub<F>(handler: F) -> u16
    where
        F: Fn(String) -> Option<(u16, String)> + Send + Sync + 'static,
    {
        use std::convert::Infallible;
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handler = Arc::new(handler);
        let _server: tokio::task::JoinHandle<Infallible> = tokio::spawn(async move {
            loop {
                let (mut sock, _) = listener.accept().await.unwrap();
                let h = handler.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 16384];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let (status, body) = h(req).unwrap_or((404, "{}".into()));
                    let line = match status {
                        200 => "200 OK",
                        201 => "201 Created",
                        400 => "400 Bad Request",
                        401 => "401 Unauthorized",
                        _ => "500 Internal Server Error",
                    };
                    let resp = format!(
                        "HTTP/1.1 {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                        line,
                        body.len(),
                        body,
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                });
            }
        });
        port
    }

    #[tokio::test]
    async fn publish_returns_uri_and_cid_on_success() {
        let port = run_stub(move |req: String| {
            let path = req.lines().next().unwrap_or("");
            if !path.contains("/api/pds/createRecord") {
                return Some((404, "{}".into()));
            }
            // Bearer auth header should carry the API key.
            assert!(
                req.lines()
                    .any(|l| l.to_lowercase().contains("authorization: bearer cocore-")),
                "expected Bearer auth header in request: {req}"
            );
            Some((
                200,
                serde_json::json!({
                    "uri": "at://did:plc:test/dev.cocore.compute.receipt/abc",
                    "cid": "bafyreigh2akiscaildc5sgz5wybizysiehxiv4dhpwwqouytxnvgkpkcaq",
                })
                .to_string(),
            ))
        })
        .await;

        let session = fake_session(&format!("http://127.0.0.1:{port}"));
        let client = PdsClient::new(session);
        let published = client
            .publish(
                "dev.cocore.compute.receipt",
                &serde_json::json!({"foo": "bar"}),
            )
            .await
            .expect("publish should succeed");
        assert_eq!(
            published.uri,
            "at://did:plc:test/dev.cocore.compute.receipt/abc"
        );
        assert!(published.cid.starts_with("bafy"));
    }

    #[tokio::test]
    async fn publish_propagates_4xx_errors() {
        let port = run_stub(move |_| {
            Some((
                400,
                r#"{"error":"pds createRecord dev.cocore.compute.receipt: bad rkey"}"#.into(),
            ))
        })
        .await;
        let session = fake_session(&format!("http://127.0.0.1:{port}"));
        let client = PdsClient::new(session);
        let err = client
            .publish("dev.cocore.compute.receipt", &serde_json::json!({}))
            .await
            .unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("400"), "expected 400 in error, got {msg}");
        assert!(msg.contains("bad rkey"));
    }

    #[tokio::test]
    async fn publish_propagates_401_unauthorized() {
        // If the API key was revoked or never existed, the console
        // returns 401. The agent should surface that to the operator
        // — there's no useful retry.
        let port = run_stub(move |_| Some((401, r#"{"error":"invalid API key"}"#.into()))).await;
        let session = fake_session(&format!("http://127.0.0.1:{port}"));
        let client = PdsClient::new(session);
        let err = client
            .publish("dev.cocore.compute.receipt", &serde_json::json!({}))
            .await
            .unwrap_err();
        assert!(format!("{err:?}").contains("401"));
    }
}
