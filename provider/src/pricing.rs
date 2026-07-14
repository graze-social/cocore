//! Per-model price catalog.
//!
//! The provider record carries a `priceList` of
//! `dev.cocore.compute.defs#modelPrice` entries — input/output rates
//! per million tokens, in integer minor units of a currency. Receipts
//! reference the same `modelId` so the aggregator can compute a
//! per-token charge after the fact.
//!
//! Today the priceList is a denormalization of the exchange's
//! `dev.cocore.compute.exchangePolicy.tokenRate` — every entry honors
//! the same uniform rate. The exchange's tokenRate is canonical; the
//! priceList exists in the lexicon for forward-compat with a future
//! per-provider-override flow but is currently informational.
//!
//! Current rate (matches cocore.dev's published exchangePolicy):
//! 1,000,000 CC per million input tokens + 1,000,000 CC per million
//! output tokens — i.e. one balance token per model token, 1:1.
//! Bumping this number requires also bumping
//! COCORE_TOKEN_RATE_*_PER_MTOK on the services container so the
//! exchange's tokenRate continues to match what receipts get stamped
//! with.

/// One model the agent can plausibly serve, plus its per-token rate
/// and the rough RAM budget it expects to have. The hardware budget
/// drives `models_for_machine`: an 8GB Mac mini doesn't pretend it
/// can serve a 122B model just because the rate table says so.
///
/// `min_ram_gb` is the conservative floor. We assume the OS reserves
/// ~3GB on macOS, weights are loaded in 4-bit, and there's some
/// activation budget left for the KV cache. Concretely:
///   * 0.5B 4-bit ≈ 0.4GB weights → fits 4GB+
///   * 3B 4-bit ≈ 2GB weights → fits 8GB (tight)
///   * 7B 4-bit ≈ 4GB weights → wants 16GB+
///   * 27B 4-bit ≈ 14GB weights → wants 32GB+
///   * 70B 4-bit ≈ 36GB weights → wants 64GB+
///   * 122B 4-bit ≈ 65GB weights → wants 96GB+
///   * 397B 4-bit ≈ 220GB weights → wants 256GB+
pub struct ModelRate {
    pub model_id: &'static str,
    pub input_per_mtok: u64,
    pub output_per_mtok: u64,
    pub currency: &'static str,
    pub min_ram_gb: u32,
    /// One-line human-readable hint surfaced by the CLI picker and the
    /// console's `/start` model selector. Not part of any on-wire
    /// format — this is purely UX copy, can change without breaking
    /// receipts. Keep it under ~60 chars so it lines up in the
    /// terminal menu and doesn't wrap in the web Select item.
    pub description: &'static str,
    /// True for the current "latest & greatest" rotation — the set the
    /// Secure Mode upgrade urges providers to pin. The older entries stay
    /// in the catalog (so a machine that already pinned one keeps its RAM
    /// floor + price) but are NOT recommended. UX-only; never on the wire.
    pub recommended: bool,
    /// The vLLM `--tool-call-parser` name this model pairs with, when cocore
    /// knows one (`hermes` for the Qwen rotation, `llama4_pythonic` for
    /// Llama 4, …). `None` means cocore has no vetted parser pairing for this
    /// id, so it stays OUT of the curated tool-calling set: when the owner
    /// flips the per-machine `toolCalls` switch the agent only enables
    /// automatic tool choice for entries that carry a parser here, then still
    /// gates advertisement behind the forced-tool startup canary. This is the
    /// "restrict to top models for now" boundary — adding a new model to the
    /// tool-calling rotation is a one-line parser pairing here, not a code
    /// change. UX/config only; never on the wire (the canary, not this field,
    /// decides what the machine advertises). An operator can still force the
    /// raw vLLM passthrough on any model via `COCORE_VLLM_TOOL_CALL_PARSER`.
    pub tool_call_parser: Option<&'static str>,
}

/// Catalog of every model cocore knows about. `supportedModels` on
/// the provider record is filtered to those entries this machine has
/// the RAM to plausibly run (see `models_for_machine`). Rates mirror
/// the cocore.dev exchange's uniform `tokenRate` (10/10 USD per MTok
/// = $0.10 per million tokens in each direction).
pub const RATES: &[ModelRate] = &[
    // Always-available smoke-test target. No real model attached
    // (the StubEngine just echoes the prompt) but every machine can
    // serve it — useful for protocol-level tests.
    ModelRate {
        model_id: "stub",
        input_per_mtok: 1_000_000,
        output_per_mtok: 1_000_000,
        currency: "CC",
        min_ram_gb: 0,
        description: "echo-only smoke-test target; not a real model",
        recommended: false,
        tool_call_parser: None,
    },
    // ---- Current rotation (recommended) -------------------------------
    // The "latest & greatest" set the Secure Mode upgrade urges providers
    // to pin. min_ram_gb is the conservative MINIMUM machine RAM (4-bit
    // weights resident + OS + KV headroom). MoE entries (Axx suffix /
    // NxE experts) keep ALL experts resident, so memory tracks total
    // params, not active params.
    ModelRate {
        model_id: "mlx-community/Qwen3.5-0.8B-MLX-4bit",
        input_per_mtok: 1_000_000,
        output_per_mtok: 1_000_000,
        currency: "CC",
        min_ram_gb: 4,
        description: "Qwen3.5 0.8B — fast, low quality; fits any Apple Silicon",
        recommended: true,
        tool_call_parser: Some("hermes"),
    },
    ModelRate {
        model_id: "mlx-community/Qwen3.5-2B-MLX-4bit",
        input_per_mtok: 1_000_000,
        output_per_mtok: 1_000_000,
        currency: "CC",
        min_ram_gb: 6,
        description: "Qwen3.5 2B — small but coherent; good on 8GB",
        recommended: true,
        tool_call_parser: Some("hermes"),
    },
    ModelRate {
        model_id: "mlx-community/Qwen3.5-4B-MLX-4bit",
        input_per_mtok: 1_000_000,
        output_per_mtok: 1_000_000,
        currency: "CC",
        min_ram_gb: 8,
        description: "Qwen3.5 4B — balanced default for 8GB+ Macs",
        recommended: true,
        tool_call_parser: Some("hermes"),
    },
    // NOTE: `mlx-community/gemma-4-e4b-it-4bit` was previously here. It is a
    // merged/multimodal (Gemma "E4B") checkpoint whose weights are nested under
    // `language_model.*`, which the text runtime can't map onto a plain text
    // model — every machine that pinned it failed provisioning and fell back to
    // the no-op `stub` engine (see issue #141). Removed from the catalog rather
    // than demoted to legacy: legacy entries are "still servable", and this one
    // is not servable at all. Do not re-add a multimodal/merged checkpoint to
    // this rotation; only standard MLX text models belong here.
    ModelRate {
        model_id: "mlx-community/Qwen3.5-9B-MLX-4bit",
        input_per_mtok: 1_000_000,
        output_per_mtok: 1_000_000,
        currency: "CC",
        min_ram_gb: 16,
        description: "Qwen3.5 9B — strong general-purpose; 16GB+ recommended",
        recommended: true,
        tool_call_parser: Some("hermes"),
    },
    ModelRate {
        model_id: "mlx-community/Qwen3.5-27B-4bit",
        input_per_mtok: 1_000_000,
        output_per_mtok: 1_000_000,
        currency: "CC",
        min_ram_gb: 24,
        description: "Qwen3.5 27B — high-quality dense model; 24GB+",
        recommended: true,
        tool_call_parser: Some("hermes"),
    },
    ModelRate {
        model_id: "mlx-community/Qwen3.6-27B-4bit",
        input_per_mtok: 1_000_000,
        output_per_mtok: 1_000_000,
        currency: "CC",
        min_ram_gb: 24,
        description: "Qwen3.6 27B — frontier-class dense; 24GB+",
        recommended: true,
        tool_call_parser: Some("hermes"),
    },
    ModelRate {
        model_id: "mlx-community/Qwen3.5-35B-A3B-4bit",
        input_per_mtok: 1_000_000,
        output_per_mtok: 1_000_000,
        currency: "CC",
        min_ram_gb: 32,
        description: "Qwen3.5 35B-A3B MoE — fast for its size; 32GB+",
        recommended: true,
        tool_call_parser: Some("hermes"),
    },
    ModelRate {
        model_id: "mlx-community/Qwen3.6-35B-A3B-4bit",
        input_per_mtok: 1_000_000,
        output_per_mtok: 1_000_000,
        currency: "CC",
        min_ram_gb: 32,
        description: "Qwen3.6 35B-A3B MoE — fast for its size; 32GB+",
        recommended: true,
        tool_call_parser: Some("hermes"),
    },
    // DWQ re-quant of the entry above. Same architecture and chat/tool
    // template, so it pairs with the same parser — machines already serving
    // it (via desiredModels) can pass the tool-call canary instead of being
    // silently excluded from the curated set (issue #166). Not `recommended`:
    // the picker rotation stays on the canonical 4bit quant.
    ModelRate {
        model_id: "mlx-community/Qwen3.6-35B-A3B-4bit-DWQ",
        input_per_mtok: 1_000_000,
        output_per_mtok: 1_000_000,
        currency: "CC",
        min_ram_gb: 32,
        description: "Qwen3.6 35B-A3B MoE (DWQ quant) — fast for its size; 32GB+",
        recommended: false,
        tool_call_parser: Some("hermes"),
    },
    ModelRate {
        model_id: "mlx-community/Llama-4-Scout-17B-16E-Instruct-4bit",
        input_per_mtok: 1_000_000,
        output_per_mtok: 1_000_000,
        currency: "CC",
        min_ram_gb: 64,
        description: "Llama 4 Scout 17B×16E MoE — heavyweight; 64GB+",
        recommended: true,
        tool_call_parser: Some("llama4_pythonic"),
    },
    ModelRate {
        model_id: "mlx-community/Qwen3.5-122B-A10B-4bit",
        input_per_mtok: 1_000_000,
        output_per_mtok: 1_000_000,
        currency: "CC",
        min_ram_gb: 96,
        description: "Qwen3.5 122B-A10B MoE — flagship; 96GB+ Mac Studio/Ultra",
        recommended: true,
        tool_call_parser: Some("hermes"),
    },
    ModelRate {
        model_id: "mlx-community/Qwen3.5-397B-A17B-4bit",
        input_per_mtok: 1_000_000,
        output_per_mtok: 1_000_000,
        currency: "CC",
        min_ram_gb: 256,
        description: "Qwen3.5 397B-A17B MoE — flagship; 256GB+ Ultra",
        recommended: true,
        tool_call_parser: Some("hermes"),
    },
    // ---- Legacy catalog (still servable; not recommended) -------------
    // Kept so a machine that already pinned one of these keeps its RAM
    // floor + price entry. The Secure Mode dialog nudges providers off
    // these and onto the rotation above.
    ModelRate {
        model_id: "mlx-community/Qwen2.5-0.5B-Instruct-4bit",
        input_per_mtok: 1_000_000,
        output_per_mtok: 1_000_000,
        currency: "CC",
        min_ram_gb: 4,
        description: "Qwen 0.5B (legacy) — fast, low quality",
        recommended: false,
        tool_call_parser: None,
    },
    ModelRate {
        model_id: "mlx-community/Qwen2.5-3B-Instruct-4bit",
        input_per_mtok: 1_000_000,
        output_per_mtok: 1_000_000,
        currency: "CC",
        min_ram_gb: 8,
        description: "Qwen 3B (legacy) — small but coherent",
        recommended: false,
        tool_call_parser: None,
    },
    ModelRate {
        model_id: "mlx-community/Qwen2.5-7B-Instruct-4bit",
        input_per_mtok: 1_000_000,
        output_per_mtok: 1_000_000,
        currency: "CC",
        min_ram_gb: 16,
        description: "Qwen 7B (legacy) — strong general-purpose",
        recommended: false,
        tool_call_parser: None,
    },
    ModelRate {
        model_id: "mlx-community/gemma-3-4b-it-qat-4bit",
        input_per_mtok: 1_000_000,
        output_per_mtok: 1_000_000,
        currency: "CC",
        min_ram_gb: 8,
        description: "Gemma 3 4B QAT (legacy) — balanced for 8GB+",
        recommended: false,
        tool_call_parser: None,
    },
    ModelRate {
        model_id: "mlx-community/Qwen2.5-32B-Instruct-4bit",
        input_per_mtok: 1_000_000,
        output_per_mtok: 1_000_000,
        currency: "CC",
        min_ram_gb: 32,
        description: "Qwen 32B (legacy) — frontier-class",
        recommended: false,
        tool_call_parser: None,
    },
    ModelRate {
        model_id: "mlx-community/Llama-3.3-70B-Instruct-4bit",
        input_per_mtok: 1_000_000,
        output_per_mtok: 1_000_000,
        currency: "CC",
        min_ram_gb: 64,
        description: "Llama 3.3 70B (legacy) — heavyweight",
        recommended: false,
        tool_call_parser: None,
    },
];

/// Catalog entries this machine can plausibly run, excluding the stub
/// (which is always-loaded; adding it via `models add` is a no-op).
/// Used by `cocore agent models add` (no arg → interactive picker)
/// and mirrored TS-side for the `/start` web picker. Order matches
/// `RATES` order so the menu walks small → large.
pub fn pickable_for_machine(ram_gb: u32) -> Vec<&'static ModelRate> {
    RATES
        .iter()
        .filter(|m| m.model_id != "stub" && m.min_ram_gb <= ram_gb)
        .collect()
}

/// The catalog RAM floor for a model id, or `None` for an off-catalog
/// (custom MLX) model whose footprint we can't reason about.
pub fn min_ram_gb(model_id: &str) -> Option<u32> {
    RATES
        .iter()
        .find(|r| r.model_id == model_id)
        .map(|r| r.min_ram_gb)
}

/// The vetted vLLM `--tool-call-parser` for a model id, or `None` when cocore
/// has no parser pairing for it (off-catalog model, or a catalog entry we
/// haven't vetted for tool calls — every legacy entry, the stub). This is the
/// curated "top models" boundary the per-machine `toolCalls` switch reconciles
/// against: only a model that returns `Some` here is eligible to attempt tool
/// calling, and even then the forced-tool startup canary still decides whether
/// the engine actually advertises it. Adding a model to the rotation is a
/// one-line parser pairing in `RATES`, never a code change here.
pub fn tool_call_parser(model_id: &str) -> Option<&'static str> {
    RATES
        .iter()
        .find(|r| r.model_id == model_id)
        .and_then(|r| r.tool_call_parser)
}

/// Overprovisioning guard. Pick the subset of `models` whose summed
/// catalog RAM floors fit within `ram_gb`, dropping the LARGEST models
/// first until the rest fit. Returns `(kept, dropped)`, `kept` in the
/// original order.
///
/// Why: the per-model RAM guard only checks each model against its floor
/// individually, so a 7B (16 GB floor) AND a 3B (8 GB) could both be
/// configured on a 16 GB Mac and OOM. Per-model scheduling makes this
/// sharper (overlapping windows load several at once), so we sum the
/// concurrent set here. Off-catalog models have no known floor — they're
/// always KEPT and contribute 0 to the budget (we can't reason about
/// them; let the subprocess arbitrate rather than guess). `stub` is free.
/// Ties break by model id so the result is deterministic.
pub fn fit_within_budget(models: &[String], ram_gb: u32) -> (Vec<String>, Vec<String>) {
    // Largest-known-floor first; unknown/stub (floor 0) sort last and are
    // never chosen as a prune victim.
    let mut by_size: Vec<usize> = (0..models.len()).collect();
    by_size.sort_by(|&a, &b| {
        let ra = min_ram_gb(&models[a]).unwrap_or(0);
        let rb = min_ram_gb(&models[b]).unwrap_or(0);
        rb.cmp(&ra).then_with(|| models[a].cmp(&models[b]))
    });
    let mut keep = vec![true; models.len()];
    loop {
        let used: u32 = (0..models.len())
            .filter(|&i| keep[i])
            .map(|i| min_ram_gb(&models[i]).unwrap_or(0))
            .sum();
        if used <= ram_gb {
            break;
        }
        // Drop the largest still-kept model that has a known floor > 0.
        let victim = by_size
            .iter()
            .copied()
            .find(|&i| keep[i] && min_ram_gb(&models[i]).unwrap_or(0) > 0);
        match victim {
            Some(i) => keep[i] = false,
            None => break, // only unknown/stub left — nothing safe to prune.
        }
    }
    let mut kept = Vec::new();
    let mut dropped = Vec::new();
    for (i, m) in models.iter().enumerate() {
        if keep[i] {
            kept.push(m.clone());
        } else {
            dropped.push(m.clone());
        }
    }
    (kept, dropped)
}

/// The "latest & greatest" rotation, in catalog order. The Secure Mode
/// upgrade dialog shows these and urges the provider to pin them.
pub fn recommended_models() -> Vec<&'static ModelRate> {
    RATES.iter().filter(|m| m.recommended).collect()
}

/// Recommended models this machine can individually run (floor ≤ RAM).
pub fn recommended_for_machine(ram_gb: u32) -> Vec<&'static ModelRate> {
    RATES
        .iter()
        .filter(|m| m.recommended && m.min_ram_gb <= ram_gb)
        .collect()
}

/// RAM (GB) to hold back for the OS + the user's own apps (browser, IDE)
/// so a personal Mac stays usable while it serves. The per-model
/// `min_ram_gb` floors already bake in a basic single-model OS reserve;
/// this is the ADDITIONAL working-set headroom that gets eaten when a
/// provider stacks several models. ~20% of RAM, clamped to [2, 12] so a
/// tiny Mac isn't locked out and a 192GB Studio doesn't reserve absurdly.
pub fn user_reserve_gb(total_ram_gb: u32) -> u32 {
    let pct = total_ram_gb.div_ceil(5); // ceil(total/5) = 20%
    pct.clamp(2, 12)
}

/// Traffic-light verdict for a pinned set on a machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetStatus {
    /// Fits with comfortable headroom for the user. (green)
    Comfortable,
    /// Fits the machine, but leaves less than the user reserve free —
    /// the Mac may get sluggish under the owner's own work. (yellow)
    Tight,
    /// Summed floors exceed total RAM; the agent will drop the largest
    /// models to fit. (red)
    Oversubscribed,
}

/// A computed budget verdict for a pinned model set, suitable for driving
/// a meter + traffic-light in the UI and a startup log line in the agent.
#[derive(Debug, Clone)]
pub struct BudgetReport {
    /// Sum of known catalog floors for the set (off-catalog/stub = 0).
    pub used_gb: u32,
    /// Headroom held back for the OS + user (see `user_reserve_gb`).
    pub reserve_gb: u32,
    /// Machine total RAM.
    pub total_gb: u32,
    pub status: BudgetStatus,
    /// Models the agent's hard guard would drop (largest-first) because
    /// the set exceeds total RAM. Empty unless `status == Oversubscribed`.
    pub dropped: Vec<String>,
}

/// Classify a pinned set against a machine's RAM. This is the single
/// source of truth the tray meter, the CLI warning, and the agent's
/// startup log all derive from, so the green/yellow/red verdict is
/// identical everywhere. `used` sums the concurrent set's catalog floors;
/// callers that respect per-model schedules should pass the worst
/// overlapping hour's set. Off-catalog models contribute 0 (unknown
/// footprint) and never trip the guard on their own.
pub fn budget_report(models: &[String], total_ram_gb: u32) -> BudgetReport {
    let used_gb: u32 = models.iter().map(|m| min_ram_gb(m).unwrap_or(0)).sum();
    let reserve_gb = user_reserve_gb(total_ram_gb);
    let (status, dropped) = if used_gb > total_ram_gb {
        let (_, dropped) = fit_within_budget(models, total_ram_gb);
        (BudgetStatus::Oversubscribed, dropped)
    } else if used_gb + reserve_gb > total_ram_gb {
        (BudgetStatus::Tight, Vec::new())
    } else {
        (BudgetStatus::Comfortable, Vec::new())
    };
    BudgetReport {
        used_gb,
        reserve_gb,
        total_gb: total_ram_gb,
        status,
        dropped,
    }
}

/// Look up the rate for a model id; falls back to the stub rate so
/// receipts always carry _some_ price.
pub fn rate_for(model_id: &str) -> &'static ModelRate {
    RATES
        .iter()
        .find(|r| r.model_id == model_id)
        .unwrap_or(&RATES[0])
}

/// The uniform exchange rate every cocore model is priced at today:
/// 1,000,000 CC per MTok in each direction (1:1 between model tokens and
/// balance tokens), matching cocore.dev's published exchangePolicy
/// `tokenRate`. Off-catalog models fall back to this. When the exchange's
/// tokenRate moves, these and the catalog rates move together — see the
/// module docs.
pub const UNIFORM_INPUT_PER_MTOK: u64 = 1_000_000;
pub const UNIFORM_OUTPUT_PER_MTOK: u64 = 1_000_000;
pub const UNIFORM_CURRENCY: &str = "CC";

/// Price components `(input_per_mtok, output_per_mtok, currency)` for the
/// `priceList` entry of ANY loaded model id — catalog or not. A custom
/// MLX model a provider added by hand isn't in `RATES`, but it still
/// loads and serves; without an entry here it would land in
/// `supportedModels` with no price, so the requester-facing model
/// directory shows it priceless and `pickPrice` can't rate it. We give
/// off-catalog models the uniform exchange rate (the same rate every
/// catalog entry carries and the rate the exchange actually charges), so
/// a custom model is advertised AND priced. The caller pairs these
/// components with the real loaded id for the `modelId` field.
pub fn price_components_for(model_id: &str) -> (u64, u64, &'static str) {
    match RATES.iter().find(|r| r.model_id == model_id) {
        Some(r) => (r.input_per_mtok, r.output_per_mtok, r.currency),
        None => (
            UNIFORM_INPUT_PER_MTOK,
            UNIFORM_OUTPUT_PER_MTOK,
            UNIFORM_CURRENCY,
        ),
    }
}

/// Models this machine can plausibly serve given its RAM. Used to
/// build the provider record's `supportedModels` + `priceList`. We
/// always include `stub` so the protocol-level test path keeps
/// working on any machine. Machines can be allow-listed beyond what
/// RAM suggests via `COCORE_EXTRA_MODELS` (comma-separated model ids
/// — useful when running under heavy memory pressure where the
/// conservative floor would lock the user out of a model they know
/// will work).
pub fn models_for_machine(ram_gb: u32) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = RATES
        .iter()
        .filter(|m| m.min_ram_gb <= ram_gb)
        .map(|m| m.model_id)
        .collect();
    if let Ok(extra) = std::env::var("COCORE_EXTRA_MODELS") {
        for id in extra.split(',') {
            let id = id.trim();
            if id.is_empty() {
                continue;
            }
            // Only add it if the catalog knows about it; otherwise
            // we'd advertise a model nothing can rate, and receipts
            // would land at the stub fallback rate.
            if let Some(m) = RATES.iter().find(|r| r.model_id == id) {
                if !out.contains(&m.model_id) {
                    out.push(m.model_id);
                }
            }
        }
    }
    out
}

/// Compute price in integer minor units (cents) for a billing line
/// of `(input_tokens, output_tokens)` against a rate. **No floor**:
/// receipts for small jobs may legitimately come out at 0 minor
/// units, because $0.10 / 1M tokens × a few-thousand-token job is
/// well under one cent. The earlier `max(1, …)` floor existed for
/// the v0.3.x stub (which generated tiny replies) so receipts
/// would be visible on the earnings dashboard, but with real
/// tokenization that floor over-charges by 100–1000× on small
/// requests. Stripe doesn't charge $0 anyway; the exchange's
/// existing `minPayoutMinor` accumulator (and a forthcoming
/// `minChargeMinor` mirror for charges) is the right place to
/// gate "actually move money" semantics.
pub fn price_minor(rate: &ModelRate, input_tokens: u64, output_tokens: u64) -> u64 {
    let in_charge = rate.input_per_mtok.saturating_mul(input_tokens) / 1_000_000;
    let out_charge = rate.output_per_mtok.saturating_mul(output_tokens) / 1_000_000;
    in_charge.saturating_add(out_charge)
}

/// Cheap byte→token estimate. ~4 chars per token holds for English
/// text against gpt-style BPE tokenizers; close enough for the stub
/// where exact counts don't matter. Real engines plug in their own
/// tokenizer.
pub fn estimate_tokens(bytes: &[u8]) -> u64 {
    (bytes.len() as u64).div_ceil(4)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_for_known_model() {
        let r = rate_for("stub");
        assert_eq!(r.model_id, "stub");
        // 1M rate units per MTok of tokens = 1:1 between model tokens
        // and balance tokens, matching the exchange's tokenRate.
        assert_eq!(r.input_per_mtok, 1_000_000);
        assert_eq!(r.output_per_mtok, 1_000_000);
        assert_eq!(r.currency, "CC");
        assert_eq!(r.min_ram_gb, 0);
    }

    #[test]
    fn models_for_machine_filters_by_ram() {
        // 0GB: only `stub`. Used for guards / boundary cases.
        let zero = models_for_machine(0);
        assert_eq!(zero, vec!["stub"]);

        // 8GB M1: stub + the 0.5B + the 3B + the gemma-3-4b. The 7B
        // and bigger are filtered out so the advisor never routes
        // those models to this machine.
        let eight = models_for_machine(8);
        assert!(eight.contains(&"stub"));
        assert!(eight.contains(&"mlx-community/Qwen2.5-0.5B-Instruct-4bit"));
        assert!(eight.contains(&"mlx-community/Qwen2.5-3B-Instruct-4bit"));
        assert!(eight.contains(&"mlx-community/gemma-3-4b-it-qat-4bit"));
        assert!(!eight.contains(&"mlx-community/Qwen2.5-7B-Instruct-4bit"));
        assert!(!eight.contains(&"mlx-community/Qwen2.5-32B-Instruct-4bit"));
        assert!(!eight.contains(&"mlx-community/Llama-3.3-70B-Instruct-4bit"));

        // 64GB Mac Studio: everything except the 70B's 64GB ceiling
        // is included (the floor is `<= 64`, so 70B is in too).
        let sixty_four = models_for_machine(64);
        assert!(sixty_four.contains(&"mlx-community/Qwen2.5-32B-Instruct-4bit"));
        assert!(sixty_four.contains(&"mlx-community/Llama-3.3-70B-Instruct-4bit"));
    }

    #[test]
    fn rate_for_unknown_falls_back_to_first() {
        let r = rate_for("not-a-real-model");
        assert_eq!(r.model_id, RATES[0].model_id);
    }

    #[test]
    fn price_components_for_catalog_uses_catalog_rate() {
        let (i, o, c) = price_components_for("mlx-community/Qwen2.5-7B-Instruct-4bit");
        assert_eq!(i, 1_000_000);
        assert_eq!(o, 1_000_000);
        assert_eq!(c, "CC");
    }

    #[test]
    fn price_components_for_off_catalog_uses_uniform_rate() {
        // A custom MLX model a provider added by hand is not in RATES but
        // must still get a price entry at the uniform exchange rate so it
        // isn't advertised priceless.
        let (i, o, c) = price_components_for("some-org/Custom-Model-MLX-4bit");
        assert_eq!(i, UNIFORM_INPUT_PER_MTOK);
        assert_eq!(o, UNIFORM_OUTPUT_PER_MTOK);
        assert_eq!(c, UNIFORM_CURRENCY);
    }

    #[test]
    fn price_minor_at_one_to_one_rate() {
        let r = rate_for("stub");
        // 1M rate units per MTok of model tokens = 1:1. A 10-token
        // job costs 10 balance tokens; a 100K-token job costs 100K.
        assert_eq!(price_minor(r, 10, 0), 10);
        assert_eq!(price_minor(r, 99_000, 0), 99_000);
        assert_eq!(price_minor(r, 100_000, 0), 100_000);
        // Symmetric across input/output: floor(0 * 1M / 1M) +
        // floor(50 * 1M / 1M) = 50.
        assert_eq!(price_minor(r, 0, 50), 50);
    }

    #[test]
    fn price_minor_scales_with_tokens() {
        let r = &ModelRate {
            model_id: "test",
            input_per_mtok: 1_000,
            output_per_mtok: 2_000,
            currency: "CC",
            min_ram_gb: 0,
            description: "synthetic test rate",
            recommended: false,
            tool_call_parser: None,
        };
        // 1M input × 1000 / 1M = 1000 cents = $10
        assert_eq!(price_minor(r, 1_000_000, 0), 1_000);
        // 1M output × 2000 / 1M = 2000 cents = $20
        assert_eq!(price_minor(r, 0, 1_000_000), 2_000);
        // Mixed
        assert_eq!(price_minor(r, 1_000_000, 1_000_000), 3_000);
    }

    #[test]
    fn pickable_for_machine_excludes_stub_and_filters_by_ram() {
        // stub is always-loaded so it's not in the picker. 0GB: only
        // stub fits, so the pickable list is empty.
        let zero = pickable_for_machine(0);
        assert!(
            zero.is_empty(),
            "stub-only machine should have empty picker"
        );

        // 8GB: 0.5B + 3B + gemma-3-4b fit; 7B and bigger don't.
        let eight: Vec<&str> = pickable_for_machine(8).iter().map(|m| m.model_id).collect();
        assert!(eight.contains(&"mlx-community/Qwen2.5-0.5B-Instruct-4bit"));
        assert!(eight.contains(&"mlx-community/Qwen2.5-3B-Instruct-4bit"));
        assert!(eight.contains(&"mlx-community/gemma-3-4b-it-qat-4bit"));
        assert!(!eight.contains(&"mlx-community/Qwen2.5-7B-Instruct-4bit"));
        assert!(!eight.contains(&"stub"));

        // 64GB: everything except stub.
        let sixty_four: Vec<&str> = pickable_for_machine(64)
            .iter()
            .map(|m| m.model_id)
            .collect();
        assert!(sixty_four.contains(&"mlx-community/Llama-3.3-70B-Instruct-4bit"));
        assert!(!sixty_four.contains(&"stub"));
    }

    #[test]
    fn estimate_tokens_rounds_up() {
        assert_eq!(estimate_tokens(b""), 0);
        assert_eq!(estimate_tokens(b"a"), 1);
        assert_eq!(estimate_tokens(b"abcd"), 1);
        assert_eq!(estimate_tokens(b"abcde"), 2);
        assert_eq!(estimate_tokens(&vec![0u8; 401]), 101);
    }

    fn sv(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn dwq_requant_pairs_with_same_parser_but_stays_off_the_rotation() {
        // The DWQ re-quant shares the canonical entry's chat/tool template,
        // so it must carry the same parser pairing (issue #166: a machine
        // serving it could never pass the tool-call canary)…
        assert_eq!(
            tool_call_parser("mlx-community/Qwen3.6-35B-A3B-4bit-DWQ"),
            Some("hermes")
        );
        assert_eq!(
            tool_call_parser("mlx-community/Qwen3.6-35B-A3B-4bit"),
            Some("hermes")
        );
        // …while the picker rotation keeps recommending only the canonical
        // quant.
        let rec: Vec<&str> = recommended_models().iter().map(|m| m.model_id).collect();
        assert!(!rec.contains(&"mlx-community/Qwen3.6-35B-A3B-4bit-DWQ"));
        // Unknown ids still resolve to "no vetted pairing".
        assert_eq!(tool_call_parser("custom/whatever-4bit"), None);
    }

    #[test]
    fn fit_within_budget_prunes_largest_first() {
        // 7B (16 GB floor) + 3B (8 GB) on a 16 GB Mac → drop the 7B, keep 3B.
        let models = sv(&[
            "mlx-community/Qwen2.5-7B-Instruct-4bit",
            "mlx-community/Qwen2.5-3B-Instruct-4bit",
        ]);
        let (kept, dropped) = fit_within_budget(&models, 16);
        assert_eq!(kept, sv(&["mlx-community/Qwen2.5-3B-Instruct-4bit"]));
        assert_eq!(dropped, sv(&["mlx-community/Qwen2.5-7B-Instruct-4bit"]));
    }

    #[test]
    fn fit_within_budget_keeps_all_when_fitting() {
        let models = sv(&[
            "mlx-community/Qwen2.5-3B-Instruct-4bit",
            "mlx-community/Qwen2.5-0.5B-Instruct-4bit",
        ]); // 8 + 4 = 12 ≤ 16
        let (kept, dropped) = fit_within_budget(&models, 16);
        assert_eq!(kept, models);
        assert!(dropped.is_empty());
    }

    #[test]
    fn recommended_set_is_the_rotation() {
        let rec: Vec<&str> = recommended_models().iter().map(|m| m.model_id).collect();
        for model_id in [
            "mlx-community/Qwen3.5-0.8B-MLX-4bit",
            "mlx-community/Qwen3.5-2B-MLX-4bit",
            "mlx-community/Qwen3.5-4B-MLX-4bit",
            "mlx-community/Qwen3.5-9B-MLX-4bit",
            "mlx-community/Qwen3.5-27B-4bit",
            "mlx-community/Qwen3.5-35B-A3B-4bit",
            "mlx-community/Qwen3.5-122B-A10B-4bit",
            "mlx-community/Qwen3.5-397B-A17B-4bit",
        ] {
            assert!(
                rec.contains(&model_id),
                "missing recommended model {model_id}"
            );
        }
        // legacy + stub are NOT recommended
        assert!(!rec.contains(&"mlx-community/Qwen2.5-7B-Instruct-4bit"));
        assert!(!rec.contains(&"stub"));
    }

    #[test]
    fn user_reserve_is_clamped() {
        assert_eq!(user_reserve_gb(8), 2); // 20% = 1.6 → ceil 2, clamp floor 2
        assert_eq!(user_reserve_gb(16), 4); // ceil(16/5)=4
        assert_eq!(user_reserve_gb(64), 12); // 20% = 12.8 → clamp ceiling 12
        assert_eq!(user_reserve_gb(192), 12);
    }

    #[test]
    fn budget_report_traffic_light() {
        // 16GB Mac, reserve 4 → usable 12.
        // Single 9B (floor 16) → used 16 == total → fits but 0 free < reserve → Tight.
        let nine = sv(&["mlx-community/Qwen3.5-9B-MLX-4bit"]);
        let r = budget_report(&nine, 16);
        assert_eq!(r.status, BudgetStatus::Tight);
        assert!(r.dropped.is_empty());

        // 4B (floor 8) on 16GB → used 8, free 8 ≥ reserve 4 → Comfortable.
        let four = sv(&["mlx-community/Qwen3.5-4B-MLX-4bit"]);
        assert_eq!(budget_report(&four, 16).status, BudgetStatus::Comfortable);

        // 9B (16) + 4B (8) = 24 > 16 → Oversubscribed; drops the 9B.
        let both = sv(&[
            "mlx-community/Qwen3.5-9B-MLX-4bit",
            "mlx-community/Qwen3.5-4B-MLX-4bit",
        ]);
        let r = budget_report(&both, 16);
        assert_eq!(r.status, BudgetStatus::Oversubscribed);
        assert_eq!(r.dropped, sv(&["mlx-community/Qwen3.5-9B-MLX-4bit"]));
    }

    #[test]
    fn fit_within_budget_never_prunes_unknown_or_stub() {
        // Off-catalog (unknown floor) + stub contribute 0 and are always kept,
        // even on a tiny RAM budget.
        let models = sv(&["custom/whatever-4bit", "stub"]);
        let (kept, dropped) = fit_within_budget(&models, 1);
        assert_eq!(kept, models);
        assert!(dropped.is_empty());
    }
}
