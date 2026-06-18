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
    },
    // Tiniest credible MLX model; 4-bit Qwen2.5-0.5B fits in any
    // Apple Silicon Mac (~0.4GB resident).
    ModelRate {
        model_id: "mlx-community/Qwen2.5-0.5B-Instruct-4bit",
        input_per_mtok: 1_000_000,
        output_per_mtok: 1_000_000,
        currency: "CC",
        min_ram_gb: 4,
        description: "Qwen 0.5B — fast, low quality; fits any Apple Silicon",
    },
    // 3B 4-bit. Tight but viable on 8GB; comfortable on 16GB+.
    ModelRate {
        model_id: "mlx-community/Qwen2.5-3B-Instruct-4bit",
        input_per_mtok: 1_000_000,
        output_per_mtok: 1_000_000,
        currency: "CC",
        min_ram_gb: 8,
        description: "Qwen 3B — small but coherent; tight on 8GB",
    },
    // 7B 4-bit. Wants 16GB+ headroom.
    ModelRate {
        model_id: "mlx-community/Qwen2.5-7B-Instruct-4bit",
        input_per_mtok: 1_000_000,
        output_per_mtok: 1_000_000,
        currency: "CC",
        min_ram_gb: 16,
        description: "Qwen 7B — strong general-purpose; 16GB+ recommended",
    },
    ModelRate {
        model_id: "mlx-community/gemma-3-4b-it-qat-4bit",
        input_per_mtok: 1_000_000,
        output_per_mtok: 1_000_000,
        currency: "CC",
        min_ram_gb: 8,
        description: "Gemma 3 4B QAT — balanced default for 8GB+ Macs",
    },
    ModelRate {
        model_id: "mlx-community/Qwen2.5-32B-Instruct-4bit",
        input_per_mtok: 1_000_000,
        output_per_mtok: 1_000_000,
        currency: "CC",
        min_ram_gb: 32,
        description: "Qwen 32B — frontier-class; 32GB+ Mac Studio class",
    },
    ModelRate {
        model_id: "mlx-community/Llama-3.3-70B-Instruct-4bit",
        input_per_mtok: 1_000_000,
        output_per_mtok: 1_000_000,
        currency: "CC",
        min_ram_gb: 64,
        description: "Llama 3.3 70B — heavyweight; 64GB+ Mac Studio class",
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
    fn fit_within_budget_never_prunes_unknown_or_stub() {
        // Off-catalog (unknown floor) + stub contribute 0 and are always kept,
        // even on a tiny RAM budget.
        let models = sv(&["custom/whatever-4bit", "stub"]);
        let (kept, dropped) = fit_within_budget(&models, 1);
        assert_eq!(kept, models);
        assert!(dropped.is_empty());
    }
}
