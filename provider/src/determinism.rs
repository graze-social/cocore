//! Deterministic generation mode for the provider agent.
//!
//! ## Why determinism matters for verification
//!
//! Without hardware attestation (Secure Enclave / Apple MDA), the Linux
//! provider can't cryptographically prove *how* inference was run — only that
//! it produced a specific output for a specific input (via the receipt's
//! `inputCommitment` / `outputCommitment` / `enclaveSignature`). Determinism
//! turns this into a *verifiable claim*: at `temperature=0` with a fixed seed,
//! two independent providers running the same model on the same input should
//! produce the same output. A verifier can re-run the inference and compare
//! hashes rather than trusting the provider's hardware.
//!
//! This is the first link in the web-of-trust chain intended for Linux
//! providers: multiple nodes agreeing on the output is stronger evidence than
//! any one node's self-assertion.
//!
//! ## Configuration
//!
//! | Env var | Default | Meaning |
//! |---|---|---|
//! | `COCORE_DETERMINISTIC` | unset (off) | Set to `1` or `true` to enable |
//! | `COCORE_DETERMINISTIC_SEED` | `42` | RNG seed sent to the backend |
//!
//! When deterministic mode is **off** (the default), `params()` returns
//! `(None, None)` and the provider behaves exactly as before — no temperature
//! or seed is injected.
//!
//! When deterministic mode is **on**, `params()` returns `(Some(0.0), Some(seed))`.
//! The `temperature=0` selects greedy decoding (the deterministic path on
//! llama.cpp, Ollama, and most vLLM deployments); `seed` pins the PRNG for
//! backends that use one even at temperature=0.
//!
//! The actual params used are committed to the receipt's `params` field so a
//! verifier can reproduce the call without guessing the settings.

/// Returns the `(temperature, seed)` to use for this generation, driven by
/// the operator's env-var configuration. `(None, None)` means "use whatever
/// the backend defaults to" (non-deterministic, the historical behavior).
pub fn params() -> (Option<f32>, Option<u64>) {
    let on = std::env::var("COCORE_DETERMINISTIC")
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            v == "1" || v == "true" || v == "yes"
        })
        .unwrap_or(false);

    if !on {
        return (None, None);
    }

    let seed = std::env::var("COCORE_DETERMINISTIC_SEED")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(42);

    (Some(0.0), Some(seed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn off_by_default() {
        // Ensure the env var is not set for this test.
        unsafe { std::env::remove_var("COCORE_DETERMINISTIC") };
        assert_eq!(params(), (None, None));
    }

    #[test]
    fn enabled_with_default_seed() {
        unsafe { std::env::set_var("COCORE_DETERMINISTIC", "1") };
        unsafe { std::env::remove_var("COCORE_DETERMINISTIC_SEED") };
        let (temp, seed) = params();
        unsafe { std::env::remove_var("COCORE_DETERMINISTIC") };
        assert_eq!(temp, Some(0.0));
        assert_eq!(seed, Some(42));
    }

    #[test]
    fn enabled_with_custom_seed() {
        unsafe { std::env::set_var("COCORE_DETERMINISTIC", "true") };
        unsafe { std::env::set_var("COCORE_DETERMINISTIC_SEED", "1337") };
        let (temp, seed) = params();
        unsafe { std::env::remove_var("COCORE_DETERMINISTIC") };
        unsafe { std::env::remove_var("COCORE_DETERMINISTIC_SEED") };
        assert_eq!(temp, Some(0.0));
        assert_eq!(seed, Some(1337));
    }
}
