//! Native in-process MLX inference engine (WS-ENGINE) — the long pole of
//! darkbloom parity. Feature-gated behind `native_mlx`.
//!
//! WHY THIS EXISTS: today the agent decrypts the prompt and hands it to an
//! owner-controlled Python subprocess (`engines/subprocess.rs`) that no
//! attestation covers — so the SE attestation vouches for the wrong process.
//! This engine processes the plaintext ENTIRELY inside the measured, signed
//! `cocore` binary (no subprocess, no IPC), which is the load-bearing
//! confidential property (darkbloom's "in-process inference, no observation
//! surface"). Only with this does `inProcessBackend` become true and the
//! confidential tier become reachable.
//!
//! METAL / JIT (S1 finding, see provider/spikes/SPIKE_RESULTS.md): MLX runs its
//! standard kernels from a PRECOMPILED `mlx.metallib` loaded at runtime — no
//! runtime shader JIT — so the agent is signed with `allow-jit=false` and the
//! metallib is signed by the same team (library validation). The metallib is
//! hashed at load and pinned into the attestation (`metallibHash`) so a
//! confidential verifier checks the GPU kernels too, not just the binary.
//!
//! STATUS: the engine plumbing (Engine trait, in-process + metallib reporting,
//! metallib hashing) is complete and compiles WITHOUT mlx-rs. The actual MLX
//! token loop is gated on a build host with the full Xcode Metal toolchain
//! (absent in the dev environment this was authored in). `generate_once`
//! returns a clear error until that wiring lands, rather than silently
//! degrading — a provider running this unwired must not serve, and must never
//! claim to have produced output it didn't.

use super::{Engine, GenerateRequest, GenerateResponse};
use anyhow::Result;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// In-process MLX engine. Holds the precompiled-metallib hash so the
/// attestation can pin the GPU kernels; the model handle + tokenizer are added
/// when mlx-rs is wired on a Metal-capable build host.
pub struct NativeMlxEngine {
    /// SHA-256 hex of the precompiled, signed `mlx.metallib`, when present.
    metallib_hash: Option<String>,
    /// Model directory (safetensors weights + tokenizer) loaded in-process.
    #[allow(dead_code)]
    model_dir: PathBuf,
}

impl NativeMlxEngine {
    /// Load an MLX model from `model_dir`, pinning `metallib_path` (the
    /// precompiled signed shader library) into the attestation by hashing it at
    /// load. The prompt never leaves this process.
    pub fn load(model_dir: PathBuf, metallib_path: Option<PathBuf>) -> Result<Self> {
        let metallib_hash = match metallib_path {
            Some(p) => Some(hash_file(&p)?),
            None => None,
        };
        Ok(Self {
            metallib_hash,
            model_dir,
        })
    }
}

impl Engine for NativeMlxEngine {
    fn name(&self) -> &'static str {
        "native-mlx"
    }

    fn ready(&self) -> bool {
        // Until the MLX token loop is wired, the engine is NOT ready to serve,
        // so the registry won't route real jobs to it (it falls back to the
        // stub / a best-effort backend). Flip to a real readiness check
        // (model + metallib loaded) when mlx-rs lands.
        false
    }

    /// THE load-bearing confidential property: inference runs in this measured
    /// binary, not an owner-controlled subprocess.
    fn in_process(&self) -> bool {
        true
    }

    fn metallib_hash(&self) -> Option<String> {
        self.metallib_hash.clone()
    }

    fn generate_once(&self, _request: &GenerateRequest) -> Result<GenerateResponse> {
        // TODO(WS-ENGINE): drive mlx-rs token generation here, streaming deltas
        // through `generate_stream`'s callback, with the prompt held only in
        // this address space (Zeroizing on drop). Requires the Metal toolchain
        // (full Xcode) on the build host — see provider/spikes/SPIKE_RESULTS.md.
        anyhow::bail!(
            "native_mlx engine is not yet wired to MLX (needs a full-Xcode build host); \
             refusing to serve rather than produce unattested output"
        )
    }
}

fn hash_file(path: &Path) -> Result<String> {
    let mut h = Sha256::new();
    let mut f = std::fs::File::open(path)
        .map_err(|e| anyhow::anyhow!("open metallib {}: {e}", path.display()))?;
    std::io::copy(&mut f, &mut h)?;
    Ok(hex::encode(h.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_in_process_and_hashes_metallib() {
        let dir = std::env::temp_dir();
        let metallib = dir.join("cocore-test.metallib");
        std::fs::write(&metallib, b"fake-metallib-bytes").unwrap();
        let eng = NativeMlxEngine::load(dir.clone(), Some(metallib.clone())).unwrap();
        // The confidential property + the GPU-kernel pin are reported.
        assert!(eng.in_process());
        let h = eng.metallib_hash().expect("metallib hashed");
        assert_eq!(h.len(), 64);
        // Not ready / refuses to serve until MLX is wired — never fakes output.
        assert!(!eng.ready());
        let req = GenerateRequest {
            model: "m".into(),
            messages: vec![],
            max_tokens: 1,
            temperature: None,
            top_p: None,
        };
        assert!(eng.generate_once(&req).is_err());
        std::fs::remove_file(&metallib).ok();
    }
}
