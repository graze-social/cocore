//! Secure Enclave key wrapper.
//!
//! On macOS, this links against the Swift `CoCoreEnclave` framework
//! (see `provider/enclave/`) and exposes a `SecureEnclaveIdentity`
//! that signs canonical JSON for attestations and receipts. The
//! private key never leaves the Secure Enclave; we only hold an
//! opaque handle.
//!
//! On non-macOS platforms (CI, Linux dev), we fall back to a software
//! P-256 key. Records signed with the software key carry trust level
//! `self-attested` (no Apple MDA chain available) — the lexicon already
//! distinguishes these cases.

use anyhow::Result;
use once_cell::sync::OnceCell;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, thiserror::Error)]
pub enum EnclaveError {
    #[error("secure enclave unavailable on this platform")]
    Unavailable,
    #[error("ffi: {0}")]
    Ffi(String),
}

/// Signing identity bound to a single physical machine.
pub trait SigningIdentity: Send + Sync {
    /// Raw P-256 public key bytes (uncompressed, 64 bytes: X || Y).
    fn public_key_bytes(&self) -> [u8; 64];
    /// Base64 encoding of `public_key_bytes`.
    fn public_key_b64(&self) -> String {
        use base64::{engine::general_purpose::STANDARD as B64, Engine};
        B64.encode(self.public_key_bytes())
    }
    /// Sign `message` with the bound key. Returns DER-encoded ECDSA signature.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, EnclaveError>;
    /// True if the underlying key material is hardware-bound (Secure Enclave).
    fn is_hardware_bound(&self) -> bool;
}

/// Entry point: returns the best available signing identity for this host.
///
/// On macOS in release builds, this calls into the Swift FFI module. In
/// every other configuration (CI, Linux, or `cargo test` without the
/// `secure_enclave` feature) it returns a software fallback so the rest
/// of the pipeline stays testable.
pub fn load_or_create_identity() -> Result<Box<dyn SigningIdentity>> {
    #[cfg(all(target_os = "macos", feature = "secure_enclave"))]
    {
        // Fall back rather than abort if the enclave is compiled in but
        // unavailable at runtime (a chip-replaced host, a VM). The machine then
        // signs with a software key, reports is_hardware_bound()=false, and
        // self-caps at best-effort — no crash. This shouldn't fire on Apple
        // Silicon, but the soft-degradation keeps such an edge host serving.
        match macos::EnclaveIdentity::load_or_create() {
            Ok(id) => return Ok(Box::new(id)),
            Err(e) => tracing::warn!(
                error = %e,
                "Secure Enclave signing identity unavailable; falling back to software identity (best-effort)"
            ),
        }
    }
    #[allow(unreachable_code)]
    Ok(Box::new(software::SoftwareIdentity::generate()?))
}

/// Process-global signing identity, loaded exactly ONCE and shared thereafter.
///
/// Loading is NOT deterministic across repeated calls on a real machine: an SE
/// key created/accessible in one process context is not always reconstructible
/// in another, so a fresh `load_or_create_identity()` on each call could return
/// DIFFERENT keys within the same process (observed: a serve publishing one
/// attestation under `1feH…` then the rest under `1MPNTd…`). That flapping is
/// fatal for MDM attestation — the captured chain binds `sha256(signing pubkey)`,
/// so a moving key never binds. Memoizing here pins the process to the first key
/// it successfully loads, which is what every in-process caller must share.
static SHARED_IDENTITY: OnceCell<Arc<dyn SigningIdentity>> = OnceCell::new();

pub fn shared_identity() -> Result<Arc<dyn SigningIdentity>> {
    SHARED_IDENTITY
        .get_or_try_init(|| -> Result<Arc<dyn SigningIdentity>> {
            let arc: Arc<dyn SigningIdentity> = load_or_create_identity()?.into();
            // DIAGNOSTIC (load-bearing for triaging Secure Mode): record exactly
            // which key this process pinned and whether it's hardware-bound, so a
            // serve↔wizard key mismatch is visible in the log instead of inferred
            // from attestation records.
            tracing::info!(
                pubkey = %arc.public_key_b64(),
                hardware_bound = arc.is_hardware_bound(),
                "pinned process signing identity (memoized)"
            );
            Ok(arc)
        })
        .cloned()
}

/// `~/.cocore/signing-pubkey` — the serve's canonical signing public key in
/// plaintext base64. The serve is the SINGLE process that holds the SE key; every
/// other context (the `agent pubkey` CLI that backs the Secure Mode wizard) reads
/// THIS file instead of loading its own SE key, so the wizard always requests MDM
/// attestation for the exact key the serve signs with. This sidesteps the
/// cross-context SE-key problem entirely: only one process ever touches the key.
pub fn signing_pubkey_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".cocore").join("signing-pubkey"))
}

/// Called by the SERVE (and only the serve) after it pins its identity, so the
/// file always reflects the key the running serve actually uses. Best-effort.
pub fn publish_signing_pubkey(pubkey_b64: &str) {
    let Some(path) = signing_pubkey_path() else {
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = std::fs::write(&path, pubkey_b64) {
        tracing::warn!(error = %e, "could not publish signing-pubkey file");
    } else {
        tracing::info!(pubkey = %pubkey_b64, "published serve signing pubkey for the wizard/CLI");
    }
}

/// Read the serve's published signing pubkey, if a serve has written it. `None`
/// when absent (no serve has run yet) — the caller falls back to loading a key.
pub fn read_published_signing_pubkey() -> Option<String> {
    let raw = std::fs::read_to_string(signing_pubkey_path()?).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg(all(target_os = "macos", feature = "secure_enclave"))]
mod macos {
    use super::*;
    use std::os::raw::{c_int, c_void};

    extern "C" {
        fn cocore_enclave_create_or_load(out_handle: *mut *mut c_void) -> c_int;
        fn cocore_enclave_public_key(handle: *mut c_void, out: *mut u8, len: usize) -> c_int;
        fn cocore_enclave_sign(
            handle: *mut c_void,
            data: *const u8,
            data_len: usize,
            out_sig: *mut u8,
            out_sig_len: *mut usize,
        ) -> c_int;
        fn cocore_enclave_release(handle: *mut c_void);
    }

    pub struct EnclaveIdentity {
        handle: *mut c_void,
        public_key: [u8; 64],
    }

    unsafe impl Send for EnclaveIdentity {}
    unsafe impl Sync for EnclaveIdentity {}

    impl EnclaveIdentity {
        pub fn load_or_create() -> Result<Self> {
            // FFI scaffold; the Swift implementation lives under
            // provider/enclave/ and ships in M1.5.
            let mut handle: *mut c_void = std::ptr::null_mut();
            let rc = unsafe { cocore_enclave_create_or_load(&mut handle) };
            if rc != 0 || handle.is_null() {
                anyhow::bail!("cocore_enclave_create_or_load returned {rc}");
            }
            let mut pub_bytes = [0u8; 64];
            let rc = unsafe {
                cocore_enclave_public_key(handle, pub_bytes.as_mut_ptr(), pub_bytes.len())
            };
            if rc != 0 {
                unsafe { cocore_enclave_release(handle) };
                anyhow::bail!("cocore_enclave_public_key returned {rc}");
            }
            Ok(Self {
                handle,
                public_key: pub_bytes,
            })
        }
    }

    impl SigningIdentity for EnclaveIdentity {
        fn public_key_bytes(&self) -> [u8; 64] {
            self.public_key
        }
        fn sign(&self, message: &[u8]) -> Result<Vec<u8>, EnclaveError> {
            let mut buf = vec![0u8; 128];
            let mut len: usize = buf.len();
            let rc = unsafe {
                cocore_enclave_sign(
                    self.handle,
                    message.as_ptr(),
                    message.len(),
                    buf.as_mut_ptr(),
                    &mut len,
                )
            };
            if rc != 0 {
                return Err(EnclaveError::Ffi(format!("rc={rc}")));
            }
            buf.truncate(len);
            Ok(buf)
        }
        fn is_hardware_bound(&self) -> bool {
            true
        }
    }

    impl Drop for EnclaveIdentity {
        fn drop(&mut self) {
            unsafe { cocore_enclave_release(self.handle) };
        }
    }
}

mod software {
    use super::*;
    use p256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};
    use p256::EncodedPoint;
    use rand::rngs::OsRng;

    /// Software P-256 signing identity. Used on non-macOS builds and
    /// when the `secure_enclave` feature is off. Records signed by
    /// this identity carry trust level `self-attested` (no Apple MDA
    /// chain). The signature itself is a real ECDSA-P256-DER over
    /// SHA-256(message), interoperable with WebCrypto and the
    /// SecureEnclave path.
    ///
    /// Persistence: written to `~/.cocore/identity.pem` by default
    /// so the identity survives `cocore agent serve` restarts —
    /// without that, every serve startup generated a fresh keypair
    /// and the on-PDS view grew an N-th provider record per machine
    /// per restart (the bug we hit on 2026-05-10). The file is
    /// 0600-permission'd. `COCORE_SOFTWARE_KEY_PATH` overrides the
    /// default for tests and for cocore-services / docker-compose
    /// where ~ might not exist.
    pub struct SoftwareIdentity {
        signing_key: SigningKey,
        public_raw: [u8; 64],
    }

    impl SoftwareIdentity {
        pub fn generate() -> Result<Self> {
            if let Some(path) = key_path() {
                if path.exists() {
                    let pem = std::fs::read_to_string(&path)
                        .map_err(|e| anyhow::anyhow!("read {}: {e}", path.display()))?;
                    use p256::pkcs8::DecodePrivateKey;
                    let signing_key = SigningKey::from_pkcs8_pem(&pem)
                        .map_err(|e| anyhow::anyhow!("parse PKCS#8 PEM: {e}"))?;
                    return Ok(Self::from_signing_key(signing_key));
                }
            }
            let signing_key = SigningKey::random(&mut OsRng);
            if let Some(path) = key_path() {
                use p256::pkcs8::{EncodePrivateKey, LineEnding};
                let pem = signing_key
                    .to_pkcs8_pem(LineEnding::LF)
                    .map_err(|e| anyhow::anyhow!("encode PKCS#8 PEM: {e}"))?;
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent).ok();
                }
                std::fs::write(&path, pem.as_bytes())
                    .map_err(|e| anyhow::anyhow!("write {}: {e}", path.display()))?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
                }
            }
            Ok(Self::from_signing_key(signing_key))
        }

        fn from_signing_key(signing_key: SigningKey) -> Self {
            let verifying_key: VerifyingKey = *signing_key.verifying_key();
            let encoded: EncodedPoint = verifying_key.to_encoded_point(false);
            // Uncompressed encoding is 0x04 || X(32) || Y(32) = 65 bytes.
            let bytes = encoded.as_bytes();
            assert_eq!(bytes.len(), 65, "expected uncompressed P-256 point");
            assert_eq!(bytes[0], 0x04);
            let mut public_raw = [0u8; 64];
            public_raw.copy_from_slice(&bytes[1..]);
            Self {
                signing_key,
                public_raw,
            }
        }
    }

    impl SigningIdentity for SoftwareIdentity {
        fn public_key_bytes(&self) -> [u8; 64] {
            self.public_raw
        }
        fn sign(&self, message: &[u8]) -> Result<Vec<u8>, EnclaveError> {
            // Signer trait pre-hashes with SHA-256 by default for
            // P-256 — matches CryptoKit and WebCrypto behaviour.
            let signature: Signature = self.signing_key.sign(message);
            Ok(signature.to_der().as_bytes().to_vec())
        }
        fn is_hardware_bound(&self) -> bool {
            false
        }
    }

    fn key_path() -> Option<std::path::PathBuf> {
        if let Some(p) = std::env::var_os("COCORE_SOFTWARE_KEY_PATH") {
            // An explicit empty value disables persistence — useful for
            // tests that want fresh keys per run.
            if p.is_empty() {
                return None;
            }
            return Some(std::path::PathBuf::from(p));
        }
        // `cargo test` builds compile under cfg(test); we want tests
        // hermetic — never read or write ~/.cocore/identity.pem from
        // a dev's machine. Production builds (release / debug, both
        // cfg(not(test))) fall through to the default path.
        if cfg!(test) {
            return None;
        }
        // Default to ~/.cocore/identity.pem so the LaunchAgent's
        // bounced serve cycles share a stable identity across
        // restarts. dirs::home_dir() returns None for users with no
        // HOME (rare; pid 1 in some containers).
        dirs::home_dir().map(|h| h.join(".cocore").join("identity.pem"))
    }
}

/// Crate-wide test serialization for any test that creates/loads a software
/// identity. They all resolve their key path from the process-global
/// `COCORE_SOFTWARE_KEY_PATH` (or the shared default `~/.cocore/identity.pem`),
/// so two running in parallel race on the same file — interleaved writes corrupt
/// the PEM (NUL padding) and the readback panics. The `attestation` and
/// `receipt` tests call `load_or_create_identity()` too (it falls to the
/// software path when the Secure Enclave isn't compiled in), so this lock is
/// crate-visible and they take it as well. Recovers from a poisoned lock so a
/// single failing test doesn't cascade into every later one panicking on `lock()`.
#[cfg(test)]
pub(crate) fn identity_lock() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::Mutex;
    static IDENTITY_GUARD: Mutex<()> = Mutex::new(());
    IDENTITY_GUARD.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    use p256::EncodedPoint;

    #[test]
    fn software_signature_round_trips() {
        let _g = identity_lock();
        let id = load_or_create_identity().unwrap();
        let sig = id.sign(b"hello cocore").unwrap();

        // Reconstruct the verifying key from the public bytes the
        // identity exposes — exactly what an external verifier
        // (AppView, exchange, audit tool) would do.
        let pub_bytes = id.public_key_bytes();
        let mut uncompressed = [0u8; 65];
        uncompressed[0] = 0x04;
        uncompressed[1..].copy_from_slice(&pub_bytes);
        let point = EncodedPoint::from_bytes(uncompressed).unwrap();
        let vk = VerifyingKey::from_encoded_point(&point).unwrap();
        let parsed_sig = Signature::from_der(&sig).unwrap();
        vk.verify(b"hello cocore", &parsed_sig).unwrap();
    }

    #[test]
    fn signature_is_der_encoded() {
        let _g = identity_lock();
        let id = load_or_create_identity().unwrap();
        let sig = id.sign(b"x").unwrap();
        // DER ECDSA: SEQUENCE ( INTEGER r, INTEGER s ).
        assert_eq!(sig[0], 0x30, "DER SEQUENCE prefix");
        // Length byte is short-form (≤127); whole sig is well under.
        assert!(sig.len() < 80);
        assert!(sig.len() > 8);
    }

    #[test]
    fn wrong_message_fails_verification() {
        let _g = identity_lock();
        let id = load_or_create_identity().unwrap();
        let sig = id.sign(b"hello").unwrap();
        let pub_bytes = id.public_key_bytes();
        let mut uncompressed = [0u8; 65];
        uncompressed[0] = 0x04;
        uncompressed[1..].copy_from_slice(&pub_bytes);
        let point = EncodedPoint::from_bytes(uncompressed).unwrap();
        let vk = VerifyingKey::from_encoded_point(&point).unwrap();
        let parsed_sig = Signature::from_der(&sig).unwrap();
        assert!(vk.verify(b"world", &parsed_sig).is_err());
    }

    #[test]
    fn public_key_is_64_bytes() {
        let _g = identity_lock();
        let id = load_or_create_identity().unwrap();
        assert_eq!(id.public_key_bytes().len(), 64);
    }

    #[test]
    fn software_identity_persists_across_loads_when_path_set() {
        // Pins the survive-restart property: pre-2026-05 every
        // serve startup minted a fresh key (no persist by default),
        // so two loads in a row produced two different
        // attestationPubKeys. Now: a path-bound load returns the
        // same key twice. The production default uses
        // ~/.cocore/identity.pem; this test scopes to a tempfile so
        // it stays hermetic regardless of the dev's home dir.
        let _g = identity_lock();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("id.pem");
        // SAFETY: env::set_var is unsafe in 2024+ Rust; identity_lock()
        // gives this test exclusive ownership of the env-var window. We
        // capture the results and ALWAYS remove the var BEFORE any unwrap,
        // so a failed generate() can't leak the var (pointing at a tempdir
        // we're about to drop) into a later test.
        unsafe {
            std::env::set_var("COCORE_SOFTWARE_KEY_PATH", &path);
        }
        let first = software::SoftwareIdentity::generate();
        let second = software::SoftwareIdentity::generate();
        unsafe {
            std::env::remove_var("COCORE_SOFTWARE_KEY_PATH");
        }
        let first = first.expect("first software identity generate");
        let second = second.expect("second software identity generate");
        assert_eq!(
            first.public_key_bytes(),
            second.public_key_bytes(),
            "second load should reuse the on-disk key, not generate a new one"
        );
        assert!(
            path.exists(),
            "first call should have written the PEM at {}",
            path.display()
        );
    }
}
