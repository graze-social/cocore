//! Provider encryption keys: X25519 (software) and P-256 ECIES (Secure Enclave).
//!
//! Two wire formats, selected by the provider's advertised `encScheme`:
//!
//! * `x25519-xsalsa20-poly1305` — `crypto_box::SalsaBox` (X25519 +
//!   XSalsa20-Poly1305), 24-byte random nonce prefix followed by tag+ciphertext.
//!   The canonical NaCl `crypto_box` layout, so any NaCl-compatible client can
//!   encrypt prompts without bespoke wire handling. The software fallback.
//!
//! * `p256-ecies-se` — ephemeral-static P-256 ECDH → HKDF-SHA256 → AES-256-GCM
//!   (see the [`ecies`] module for the byte-exact spec). The recipient's static
//!   P-256 private key lives in the **Secure Enclave** and never leaves it; the
//!   enclave performs the scalar-mult and hands Rust the raw 32-byte shared
//!   secret `Z`, over which Rust runs the (cross-language) HKDF + AEAD. This is
//!   the confidential-tier key: an operator cannot lift it off the machine, so
//!   the 2026-07-05 copy-the-key spoof (a software `identity.pem` replayed on a
//!   non-Apple box) can't recover the sealed APNs nonce or a sealed prompt.
//!
//! Both schemes expose the SAME [`EncryptionKey`] trait
//! (`open_from(peer_pub, blob)` / `seal_to(peer_pub, blob)`) so the serve loop
//! is codec-agnostic — the wire never mixes the two because `encScheme` selects
//! the decoder.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use crypto_box::{
    aead::{Aead, AeadCore, OsRng, Payload},
    PublicKey, SalsaBox, SecretKey,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("invalid key length")]
    BadKeyLength,
    #[error("decode: {0}")]
    Decode(#[from] base64::DecodeError),
    #[error("aead: {0}")]
    Aead(String),
    #[error("ciphertext truncated (need >=24-byte nonce + tag)")]
    Truncated,
    #[error("secure enclave: {0}")]
    Enclave(String),
}

const NONCE_LEN: usize = 24;

/// A provider encryption key that can open ciphertexts sealed to it and seal
/// replies back to a peer, independent of the underlying scheme (X25519 or
/// SE-resident P-256 ECIES). Every call site only needs these four methods, so
/// the serve loop holds a `&dyn EncryptionKey` and never branches on scheme.
pub trait EncryptionKey: Send + Sync {
    /// Base64 of this key's public part (32-byte X25519, or 64-byte
    /// uncompressed P-256 `X || Y`). Published as the attestation
    /// `encryptionPubKey`.
    fn public_key_b64(&self) -> String;
    /// The stable, self-describing descriptor (algorithm + public key) for the
    /// provider record's `encryptionKey`.
    fn descriptor(&self) -> EncryptionKeyDescriptor;
    /// The short attestation `encScheme` tag (`"x25519"` | `"p256-ecies-se"`) —
    /// the lexicon enum, NOT the descriptor's long `algorithm` string.
    fn enc_scheme(&self) -> &'static str;
    /// Decrypt a blob sealed to us. `peer_pub_b64` is the sender's public key
    /// (X25519 static peer, or the ephemeral `epk` for ECIES).
    fn open_from(&self, peer_pub_b64: &str, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError>;
    /// Encrypt a reply to a peer identified by `peer_pub_b64`.
    fn seal_to(&self, peer_pub_b64: &str, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError>;
    /// Whether the private half is non-extractable (Secure-Enclave-resident).
    /// `false` for the software X25519 key. Feeds the attestation's
    /// `secureEnclaveAvailable` evidence for the confidential-tier gate.
    fn is_hardware_bound(&self) -> bool {
        false
    }
}

/// An X25519 keypair owned by the provider.
///
/// `crypto_box::SecretKey` zeroizes itself on drop internally; we don't
/// re-derive `ZeroizeOnDrop` here. We deliberately do **not** persist
/// the secret to disk in this module — that's the caller's choice (e.g.
/// derive deterministically from a Secure Enclave wrapper, or store in
/// the macOS keychain).
pub struct ProviderKeypair {
    secret: SecretKey,
    public: PublicKey,
}

impl ProviderKeypair {
    pub fn generate() -> Self {
        let secret = SecretKey::generate(&mut OsRng);
        let public = secret.public_key();
        Self { secret, public }
    }

    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != 32 {
            return Err(CryptoError::BadKeyLength);
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(bytes);
        let secret = SecretKey::from(buf);
        let public = secret.public_key();
        Ok(Self { secret, public })
    }

    pub fn public_key_b64(&self) -> String {
        B64.encode(self.public.as_bytes())
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        *self.public.as_bytes()
    }

    /// Decrypt a ciphertext produced by `seal_to`.
    pub fn open_from(
        &self,
        sender_pub_b64: &str,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if ciphertext.len() <= NONCE_LEN {
            return Err(CryptoError::Truncated);
        }
        let sender_pub = decode_pub(sender_pub_b64)?;
        let salsabox = SalsaBox::new(&sender_pub, &self.secret);
        let (nonce, body) = ciphertext.split_at(NONCE_LEN);
        let plaintext = salsabox
            .decrypt(
                nonce.into(),
                Payload {
                    msg: body,
                    aad: &[],
                },
            )
            .map_err(|e| CryptoError::Aead(e.to_string()))?;
        Ok(plaintext)
    }

    /// Encrypt a plaintext to a recipient.
    pub fn seal_to(
        &self,
        recipient_pub_b64: &str,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let recipient_pub = decode_pub(recipient_pub_b64)?;
        let salsabox = SalsaBox::new(&recipient_pub, &self.secret);
        let nonce = SalsaBox::generate_nonce(&mut OsRng);
        let body = salsabox
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &[],
                },
            )
            .map_err(|e| CryptoError::Aead(e.to_string()))?;
        let mut out = Vec::with_capacity(NONCE_LEN + body.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&body);
        Ok(out)
    }
}

fn decode_pub(b64: &str) -> Result<PublicKey, CryptoError> {
    let raw = B64.decode(b64)?;
    if raw.len() != 32 {
        return Err(CryptoError::BadKeyLength);
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&raw);
    Ok(PublicKey::from(buf))
}

/// Stable public-facing description of a provider's encryption key,
/// suitable for inclusion in `dev.cocore.compute.provider` records.
#[allow(non_snake_case)]
#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptionKeyDescriptor {
    pub algorithm: String,
    pub publicKey: String,
}

impl EncryptionKeyDescriptor {
    pub fn x25519(public_key_b64: String) -> Self {
        Self {
            algorithm: "x25519-xsalsa20-poly1305".into(),
            publicKey: public_key_b64,
        }
    }

    /// The Secure-Enclave-resident P-256 ECIES key (see [`ecies`]). `publicKey`
    /// is base64 of the 64-byte uncompressed point (`X || Y`, no `0x04` prefix).
    pub fn p256_ecies_se(public_key_b64: String) -> Self {
        Self {
            algorithm: "p256-ecies-se".into(),
            publicKey: public_key_b64,
        }
    }
}

/// The X25519 software key is the default (best-effort) encryption key.
impl EncryptionKey for ProviderKeypair {
    fn public_key_b64(&self) -> String {
        ProviderKeypair::public_key_b64(self)
    }
    fn descriptor(&self) -> EncryptionKeyDescriptor {
        EncryptionKeyDescriptor::x25519(self.public_key_b64())
    }
    fn enc_scheme(&self) -> &'static str {
        "x25519"
    }
    fn open_from(&self, peer_pub_b64: &str, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        ProviderKeypair::open_from(self, peer_pub_b64, ciphertext)
    }
    fn seal_to(&self, peer_pub_b64: &str, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        ProviderKeypair::seal_to(self, peer_pub_b64, plaintext)
    }
    // is_hardware_bound() defaults to false — the X25519 secret is in process
    // memory, not the Secure Enclave.
}

/// Select the provider's encryption key for this host: the SE-resident P-256
/// ECIES key when compiled with `secure_enclave` on a Mac that has one, else
/// the software X25519 key. Mirrors `secure_enclave::load_or_create_identity`.
/// Never fails: a compiled-in-but-unavailable enclave logs and falls back to
/// software (the machine then self-reports best-effort — no crash).
pub fn load_or_create_encryption_key() -> Box<dyn EncryptionKey> {
    #[cfg(all(target_os = "macos", feature = "secure_enclave"))]
    {
        match enclave_enc::EnclaveEncryptionKey::load_or_create() {
            Ok(k) => return Box::new(k),
            Err(e) => tracing::warn!(
                error = %e,
                "Secure Enclave encryption key unavailable; falling back to software X25519 (best-effort)"
            ),
        }
    }
    Box::new(ProviderKeypair::generate())
}

/// SE-resident P-256 ECIES encryption key (the confidential-tier key). The
/// private scalar lives in the enclave; we hold only an opaque handle and the
/// public point. Every `open_from`/`seal_to` asks the enclave for a fresh ECDH
/// shared secret and runs the [`ecies`] HKDF+AEAD over it in-process.
#[cfg(all(target_os = "macos", feature = "secure_enclave"))]
mod enclave_enc {
    use super::{ecies, CryptoError, EncryptionKey, EncryptionKeyDescriptor, B64};
    use base64::Engine as _;
    use std::os::raw::{c_int, c_void};

    extern "C" {
        fn cocore_enclave_enc_create_or_load(out_handle: *mut *mut c_void) -> c_int;
        fn cocore_enclave_enc_public_key(handle: *mut c_void, out: *mut u8, len: usize) -> c_int;
        fn cocore_enclave_enc_ecdh(
            handle: *mut c_void,
            peer_pub_64: *const u8,
            peer_len: usize,
            out_shared: *mut u8,
            out_len: usize,
        ) -> c_int;
        fn cocore_enclave_enc_release(handle: *mut c_void);
    }

    pub struct EnclaveEncryptionKey {
        handle: *mut c_void,
        public_key: [u8; 64],
    }

    // The handle is a retained Swift object used only through the C-ABI, which
    // is internally thread-safe for our read/ECDH usage.
    unsafe impl Send for EnclaveEncryptionKey {}
    unsafe impl Sync for EnclaveEncryptionKey {}

    impl EnclaveEncryptionKey {
        pub fn load_or_create() -> Result<Self, CryptoError> {
            let mut handle: *mut c_void = std::ptr::null_mut();
            let rc = unsafe { cocore_enclave_enc_create_or_load(&mut handle) };
            if rc != 0 || handle.is_null() {
                return Err(CryptoError::Enclave(format!(
                    "enc_create_or_load returned {rc}"
                )));
            }
            let mut pub_bytes = [0u8; 64];
            let rc = unsafe {
                cocore_enclave_enc_public_key(handle, pub_bytes.as_mut_ptr(), pub_bytes.len())
            };
            if rc != 0 {
                unsafe { cocore_enclave_enc_release(handle) };
                return Err(CryptoError::Enclave(format!(
                    "enc_public_key returned {rc}"
                )));
            }
            Ok(Self {
                handle,
                public_key: pub_bytes,
            })
        }

        /// ECDH with an ephemeral peer key (64-byte uncompressed X||Y) → raw
        /// 32-byte shared secret. The scalar-mult happens in the enclave.
        fn ecdh(&self, peer_pub_b64: &str) -> Result<[u8; 32], CryptoError> {
            let peer = B64.decode(peer_pub_b64)?;
            if peer.len() != 64 {
                return Err(CryptoError::BadKeyLength);
            }
            let mut z = [0u8; 32];
            let rc = unsafe {
                cocore_enclave_enc_ecdh(
                    self.handle,
                    peer.as_ptr(),
                    peer.len(),
                    z.as_mut_ptr(),
                    z.len(),
                )
            };
            if rc != 0 {
                return Err(CryptoError::Enclave(format!("enc_ecdh returned {rc}")));
            }
            Ok(z)
        }
    }

    impl EncryptionKey for EnclaveEncryptionKey {
        fn public_key_b64(&self) -> String {
            B64.encode(self.public_key)
        }
        fn descriptor(&self) -> EncryptionKeyDescriptor {
            EncryptionKeyDescriptor::p256_ecies_se(self.public_key_b64())
        }
        fn enc_scheme(&self) -> &'static str {
            "p256-ecies-se"
        }
        fn open_from(&self, peer_pub_b64: &str, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
            let z = self.ecdh(peer_pub_b64)?;
            ecies::open(&z, ciphertext)
        }
        fn seal_to(&self, peer_pub_b64: &str, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
            let z = self.ecdh(peer_pub_b64)?;
            Ok(ecies::seal(&z, plaintext))
        }
        fn is_hardware_bound(&self) -> bool {
            true
        }
    }

    impl Drop for EnclaveEncryptionKey {
        fn drop(&mut self) {
            unsafe { cocore_enclave_enc_release(self.handle) };
        }
    }
}

/// `p256-ecies-se` sealed-box construction — the byte-exact spec the Rust
/// provider (recipient), the TypeScript advisor/SDK, and the Python SDK all
/// mirror. Given a raw 32-byte ECDH shared secret `Z` (the X-coordinate of the
/// ephemeral-static shared point), the wire is:
///
/// ```text
/// key  = HKDF-SHA256(salt = 0x00*32, IKM = Z, info = "cocore/p256-ecies-se/v1", L = 32)
/// iv   = 12 random bytes                         (fresh per message, ON the wire)
/// blob = iv(12) || AES-256-GCM(key, iv, aad = <empty>, plaintext)   // ct || 16-byte tag
/// ```
///
/// The peer's ephemeral public key (`epk` / `requester_pub_key`, 64-byte
/// uncompressed) travels in the SAME out-of-band field the X25519 path uses for
/// the sender key, so this parallels `SalsaBox` exactly: one shared key both
/// directions, a random per-message nonce, empty AAD (a wrong peer key yields a
/// wrong `Z` → GCM tag failure, so AAD binding adds nothing).
pub mod ecies {
    use super::CryptoError;
    use aes_gcm::{
        aead::{Aead, KeyInit, Payload},
        Aes256Gcm, Nonce,
    };
    use hkdf::Hkdf;
    use rand::RngCore;
    use sha2::Sha256;

    /// HKDF `info` label — domain-separates this construction. Bump the `/vN`
    /// suffix (and mint a new `encScheme`) if the construction ever changes.
    pub const INFO: &[u8] = b"cocore/p256-ecies-se/v1";
    pub const IV_LEN: usize = 12;
    pub const TAG_LEN: usize = 16;

    /// Derive the AES-256 key from the raw ECDH shared secret `Z`.
    pub fn derive_key(z: &[u8; 32]) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), z);
        let mut okm = [0u8; 32];
        // HKDF-Expand of 32 bytes with a fixed info never errors.
        hk.expand(INFO, &mut okm)
            .expect("hkdf expand of 32 bytes cannot fail");
        okm
    }

    /// Seal `plaintext` with an explicit IV. Deterministic — used by the
    /// cross-language golden vector. Returns `iv || ct || tag`.
    pub fn seal_with_iv(z: &[u8; 32], iv: &[u8; IV_LEN], plaintext: &[u8]) -> Vec<u8> {
        let key = derive_key(z);
        let cipher = Aes256Gcm::new((&key).into());
        let ct = cipher
            .encrypt(
                Nonce::from_slice(iv),
                Payload {
                    msg: plaintext,
                    aad: &[],
                },
            )
            // AES-GCM encryption of an in-memory buffer cannot fail.
            .expect("aes-256-gcm seal cannot fail");
        let mut out = Vec::with_capacity(IV_LEN + ct.len());
        out.extend_from_slice(iv);
        out.extend_from_slice(&ct);
        out
    }

    /// Seal `plaintext` with a fresh random IV. Returns `iv || ct || tag`.
    pub fn seal(z: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
        let mut iv = [0u8; IV_LEN];
        rand::thread_rng().fill_bytes(&mut iv);
        seal_with_iv(z, &iv, plaintext)
    }

    /// Open an `iv || ct || tag` blob given the shared secret `Z`.
    pub fn open(z: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if blob.len() < IV_LEN + TAG_LEN {
            return Err(CryptoError::Truncated);
        }
        let key = derive_key(z);
        let cipher = Aes256Gcm::new((&key).into());
        let (iv, body) = blob.split_at(IV_LEN);
        cipher
            .decrypt(
                Nonce::from_slice(iv),
                Payload {
                    msg: body,
                    aad: &[],
                },
            )
            .map_err(|e| CryptoError::Aead(e.to_string()))
    }

    /// Software P-256 ECDH producing the raw 32-byte shared secret `Z` (the
    /// SEC1 X-coordinate). Used by senders (which are never SE-resident) and by
    /// the parity tests; the SE recipient obtains the identical `Z` from the
    /// enclave FFI instead. `peer_pub_64` is the uncompressed point `X || Y`.
    pub fn ecdh_software(
        our_secret: &p256::SecretKey,
        peer_pub_64: &[u8],
    ) -> Result<[u8; 32], CryptoError> {
        use p256::elliptic_curve::sec1::FromEncodedPoint;
        if peer_pub_64.len() != 64 {
            return Err(CryptoError::BadKeyLength);
        }
        // Rebuild the uncompressed SEC1 point (prepend the 0x04 tag).
        let mut sec1 = [0u8; 65];
        sec1[0] = 0x04;
        sec1[1..].copy_from_slice(peer_pub_64);
        let ep = p256::EncodedPoint::from_bytes(sec1)
            .map_err(|e| CryptoError::Aead(format!("peer point: {e}")))?;
        let affine = p256::AffinePoint::from_encoded_point(&ep);
        if affine.is_none().into() {
            return Err(CryptoError::BadKeyLength);
        }
        let shared = p256::elliptic_curve::ecdh::diffie_hellman(
            our_secret.to_nonzero_scalar(),
            affine.unwrap(),
        );
        let mut z = [0u8; 32];
        z.copy_from_slice(shared.raw_secret_bytes().as_slice());
        Ok(z)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let alice = ProviderKeypair::generate();
        let bob = ProviderKeypair::generate();
        let msg = b"prompt with very secret content";
        let ct = alice.seal_to(&bob.public_key_b64(), msg).unwrap();
        let pt = bob.open_from(&alice.public_key_b64(), &ct).unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn truncated_ciphertext_errors() {
        let kp = ProviderKeypair::generate();
        let other = ProviderKeypair::generate();
        let err = kp
            .open_from(&other.public_key_b64(), &[0u8; 8])
            .unwrap_err();
        assert!(matches!(err, CryptoError::Truncated));
    }

    #[test]
    fn wrong_sender_key_errors() {
        let alice = ProviderKeypair::generate();
        let bob = ProviderKeypair::generate();
        let mallory = ProviderKeypair::generate();
        let ct = alice.seal_to(&bob.public_key_b64(), b"hi").unwrap();
        let err = bob.open_from(&mallory.public_key_b64(), &ct).unwrap_err();
        assert!(matches!(err, CryptoError::Aead(_)));
    }

    #[test]
    fn public_key_is_32_bytes() {
        let kp = ProviderKeypair::generate();
        assert_eq!(kp.public_key_bytes().len(), 32);
        let decoded = B64.decode(kp.public_key_b64()).unwrap();
        assert_eq!(decoded.len(), 32);
    }

    // ---- p256-ecies-se ----

    /// Fixed test scalars (both well below the P-256 group order) + a fixed IV
    /// and plaintext. These EXACT bytes are mirrored in the TS and Python
    /// parity tests, so all three implementations must derive the same `Z`,
    /// AES key, and sealed blob. `K` is the recipient (the SE-resident key, here
    /// simulated in software); `E` is the sender's ephemeral.
    fn k_priv() -> p256::SecretKey {
        let mut b = [0u8; 32];
        for (i, x) in b.iter_mut().enumerate() {
            *x = (i as u8) + 1; // 0x01..=0x20
        }
        p256::SecretKey::from_bytes(&b.into()).unwrap()
    }
    fn e_priv() -> p256::SecretKey {
        let mut b = [0u8; 32];
        for (i, x) in b.iter_mut().enumerate() {
            *x = (i as u8) + 0x21; // 0x21..=0x40
        }
        p256::SecretKey::from_bytes(&b.into()).unwrap()
    }
    fn pub64(sk: &p256::SecretKey) -> [u8; 64] {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let ep = sk.public_key().to_encoded_point(false);
        let mut out = [0u8; 64];
        out.copy_from_slice(&ep.as_bytes()[1..]); // strip 0x04
        out
    }

    #[test]
    fn ecies_ecdh_is_symmetric() {
        // Z computed by the sender (E_priv, K_pub) equals Z computed by the
        // recipient (K_priv, E_pub) — the property the SE FFI must satisfy.
        let z_sender = ecies::ecdh_software(&e_priv(), &pub64(&k_priv())).unwrap();
        let z_recip = ecies::ecdh_software(&k_priv(), &pub64(&e_priv())).unwrap();
        assert_eq!(z_sender, z_recip);
    }

    #[test]
    fn ecies_round_trip() {
        let z = ecies::ecdh_software(&e_priv(), &pub64(&k_priv())).unwrap();
        let blob = ecies::seal(&z, b"secret prompt bytes");
        // recipient side recomputes Z from its own key + the ephemeral pub
        let z2 = ecies::ecdh_software(&k_priv(), &pub64(&e_priv())).unwrap();
        let pt = ecies::open(&z2, &blob).unwrap();
        assert_eq!(pt, b"secret prompt bytes");
    }

    #[test]
    fn ecies_golden_vector() {
        // The cross-language artifact. Fixed inputs → fixed Z, key, blob.
        // Mirrored byte-for-byte in packages/sdk + sdk/py parity tests.
        let iv = [
            0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        ];
        let plaintext = b"cocore-ecies-golden";

        let z = ecies::ecdh_software(&e_priv(), &pub64(&k_priv())).unwrap();
        let key = ecies::derive_key(&z);
        let blob = ecies::seal_with_iv(&z, &iv, plaintext);

        // Pinned expected values (hex). Any drift in the KDF/AEAD/point
        // handling breaks these — and TS/Py must produce the identical bytes.
        // Shared inputs (mirrored in TS/Py): K = 0x01..=0x20, E = 0x21..=0x40,
        // iv = 0x000102..0b, plaintext = "cocore-ecies-golden".
        assert_eq!(
            hex::encode(z),
            "4fe243908f378aa1c2a69538822e6ed908c3225d8692575507c649901245150a",
            "shared secret Z drifted"
        );
        assert_eq!(
            hex::encode(key),
            "1a5b4a77a470f8bb76f5730392220ecde4f197eaec447be77ac55073c5b0782e",
            "derived AES key drifted"
        );
        assert_eq!(
            hex::encode(&blob),
            "000102030405060708090a0b18d935a95421e46242ea5aac5e58adf5ca4a6ec3cf3fdfdec85ba2f014b13c83cf0958",
            "sealed blob drifted"
        );

        // And it must round-trip regardless of the pins.
        let z2 = ecies::ecdh_software(&k_priv(), &pub64(&e_priv())).unwrap();
        assert_eq!(ecies::open(&z2, &blob).unwrap(), plaintext);
    }
}
