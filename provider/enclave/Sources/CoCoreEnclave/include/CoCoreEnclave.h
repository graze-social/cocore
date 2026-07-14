// CoCoreEnclave: C-ABI surface that the cocore-provider Rust agent
// links against to access the Secure Enclave. The Rust side declares
// these in provider/src/secure_enclave.rs under
// `cfg(all(target_os = "macos", feature = "secure_enclave"))`.
//
// All functions return 0 on success and a negative integer on
// failure. A single process should call cocore_enclave_create_or_load
// at most once; the returned handle is opaque and must be freed with
// cocore_enclave_release.

#ifndef COCORE_ENCLAVE_H
#define COCORE_ENCLAVE_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Load the existing Secure Enclave identity for this user, or
/// create one if none exists. The handle is non-portable: it will
/// only work on the Mac it was created on.
int cocore_enclave_create_or_load(void **out_handle);

/// Copy the raw P-256 public key (uncompressed, 64 bytes: X || Y)
/// into the caller's buffer. `len` must be at least 64.
int cocore_enclave_public_key(void *handle, unsigned char *out, size_t len);

/// Produce an ECDSA-P256 signature over `data`. The signature is
/// DER-encoded and written into `out_sig`; on entry, `*out_sig_len`
/// is the buffer capacity, on exit, the actual length.
int cocore_enclave_sign(
    void *handle,
    const unsigned char *data,
    size_t data_len,
    unsigned char *out_sig,
    size_t *out_sig_len
);

/// Release the handle. Safe to call with NULL.
void cocore_enclave_release(void *handle);

// --- Encryption key (P-256 ECDH / KeyAgreement), for `p256-ecies-se` ---
// A SECOND, independent Secure-Enclave-resident key used to seal/open the APNs
// code-challenge nonce and confidential prompts. Same shapes as the signing
// key; distinct handle + keychain slot. The private half never leaves the SEP —
// only ECDH shared secrets come out.

/// Load or create the SE-resident P-256 KeyAgreement key. Distinct handle from
/// the signing identity; free with cocore_enclave_enc_release.
int cocore_enclave_enc_create_or_load(void **out_handle);

/// Copy the raw P-256 public key (uncompressed, 64 bytes: X || Y). `len` >= 64.
int cocore_enclave_enc_public_key(void *handle, unsigned char *out, size_t len);

/// Raw ECDH: scalar-mult the SE private key with `peer_pub` (64 bytes, X || Y)
/// and write the 32-byte shared X-coordinate into `out_shared`. The caller runs
/// HKDF over it (see crypto::ecies) — this is deliberately the raw secret so the
/// KDF stays reproducible across Rust/TS/Python. `out_len` must be >= 32.
int cocore_enclave_enc_ecdh(
    void *handle,
    const unsigned char *peer_pub_64,
    size_t peer_len,
    unsigned char *out_shared,
    size_t out_len
);

/// Release the encryption-key handle. Safe to call with NULL.
void cocore_enclave_enc_release(void *handle);

#ifdef __cplusplus
}
#endif

#endif // COCORE_ENCLAVE_H
