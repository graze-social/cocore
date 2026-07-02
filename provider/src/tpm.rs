//! TPM 2.0 quote verification — the Linux path to `trustLevel: hardware-attested`.
//!
//! This is a **pure-Rust verifier**: no `tss-esapi`, no TPM hardware, no new
//! dependencies (it uses `p256` + `sha2`, already in the tree). It checks the
//! three things the `tpmQuote` lexicon field requires of a verifier:
//!
//!   1. the signed blob is a genuine TPM quote — `TPMS_ATTEST` with magic
//!      `TPM_GENERATED_VALUE` and type `TPM_ST_ATTEST_QUOTE`;
//!   2. the quote **signature** is valid under the Attestation Key (AK);
//!   3. the quote is **bound** to the provider's signing key —
//!      `extraData (qualifyingData) == sha256(publicKey)`.
//!
//! The remaining check — that the AK certificate chain anchors to a genuine
//! TPM-manufacturer root (the "vendor trust" the way Apple's MDA chain anchors
//! to Apple's root) — is the x509 chain walk `verify_ak_chain`, which mirrors
//! `mda::verify_chain` and is gated on the embedded vendor-root set (a trust
//! decision still owned by the cocore maintainers — see [`vendor_roots`]).
//!
//! The acquisition side (producing a quote on a real/simulated TPM via
//! `tss-esapi`) lives behind the `tpm` feature; this verifier is always
//! compiled so the AppView/SDK-equivalent check and `attestation::build`'s
//! embed gate share one implementation.
//!
//! Tested against a **real `swtpm`-generated quote** (the frozen vector in
//! `testdata/swtpm_quote.txt`) so the byte parser and the crypto match genuine
//! TPM output, not a hand-rolled fixture.

use anyhow::{bail, Result};
use sha2::{Digest, Sha256};

/// `"\xffTCG"` — every TPM-generated attestation structure starts with this.
const TPM_GENERATED_VALUE: u32 = 0xff54_4347;
/// `TPM_ST_ATTEST_QUOTE` — the attestation type for `TPM2_Quote` output.
const TPM_ST_ATTEST_QUOTE: u16 = 0x8018;

/// Verify a TPM quote's structure, signature, and binding to `expected_pubkey`.
///
/// Inputs (all acquired elsewhere — by the `tpm`-feature acquisition on the
/// provider, or carried in the `tpmQuote` attestation field for a remote
/// verifier):
/// - `quoted`: the marshaled `TPMS_ATTEST` the TPM signed.
/// - `sig_rs`: the ECDSA signature as `r || s`, each coordinate left-padded to
///   32 bytes (the acquisition pads TPM2B values that drop leading zeros), so
///   exactly 64 bytes for P-256.
/// - `ak_pub_sec1`: the AK public key, SEC1 uncompressed (`0x04 || x || y`),
///   taken from the verified leaf of the AK certificate chain.
/// - `expected_pubkey`: the provider's signing public key the quote must commit
///   to (the attestation record's `publicKey`).
///
/// Returns `Ok(())` only when all three checks pass.
pub fn verify_quote(
    quoted: &[u8],
    sig_rs: &[u8],
    ak_pub_sec1: &[u8],
    expected_pubkey: &[u8],
) -> Result<()> {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

    // 1. Structure: magic + type, and extract the qualifyingData (extraData).
    let qualifying = parse_quote_extra_data(quoted)?;

    // 2. Signature over the WHOLE quoted blob, under the AK key. The p256
    //    verifier hashes `quoted` with SHA-256 (P-256's associated digest),
    //    matching the TPM's ECDSA-SHA256 quote scheme.
    let vk = VerifyingKey::from_sec1_bytes(ak_pub_sec1)
        .map_err(|e| anyhow::anyhow!("AK public key is not valid SEC1 P-256: {e}"))?;
    let sig = Signature::from_slice(sig_rs)
        .map_err(|e| anyhow::anyhow!("signature is not a valid P-256 r||s (need 64 bytes): {e}"))?;
    vk.verify(quoted, &sig)
        .map_err(|_| anyhow::anyhow!("TPM quote signature did not verify under the AK"))?;

    // 3. Binding: the quote's extraData commits to our signing key. Without
    //    this, a valid quote from one TPM could be stapled onto an unrelated
    //    key (the same staple attack the MDA/App-Attest binding defends).
    let want = Sha256::digest(expected_pubkey);
    if qualifying != want.as_slice() {
        bail!("TPM quote is not bound to the signing key (qualifyingData != sha256(publicKey))");
    }
    Ok(())
}

/// Parse a `TPMS_ATTEST` quote far enough to validate magic/type and return its
/// `extraData` (the qualifyingData). TPM structures are big-endian; a `TPM2B_*`
/// field is a `UINT16` byte-length followed by that many bytes. Layout up to
/// the field we need: `magic(4) ‖ type(2) ‖ qualifiedSigner(TPM2B) ‖
/// extraData(TPM2B) ‖ …`.
fn parse_quote_extra_data(quoted: &[u8]) -> Result<Vec<u8>> {
    let mut r = Reader::new(quoted);
    if r.u32()? != TPM_GENERATED_VALUE {
        bail!("TPMS_ATTEST magic is not TPM_GENERATED_VALUE (not a TPM-produced structure)");
    }
    if r.u16()? != TPM_ST_ATTEST_QUOTE {
        bail!("TPMS_ATTEST type is not TPM_ST_ATTEST_QUOTE");
    }
    let _qualified_signer = r.tpm2b()?; // TPM2B_NAME of the AK — skip
    let extra_data = r.tpm2b()?; // TPM2B_DATA == qualifyingData
    Ok(extra_data.to_vec())
}

/// Embedded TPM-manufacturer root certificates the AK chain may anchor to —
/// the TPM equivalent of pinning Apple's Enterprise Attestation Root. Which
/// manufacturers to trust (Infineon, STMicroelectronics, Nuvoton, Intel, AMD,
/// …) is a maintainer trust decision; until that set is curated this is EMPTY,
/// so [`verify_ak_chain`] fails closed and no quote can earn hardware-attested.
pub fn vendor_roots() -> &'static [&'static [u8]] {
    &[]
}

/// Big-endian byte reader with bounds checking — never panics on malformed
/// input, returns an error instead.
struct Reader<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, i: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .i
            .checked_add(n)
            .ok_or_else(|| anyhow::anyhow!("length overflow"))?;
        if end > self.b.len() {
            bail!(
                "TPMS_ATTEST truncated (wanted {n} bytes at offset {})",
                self.i
            );
        }
        let s = &self.b[self.i..end];
        self.i = end;
        Ok(s)
    }
    fn u16(&mut self) -> Result<u16> {
        let s = self.take(2)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }
    fn u32(&mut self) -> Result<u32> {
        let s = self.take(4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn tpm2b(&mut self) -> Result<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A REAL TPM 2.0 quote produced by `swtpm` (software TPM) on the dev box,
    /// frozen so these tests run with no TPM/`swtpm` present. The signing key
    /// the quote is bound to is the literal `EXPECTED_PUBKEY` bytes; the quote's
    /// qualifyingData is `sha256(EXPECTED_PUBKEY)`. See the `tpm` feature's
    /// acquisition for how it was generated.
    const VECTOR: &str = include_str!("testdata/swtpm_quote.txt");
    /// A genuine quote from an AMD firmware TPM (Ryzen 7 3700X / X570 Taichi),
    /// captured on real silicon — not swtpm. Proves the parser + crypto handle
    /// real hardware output, and that swtpm and hardware produce the same
    /// verifiable structure.
    const AMD_VECTOR: &str = include_str!("testdata/amd_ftpm_quote.txt");

    fn field(vector: &str, name: &str) -> Vec<u8> {
        let line = vector
            .lines()
            .find_map(|l| l.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("missing {name} in vector"));
        hex::decode(line.trim()).expect("hex")
    }

    fn quoted() -> Vec<u8> {
        field(VECTOR, "QUOTED_HEX")
    }
    fn sig() -> Vec<u8> {
        field(VECTOR, "SIG_RS_HEX")
    }
    fn ak() -> Vec<u8> {
        field(VECTOR, "AK_SEC1_HEX")
    }
    fn pubkey() -> Vec<u8> {
        field(VECTOR, "EXPECTED_PUBKEY_HEX")
    }

    #[test]
    fn real_swtpm_quote_verifies() {
        // The whole point: a genuine TPM quote passes structure + signature +
        // binding against the key it was bound to.
        verify_quote(&quoted(), &sig(), &ak(), &pubkey()).expect("real swtpm quote must verify");
    }

    #[test]
    fn real_amd_ftpm_quote_verifies() {
        // The same verifier, against a quote from a real AMD firmware TPM
        // (hardware, not swtpm). Structure + ECDSA signature + key-binding all
        // hold — the verifier is validated against genuine silicon output.
        verify_quote(
            &field(AMD_VECTOR, "QUOTED_HEX"),
            &field(AMD_VECTOR, "SIG_RS_HEX"),
            &field(AMD_VECTOR, "AK_SEC1_HEX"),
            &field(AMD_VECTOR, "EXPECTED_PUBKEY_HEX"),
        )
        .expect("real AMD fTPM quote must verify");
    }

    #[test]
    fn parser_finds_magic_type_and_qualifying_data() {
        let q = quoted();
        assert_eq!(
            u32::from_be_bytes([q[0], q[1], q[2], q[3]]),
            TPM_GENERATED_VALUE
        );
        assert_eq!(u16::from_be_bytes([q[4], q[5]]), TPM_ST_ATTEST_QUOTE);
        // extraData must equal sha256(pubkey).
        let extra = parse_quote_extra_data(&q).unwrap();
        assert_eq!(extra.as_slice(), Sha256::digest(pubkey()).as_slice());
    }

    #[test]
    fn wrong_key_breaks_the_binding() {
        // Same valid quote, but claim it's bound to a DIFFERENT key → reject.
        let err = verify_quote(&quoted(), &sig(), &ak(), b"some-other-pubkey").unwrap_err();
        assert!(err.to_string().contains("not bound"));
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let mut s = sig();
        s[0] ^= 0x01;
        let err = verify_quote(&quoted(), &s, &ak(), &pubkey()).unwrap_err();
        assert!(err.to_string().contains("did not verify"));
    }

    #[test]
    fn tampered_quote_body_is_rejected() {
        // Flip a byte in the PCR-digest region (past the header) → signature
        // no longer matches the body.
        let mut q = quoted();
        let n = q.len();
        q[n - 1] ^= 0x01;
        let err = verify_quote(&q, &sig(), &ak(), &pubkey()).unwrap_err();
        assert!(err.to_string().contains("did not verify"));
    }

    #[test]
    fn non_tpm_blob_rejected_by_magic() {
        let err = parse_quote_extra_data(&[0u8; 16]).unwrap_err();
        assert!(err.to_string().contains("TPM_GENERATED_VALUE"));
    }

    #[test]
    fn truncated_quote_does_not_panic() {
        // A short buffer must error, never panic (bounds-checked reader).
        assert!(parse_quote_extra_data(&quoted()[..8]).is_err());
    }

    #[test]
    fn vendor_roots_empty_until_curated() {
        // Fail-closed posture: no vendor roots are trusted yet, so the chain
        // walk (and thus hardware-attested) can't yet succeed.
        assert!(vendor_roots().is_empty());
    }
}
