use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProviderError {
    #[error("not authenticated; run `cocore agent pair` first")]
    NotAuthenticated,
    #[error("attestation expired or absent; run `cocore agent attest`")]
    AttestationStale,
    #[error("advisor: {0}")]
    Advisor(String),
    /// The advisor WebSocket never came up — the Register frame never
    /// reached the advisor. Distinct from [`ProviderError::Advisor`] (which
    /// also covers post-connect drops) so the serve loop can count
    /// consecutive CONNECT failures and publish an `advisorFault` on the
    /// provider record. `code` is the machine-readable class the fault
    /// publishes (e.g. `dns-failure`, `connect-timeout`); `detail` is for
    /// local logs only and never leaves the machine.
    #[error("advisor connect ({code}): {detail}")]
    AdvisorConnect { code: String, detail: String },
    #[error("pds: {0}")]
    Pds(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("crypto: {0}")]
    Crypto(#[from] crate::crypto::CryptoError),
    #[error("canonical: {0}")]
    Canonical(#[from] crate::canonical::CanonicalError),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, ProviderError>;
