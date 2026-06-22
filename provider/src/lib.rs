//! cocore — hardened compute provider agent. The user-facing
//! binary is `cocore` (with the `agent` subcommand group);
//! the Cargo crate name stays `cocore-provider` for
//! backward-compatible imports.
//!
//! Layered modules, intended to be navigable in this order:
//!
//!   security        — process hardening, runs before anything else
//!   crypto          — X25519 keypair + NaCl-compatible encryption
//!   secure_enclave  — Secure-Enclave-bound P-256 signing identity
//!   canonical       — sorted-key JSON serializer (sig stability)
//!   attestation     — builds and signs attestation records
//!   protocol        — wire types for advisor ↔ provider WebSocket
//!   advisor         — outbound WebSocket client
//!   oauth           — device-pair code flow, session storage
//!   pds             — publishes records via com.atproto.repo.applyWrites

pub mod advisor;
pub mod attestation;
pub mod canonical;
pub mod codesign;
pub mod crypto;
pub mod diagnostics;
pub mod engines;
pub mod error;
pub mod hypervisor;
// `inference` (the PyO3 Python-sandbox module) was removed in v0.6.0
// alongside the rest of the in-process Python design. See
// `engines::subprocess` for the replacement (out-of-process Python via
// uvicorn-on-UDS).
pub mod appattest;
pub mod mda;
pub mod mda_loader;
pub mod oauth;
pub mod pds;
pub mod pricing;
pub mod protocol;
/// APNs push host (confidential-tier code identity). macOS + `apns` only; the
/// security-critical crypto lives in `advisor` and is tested cross-platform.
#[cfg(all(target_os = "macos", feature = "apns"))]
pub mod push_host;
pub mod receipt;
pub mod schedule;
pub mod secure_enclave;
pub mod security;
pub mod system_profile;
