//! Process hardening for the provider agent.
//!
//! These are best-effort, defense-in-depth controls. None of them is a
//! substitute for the hardware attestation chain — but together they make
//! casual tampering by the machine owner significantly harder.
//!
//! All of these apply to the *current* process; they cannot un-harden a
//! parent. Call [`apply_all`] as the very first thing in `main`, before
//! any allocation, before logging is set up.
//!
//! macOS-specific controls are gated behind `cfg(target_os = "macos")`;
//! on other platforms most of these become no-ops so the agent can still
//! be built and unit-tested in CI.

use anyhow::{Context, Result};
use std::sync::atomic::{AtomicBool, Ordering};

/// Set once [`apply_all`] has successfully installed every hardening control.
/// Read by the attestation producer via [`posture`] to report honest
/// capability flags (`antiDebug` / `coreDumpsDisabled` / `envScrubbed`).
static HARDENED: AtomicBool = AtomicBool::new(false);

/// Which startup hardening controls are in force. The attestation producer
/// turns these into the darkbloom-parity capability flags a confidential
/// verifier requires; they read `true` only after [`apply_all`] has fully
/// succeeded, so an un-hardened process can never claim them.
#[derive(Debug, Clone, Copy, Default)]
pub struct HardeningPosture {
    pub anti_debug: bool,
    pub core_dumps_disabled: bool,
    pub env_scrubbed: bool,
}

/// Snapshot the hardening posture for attestation. Honest: every flag is
/// `false` until `apply_all` has run to completion, and `anti_debug` is only
/// claimed when the OS actually denies attach:
///
/// - **macOS**: `PT_DENY_ATTACH` denies `task_for_pid` — always claimed.
/// - **Linux**: only when Yama LSM `ptrace_scope >= 2` (no attach except
///   for root with `CAP_SYS_PTRACE`). `PR_SET_DUMPABLE(0)` alone is not
///   enough — it only blocks non-ancestor tracers and is easily re-enabled.
pub fn posture() -> HardeningPosture {
    let on = HARDENED.load(Ordering::SeqCst);
    HardeningPosture {
        anti_debug: on && anti_debug_effective(),
        core_dumps_disabled: on,
        env_scrubbed: on,
    }
}

fn anti_debug_effective() -> bool {
    #[cfg(target_os = "macos")]
    {
        return true;
    }
    #[cfg(target_os = "linux")]
    {
        return yama_ptrace_scope_ge2();
    }
    #[allow(unreachable_code)]
    false
}

/// Yama LSM ptrace_scope >=2 means only processes with CAP_SYS_PTRACE can
/// attach — PR_SET_DUMPABLE(0) on top of that gives us a genuinely defended
/// process. We do not claim anti_debug at scope 0/1 because an unprivileged
/// user could still attach there.
#[cfg(target_os = "linux")]
fn yama_ptrace_scope_ge2() -> bool {
    std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .is_some_and(|v| v >= 2)
}

/// Apply every available hardening control. Returns the first error
/// encountered; callers MUST treat any error as fatal.
///
/// Order is load-bearing: PT_DENY_ATTACH first (kernel-level), then
/// the rlimit + Python pre-init knobs that have to be set before any
/// dynamic-linker or interpreter activity, then the env scrub that
/// removes the noisy ways someone could influence those subsystems,
/// then the SIP recheck that the rest of the program leans on.
pub fn apply_all() -> Result<()> {
    deny_debugger().context("PT_DENY_ATTACH")?;
    disable_core_dumps().context("RLIMIT_CORE")?;
    isolate_python_preinit();
    scrub_environment();
    #[cfg(target_os = "macos")]
    require_sip_enabled().context("SIP")?;
    HARDENED.store(true, Ordering::SeqCst);
    Ok(())
}

/// Refuse `ptrace` attachment from any other process, including the user.
/// On macOS this is the canonical way; on Linux we set `PR_SET_DUMPABLE`
/// to 0 which has a similar (but weaker) effect.
fn deny_debugger() -> Result<()> {
    #[cfg(target_os = "macos")]
    unsafe {
        // PT_DENY_ATTACH = 31. The kernel will deliver SIGSEGV to any
        // process that tries to attach after this point.
        const PT_DENY_ATTACH: libc::c_int = 31;
        let rc = libc::ptrace(PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0);
        if rc != 0 {
            anyhow::bail!("ptrace(PT_DENY_ATTACH) returned {}", rc);
        }
    }
    #[cfg(target_os = "linux")]
    unsafe {
        // PR_SET_DUMPABLE = 4, value 0 = SUID_DUMP_DISABLE.
        if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
            anyhow::bail!("prctl(PR_SET_DUMPABLE, 0) failed");
        }
    }
    Ok(())
}

/// Setting RLIMIT_CORE = 0 prevents the kernel from writing a coredump on
/// crash, so decrypted plaintext that lived in our address space cannot
/// leak to disk after a fault.
fn disable_core_dumps() -> Result<()> {
    let zero = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &zero) };
    if rc != 0 {
        anyhow::bail!("setrlimit(RLIMIT_CORE, 0) failed");
    }
    Ok(())
}

/// Set Python isolation env vars *before* PyO3 is initialised by the
/// `inference` feature. PYTHONNOUSERSITE prevents `~/.local/lib/...`
/// from joining sys.path; PYTHONDONTWRITEBYTECODE prevents
/// `__pycache__/` writes anywhere. Both close ways the machine owner
/// could influence the in-process interpreter without showing up in
/// the binary hash.
///
/// Harmless when the `inference` feature is off — Python never
/// loads — and load-bearing the moment it flips on.
fn isolate_python_preinit() {
    std::env::set_var("PYTHONNOUSERSITE", "1");
    std::env::set_var("PYTHONDONTWRITEBYTECODE", "1");
}

/// Remove environment variables that influence dynamic linker behaviour
/// or Python module loading. We do this after [`isolate_python_preinit`]
/// so the *positive* isolation flags above stay set while the
/// *attacker-controlled* hooks below are torn down.
fn scrub_environment() {
    const POISON: &[&str] = &[
        // dynamic linker
        "DYLD_INSERT_LIBRARIES",
        "DYLD_FORCE_FLAT_NAMESPACE",
        "DYLD_LIBRARY_PATH",
        "DYLD_FALLBACK_LIBRARY_PATH",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
        // Python
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTHONSTARTUP",
        "PYTHONOPTIMIZE",
        // misc tracing
        "MallocStackLogging",
        "MallocStackLoggingNoCompact",
    ];
    for var in POISON {
        std::env::remove_var(var);
    }
}

/// On macOS, SIP must be enabled. Disabling SIP requires a reboot, which
/// would terminate this process — so observing SIP enabled here is a
/// proof that SIP was enabled at startup *and remains enabled*.
#[cfg(target_os = "macos")]
fn require_sip_enabled() -> Result<()> {
    let output = std::process::Command::new("/usr/bin/csrutil")
        .arg("status")
        .output()
        .context("running csrutil status")?;
    if !output.status.success() {
        anyhow::bail!(
            "csrutil status exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let stdout = String::from_utf8_lossy(&output.stdout).to_lowercase();
    if !stdout.contains("enabled") || stdout.contains("disabled") {
        anyhow::bail!(
            "System Integrity Protection is not enabled (csrutil reports: {})",
            stdout.trim()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrub_clears_known_vars() {
        std::env::set_var("LD_PRELOAD", "/tmp/evil.so");
        std::env::set_var("PYTHONPATH", "/tmp/evil");
        scrub_environment();
        assert!(std::env::var("LD_PRELOAD").is_err());
        assert!(std::env::var("PYTHONPATH").is_err());
    }

    #[test]
    fn isolate_python_preinit_sets_positive_flags() {
        std::env::remove_var("PYTHONNOUSERSITE");
        std::env::remove_var("PYTHONDONTWRITEBYTECODE");
        isolate_python_preinit();
        assert_eq!(std::env::var("PYTHONNOUSERSITE").unwrap(), "1");
        assert_eq!(std::env::var("PYTHONDONTWRITEBYTECODE").unwrap(), "1");
    }

    #[test]
    fn isolate_then_scrub_preserves_isolation_flags() {
        // Re-run the production order and confirm the positive flags
        // survive the scrub pass — the scrub list deliberately does
        // not include PYTHONNOUSERSITE / PYTHONDONTWRITEBYTECODE.
        isolate_python_preinit();
        scrub_environment();
        assert_eq!(std::env::var("PYTHONNOUSERSITE").unwrap(), "1");
        assert_eq!(std::env::var("PYTHONDONTWRITEBYTECODE").unwrap(), "1");
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn disable_core_dumps_is_idempotent() {
        disable_core_dumps().unwrap();
        disable_core_dumps().unwrap();
    }
}
