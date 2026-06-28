//! Reads the OS-enforced code-signing identity of the **running** process.
//!
//! WS-CDHASH: the attestation must commit to what the kernel actually
//! enforces — the code-directory hash (cdhash) and the hardened-runtime
//! posture flags — not a whole-file digest an attacker could compute over a
//! tampered-but-unsigned binary. We read these live via `csops(2)` (the same
//! values `codesign -dvvv` reports and that the S3 spike proved match
//! byte-for-byte). `csops` is used rather than the `SecCode` CF APIs so this
//! stays dependency-free (only `libc`); the S3 Swift probe established the CF
//! path as an equivalent cross-check.
//!
//! Honest failure mode: on a non-macOS host, an unsigned binary, or any error,
//! we report `cd_hash = None`, posture flags `false`, and **`get_task_allow =
//! true`** — the unsafe default — so a missing measurement can never silently
//! earn the confidential tier.

/// OS-enforced signing identity + hardened-runtime posture of the running
/// process. Field meanings match the `dev.cocore.compute.attestation` lexicon.
#[derive(Debug, Clone)]
pub struct CodeSignInfo {
    /// Lowercase hex of the 20-byte code-directory hash the OS enforces —
    /// equals `codesign -dvvv`'s `CDHash=`. `None` if unsigned/unavailable.
    pub cd_hash: Option<String>,
    /// Apple Developer Team Identifier, when present.
    pub team_id: Option<String>,
    /// Hardened runtime (CS_RUNTIME).
    pub hardened_runtime: bool,
    /// Library validation enforced (CS_REQUIRE_LV).
    pub library_validation: bool,
    /// get-task-allow entitlement (CS_GET_TASK_ALLOW). MUST be false for
    /// the confidential tier.
    pub get_task_allow: bool,
}

impl Default for CodeSignInfo {
    fn default() -> Self {
        // Unsafe-by-default: an absent measurement reports the weakest posture.
        Self {
            cd_hash: None,
            team_id: None,
            hardened_runtime: false,
            library_validation: false,
            get_task_allow: true,
        }
    }
}

// Code-signing flags (xnu osfmk `cs_blobs.h`). Only the three the
// confidential posture depends on. macOS-only: they're consumed solely by the
// `imp` module below, which is itself `cfg(target_os = "macos")` — so on the
// Linux CI they'd be dead code and trip clippy's `-D warnings`.
#[cfg(target_os = "macos")]
const CS_GET_TASK_ALLOW: u32 = 0x0000_0004;
#[cfg(target_os = "macos")]
const CS_REQUIRE_LV: u32 = 0x0000_2000; // library validation
#[cfg(target_os = "macos")]
const CS_RUNTIME: u32 = 0x0001_0000; // hardened runtime

#[cfg(target_os = "macos")]
mod imp {
    use super::{CodeSignInfo, CS_GET_TASK_ALLOW, CS_REQUIRE_LV, CS_RUNTIME};

    // xnu `sys/codesign.h` operation selectors.
    const CS_OPS_STATUS: u32 = 0;
    const CS_OPS_CDHASH: u32 = 5;
    const CS_OPS_TEAMID: u32 = 14;
    const CS_CDHASH_LEN: usize = 20;

    extern "C" {
        // int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);
        fn csops(
            pid: libc::pid_t,
            ops: u32,
            useraddr: *mut libc::c_void,
            usersize: libc::size_t,
        ) -> libc::c_int;
    }

    pub fn read_self() -> CodeSignInfo {
        let pid = unsafe { libc::getpid() };
        let mut info = CodeSignInfo::default();

        // Status flags → posture booleans.
        let mut flags: u32 = 0;
        let rc = unsafe {
            csops(
                pid,
                CS_OPS_STATUS,
                &mut flags as *mut u32 as *mut libc::c_void,
                std::mem::size_of::<u32>(),
            )
        };
        if rc == 0 {
            info.hardened_runtime = flags & CS_RUNTIME != 0;
            info.library_validation = flags & CS_REQUIRE_LV != 0;
            info.get_task_allow = flags & CS_GET_TASK_ALLOW != 0;
        }

        // cdhash — exactly CS_CDHASH_LEN bytes or csops returns ERANGE.
        let mut cd = [0u8; CS_CDHASH_LEN];
        let rc = unsafe {
            csops(
                pid,
                CS_OPS_CDHASH,
                cd.as_mut_ptr() as *mut libc::c_void,
                CS_CDHASH_LEN,
            )
        };
        if rc == 0 {
            info.cd_hash = Some(hex::encode(cd));
        }

        // Team id — best effort. csops copies the NUL-terminated team
        // identifier; a generous buffer + trim handles the layout.
        let mut tid = [0u8; 256];
        let rc = unsafe {
            csops(
                pid,
                CS_OPS_TEAMID,
                tid.as_mut_ptr() as *mut libc::c_void,
                tid.len(),
            )
        };
        if rc == 0 {
            // The buffer holds the team id as a C string (sometimes preceded
            // by a small header on older kernels); take the longest printable
            // ASCII run, which is the team identifier.
            if let Some(s) = longest_ascii_run(&tid) {
                info.team_id = Some(s);
            }
        }

        info
    }

    /// Pick the longest run of printable ASCII from a raw csops team-id
    /// buffer — robust to a leading length/header byte or trailing NULs. A
    /// Team Identifier is 10 alphanumerics (e.g. `4L45P7CP9M`), so we require a
    /// plausible alphanumeric run to avoid returning stray bytes.
    fn longest_ascii_run(buf: &[u8]) -> Option<String> {
        let mut best: &[u8] = &[];
        let mut start = 0usize;
        for i in 0..=buf.len() {
            let printable = i < buf.len() && buf[i].is_ascii_graphic();
            if !printable {
                if i > start && i - start > best.len() {
                    best = &buf[start..i];
                }
                start = i + 1;
            }
        }
        if best.len() >= 8 && best.iter().all(|b| b.is_ascii_alphanumeric()) {
            Some(String::from_utf8_lossy(best).into_owned())
        } else {
            None
        }
    }
}

/// Linux binary self-measurement: SHA-256 of `/proc/self/exe` as the cd_hash
/// analogue. This is weaker than macOS csops(2) — the kernel doesn't enforce
/// signature policy, and an attacker with root can replace the binary — but it
/// gives the attestation path a content-addressed measurement of what's running.
///
/// Posture flags remain conservative:
/// - `hardened_runtime` and `library_validation` stay false (no kernel enforcement).
/// - `get_task_allow` reflects kernel lockdown mode: `false` only when lockdown
///   is `confidentiality` (ptrace, kprobes, /dev/mem all denied).
#[cfg(target_os = "linux")]
mod imp {
    use super::CodeSignInfo;
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::io::Read;

    pub fn read_self() -> CodeSignInfo {
        let mut info = CodeSignInfo::default();

        if let Some(hash) = sha256_proc_self_exe() {
            info.cd_hash = Some(hash);
        }

        info.get_task_allow = !kernel_lockdown_confidentiality();

        info
    }

    fn sha256_proc_self_exe() -> Option<String> {
        let mut f = fs::File::open("/proc/self/exe").ok()?;
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 8192];
        loop {
            let n = f.read(&mut buf).ok()?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Some(hex::encode(hasher.finalize()))
    }

    /// Kernel lockdown `confidentiality` mode denies ptrace attach, kprobes,
    /// /dev/mem, and module loading — the closest Linux analogue to macOS
    /// hardened runtime + library validation. We only report `true` at the
    /// strictest level; `integrity` (which still allows ptrace) is not enough.
    fn kernel_lockdown_confidentiality() -> bool {
        let Ok(content) = fs::read_to_string("/sys/kernel/security/lockdown") else {
            return false;
        };
        // Format: "none [integrity] confidentiality" — the active mode is in brackets.
        content.contains("[confidentiality]")
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod imp {
    use super::CodeSignInfo;
    pub fn read_self() -> CodeSignInfo {
        CodeSignInfo::default()
    }
}

/// Read the running process's OS-enforced code-signing identity + posture.
pub fn read_self() -> CodeSignInfo {
    imp::read_self()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_self_does_not_panic_and_is_honest_when_unsigned() {
        // The test binary is typically unsigned/ad-hoc under `cargo test`, so
        // we don't assert specific posture — only that the call is safe and the
        // defaults are the *unsafe* ones (so absence never reads as secure).
        let info = read_self();
        if info.cd_hash.is_none() {
            // No measurement → must not claim a hardened posture.
            assert!(!info.hardened_runtime);
            assert!(!info.library_validation);
        }
        // cd_hash, when present, is lowercase hex:
        //   macOS: 40 chars (20-byte cdhash from csops)
        //   Linux: 64 chars (32-byte SHA-256 of /proc/self/exe)
        if let Some(h) = &info.cd_hash {
            assert!(h.len() == 40 || h.len() == 64, "unexpected hash length {}", h.len());
            assert!(h.bytes().all(|b| b.is_ascii_hexdigit()));
        }
    }
}
