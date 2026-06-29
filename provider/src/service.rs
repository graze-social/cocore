//! Linux systemd user-service control — the parity counterpart to the macOS
//! launchctl/plist surface used by `models_cli`, `doctor`, `update`, and the
//! pair flow in `main`.
//!
//! cocore runs on Linux as a systemd **user** unit, mirroring the per-user,
//! no-root macOS LaunchAgent (`gui/<uid>/dev.cocore.provider`). The install
//! script writes the unit `cocore-provider.service` and an `EnvironmentFile`
//! at `~/.cocore/provider.env` holding the **static** config
//! (`COCORE_LLAMA_SERVER_BIN`, `COCORE_ADVISOR`, `COCORE_CONSOLE`,
//! `COCORE_LOG`). The **dynamic** model set is NOT stored here — it flows
//! through the PDS `desiredModels` field (the source of truth, invariant #1),
//! which the serve loop reconciles into `COCORE_INFERENCE_MODELS` at startup
//! (`inference_models_action`), exactly as the website model picker drives
//! macOS. So a model change is a PDS write + a service restart — there is no
//! local model list to edit, unlike the macOS plist.
//!
//! Every call degrades gracefully: if `systemctl` is absent or the unit isn't
//! installed (the operator runs the agent some other way), the helpers report
//! that so callers can print a manual hint instead of failing.

use std::process::{Command, Stdio};

/// The systemd user unit the install script writes.
pub const UNIT: &str = "cocore-provider.service";

/// True when `systemctl --user` knows this unit (its unit file exists).
/// `systemctl --user cat` exits 0 iff the unit is loadable.
fn unit_installed() -> bool {
    Command::new("systemctl")
        .args(["--user", "cat", UNIT])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Restart the user unit if it's installed. Returns `true` when a restart was
/// issued and succeeded, `false` when `systemctl`/the unit isn't present (the
/// caller prints a manual hint) or the restart failed. The macOS analogue is
/// `launchctl kickstart -k`.
pub fn restart_if_installed() -> bool {
    if !unit_installed() {
        return false;
    }
    Command::new("systemctl")
        .args(["--user", "restart", UNIT])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// `(is_active, raw_state)` for `doctor`. `None` when `systemctl`/the unit
/// isn't installed. `raw_state` is systemd's word: `active`, `inactive`,
/// `failed`, `activating`, … The macOS analogue is parsing `launchctl print`'s
/// `state =` line.
pub fn active_state() -> Option<(bool, String)> {
    if !unit_installed() {
        return None;
    }
    // `is-active` exits non-zero for inactive/failed, but still prints the
    // state word to stdout, so read stdout rather than the exit status.
    let out = Command::new("systemctl")
        .args(["--user", "is-active", UNIT])
        .output()
        .ok()?;
    let state = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let state = if state.is_empty() {
        "unknown".to_string()
    } else {
        state
    };
    Some((state == "active", state))
}
