//! Real machine telemetry for the `dev.cocore.compute.provider` record.
//!
//! Matchmakers route inference work by hardware, so `serve` publishes real
//! values (chip + RAM are the load-bearing ones). Collection is
//! platform-specific:
//!
//!   * **macOS / Apple Silicon** — `sysctl`, `system_profiler`, `sw_vers`.
//!   * **Linux** (the OpenAI-endpoint provider path) — `/proc/meminfo`,
//!     `/proc/cpuinfo`, `/etc/os-release`, `available_parallelism`.
//!
//! Every individual probe is independently fallible; a failure on any one
//! leaves that field at its `None` / fallback value rather than failing the
//! whole collect — partial data beats no data.

#[cfg(target_os = "macos")]
use std::process::Command;

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemProfile {
    pub machine_label: String,
    pub chip: String,
    pub ram_gb: u32,
    pub cpu_cores: Option<u32>,
    pub p_cores: Option<u32>,
    pub e_cores: Option<u32>,
    pub gpu_cores: Option<u32>,
    pub memory_bandwidth_gbs: Option<u32>,
    pub model_identifier: Option<String>,
    pub os: Option<String>,
}

/// Owner-chosen display name (`COCORE_MACHINE_LABEL`, set during setup) wins
/// over the system hostname, so a provider isn't forced to expose their
/// `.local` host name. Falls back to the hostname, then a generic label.
fn machine_label(fallback: &str) -> String {
    std::env::var("COCORE_MACHINE_LABEL")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(hostname)
        .unwrap_or_else(|| fallback.to_string())
}

// ─────────────────────────── macOS ───────────────────────────

/// Probe the host for a `SystemProfile`. Best-effort: any individual probe
/// failure leaves that field at its `None` / fallback value.
#[cfg(target_os = "macos")]
pub fn collect() -> SystemProfile {
    let chip = sysctl("machdep.cpu.brand_string").unwrap_or_else(|| "unknown".to_string());
    let ram_gb = sysctl("hw.memsize")
        .and_then(|s| s.parse::<u64>().ok())
        .map(|bytes| (bytes / (1024 * 1024 * 1024)) as u32)
        .unwrap_or(0);
    let cpu_cores = sysctl_u32("hw.ncpu");
    let p_cores = sysctl_u32("hw.perflevel0.physicalcpu");
    let e_cores = sysctl_u32("hw.perflevel1.physicalcpu");
    let gpu_cores = parse_gpu_cores();
    let memory_bandwidth_gbs = bandwidth_for_chip(&chip);
    let model_identifier = sysctl("hw.model");
    let os = sw_vers_product_version().map(|v| format!("macOS {v}"));

    SystemProfile {
        machine_label: machine_label("macOS host"),
        chip,
        ram_gb,
        cpu_cores,
        p_cores,
        e_cores,
        gpu_cores,
        memory_bandwidth_gbs,
        model_identifier,
        os,
    }
}

// Absolute paths for the probe binaries: `sysctl`, `system_profiler`, and
// `ioreg` live under /usr/sbin, which execvp's FALLBACK path (used when a
// parent spawns us with no PATH at all) does not include. The tray shelled
// `cocore agent diag` with a stripped env for a while, and every probe here
// silently returned None — bundles reported chip "unknown" / 0 GB RAM
// (ticket br_23e56917). These paths are stable on every macOS.
#[cfg(target_os = "macos")]
fn sysctl(key: &str) -> Option<String> {
    let out = Command::new("/usr/sbin/sysctl")
        .arg("-n")
        .arg(key)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

#[cfg(target_os = "macos")]
fn sysctl_u32(key: &str) -> Option<u32> {
    sysctl(key).and_then(|s| s.parse::<u32>().ok())
}

#[cfg(target_os = "macos")]
fn parse_gpu_cores() -> Option<u32> {
    // `system_profiler -json SPDisplaysDataType` returns an array of
    // GPU entries. Apple Silicon integrated GPUs carry an
    // `sppci_cores` field; we take the first one we find.
    let out = Command::new("/usr/sbin/system_profiler")
        .arg("-json")
        .arg("SPDisplaysDataType")
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;
    let displays = v.get("SPDisplaysDataType")?.as_array()?;
    for d in displays {
        if let Some(cores) = d.get("sppci_cores").and_then(|c| c.as_str()) {
            if let Ok(n) = cores.parse::<u32>() {
                return Some(n);
            }
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn sw_vers_product_version() -> Option<String> {
    let out = Command::new("/usr/bin/sw_vers")
        .arg("-productVersion")
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Memory-bandwidth lookup keyed by chip-family substring. Apple publishes
/// these specs but doesn't expose them via sysctl. Conservative values from
/// public spec sheets — order matters (Pro/Max/Ultra checked before bare M\d).
#[cfg(target_os = "macos")]
fn bandwidth_for_chip(chip: &str) -> Option<u32> {
    let lower = chip.to_lowercase();
    // M4 family
    if lower.contains("m4 max") {
        return Some(546);
    }
    if lower.contains("m4 pro") {
        return Some(273);
    }
    if lower.contains("m4") {
        return Some(120);
    }
    // M3 family
    if lower.contains("m3 ultra") {
        return Some(800);
    }
    if lower.contains("m3 max") {
        return Some(400);
    }
    if lower.contains("m3 pro") {
        return Some(150);
    }
    if lower.contains("m3") {
        return Some(100);
    }
    // M2 family
    if lower.contains("m2 ultra") {
        return Some(800);
    }
    if lower.contains("m2 max") {
        return Some(400);
    }
    if lower.contains("m2 pro") {
        return Some(200);
    }
    if lower.contains("m2") {
        return Some(100);
    }
    // M1 family
    if lower.contains("m1 ultra") {
        return Some(800);
    }
    if lower.contains("m1 max") {
        return Some(400);
    }
    if lower.contains("m1 pro") {
        return Some(200);
    }
    if lower.contains("m1") {
        return Some(68);
    }
    None
}

// ─────────────────────────── Linux ───────────────────────────

/// Probe a Linux host (the OpenAI-endpoint provider path). Apple-only fields
/// (`gpu_cores`, `p_cores`, `e_cores`, `model_identifier`) stay `None` — the
/// provider lexicon treats them as optional, and honest absence beats
/// fabricating Apple-shaped numbers.
#[cfg(target_os = "linux")]
pub fn collect() -> SystemProfile {
    let chip = read_to_string("/proc/cpuinfo")
        .and_then(|c| parse_cpuinfo_model(&c))
        .unwrap_or_else(|| "unknown".to_string());
    let ram_gb = read_to_string("/proc/meminfo")
        .and_then(|c| parse_meminfo_total_kb(&c))
        .map(|kb| (kb / (1024 * 1024)) as u32)
        .unwrap_or(0);
    let cpu_cores = std::thread::available_parallelism()
        .ok()
        .map(|n| n.get() as u32);
    let os = read_to_string("/etc/os-release").and_then(|c| parse_os_release_pretty(&c));

    SystemProfile {
        machine_label: machine_label("linux host"),
        chip,
        ram_gb,
        cpu_cores,
        p_cores: None,
        e_cores: None,
        gpu_cores: None,
        memory_bandwidth_gbs: None,
        model_identifier: None,
        os,
    }
}

/// `std::fs::read_to_string` that swallows errors into `None`, so a missing
/// or unreadable `/proc` entry leaves its field at the fallback rather than
/// failing the whole collect.
#[cfg(target_os = "linux")]
fn read_to_string(path: &str) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

/// Total RAM in kB from `/proc/meminfo`'s `MemTotal:` line.
#[cfg(target_os = "linux")]
fn parse_meminfo_total_kb(contents: &str) -> Option<u64> {
    for line in contents.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            // Format: `MemTotal:       131981312 kB`
            return rest.split_whitespace().next()?.parse::<u64>().ok();
        }
    }
    None
}

/// CPU brand string from `/proc/cpuinfo`. x86 reports it as `model name`;
/// some ARM kernels use `Model` / `Hardware` instead, so we fall back through
/// those. Returns the first non-empty match.
#[cfg(target_os = "linux")]
fn parse_cpuinfo_model(contents: &str) -> Option<String> {
    for key in ["model name", "Model", "Hardware"] {
        for line in contents.lines() {
            if let Some((k, v)) = line.split_once(':') {
                if k.trim() == key {
                    let v = v.trim();
                    if !v.is_empty() {
                        return Some(v.to_string());
                    }
                }
            }
        }
    }
    None
}

/// `PRETTY_NAME` from `/etc/os-release` (e.g. `Ubuntu 24.04.1 LTS`), with the
/// surrounding quotes stripped.
#[cfg(target_os = "linux")]
fn parse_os_release_pretty(contents: &str) -> Option<String> {
    for line in contents.lines() {
        if let Some(rest) = line.strip_prefix("PRETTY_NAME=") {
            return Some(rest.trim().trim_matches('"').to_string());
        }
    }
    None
}

// ─────────────────────── other platforms ───────────────────────

/// Fallback for platforms that are neither macOS nor Linux. The agent only
/// ships on those two, but keeping `collect()` defined everywhere lets the
/// crate build (and unit-test the pure parsers) on any dev host.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn collect() -> SystemProfile {
    SystemProfile {
        machine_label: machine_label("host"),
        chip: "unknown".to_string(),
        ram_gb: 0,
        cpu_cores: std::thread::available_parallelism()
            .ok()
            .map(|n| n.get() as u32),
        p_cores: None,
        e_cores: None,
        gpu_cores: None,
        memory_bandwidth_gbs: None,
        model_identifier: None,
        os: None,
    }
}

// ─────────────────────────── shared ───────────────────────────

/// Get the system hostname. On Linux, read directly from the kernel rather
/// than shelling out — no dependency on a `hostname` binary being installed.
#[cfg(target_os = "linux")]
fn hostname() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// On macOS, shell out to `hostname`.
#[cfg(target_os = "macos")]
fn hostname() -> Option<String> {
    let out = Command::new("hostname").output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Fallback for other platforms.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn hostname() -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "macos")]
    mod macos {
        use super::*;

        #[test]
        fn bandwidth_table_picks_specific_before_base() {
            assert_eq!(bandwidth_for_chip("Apple M3 Max"), Some(400));
            assert_eq!(bandwidth_for_chip("Apple M3 Pro"), Some(150));
            assert_eq!(bandwidth_for_chip("Apple M3"), Some(100));
            assert_eq!(bandwidth_for_chip("Apple M1"), Some(68));
            assert_eq!(bandwidth_for_chip("Apple M4 Pro"), Some(273));
            assert_eq!(bandwidth_for_chip("Apple M2 Ultra"), Some(800));
        }

        #[test]
        fn bandwidth_returns_none_for_unknown_chip() {
            assert_eq!(bandwidth_for_chip("Intel Core i9"), None);
            assert_eq!(bandwidth_for_chip(""), None);
        }
    }

    #[cfg(target_os = "linux")]
    mod linux {
        use super::*;

        #[test]
        fn parses_memtotal_to_kb() {
            let meminfo = "MemTotal:       131981312 kB\nMemFree:        1000 kB\n";
            assert_eq!(parse_meminfo_total_kb(meminfo), Some(131_981_312));
            assert_eq!((131_981_312u64 / (1024 * 1024)) as u32, 125);
        }

        #[test]
        fn memtotal_absent_is_none() {
            assert_eq!(parse_meminfo_total_kb("MemFree: 1000 kB\n"), None);
        }

        #[test]
        fn parses_cpuinfo_model_name() {
            let cpuinfo = "processor\t: 0\nvendor_id\t: AuthenticAMD\n\
                           model name\t: AMD Ryzen AI Max+ 395 w/ Radeon 8060S\n";
            assert_eq!(
                parse_cpuinfo_model(cpuinfo).as_deref(),
                Some("AMD Ryzen AI Max+ 395 w/ Radeon 8060S")
            );
        }

        #[test]
        fn cpuinfo_falls_back_to_arm_fields() {
            let cpuinfo = "processor\t: 0\nBogoMIPS\t: 108.00\nModel\t: Raspberry Pi 5\n";
            assert_eq!(
                parse_cpuinfo_model(cpuinfo).as_deref(),
                Some("Raspberry Pi 5")
            );
        }

        #[test]
        fn parses_pretty_name_unquoted() {
            let osr = "NAME=\"Ubuntu\"\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nID=ubuntu\n";
            assert_eq!(
                parse_os_release_pretty(osr).as_deref(),
                Some("Ubuntu 24.04.1 LTS")
            );
        }
    }

    #[test]
    fn collect_returns_plausible_data() {
        // Platform-agnostic: the probe must not panic, the chip is always at
        // least "unknown" (non-empty), and RAM is a sane magnitude.
        let p = collect();
        assert!(!p.chip.is_empty());
        assert!(p.ram_gb < 4096); // sanity: nobody has >4 TB
    }
}
