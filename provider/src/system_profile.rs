//! Real machine telemetry for the `dev.cocore.compute.provider` record.
//!
//! Matchmakers route inference work by hardware, so `serve` publishes real
//! values (chip + RAM are the load-bearing ones). Collection is
//! platform-specific:
//!
//!   * **macOS / Apple Silicon** — `sysctl`, `system_profiler`, `sw_vers`.
//!   * **Linux** — `/proc/meminfo`, `/proc/cpuinfo`, `/etc/os-release`,
//!     `std::thread::available_parallelism`.
//!
//! Every individual probe is independently fallible; a failure on any one
//! leaves that field at its `None` / fallback value rather than failing the
//! whole collect — partial data beats no data.

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

fn hostname() -> Option<String> {
    let out = std::process::Command::new("hostname").output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

// ─────────────────────────── macOS ───────────────────────────

#[cfg(target_os = "macos")]
pub fn collect() -> SystemProfile {
    use std::process::Command;

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

#[cfg(target_os = "macos")]
fn sysctl(key: &str) -> Option<String> {
    let out = std::process::Command::new("sysctl")
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
    let out = std::process::Command::new("system_profiler")
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
    let out = std::process::Command::new("sw_vers")
        .arg("-productVersion")
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Memory-bandwidth lookup keyed by chip-family substring. Apple
/// publishes these specs but doesn't expose them via sysctl.
/// Conservative values from public spec sheets — order matters
/// (Pro/Max/Ultra checked before bare M\d).
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

#[cfg(target_os = "linux")]
pub fn collect() -> SystemProfile {
    let chip = linux::cpu_model().unwrap_or_else(|| "unknown".to_string());
    let ram_gb = linux::total_ram_gb();
    let cpu_cores = std::thread::available_parallelism()
        .ok()
        .map(|n| n.get() as u32);
    let gpu_cores = linux::nvidia_gpu_count();
    let model_identifier = linux::product_name();
    let os = linux::os_pretty_name().map(|v| format!("Linux {v}"));

    SystemProfile {
        machine_label: machine_label("Linux host"),
        chip,
        ram_gb,
        cpu_cores,
        p_cores: None,
        e_cores: None,
        gpu_cores,
        memory_bandwidth_gbs: None,
        model_identifier,
        os,
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs;

    /// First `model name` line from `/proc/cpuinfo`.
    pub fn cpu_model() -> Option<String> {
        let info = fs::read_to_string("/proc/cpuinfo").ok()?;
        for line in info.lines() {
            if let Some(rest) = line.strip_prefix("model name") {
                let val = rest.trim_start_matches(|c: char| c == ':' || c.is_whitespace());
                if !val.is_empty() {
                    return Some(val.to_string());
                }
            }
        }
        None
    }

    /// `MemTotal` from `/proc/meminfo`, rounded to whole GB.
    pub fn total_ram_gb() -> u32 {
        let Ok(info) = fs::read_to_string("/proc/meminfo") else {
            return 0;
        };
        for line in info.lines() {
            if let Some(rest) = line.strip_prefix("MemTotal:") {
                let kb_str: String = rest.chars().filter(|c| c.is_ascii_digit()).collect();
                if let Ok(kb) = kb_str.parse::<u64>() {
                    return (kb / (1024 * 1024)) as u32;
                }
            }
        }
        0
    }

    /// Count of NVIDIA GPUs visible via `/proc/driver/nvidia/gpus/`.
    /// Returns `None` when the nvidia driver isn't loaded (the directory
    /// won't exist), not `Some(0)`, matching the macOS semantics of
    /// "couldn't read the data."
    pub fn nvidia_gpu_count() -> Option<u32> {
        let entries = fs::read_dir("/proc/driver/nvidia/gpus/").ok()?;
        let count = entries.filter(|e| e.is_ok()).count();
        if count > 0 {
            Some(count as u32)
        } else {
            None
        }
    }

    /// `PRETTY_NAME` from `/etc/os-release`.
    pub fn os_pretty_name() -> Option<String> {
        let content = fs::read_to_string("/etc/os-release").ok()?;
        for line in content.lines() {
            if let Some(rest) = line.strip_prefix("PRETTY_NAME=") {
                return Some(rest.trim_matches('"').to_string());
            }
        }
        None
    }

    /// DMI product name (e.g. `"PowerEdge R750"`, `"ThinkPad T14s"`).
    pub fn product_name() -> Option<String> {
        fs::read_to_string("/sys/class/dmi/id/product_name")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }
}

// ───────────────────── fallback (other OSes) ─────────────────

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn collect() -> SystemProfile {
    SystemProfile {
        machine_label: machine_label("unknown host"),
        chip: "unknown".to_string(),
        ram_gb: 0,
        cpu_cores: None,
        p_cores: None,
        e_cores: None,
        gpu_cores: None,
        memory_bandwidth_gbs: None,
        model_identifier: None,
        os: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "macos")]
    #[test]
    fn bandwidth_table_picks_specific_before_base() {
        assert_eq!(bandwidth_for_chip("Apple M3 Max"), Some(400));
        assert_eq!(bandwidth_for_chip("Apple M3 Pro"), Some(150));
        assert_eq!(bandwidth_for_chip("Apple M3"), Some(100));
        assert_eq!(bandwidth_for_chip("Apple M1 Max"), Some(400));
        assert_eq!(bandwidth_for_chip("Apple M1 Pro"), Some(200));
        assert_eq!(bandwidth_for_chip("Apple M1"), Some(68));
        assert_eq!(bandwidth_for_chip("Apple M4 Pro"), Some(273));
        assert_eq!(bandwidth_for_chip("Apple M2 Ultra"), Some(800));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn bandwidth_returns_none_for_unknown_chip() {
        assert_eq!(bandwidth_for_chip("Intel Core i9"), None);
        assert_eq!(bandwidth_for_chip(""), None);
        assert_eq!(bandwidth_for_chip("unknown"), None);
    }

    #[test]
    fn collect_returns_plausible_data() {
        let p = collect();
        assert!(!p.chip.is_empty());
        assert!(p.ram_gb < 4096);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_ram_is_nonzero() {
        assert!(
            linux::total_ram_gb() > 0,
            "/proc/meminfo should be readable"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_cpu_model_is_populated() {
        assert!(
            linux::cpu_model().is_some(),
            "/proc/cpuinfo should have a model name"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_os_pretty_name_is_populated() {
        assert!(
            linux::os_pretty_name().is_some(),
            "/etc/os-release should have PRETTY_NAME"
        );
    }
}
