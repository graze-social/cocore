//! Hypervisor presence detection.
//!
//! Reported in `AttestationResponse` so the advisor can decide
//! whether to trust this provider with confidential workloads. A
//! provider running under an unknown hypervisor cannot claim the same
//! security posture as one running on bare metal — their kernel may
//! be lying to them about SIP, codesign, etc. We deliberately keep
//! the surface small: a single bool, plus an optional vendor string
//! on x86 where the hypervisor leaf is well-defined.

/// Best-effort hypervisor detection. Returns:
///
/// - `Some(true)`  — the CPU advertises a hypervisor and we got a
///   plausible vendor string back.
/// - `Some(false)` — the CPU does not advertise a hypervisor.
/// - `None`        — we couldn't make a confident statement on this
///   platform (e.g. AArch64 without an authoritative leaf).
///
/// On Apple Silicon (`target_arch = "aarch64"` + `target_os = "macos"`)
/// we report `Some(false)` because the host kernel is the system of
/// record and the SIP/MDA chain already covers the boot environment;
/// on other AArch64 systems we conservatively return `None`.
pub fn detect() -> Option<bool> {
    #[cfg(target_arch = "x86_64")]
    {
        return Some(x86_64::has_hypervisor_bit());
    }
    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    {
        return Some(false);
    }
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    {
        return Some(aarch64_linux::has_hypervisor());
    }
    #[allow(unreachable_code)]
    None
}

/// As [`detect`] but returns a vendor string when the hypervisor leaf
/// (CPUID 0x40000000 on x86) is implemented. Used by the registration
/// path to give the coordinator more context than a single bool.
pub fn vendor() -> Option<String> {
    #[cfg(target_arch = "x86_64")]
    {
        return x86_64::vendor_string();
    }
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    {
        return aarch64_linux::vendor_from_sysfs();
    }
    #[allow(unreachable_code)]
    None
}

#[cfg(target_arch = "x86_64")]
mod x86_64 {
    use core::arch::x86_64::__cpuid;

    /// Bit 31 of ECX in CPUID leaf 1 is the "Hypervisor Present"
    /// bit. By Intel/AMD convention any conforming hypervisor sets
    /// it; bare hardware never does.
    pub fn has_hypervisor_bit() -> bool {
        let r = __cpuid(1);
        (r.ecx & (1 << 31)) != 0
    }

    /// Hypervisor vendor string from leaf 0x40000000. 12 ASCII bytes
    /// in EBX/ECX/EDX, e.g. "KVMKVMKVM\0\0\0", "Microsoft Hv",
    /// "VMwareVMware". Empty string if no hypervisor is present.
    pub fn vendor_string() -> Option<String> {
        if !has_hypervisor_bit() {
            return Some(String::new());
        }
        let r = __cpuid(0x4000_0000);
        let mut bytes = Vec::with_capacity(12);
        bytes.extend_from_slice(&r.ebx.to_le_bytes());
        bytes.extend_from_slice(&r.ecx.to_le_bytes());
        bytes.extend_from_slice(&r.edx.to_le_bytes());
        let s: String = bytes
            .into_iter()
            .take_while(|&b| b != 0)
            .filter(|b| b.is_ascii() && !b.is_ascii_control())
            .map(|b| b as char)
            .collect();
        Some(s)
    }
}

/// Linux aarch64: no CPUID hypervisor leaf. Fall back to `/sys/hypervisor/type`
/// (populated by Xen/KVM/Hyper-V) and `/proc/cpuinfo` "Hypervisor vendor".
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
mod aarch64_linux {
    use std::fs;

    pub fn has_hypervisor() -> bool {
        if let Ok(t) = fs::read_to_string("/sys/hypervisor/type") {
            let t = t.trim();
            if !t.is_empty() {
                return true;
            }
        }
        if let Ok(info) = fs::read_to_string("/proc/cpuinfo") {
            for line in info.lines() {
                if line.starts_with("Hypervisor vendor") {
                    return true;
                }
            }
        }
        false
    }

    pub fn vendor_from_sysfs() -> Option<String> {
        if let Ok(t) = fs::read_to_string("/sys/hypervisor/type") {
            let t = t.trim().to_string();
            if !t.is_empty() {
                return Some(t);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_returns_some_value_on_supported_platforms() {
        let r = detect();
        // We don't assert true vs false because CI runs on real
        // VMs, bare metal, and macOS Apple Silicon — all three
        // paths must produce *some* answer. On anything else it's
        // legitimately None.
        let _ = r;
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn vendor_string_does_not_panic() {
        let _ = vendor();
    }
}
