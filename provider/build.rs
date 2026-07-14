//! Build-time provenance.
//!
//! Embeds the git commit and build profile into the binary as
//! compile-time env vars so `cocore agent doctor`, the panic file, and
//! the crash-signature heartbeat can report exactly which build is
//! running. Crash reports that don't carry a build identity are nearly
//! useless across a fleet on mixed versions — this closes that gap with
//! zero runtime cost.
//!
//! Everything here is best-effort: a source tree built outside git (a
//! release tarball, a vendored checkout) still compiles, just with
//! `unknown` for the sha.

use std::process::Command;

fn main() {
    // Re-run if HEAD moves so the embedded sha stays honest across
    // commits without a full clean.
    println!("cargo:rerun-if-changed=../.git/HEAD");
    println!("cargo:rerun-if-env-changed=COCORE_GIT_SHA");

    // WS-ENGINE: build + link the native MLX-Swift engine dylib when the
    // `native_mlx` feature is on (macOS only — it's an Apple-silicon Metal
    // engine). The Rust agent links one libCoCoreMLX.dylib (which statically
    // contains MLX + the Swift code); enforced library validation + a pinned
    // dylib/metallib hash keep the owner from swapping it.
    println!("cargo:rerun-if-env-changed=COCORE_SKIP_NATIVE_BUILD");
    if std::env::var("CARGO_FEATURE_NATIVE_MLX").is_ok() && cfg!(target_os = "macos") {
        // COCORE_SKIP_NATIVE_BUILD lets CI TYPE-CHECK the native/apns Rust paths
        // (`cargo check --features apns`) without the Swift/Metal engine build —
        // a fast guard so the macOS-only, apns-gated code can't rot unnoticed
        // between confidential releases (see PR #93). `cargo check` never links,
        // so skipping the dylib build + link directives leaves the type-check
        // complete. NEVER set this for a real `cargo build` — the result won't
        // link against libCoCoreMLX.
        if std::env::var("COCORE_SKIP_NATIVE_BUILD").is_ok() {
            println!(
                "cargo:warning=COCORE_SKIP_NATIVE_BUILD set: skipping MLX engine build \
                 (type-check only; the resulting artifact will NOT link)"
            );
        } else {
            build_and_link_mlx_engine();
        }
    }

    // Build + statically link `libCoCoreEnclave.a` (the Secure Enclave signing
    // + P-256 ECIES key-agreement FFI, provider/enclave/) when the
    // `secure_enclave` feature is on. macOS-only; a static archive links
    // cleanest into the signed hardened-runtime binary (no nested dylib to
    // sign, library-validation-friendly). Same COCORE_SKIP_NATIVE_BUILD escape
    // so CI can type-check `--features secure_enclave` without a Swift build.
    if std::env::var("CARGO_FEATURE_SECURE_ENCLAVE").is_ok() && cfg!(target_os = "macos") {
        if std::env::var("COCORE_SKIP_NATIVE_BUILD").is_ok() {
            println!(
                "cargo:warning=COCORE_SKIP_NATIVE_BUILD set: skipping Secure Enclave lib build \
                 (type-check only; the resulting artifact will NOT link)"
            );
        } else {
            build_and_link_enclave();
        }
    }

    let sha = std::env::var("COCORE_GIT_SHA").ok().or_else(|| {
        Command::new("git")
            .args(["rev-parse", "--short=12", "HEAD"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    });
    let dirty = Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false);

    let sha = match (sha, dirty) {
        (Some(s), true) => format!("{s}-dirty"),
        (Some(s), false) => s,
        (None, _) => "unknown".to_string(),
    };
    println!("cargo:rustc-env=COCORE_GIT_SHA={sha}");

    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "unknown".to_string());
    println!("cargo:rustc-env=COCORE_BUILD_PROFILE={profile}");
}

/// Build `provider/mlx-engine` (SwiftPM) and emit the link directives so the
/// Rust agent links `libCoCoreMLX.dylib`. Panics on failure — if `native_mlx`
/// is requested, a missing engine is a hard error, not a silent best-effort.
fn build_and_link_mlx_engine() {
    use std::path::Path;
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let pkg = format!("{manifest}/mlx-engine");
    println!("cargo:rerun-if-changed={pkg}/Sources");
    println!("cargo:rerun-if-changed={pkg}/Package.swift");

    // Release config for the shipped engine (debug is far slower at inference).
    let config = if std::env::var("PROFILE").as_deref() == Ok("release") {
        "release"
    } else {
        "debug"
    };
    let status = Command::new("swift")
        .args(["build", "-c", config, "--product", "CoCoreMLX"])
        .current_dir(&pkg)
        .status()
        .expect("failed to run `swift build` for the MLX engine");
    assert!(status.success(), "swift build (CoCoreMLX) failed");

    // SwiftPM places the dylib under .build/<triple>/<config>/; the
    // .build/<config> symlink points there.
    let libdir = format!("{pkg}/.build/{config}");
    assert!(
        Path::new(&format!("{libdir}/libCoCoreMLX.dylib")).exists(),
        "libCoCoreMLX.dylib not found in {libdir}"
    );
    println!("cargo:rustc-link-search=native={libdir}");
    println!("cargo:rustc-link-lib=dylib=CoCoreMLX");
    // Find the dylib at runtime: next to the binary (release bundle) and the
    // dev build dir (so `cargo run`/tests work without an install step).
    println!("cargo:rustc-link-arg=-Wl,-rpath,@executable_path");
    println!("cargo:rustc-link-arg=-Wl,-rpath,{libdir}");
}

/// Build `provider/enclave` (SwiftPM static lib) and emit the link directives
/// for `libCoCoreEnclave.a`. Panics on failure — if `secure_enclave` is
/// requested, a missing enclave lib is a hard error. Unlike the MLX dylib, a
/// static archive doesn't carry its framework load commands, so we name the
/// Apple frameworks the Swift code references (CryptoKit / Security /
/// LocalAuthentication / Foundation) explicitly.
fn build_and_link_enclave() {
    use std::path::Path;
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let pkg = format!("{manifest}/enclave");
    println!("cargo:rerun-if-changed={pkg}/Sources");
    println!("cargo:rerun-if-changed={pkg}/Package.swift");

    let config = if std::env::var("PROFILE").as_deref() == Ok("release") {
        "release"
    } else {
        "debug"
    };
    let status = Command::new("swift")
        .args(["build", "-c", config, "--product", "CoCoreEnclave"])
        .current_dir(&pkg)
        .status()
        .expect("failed to run `swift build` for the Secure Enclave lib");
    assert!(status.success(), "swift build (CoCoreEnclave) failed");

    let libdir = format!("{pkg}/.build/{config}");
    assert!(
        Path::new(&format!("{libdir}/libCoCoreEnclave.a")).exists(),
        "libCoCoreEnclave.a not found in {libdir}"
    );
    println!("cargo:rustc-link-search=native={libdir}");
    println!("cargo:rustc-link-lib=static=CoCoreEnclave");
    // Frameworks the static archive references but doesn't record.
    println!("cargo:rustc-link-lib=framework=CryptoKit");
    println!("cargo:rustc-link-lib=framework=Security");
    println!("cargo:rustc-link-lib=framework=LocalAuthentication");
    println!("cargo:rustc-link-lib=framework=Foundation");
}
