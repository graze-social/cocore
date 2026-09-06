// VenvBootstrapper: sets up the uv-managed Python runtime
// (~/.cocore/python with vllm-mlx) that the agent's subprocess engine
// needs to serve real models. On a download-only install the headless
// installer never ran, so the app bootstraps it on demand — when the
// user enables a real (non-stub) model — streaming progress into the UI.
//
// Runs the same scripts/bootstrap-python-venv.sh the curl|sh installer
// uses, bundled into the app at Contents/Resources/scripts/. Idempotent.

import Foundation

@MainActor
final class VenvBootstrapper: ObservableObject {
    enum State: Equatable {
        case idle
        case running(String)   // latest progress line
        case done
        case failed(String)
    }

    @Published var state: State = .idle

    var isRunning: Bool { if case .running = state { return true } else { return false } }

    /// Filename the bootstrap script writes into the venv root after its
    /// own import verification passes. See "Readiness marker" in
    /// scripts/bootstrap-python-venv.sh.
    private static let readyMarker = ".cocore-venv-ready"

    /// Top-level packages the agent's engine wrapper imports. Used to judge
    /// venvs created before the marker existed.
    private static let requiredPackages = ["uvicorn", "vllm_mlx", "mlx_lm"]

    /// True once the Python runtime the agent spawns is actually usable.
    ///
    /// Deliberately NOT just "does bin/python exist?". `uv venv` creates the
    /// interpreter in about a second; the ~250MB of packages land one to
    /// several minutes later. Checking only the interpreter reported the
    /// runtime as ready throughout that entire window — so onboarding was
    /// skipped and the user was shown a ready machine that could not load a
    /// single model.
    ///
    /// Two acceptable proofs, in order of cost:
    ///   * the bootstrap's readiness marker (written only after a real
    ///     import check passed), or
    ///   * the required packages present in site-packages, for venvs
    ///     provisioned before the marker existed.
    static var isInstalled: Bool {
        let fm = FileManager.default
        let venv = NSHomeDirectory() + "/.cocore/python"
        guard fm.isExecutableFile(atPath: venv + "/bin/python") else { return false }
        if fm.fileExists(atPath: venv + "/" + readyMarker) { return true }
        return hasRequiredPackages(venv: venv)
    }

    /// Whether every required package directory exists under the venv's
    /// site-packages. A file-existence check only — the app never spawns the
    /// interpreter to answer a UI question. The agent does the authoritative
    /// import probe on the serve path.
    private static func hasRequiredPackages(venv: String) -> Bool {
        let fm = FileManager.default
        let lib = venv + "/lib"
        guard let versions = try? fm.contentsOfDirectory(atPath: lib) else { return false }
        // Exactly one `python3.x` dir in practice; scan them all so a version
        // bump doesn't silently start reporting "not installed".
        for v in versions where v.hasPrefix("python3") {
            let site = "\(lib)/\(v)/site-packages"
            if requiredPackages.allSatisfy({ fm.fileExists(atPath: "\(site)/\($0)") }) {
                return true
            }
        }
        return false
    }

    /// Run the bundled bootstrap script, streaming its phase lines into
    /// `state`. ~30MB Python + ~250MB deps on first run; idempotent after.
    func bootstrap() async {
        guard !isRunning else { return }
        guard let script = Self.bundledScript() else {
            state = .failed("Setup script missing from the app bundle.")
            return
        }
        state = .running("Starting…")
        let venv = NSHomeDirectory() + "/.cocore/python"
        let exit: Int32 = await withCheckedContinuation { cont in
            DispatchQueue.global().async { [weak self] in
                let p = Process()
                p.executableURL = URL(fileURLWithPath: "/bin/sh")
                p.arguments = [script]
                var env = ProcessInfo.processInfo.environment
                env["HOME"] = NSHomeDirectory()
                env["COCORE_PYTHON_VENV"] = venv
                p.environment = env
                let pipe = Pipe()
                p.standardOutput = pipe
                p.standardError = pipe
                pipe.fileHandleForReading.readabilityHandler = { [weak self] h in
                    guard let chunk = String(data: h.availableData, encoding: .utf8) else { return }
                    NSLog("cocore venv: %@", chunk)
                    let latest = chunk
                        .split(whereSeparator: \.isNewline)
                        .map { $0.trimmingCharacters(in: .whitespaces) }
                        .last(where: { !$0.isEmpty })
                    guard let latest else { return }
                    let clean = latest.replacingOccurrences(of: "==> ", with: "")
                    Task { @MainActor [weak self] in
                        if case .running = self?.state { self?.state = .running(clean) }
                    }
                }
                do {
                    try p.run()
                    p.waitUntilExit()
                    pipe.fileHandleForReading.readabilityHandler = nil
                    cont.resume(returning: p.terminationStatus)
                } catch {
                    cont.resume(returning: -1)
                }
            }
        }
        state = exit == 0 ? .done : .failed("Setup failed (exit \(exit)). See Console.app logs.")
    }

    private static func bundledScript() -> String? {
        let path = Bundle.main.bundleURL
            .appendingPathComponent("Contents/Resources/scripts/bootstrap-python-venv.sh").path
        return FileManager.default.fileExists(atPath: path) ? path : nil
    }
}
