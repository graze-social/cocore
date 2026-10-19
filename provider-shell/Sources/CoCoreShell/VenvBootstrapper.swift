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
        let log = Self.startLog()
        // Last `error:` line the script printed, so a failure can say WHAT
        // went wrong instead of just an exit code. Touched only from the
        // pipe's readability handler (serial) and read after the process exits.
        let lastError = LockedString()
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
                    Self.append(chunk, to: log)
                    let lines = chunk
                        .split(whereSeparator: \.isNewline)
                        .map { Self.stripAnsi(String($0)).trimmingCharacters(in: .whitespaces) }
                    if let e = lines.last(where: { $0.hasPrefix("error:") }) {
                        lastError.set(e)
                    }
                    let latest = lines.last(where: { !$0.isEmpty })
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
        if exit == 0 {
            state = .done
        } else {
            // Name the real cause and a file the user can actually open. The
            // old "See Console.app logs" sent people hunting through the
            // unified log (where NSLog ages out within hours) for output that
            // was never written anywhere durable.
            let cause = lastError.get().map { " \($0)." } ?? ""
            state = .failed("Setup failed (exit \(exit)).\(cause) Full log: ~/.cocore/logs/\(Self.logName)")
        }
    }

    /// Durable copy of the last bootstrap run, alongside the agent's own logs
    /// in `~/.cocore/logs/` (which the diagnostic bundle collects).
    private static let logName = "venv-bootstrap.log"

    /// Truncate-and-open the bootstrap log for a fresh run.
    private static func startLog() -> URL {
        let dir = URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent(".cocore/logs")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let url = dir.appendingPathComponent(logName)
        let header = "\(ISO8601DateFormatter().string(from: Date())) venv bootstrap started\n"
        try? header.data(using: .utf8)?.write(to: url)
        return url
    }

    nonisolated private static func append(_ s: String, to url: URL) {
        guard let data = s.data(using: .utf8), let h = try? FileHandle(forWritingTo: url) else { return }
        defer { try? h.close() }
        _ = try? h.seekToEnd()
        try? h.write(contentsOf: data)
    }

    /// The script colors its `error:` prefix; drop SGR escapes before matching.
    nonisolated private static func stripAnsi(_ s: String) -> String {
        s.replacingOccurrences(of: "\u{1B}\\[[0-9;]*m", with: "", options: .regularExpression)
    }

    private static func bundledScript() -> String? {
        let path = Bundle.main.bundleURL
            .appendingPathComponent("Contents/Resources/scripts/bootstrap-python-venv.sh").path
        return FileManager.default.fileExists(atPath: path) ? path : nil
    }
}

/// Minimal thread-safe box for a string written from the pipe handler.
private final class LockedString: @unchecked Sendable {
    private let lock = NSLock()
    private var value: String?
    func set(_ v: String) { lock.lock(); value = v; lock.unlock() }
    func get() -> String? { lock.lock(); defer { lock.unlock() }; return value }
}
