// AgentSupervisor: controls the `cocore` Rust agent. The agent is the
// only thing that ever decrypts a prompt; the Swift app sees no
// inference data.
//
// Two modes, chosen at runtime:
//
//   * Installed machine — a `dev.cocore.provider` LaunchAgent already
//     owns the long-running `cocore agent serve` process (RunAtLoad +
//     KeepAlive). We must NOT spawn our own, or two agents fight over
//     the same session. So start/stop/serving status all go through
//     `launchctl` against that label.
//
//   * Dev (`swift run`, no LaunchAgent installed) — fall back to
//     spawning + monitoring the binary ourselves so the app is still
//     useful in a working tree.
//
// Binary discovery (for the dev-spawn fallback + the pair flow):
//   1. $COCORE_PROVIDER_BIN (developer override)
//   2. <Bundle>/Contents/MacOS/cocore (release builds bundle it)
//   3. ~/.local/bin/cocore (the standard installer location)
//   4. <repo>/provider/target/release/cocore (dev `swift run`)

import Foundation

@MainActor
final class AgentSupervisor {
    private var process: Process?          // dev fallback only
    private var stdoutPipe: Pipe?
    private var stderrPipe: Pipe?
    var onLine: ((String) -> Void)?
    /// Fired when the supervised agent has exited unexpectedly several
    /// times in quick succession (a crash loop). The argument is the
    /// running crash count. The menu bar uses this to surface a "this
    /// machine keeps crashing — Send bug report?" affordance instead of
    /// silently respawning while the ledger stays flat.
    var onCrashLoop: ((Int) -> Void)?
    /// Unexpected exits since the last clean run. Reset when the agent
    /// stays up long enough to look healthy.
    private var crashCount = 0
    /// At how many rapid crashes we start nudging the user.
    private let crashLoopThreshold = 3

    // Crash-restart bookkeeping for the app-supervised (no-LaunchAgent)
    // path. When we own the agent process, nothing else resurrects it on an
    // unexpected exit — so we respawn, with a backoff that widens if it's
    // crash-looping. `intentionalStop` suppresses the respawn when WE asked
    // it to stop (Pause serving, schedule idle, app quit).
    private var intentionalStop = false
    private var restartBackoff: TimeInterval = 2
    private var lastSpawnAt: Date?

    private let label = "dev.cocore.provider"
    private var domainTarget: String { "gui/\(getuid())/\(label)" }
    private var domain: String { "gui/\(getuid())" }
    private var plistURL: URL {
        URL(fileURLWithPath: NSHomeDirectory())
            .appendingPathComponent("Library/LaunchAgents/\(label).plist")
    }

    /// True when this machine has the LaunchAgent installed — i.e. the
    /// agent's lifecycle is owned by launchd, not by us.
    var isLaunchAgentManaged: Bool {
        FileManager.default.fileExists(atPath: plistURL.path)
    }

    /// Whether the agent is currently serving. Prefers the LaunchAgent's
    /// view (so externally-started/stopped agents are reflected); falls
    /// back to our own child process in dev.
    func isServing() -> Bool {
        if isLaunchAgentManaged {
            let (_, out) = runLaunchctl(["print", domainTarget])
            return out.contains("state = running")
        }
        return process?.isRunning ?? false
    }

    func start() async {
        if isLaunchAgentManaged {
            // `disable` leaves a persistent denylist entry that makes a
            // later `bootstrap` fail with "Input/output error"; enable
            // first (no-op if already enabled). bootstrap loads it if it
            // isn't; kickstart (re)starts the process.
            _ = runLaunchctl(["enable", domainTarget])
            _ = runLaunchctl(["bootstrap", domain, plistURL.path])
            _ = runLaunchctl(["kickstart", "-k", domainTarget])
            return
        }
        spawnChild()
    }

    func stop() async {
        if isLaunchAgentManaged {
            // bootout removes the service so KeepAlive won't resurrect
            // it; start() bootstraps it back.
            _ = runLaunchctl(["bootout", domainTarget])
            return
        }
        // Mark BEFORE we signal the process so the terminationHandler
        // (which fires on exit) doesn't treat this as a crash and respawn.
        intentionalStop = true
        guard let p = process else { return }
        p.interrupt()
        await waitForExit(p, timeout: 5)
        if p.isRunning { p.terminate() }
        process = nil
    }

    /// Synchronous teardown for `applicationWillTerminate`. The async
    /// `stop()` spawned from a detached `Task` often loses the race with
    /// process exit, so the agent child is left orphaned (reparented to
    /// launchd) — which is precisely how two agents end up registered for
    /// one DID. Here we SIGTERM + briefly block inline so the child is
    /// actually gone before the app exits. No-op under a LaunchAgent (its
    /// lifecycle isn't ours to end).
    func stopSynchronously() {
        guard !isLaunchAgentManaged else { return }
        intentionalStop = true
        guard let p = process, p.isRunning else { return }
        p.interrupt() // SIGINT → agent's graceful shutdown (flips serving=false)
        let deadline = Date().addingTimeInterval(3)
        while p.isRunning && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.05)
        }
        if p.isRunning { p.terminate() }
        process = nil
    }

    // MARK: - Bug reports

    /// Generate a content-safe diagnostic bundle via `cocore agent diag`
    /// and return its path on disk, or `nil` on failure. The bundle
    /// contains crash + health telemetry only (no prompts, no API key, no
    /// signing key) — see the Rust `make_diagnostic_bundle`.
    nonisolated static func generateBugReportBundle() -> URL? {
        guard let bin = locateBinary() else { return nil }
        let p = Process()
        p.executableURL = bin
        p.arguments = ["agent", "diag"]
        p.environment = ["HOME": NSHomeDirectory()]
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = FileHandle.nullDevice
        do {
            try p.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            p.waitUntilExit()
            guard p.terminationStatus == 0,
                  let out = String(data: data, encoding: .utf8)?
                      .trimmingCharacters(in: .whitespacesAndNewlines),
                  !out.isEmpty
            else { return nil }
            return URL(fileURLWithPath: out)
        } catch {
            NSLog("cocore: diag bundle generation failed: %@", String(describing: error))
            return nil
        }
    }

    /// Generate a diagnostic bundle and upload it to the console's
    /// bug-report endpoint, returning the ticket id on success. The upload
    /// is bearer-authed with the paired session's API key. Falls back to
    /// returning the local bundle path (as `file://…`) if there's no
    /// session or the upload fails, so the user can still attach it by hand.
    func sendBugReport(note: String? = nil) async -> String? {
        guard let bundle = Self.generateBugReportBundle() else { return nil }
        // Target session.apiBase — the service that paired us holds our bearer
        // key. (Follow-up: the AppView should serve /api/agent/bug-report too,
        // so device-pair'd agents can upload; today only the console does.)
        guard let session = SessionStore.load(),
              let apiKey = session.apiKey,
              let base = session.apiBase,
              let url = URL(string: "\(base)/api/agent/bug-report"),
              let body = try? Data(contentsOf: bundle)
        else {
            return bundle.absoluteString // local fallback
        }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("Bearer \(apiKey)", forHTTPHeaderField: "Authorization")
        req.setValue("application/gzip", forHTTPHeaderField: "Content-Type")
        if let note, !note.isEmpty {
            req.setValue(note, forHTTPHeaderField: "X-Cocore-Note")
        }
        req.timeoutInterval = 30
        do {
            let (data, resp) = try await URLSession.shared.upload(for: req, from: body)
            guard let http = resp as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
                return bundle.absoluteString
            }
            struct Ticket: Decodable { let ticketId: String }
            if let t = try? JSONDecoder().decode(Ticket.self, from: data) {
                return t.ticketId
            }
            return bundle.absoluteString
        } catch {
            return bundle.absoluteString
        }
    }

    // MARK: - launchctl

    @discardableResult
    private func runLaunchctl(_ args: [String]) -> (status: Int32, output: String) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        p.arguments = args
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = pipe
        do {
            try p.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            p.waitUntilExit()
            return (p.terminationStatus, String(data: data, encoding: .utf8) ?? "")
        } catch {
            NSLog("cocore: launchctl %@ failed: %@", args.joined(separator: " "), String(describing: error))
            return (-1, "")
        }
    }

    // MARK: - dev-spawn fallback

    private func spawnChild() {
        guard process == nil else { return }
        // A fresh deliberate start clears the stop latch so a later
        // unexpected exit is treated as a crash and respawned.
        intentionalStop = false
        guard let bin = Self.serveBinary() else {
            NSLog("cocore: provider binary not found")
            return
        }
        let advisor = Endpoints.advisorURL
        let p = Process()
        p.executableURL = bin
        p.arguments = ["agent", "serve", "--advisor", advisor]
        // Strip the environment we inherited from launchd / Finder; the
        // agent re-applies its own scrubbing as defence in depth. In the
        // self-contained-app case there's no LaunchAgent plist, so we pass
        // the agent's config (console, Python venv, configured models)
        // here — UserDefaults is the app's store for the no-plist path.
        var env: [String: String] = [
            "HOME": NSHomeDirectory(),
            "PATH": "\(NSHomeDirectory())/.local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
            "COCORE_LOG": "info",
            "COCORE_CONSOLE": Endpoints.consoleURL,
            "COCORE_PYTHON_VENV": "\(NSHomeDirectory())/.cocore/python",
            // Full backtraces so the next panic the agent writes to
            // ~/.cocore/last-panic.txt names the exact frame, not just
            // file:line. The agent's panic hook captures one regardless,
            // but this also enriches the stderr line we persist below.
            "RUST_BACKTRACE": "full",
        ]
        let models = (UserDefaults.standard.string(forKey: "inferenceModels") ?? "")
            .trimmingCharacters(in: .whitespaces)
        if !models.isEmpty { env["COCORE_INFERENCE_MODELS"] = models }
        // Owner-chosen display name (set in the tray during setup), so the
        // provider record shows that instead of the raw `.local` hostname.
        let label = (UserDefaults.standard.string(forKey: "machineLabel") ?? "")
            .trimmingCharacters(in: .whitespaces)
        if !label.isEmpty { env["COCORE_MACHINE_LABEL"] = label }
        // Serve schedule — the no-LaunchAgent analogue of the plist's
        // COCORE_SERVE_START/END. Without this the spawned agent has no
        // serve window, so ServeWindow::from_env() is None and it serves
        // 24/7 — ignoring the Schedule setting entirely. (Defaults match
        // PreferencesView's @AppStorage defaults.)
        let d = UserDefaults.standard
        if d.bool(forKey: "scheduleLimited") {
            let start = d.object(forKey: "idleStart") as? Int ?? 22
            let end = d.object(forKey: "idleEnd") as? Int ?? 8
            env["COCORE_SERVE_START"] = String(start)
            env["COCORE_SERVE_END"] = String(end)
        }
        // Per-model schedules — the no-LaunchAgent analogue of the plist's
        // COCORE_MODEL_SCHEDULES. The agent's `ModelSchedules::from_env()`
        // reads this; absent/empty means every model is always-on.
        if let json = ModelManager.modelSchedulesEnvJSON() {
            env["COCORE_MODEL_SCHEDULES"] = json
        }
        p.environment = env

        let outPipe = Pipe(), errPipe = Pipe()
        p.standardOutput = outPipe
        p.standardError = errPipe
        outPipe.fileHandleForReading.readabilityHandler = { [weak self] h in
            guard let line = String(data: h.availableData, encoding: .utf8), !line.isEmpty else { return }
            Task { @MainActor [weak self] in self?.onLine?(line) }
        }
        errPipe.fileHandleForReading.readabilityHandler = { h in
            if let s = String(data: h.availableData, encoding: .utf8), !s.isEmpty {
                NSLog("cocore agent: %@", s)
                // Persist stderr durably too. NSLog ages out of the unified
                // log within hours, which is exactly why the primary panic
                // that took machines offline was unrecoverable. The agent's
                // own panic hook writes ~/.cocore/last-panic.txt, but this
                // captures the full stderr stream (including non-panic warns)
                // for the diagnostic bundle. Content-safe: the agent never
                // writes prompt/token text to stderr.
                Self.appendAgentStderr(s)
            }
        }
        p.terminationHandler = { [weak self] proc in
            Task { @MainActor [weak self] in
                guard let self else { return }
                self.process = nil
                NSLog("cocore agent exited with %d", proc.terminationStatus)
                // Deliberate stop → leave it down.
                guard !self.intentionalStop else { return }
                // Unexpected exit (crash/kill) and we own its lifecycle:
                // respawn. Widen the backoff if it died soon after starting
                // (crash loop — e.g. a misconfig), reset it if it ran a
                // while. Capped so we keep retrying without hammering.
                let ranFor = self.lastSpawnAt.map { Date().timeIntervalSince($0) } ?? 0
                if ranFor < 10 {
                    self.restartBackoff = min(self.restartBackoff * 2, 60)
                    self.crashCount += 1
                    // Surface a sustained crash loop so the user can send a
                    // bug report instead of staring at a flat ledger.
                    if self.crashCount >= self.crashLoopThreshold {
                        self.onCrashLoop?(self.crashCount)
                    }
                } else {
                    // Ran long enough to look healthy — clear the loop state.
                    self.restartBackoff = 2
                    self.crashCount = 0
                }
                let delay = self.restartBackoff
                NSLog("cocore agent: unexpected exit (#%d); respawning in %.0fs", self.crashCount, delay)
                try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
                guard !self.intentionalStop, self.process == nil else { return }
                self.spawnChild()
            }
        }

        // Singleton guarantee. A previous app session's agent can survive
        // as an orphan reparented to launchd (the shell quit without
        // reaping it), and it keeps its advisor connection alive. If we
        // then spawn a second one, the advisor briefly has TWO sessions for
        // this DID — and when the orphan dies its disconnect cleanup can
        // tear the machine out of routing, stranding the live agent
        // connected-but-unrouted (the exact "jobs reported, ledger flat"
        // failure). Reap any stray `cocore agent serve` we don't own before
        // starting a fresh one. Only in the app-supervised path — when a
        // LaunchAgent owns the agent we never reach spawnChild.
        Self.killStrayAgents()

        do {
            try p.run()
            self.process = p
            self.lastSpawnAt = Date()
            self.stdoutPipe = outPipe
            self.stderrPipe = errPipe
        } catch {
            NSLog("cocore: failed to launch agent: %@", String(describing: error))
        }
    }

    /// SIGTERM any `cocore agent serve` process owned by this user that we
    /// aren't currently tracking. Best-effort and synchronous (it runs
    /// before a spawn, where a ~half-second wait is acceptable). Uses
    /// `pgrep`/`kill` rather than `pkill` so we can exclude our own PID and
    /// log what we reaped.
    private static func killStrayAgents() {
        let pgrep = Process()
        pgrep.executableURL = URL(fileURLWithPath: "/usr/bin/pgrep")
        // Match both the default CLI (`cocore agent serve`) and the nested
        // confidential worker (`cocore-provider agent serve`) — a confidential
        // machine runs the latter, and an orphan of either kind must be reaped.
        pgrep.arguments = ["-f", "cocore(-provider)? agent serve"]
        let pipe = Pipe()
        pgrep.standardOutput = pipe
        pgrep.standardError = FileHandle.nullDevice
        do {
            try pgrep.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            pgrep.waitUntilExit()
            let mine = ProcessInfo.processInfo.processIdentifier
            let pids = (String(data: data, encoding: .utf8) ?? "")
                .split(whereSeparator: \.isNewline)
                .compactMap { Int32($0.trimmingCharacters(in: .whitespaces)) }
                .filter { $0 != mine }
            guard !pids.isEmpty else { return }
            NSLog("cocore: reaping %d stray agent process(es) before spawn: %@",
                  pids.count, pids.map(String.init).joined(separator: ","))
            for pid in pids { kill(pid, SIGTERM) }
            // Give them a moment to unwind (their Drop SIGTERMs the Python
            // child + flips the provider record to serving=false) so we
            // don't race a half-dead registration.
            Thread.sleep(forTimeInterval: 0.5)
            for pid in pids where kill(pid, 0) == 0 { kill(pid, SIGKILL) }
        } catch {
            // pgrep absent / failed — nothing to reap, proceed.
        }
    }

    /// Append a chunk of agent stderr to the durable log at
    /// `~/.cocore/logs/agent-stderr.log`. Best-effort; never throws into
    /// the readability handler. `nonisolated` because the pipe's
    /// readability handler runs off the main actor — this touches only the
    /// filesystem, no actor state.
    nonisolated private static func appendAgentStderr(_ s: String) {
        let dir = URL(fileURLWithPath: NSHomeDirectory())
            .appendingPathComponent(".cocore/logs")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let url = dir.appendingPathComponent("agent-stderr.log")
        guard let data = s.data(using: .utf8) else { return }
        if let h = try? FileHandle(forWritingTo: url) {
            defer { try? h.close() }
            _ = try? h.seekToEnd()
            try? h.write(contentsOf: data)
        } else {
            try? data.write(to: url)
        }
    }

    private func waitForExit(_ p: Process, timeout: TimeInterval) async {
        let deadline = Date().addingTimeInterval(timeout)
        while p.isRunning && Date() < deadline {
            try? await Task.sleep(nanoseconds: 100_000_000)
        }
    }

    /// Write the console + advisor URLs into the LaunchAgent plist's
    /// EnvironmentVariables and bounce the daemon so it reconnects with
    /// the new endpoints. No-op when there's no LaunchAgent (dev runs),
    /// where the URLs come from UserDefaults at spawn time instead.
    /// `nonisolated static` so PreferencesView can call it directly.
    /// Apply the current Schedule settings (from UserDefaults) to the
    /// RUNNING agent and reconnect. Mode-aware: a LaunchAgent install
    /// writes the plist env + bounces launchd; an app-supervised install
    /// (no plist) restarts the child we own so `spawnChild` re-reads
    /// COCORE_SERVE_START/END. Previously the schedule only ever reached
    /// the LaunchAgent path, so on a self-contained app the agent kept
    /// serving 24/7 no matter what the user picked.
    func applyScheduleAndReconnect() async {
        let d = UserDefaults.standard
        let limited = d.bool(forKey: "scheduleLimited")
        let startHour = d.object(forKey: "idleStart") as? Int ?? 22
        let endHour = d.object(forKey: "idleEnd") as? Int ?? 8
        if isLaunchAgentManaged {
            Self.applySchedule(limited: limited, startHour: startHour, endHour: endHour)
        } else {
            await stop()
            await start()
        }
    }

    /// Apply the current per-model schedules (`COCORE_MODEL_SCHEDULES`) to the
    /// running agent and reload. Same mode split as the whole-app schedule:
    /// edit the plist + bounce (LaunchAgent), or restart the supervised child
    /// (which re-reads the env in `spawnChild`).
    func applyModelSchedulesAndReconnect() async {
        if isLaunchAgentManaged {
            Self.applyModelSchedules(json: ModelManager.modelSchedulesEnvJSON())
        } else {
            await stop()
            await start()
        }
    }

    /// Write/clear `COCORE_MODEL_SCHEDULES` in the LaunchAgent plist + bounce.
    /// `json == nil` (no per-model schedules) deletes the key so the agent
    /// treats every model as always-on. No-op without a LaunchAgent.
    nonisolated static func applyModelSchedules(json: String?) {
        let label = "dev.cocore.provider"
        let plist = NSHomeDirectory() + "/Library/LaunchAgents/\(label).plist"
        guard FileManager.default.fileExists(atPath: plist) else { return }
        func plistBuddy(_ command: String) {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/usr/libexec/PlistBuddy")
            p.arguments = ["-c", command, plist]
            try? p.run()
            p.waitUntilExit()
        }
        let path = ":EnvironmentVariables:COCORE_MODEL_SCHEDULES"
        if let json {
            plistBuddy("Set \(path) \(json)")
            plistBuddy("Add \(path) string \(json)")
        } else {
            plistBuddy("Delete \(path)")
        }
        bounce(label: label)
    }

    /// Apply the current Network settings (console/advisor URLs, from
    /// UserDefaults) to the running agent and reconnect. Same mode split
    /// as `applyScheduleAndReconnect`.
    func applyNetworkAndReconnect() async {
        let console = Endpoints.consoleURL
        let advisor = Endpoints.advisorURL
        if isLaunchAgentManaged {
            Self.applyNetworkConfig(console: console, advisor: advisor)
        } else {
            await stop()
            await start()
        }
    }

    /// Apply the owner-chosen machine name (from UserDefaults) to the running
    /// agent and reconnect, so the provider record re-publishes with the new
    /// `machineLabel`. Same mode split as `applyScheduleAndReconnect`: a
    /// LaunchAgent install edits the plist env + bounces; an app-supervised
    /// install restarts the child we own so `spawnChild` re-reads
    /// COCORE_MACHINE_LABEL.
    func applyMachineNameAndReconnect() async {
        let name = (UserDefaults.standard.string(forKey: "machineLabel") ?? "")
            .trimmingCharacters(in: .whitespaces)
        if isLaunchAgentManaged {
            Self.applyMachineLabel(name: name)
        } else {
            await stop()
            await start()
        }
    }

    /// Write (or clear) COCORE_MACHINE_LABEL in the LaunchAgent plist's
    /// EnvironmentVariables and bounce the daemon. Empty name deletes the key
    /// so the agent falls back to the system hostname. No-op without a
    /// LaunchAgent (app-supervised passes the name via `spawnChild` env).
    nonisolated static func applyMachineLabel(name: String) {
        let label = "dev.cocore.provider"
        let plist = NSHomeDirectory() + "/Library/LaunchAgents/\(label).plist"
        guard FileManager.default.fileExists(atPath: plist) else { return }

        func plistBuddy(_ command: String) {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/usr/libexec/PlistBuddy")
            p.arguments = ["-c", command, plist]
            try? p.run()
            p.waitUntilExit()
        }
        let path = ":EnvironmentVariables:COCORE_MACHINE_LABEL"
        if name.isEmpty {
            plistBuddy("Delete \(path)")
        } else {
            // Set updates an existing key; Add creates it (the template
            // doesn't predefine this one). Names can contain spaces — the
            // whole command is one PlistBuddy `-c` arg, so they're preserved.
            plistBuddy("Set \(path) \(name)")
            plistBuddy("Add \(path) string \(name)")
        }
        bounce(label: label)
    }

    nonisolated static func applyNetworkConfig(console: String, advisor: String) {
        let label = "dev.cocore.provider"
        let plist = NSHomeDirectory() + "/Library/LaunchAgents/\(label).plist"
        guard FileManager.default.fileExists(atPath: plist) else { return }

        func plistBuddy(_ command: String) {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/usr/libexec/PlistBuddy")
            p.arguments = ["-c", command, plist]
            try? p.run()
            p.waitUntilExit()
        }
        // The plist template always defines these keys, so Set succeeds;
        // Add is a belt-and-suspenders fallback for hand-edited plists.
        for (key, value) in [("COCORE_CONSOLE", console), ("COCORE_ADVISOR", advisor)] {
            let path = ":EnvironmentVariables:\(key)"
            plistBuddy("Set \(path) \(value)")
            plistBuddy("Add \(path) string \(value)")
        }
        bounce(label: label)
    }

    /// Write (or clear) the daily serve window into the LaunchAgent
    /// plist's EnvironmentVariables and bounce the daemon. When
    /// `limited` is false the env vars are removed, so the agent serves
    /// continuously. The agent reads these at startup
    /// (cocore_provider::schedule::ServeWindow). No-op without a
    /// LaunchAgent (dev runs).
    nonisolated static func applySchedule(limited: Bool, startHour: Int, endHour: Int) {
        let label = "dev.cocore.provider"
        let plist = NSHomeDirectory() + "/Library/LaunchAgents/\(label).plist"
        guard FileManager.default.fileExists(atPath: plist) else { return }

        func plistBuddy(_ command: String) {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/usr/libexec/PlistBuddy")
            p.arguments = ["-c", command, plist]
            try? p.run()
            p.waitUntilExit()
        }
        let entries = [("COCORE_SERVE_START", startHour), ("COCORE_SERVE_END", endHour)]
        for (key, value) in entries {
            let path = ":EnvironmentVariables:\(key)"
            if limited {
                plistBuddy("Set \(path) \(value)")
                plistBuddy("Add \(path) string \(value)")
            } else {
                plistBuddy("Delete \(path)")
            }
        }
        bounce(label: label)
    }

    /// Reload the LaunchAgent so launchd re-reads the plist's edited
    /// EnvironmentVariables (serve window, console/advisor URLs). A plain
    /// `kickstart -k` restarts the process but reuses the job definition
    /// cached at the last `bootstrap`, so env edits would be ignored —
    /// that's why an applied schedule never reached the running agent.
    /// Mirrors the CLI's bounce: bootout → bootstrap → enable → kickstart,
    /// each best-effort (bootout fails if not loaded, bootstrap if already
    /// loaded, etc.).
    private nonisolated static func bounce(label: String) {
        let domain = "gui/\(getuid())"
        let target = "\(domain)/\(label)"
        let plist = NSHomeDirectory() + "/Library/LaunchAgents/\(label).plist"
        func lc(_ args: [String]) {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/bin/launchctl")
            p.arguments = args
            p.standardOutput = FileHandle.nullDevice
            p.standardError = FileHandle.nullDevice
            try? p.run()
            p.waitUntilExit()
        }
        lc(["bootout", target])
        lc(["bootstrap", domain, plist])
        lc(["enable", target])
        lc(["kickstart", "-k", target])
    }

    /// Locate the installed `cocore` binary. `nonisolated static` so the
    /// device-pair sign-in flow (PairFlow) can find it too — it touches
    /// no actor state.
    nonisolated static func locateBinary() -> URL? {
        if let override = ProcessInfo.processInfo.environment["COCORE_PROVIDER_BIN"] {
            let url = URL(fileURLWithPath: override)
            if FileManager.default.isExecutableFile(atPath: url.path) { return url }
        }
        let bundled = Bundle.main.bundleURL
            .appendingPathComponent("Contents/MacOS/cocore")
        if FileManager.default.isExecutableFile(atPath: bundled.path) { return bundled }

        let installed = URL(fileURLWithPath: NSHomeDirectory())
            .appendingPathComponent(".local/bin/cocore")
        if FileManager.default.isExecutableFile(atPath: installed.path) { return installed }

        var candidate = Bundle.main.bundleURL
        for _ in 0..<6 {
            let probe = candidate.appendingPathComponent("provider/target/release/cocore")
            if FileManager.default.isExecutableFile(atPath: probe.path) { return probe }
            candidate = candidate.deletingLastPathComponent()
        }
        return nil
    }

    /// This machine's owner-chosen trust tier, read by running the bundled
    /// CLI's `agent tier` (which consults the PDS provider record). Returns
    /// `"best-effort"` on any error — the safe default that runs the
    /// non-entitled default binary. Synchronous + called once per spawn (the
    /// same pattern as the other CLI shell-outs in this type).
    nonisolated static func probeTier() -> String {
        guard let bin = locateBinary() else { return "best-effort" }
        let p = Process()
        p.executableURL = bin
        p.arguments = ["agent", "tier"]
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = FileHandle.nullDevice
        do {
            try p.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            p.waitUntilExit()
            let out = (String(data: data, encoding: .utf8) ?? "")
                .trimmingCharacters(in: .whitespacesAndNewlines)
            return out == "attested-confidential" ? "attested-confidential" : "best-effort"
        } catch {
            return "best-effort"
        }
    }

    /// The binary to run for `agent serve`. On a machine the owner opted into
    /// attested-confidential we spawn the nested, measured push-receiver bundle
    /// `Contents/CoCoreProvider.app/Contents/MacOS/cocore-provider` — it holds
    /// the embedded provisioning profile + aps-environment entitlement that lets
    /// it answer the advisor's APNs code-identity challenge, and it runs the
    /// in-process MLX engine so plaintext never leaves the measured binary.
    /// Every other machine runs the default `cocore`: no provisioning profile
    /// to expire, behaviour identical to a normal release. Falls back to the
    /// default binary when the worker bundle isn't present (a non-apns build).
    nonisolated static func serveBinary() -> URL? {
        if probeTier() == "attested-confidential" {
            let worker = Bundle.main.bundleURL
                .appendingPathComponent(
                    "Contents/CoCoreProvider.app/Contents/MacOS/cocore-provider")
            if FileManager.default.isExecutableFile(atPath: worker.path) {
                NSLog("cocore: confidential tier — spawning nested worker %@", worker.path)
                return worker
            }
            NSLog(
                "cocore: confidential tier requested but nested worker bundle missing; using default binary"
            )
        }
        return locateBinary()
    }
}
