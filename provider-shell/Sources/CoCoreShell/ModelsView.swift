// ModelsView: a window to manage which inference models this machine
// loads + advertises. Backed by the `cocore agent models` CLI, which
// edits the LaunchAgent's COCORE_INFERENCE_MODELS and bounces the
// daemon — the bounced agent re-publishes its provider record, so the
// change is visible on PDS + the AppView within seconds.

import AppKit
import SwiftUI

@MainActor
final class ModelManager: ObservableObject {
    @Published var models: [String] = []
    @Published var busy = false
    @Published var error: String?
    /// Non-fatal feedback about the most recent add: whether the model
    /// actually loaded, failed, or is still downloading. Distinct from
    /// `error` (which is a hard command failure) — this is rendered in a
    /// softer style. Cleared at the start of each mutation.
    @Published var loadStatus: LoadStatus?

    enum LoadStatus {
        case loaded(String)
        case failed(String)
        case pending(String)

        var text: String {
            switch self {
            case .loaded(let m): return "✓ \(m) loaded and serving."
            case .failed(let m):
                return "✗ \(m) failed to load. co/core runs MLX-format models only "
                    + "(mlx-community/… or another repo with MLX 4-bit weights); a stock "
                    + "PyTorch repo won't load. See this machine on console.cocore.dev for details."
            case .pending(let m):
                return "Added \(m). First-time downloads can take a minute — watch this "
                    + "machine on console.cocore.dev to confirm it starts serving."
            }
        }

        var isFailure: Bool { if case .failed = self { return true }; return false }
    }

    /// App-managed (no-LaunchAgent) installs have no plist for `cocore
    /// agent models` to edit, so the app owns the model list in
    /// UserDefaults and restarts the supervised agent on change. With a
    /// LaunchAgent present, we defer to the CLI (which edits the plist +
    /// bounces launchd). `supervisor == nil` keeps the CLI path.
    static let modelsDefaultsKey = "inferenceModels"
    private let supervisor: AgentSupervisor?
    init(supervisor: AgentSupervisor? = nil) { self.supervisor = supervisor }
    private var appManaged: Bool { supervisor.map { !$0.isLaunchAgentManaged } ?? false }

    /// Curated quick-add catalog. `minRamGB` floors mirror the agent's
    /// `pricing::pickable_for_machine`. These are suggestions, not an
    /// allowlist — any MLX-format HuggingFace `org/model` NSID works via
    /// the custom field.
    static let catalog: [(nsid: String, label: String, minRamGB: Int)] = [
        ("mlx-community/Qwen2.5-0.5B-Instruct-4bit", "Qwen 2.5 0.5B", 4),
        ("mlx-community/Qwen2.5-3B-Instruct-4bit", "Qwen 2.5 3B", 8),
        ("mlx-community/gemma-3-4b-it-qat-4bit", "Gemma 3 4B", 8),
        ("mlx-community/Qwen2.5-7B-Instruct-4bit", "Qwen 2.5 7B", 16),
        ("mlx-community/Qwen2.5-32B-Instruct-4bit", "Qwen 2.5 32B", 32),
        ("mlx-community/Llama-3.3-70B-Instruct-4bit", "Llama 3.3 70B", 64),
    ]

    /// This Mac's physical RAM in GB (rounded), via sysctl `hw.memsize`.
    /// 0 if the probe fails, in which case the picker degrades to showing
    /// every model without a fit judgment.
    static let deviceRamGB: Int = {
        var bytes: UInt64 = 0
        var size = MemoryLayout<UInt64>.size
        guard sysctlbyname("hw.memsize", &bytes, &size, nil, 0) == 0, bytes > 0 else { return 0 }
        return Int((Double(bytes) / 1_073_741_824.0).rounded())
    }()

    static func fitsDevice(_ minRamGB: Int) -> Bool {
        deviceRamGB == 0 || minRamGB <= deviceRamGB
    }

    /// The biggest catalog model that fits this Mac — the suggested
    /// default. nil when RAM is unknown or nothing fits.
    static var recommendedNSID: String? {
        guard deviceRamGB > 0 else { return nil }
        return catalog.filter { $0.minRamGB <= deviceRamGB }
            .max(by: { $0.minRamGB < $1.minRamGB })?
            .nsid
    }

    /// Catalog ordered best-for-this-device first: fitting models by
    /// descending size (recommended on top), then the ones that need more
    /// RAM than this Mac has. Falls back to declaration order when RAM is
    /// unknown.
    static var catalogForDevice: [(nsid: String, label: String, minRamGB: Int)] {
        guard deviceRamGB > 0 else { return catalog }
        let fits = catalog.filter { $0.minRamGB <= deviceRamGB }.sorted { $0.minRamGB > $1.minRamGB }
        let tooBig = catalog.filter { $0.minRamGB > deviceRamGB }.sorted { $0.minRamGB < $1.minRamGB }
        return fits + tooBig
    }

    // MARK: per-model schedules

    /// A per-model serve window: hours 0–23, `end` exclusive, wrap allowed
    /// (start > end = overnight). Byte-compatible with the agent's
    /// `COCORE_MODEL_SCHEDULES` JSON.
    struct Window: Equatable, Codable {
        var start: Int
        var end: Int
    }
    static let schedulesDefaultsKey = "inferenceModelsSchedules"

    /// Per-model windows from UserDefaults, stored as JSON
    /// `{"model":{"start":9,"end":17}}` — the same shape the agent reads.
    /// Out-of-range / empty windows are dropped (that model stays always-on).
    static func loadSchedules() -> [String: Window] {
        guard let raw = UserDefaults.standard.string(forKey: schedulesDefaultsKey),
            let data = raw.data(using: .utf8),
            let obj = try? JSONDecoder().decode([String: Window].self, from: data)
        else { return [:] }
        return obj.filter { (0...23).contains($0.value.start) && (0...23).contains($0.value.end) && $0.value.start != $0.value.end }
    }

    static func saveSchedules(_ schedules: [String: Window]) {
        let clean = schedules.filter { $0.value.start != $0.value.end }
        if clean.isEmpty {
            UserDefaults.standard.removeObject(forKey: schedulesDefaultsKey)
            return
        }
        if let data = try? JSONEncoder().encode(clean), let json = String(data: data, encoding: .utf8) {
            UserDefaults.standard.set(json, forKey: schedulesDefaultsKey)
        }
    }

    /// The `COCORE_MODEL_SCHEDULES` value to hand the agent, or nil when no
    /// per-model schedules are set (every model always-on).
    static func modelSchedulesEnvJSON() -> String? {
        let s = loadSchedules()
        guard !s.isEmpty, let data = try? JSONEncoder().encode(s),
            let json = String(data: data, encoding: .utf8)
        else { return nil }
        return json
    }

    /// Catalog RAM floor for a model id, or 0 for an off-catalog/unknown one
    /// (mirrors the agent's `pricing::min_ram_gb` → None handling).
    static func minRamGB(for nsid: String) -> Int {
        catalog.first(where: { $0.nsid == nsid })?.minRamGB ?? 0
    }

    /// Is a model active at `hour` given its window? No window = always on.
    static func active(at hour: Int, window: Window?) -> Bool {
        guard let w = window else { return true }
        return w.start < w.end ? (hour >= w.start && hour < w.end) : (hour >= w.start || hour < w.end)
    }

    /// Overprovisioning check (the validator half): for each hour, sum the
    /// active models' RAM floors; if any hour's total exceeds this Mac's RAM,
    /// return a human warning naming the worst hour. nil when every hour fits
    /// (or device RAM is unknown). The agent enforces the same budget by
    /// pruning largest-first, so this is a "you didn't mean to do that" nudge.
    static func overprovisionWarning(models: [String], schedules: [String: Window]) -> String? {
        guard deviceRamGB > 0 else { return nil }
        var worstHour = 0
        var worstSum = 0
        for hour in 0..<24 {
            let sum = models
                .filter { active(at: hour, window: schedules[$0]) }
                .map { minRamGB(for: $0) }
                .reduce(0, +)
            if sum > worstSum {
                worstSum = sum
                worstHour = hour
            }
        }
        guard worstSum > deviceRamGB else { return nil }
        return "At \(PreferencesView.hourLabel(worstHour)), \(worstSum)GB of models are scheduled at once — more than this Mac's \(deviceRamGB)GB. The agent will drop the largest until they fit; stagger their hours so they don't overlap."
    }

    /// Persist the full per-model schedule set and reload the agent. Called
    /// debounced from the editor so dragging a picker doesn't bounce the
    /// agent on every tick.
    func applySchedules(_ schedules: [String: Window]) async {
        Self.saveSchedules(schedules)
        if let sup = supervisor {
            await sup.applyModelSchedulesAndReconnect()
        } else {
            // LaunchAgent install (no supervisor handle here): edit plist + bounce.
            AgentSupervisor.applyModelSchedules(json: Self.modelSchedulesEnvJSON())
        }
    }

    static func storedModels() -> [String] {
        (UserDefaults.standard.string(forKey: modelsDefaultsKey) ?? "")
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    func refresh() async {
        if appManaged {
            models = Self.storedModels()
            error = nil
            return
        }
        let (status, out) = await Self.run(["agent", "models", "list"])
        if status == 0 {
            models = out.split(whereSeparator: \.isNewline)
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty }
            error = nil
        } else {
            error = out.isEmpty ? "`models list` failed (exit \(status))" : out
        }
    }

    func add(_ nsid: String) async {
        if appManaged { await applyAppManaged(adding: nsid) } else { await mutate(["agent", "models", "add", nsid], model: nsid) }
    }
    func remove(_ nsid: String) async {
        if appManaged { await applyAppManaged(removing: nsid) } else { await mutate(["agent", "models", "remove", nsid]) }
    }

    /// Classify the `cocore agent models add` CLI output for `model`. The
    /// CLI bounces the LaunchAgent and tails the log for ~10s, printing
    /// `✓ <m> loaded` / `✗ <m> failed to load`, or a "couldn't confirm"
    /// note when a cold download outruns its window. Mirrors the markers
    /// in `models_cli::report_outcomes`.
    nonisolated static func classifyCliOutput(_ out: String, model: String) -> LoadStatus? {
        if out.contains("✗ \(model) failed") { return .failed(model) }
        if out.contains("✓ \(model) loaded") { return .loaded(model) }
        if out.contains("did not finish loading") || out.contains("couldn't confirm") {
            return .pending(model)
        }
        return nil
    }

    /// Classify a raw agent stdout line for `model`. Matches the per-model
    /// terminal lines `build_engines` emits — keep in sync with
    /// `models_cli::match_log_line` on the Rust side.
    nonisolated static func classifyAgentLine(_ line: String, model: String) -> LoadStatus? {
        guard line.contains(model) else { return nil }
        if line.contains("inference subprocess engine ready") { return .loaded(model) }
        if line.contains("inference engine load failed") { return .failed(model) }
        return nil
    }

    /// True when this engine list is the one the onboarding wizard can
    /// edit without going through the CLI/plist path.
    var isAppManaged: Bool { appManaged }

    /// Onboarding mutation: toggle a model in the stored list WITHOUT
    /// bouncing/starting the agent. The wizard starts the agent exactly
    /// once, in its final "Start serving" step, after the Python runtime
    /// is in place — going through `add`/`remove` here would bounce (and
    /// thus start) the agent on every pick, before the runtime exists,
    /// thrashing it into stub-only serving. App-managed installs keep the
    /// list in UserDefaults; with a LaunchAgent present we defer to the
    /// normal CLI path (launchd already runs the agent there).
    func onboardingToggle(_ nsid: String) async {
        guard appManaged else {
            if models.contains(nsid) { await remove(nsid) } else { await add(nsid) }
            return
        }
        var list = Self.storedModels()
        if let i = list.firstIndex(of: nsid) { list.remove(at: i) } else { list.append(nsid) }
        UserDefaults.standard.set(list.joined(separator: ","), forKey: Self.modelsDefaultsKey)
        models = list
    }

    /// No-LaunchAgent path: edit the UserDefaults model list, then restart
    /// the app-supervised agent so it re-reads COCORE_INFERENCE_MODELS.
    private func applyAppManaged(adding: String? = nil, removing: String? = nil) async {
        busy = true
        loadStatus = nil
        var list = Self.storedModels()
        if let a = adding, !list.contains(a) { list.append(a) }
        if let r = removing { list.removeAll { $0 == r } }
        UserDefaults.standard.set(list.joined(separator: ","), forKey: Self.modelsDefaultsKey)
        if let sup = supervisor {
            await sup.stop()
            await sup.start()
        }
        await refresh()
        busy = false
        // Watch the restarted agent's log for this model's load outcome
        // WITHOUT holding `busy` — a cold weight download can take a
        // minute, and we don't want the UI frozen that long. loadStatus
        // updates asynchronously when the terminal line arrives.
        if let a = adding { Task { await watchLoad(of: a) } }
    }

    /// Tail the app-supervised agent's stdout (via the supervisor's free
    /// `onLine` hook) for the per-model ready/failed line, so the tray can
    /// honestly report whether a freshly-added model actually started
    /// serving — the app-managed analogue of the CLI's log-tail. Best
    /// effort: on timeout we leave the optimistic "still loading" note
    /// rather than claiming success.
    private func watchLoad(of model: String, timeout: TimeInterval = 120) async {
        guard let sup = supervisor else { return }
        loadStatus = .pending(model)
        let prev = sup.onLine
        let resolved: LoadStatus? = await withCheckedContinuation { cont in
            var done = false
            sup.onLine = { line in
                prev?(line)
                if done { return }
                if let s = Self.classifyAgentLine(line, model: model) {
                    done = true
                    cont.resume(returning: s)
                }
            }
            Task { @MainActor in
                try? await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
                if !done {
                    done = true
                    cont.resume(returning: nil)
                }
            }
        }
        sup.onLine = prev
        if let r = resolved { loadStatus = r }
    }

    private func mutate(_ args: [String], model: String? = nil) async {
        busy = true
        loadStatus = nil
        let (status, out) = await Self.run(args)
        if status != 0 {
            error = out.isEmpty ? "command failed (exit \(status))" : out
        } else if let m = model {
            loadStatus = Self.classifyCliOutput(out, model: m)
        }
        await refresh()
        busy = false
    }

    /// Run the cocore CLI off the main actor; returns (status, combined
    /// stdout+stderr).
    nonisolated static func run(_ args: [String]) async -> (Int32, String) {
        await withCheckedContinuation { (cont: CheckedContinuation<(Int32, String), Never>) in
            DispatchQueue.global().async {
                guard let bin = AgentSupervisor.locateBinary() else {
                    cont.resume(returning: (-1, "co/core binary not found"))
                    return
                }
                let p = Process()
                p.executableURL = bin
                p.arguments = args
                let pipe = Pipe()
                p.standardOutput = pipe
                p.standardError = pipe
                do {
                    try p.run()
                    let data = pipe.fileHandleForReading.readDataToEndOfFile()
                    p.waitUntilExit()
                    cont.resume(returning: (p.terminationStatus, String(data: data, encoding: .utf8) ?? ""))
                } catch {
                    cont.resume(returning: (-1, String(describing: error)))
                }
            }
        }
    }
}

struct ModelsView: View {
    @ObservedObject var manager: ModelManager
    @StateObject private var venv = VenvBootstrapper()
    @State private var customNSID = ""
    @State private var venvInstalled = VenvBootstrapper.isInstalled
    /// Editor state for per-model schedules; source of truth while editing.
    /// Loaded from UserDefaults on appear, applied (debounced) on change.
    @State private var schedules: [String: ModelManager.Window] = [:]
    @State private var scheduleApplyTask: Task<Void, Never>?

    var body: some View {
        // Scrollable: the tab area is a fixed 520×600, and the content (model
        // list + per-model schedules + catalog + custom field) easily exceeds
        // it. Without this the bottom clips AND the overflow pushes the header
        // up under the tab bar. Mirrors the Form-backed Status/Help tabs.
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                Text("Models")
                .font(.title2).bold()
                .foregroundStyle(Brand.accentText)
            Text("Models this machine loads and advertises. Changes bounce the agent and re-publish your provider record within seconds.")
                .font(.footnote)
                .foregroundStyle(.secondary)
            Text("Any MLX-format model works — not just the suggestions below. co/core runs MLX weights (mlx-community/… or another repo with MLX 4-bit weights); stock PyTorch repos won't load.")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            runtimeBanner

            GroupBox("Active") {
                if manager.models.isEmpty {
                    Text("No models configured — the agent serves the stub engine only.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.vertical, 4)
                } else {
                    ForEach(manager.models, id: \.self) { m in
                        HStack {
                            Text(m)
                                .font(.system(.body, design: .monospaced))
                                .lineLimit(1)
                                .truncationMode(.middle)
                            Spacer()
                            Button(role: .destructive) {
                                Task { await manager.remove(m) }
                            } label: {
                                Image(systemName: "trash")
                            }
                            .buttonStyle(.borderless)
                            .disabled(manager.busy)
                            .help("Remove this model")
                        }
                        .padding(.vertical, 2)
                    }
                }
            }

            scheduleSection

            GroupBox("Add from catalog") {
                ForEach(ModelManager.catalogForDevice, id: \.nsid) { item in
                    let fits = ModelManager.fitsDevice(item.minRamGB)
                    let recommended = item.nsid == ModelManager.recommendedNSID
                    HStack {
                        VStack(alignment: .leading, spacing: 1) {
                            HStack(spacing: 6) {
                                Text(item.label)
                                    .font(.caption)
                                    .fontWeight(recommended ? .semibold : .regular)
                                if recommended {
                                    Text("recommended")
                                        .font(.caption2)
                                        .padding(.horizontal, 5)
                                        .padding(.vertical, 1)
                                        .background(Color.accentColor.opacity(0.15))
                                        .clipShape(Capsule())
                                }
                            }
                            Text(item.nsid)
                                .font(.system(.caption2, design: .monospaced))
                                .lineLimit(1)
                                .truncationMode(.middle)
                                .foregroundStyle(.secondary)
                            Text(
                                ModelManager.deviceRamGB == 0
                                    ? "needs ~\(item.minRamGB)GB"
                                    : (fits
                                        ? "needs ~\(item.minRamGB)GB · fits this Mac (\(ModelManager.deviceRamGB)GB)"
                                        : "needs ~\(item.minRamGB)GB — more than this Mac's \(ModelManager.deviceRamGB)GB")
                            )
                            .font(.caption2)
                            .foregroundStyle(fits ? AnyShapeStyle(.secondary) : AnyShapeStyle(.orange))
                        }
                        Spacer()
                        Button("Add") { Task { await manager.add(item.nsid) } }
                            .disabled(manager.busy || manager.models.contains(item.nsid))
                    }
                    .opacity(fits ? 1 : 0.65)
                    .padding(.vertical, 2)
                }
            }

            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    TextField("mlx-community/… (any MLX-format NSID)", text: $customNSID)
                        .textFieldStyle(.roundedBorder)
                    Button("Add") {
                        let n = customNSID.trimmingCharacters(in: .whitespaces)
                        guard !n.isEmpty else { return }
                        customNSID = ""
                        Task { await manager.add(n) }
                    }
                    .disabled(manager.busy || customNSID.trimmingCharacters(in: .whitespaces).isEmpty)
                }
                Text("Browse MLX models at [huggingface.co/mlx-community](https://huggingface.co/mlx-community). Find a model elsewhere? Look for an MLX (4-bit) conversion — the original PyTorch repo won't load.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .tint(.accentColor)
                    .fixedSize(horizontal: false, vertical: true)
            }

            if manager.busy {
                HStack(spacing: 6) {
                    ProgressView().controlSize(.small)
                    Text("Applying… (bouncing the agent)")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
            if let e = manager.error {
                Text(e)
                    .font(.footnote)
                    .foregroundStyle(.red)
                    .lineLimit(4)
            }
            if let s = manager.loadStatus {
                Text(s.text)
                    .font(.footnote)
                    .foregroundStyle(s.isFailure ? .red : .secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            }
            .padding(20)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .frame(minWidth: 460, maxWidth: .infinity, maxHeight: .infinity)
        .brandStyled()
        .task { await manager.refresh() }
        .onAppear { schedules = ModelManager.loadSchedules() }
    }

    // MARK: per-model schedule editor

    @ViewBuilder private var scheduleSection: some View {
        GroupBox("Per-model schedule") {
            VStack(alignment: .leading, spacing: 8) {
                Text("Give a model its own hours so it only loads (and uses RAM) part of the day. A model with no schedule is always on while the agent serves.")
                    .font(.footnote).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if let warn = ModelManager.overprovisionWarning(models: manager.models, schedules: schedules) {
                    Text("⚠ \(warn)")
                        .font(.footnote).foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if manager.models.isEmpty {
                    Text("Add a model above to schedule it.")
                        .font(.footnote).foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                } else {
                    ForEach(manager.models, id: \.self) { m in scheduleRow(m) }
                }
            }
        }
    }

    @ViewBuilder private func scheduleRow(_ m: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(m)
                    .font(.system(.caption, design: .monospaced))
                    .lineLimit(1).truncationMode(.middle)
                Spacer()
                Toggle(
                    "Custom hours",
                    isOn: Binding(
                        get: { schedules[m] != nil },
                        set: { on in
                            schedules[m] = on ? ModelManager.Window(start: 9, end: 17) : nil
                            scheduleChanged()
                        }
                    )
                )
                .toggleStyle(.switch).labelsHidden().disabled(manager.busy)
            }
            if schedules[m] != nil {
                HStack(spacing: 6) {
                    Text("from").font(.caption2).foregroundStyle(.secondary)
                    hourPicker(m, isStart: true)
                    Text("to").font(.caption2).foregroundStyle(.secondary)
                    hourPicker(m, isStart: false)
                    Spacer()
                }
            }
        }
        .padding(.vertical, 2)
    }

    private func hourPicker(_ m: String, isStart: Bool) -> some View {
        Picker(
            "",
            selection: Binding(
                get: { isStart ? (schedules[m]?.start ?? 9) : (schedules[m]?.end ?? 17) },
                set: { v in
                    var w = schedules[m] ?? ModelManager.Window(start: 9, end: 17)
                    if isStart { w.start = v } else { w.end = v }
                    schedules[m] = w
                    scheduleChanged()
                }
            )
        ) {
            ForEach(0..<24) { h in Text(PreferencesView.hourLabel(h)).tag(h) }
        }
        .labelsHidden().frame(width: 116).disabled(manager.busy)
    }

    /// Debounce: the editor updates instantly, but the (expensive) agent
    /// bounce waits ~800ms after the last change so dragging a picker
    /// doesn't restart the agent on every tick.
    private func scheduleChanged() {
        scheduleApplyTask?.cancel()
        let snapshot = schedules
        scheduleApplyTask = Task {
            try? await Task.sleep(nanoseconds: 800_000_000)
            if Task.isCancelled { return }
            await manager.applySchedules(snapshot)
        }
    }

    /// Prompt to install the Python runtime real models need, with live
    /// progress. Hidden once the runtime is present (e.g. headless/curl
    /// installs that bootstrapped it already).
    @ViewBuilder
    private var runtimeBanner: some View {
        if !venvInstalled {
            GroupBox {
                VStack(alignment: .leading, spacing: 8) {
                    switch venv.state {
                    case .running(let line):
                        HStack(spacing: 6) {
                            ProgressView().controlSize(.small)
                            Text("Setting up the Python runtime… \(line)")
                                .font(.footnote).foregroundStyle(.secondary)
                                .lineLimit(1).truncationMode(.middle)
                        }
                    case .failed(let msg):
                        Text(msg).font(.footnote).foregroundStyle(.red).lineLimit(3)
                        Button("Retry runtime setup") { runBootstrap() }
                    default:
                        Text("Real models need a one-time Python runtime (~280MB). Until it's installed the agent serves the stub engine only.")
                            .font(.footnote).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                        Button("Set up real-model runtime") { runBootstrap() }
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.vertical, 2)
            }
        }
    }

    private func runBootstrap() {
        Task {
            await venv.bootstrap()
            venvInstalled = VenvBootstrapper.isInstalled
            if venvInstalled { await manager.refresh() }
        }
    }
}

/// Hosts ModelsView in a standalone window opened from the menu bar.
@MainActor
final class ModelsWindowController {
    private var window: NSWindow?
    private let manager: ModelManager

    init(supervisor: AgentSupervisor? = nil) {
        self.manager = ModelManager(supervisor: supervisor)
    }

    func show() {
        if window == nil {
            let hosting = NSHostingController(rootView: ModelsView(manager: manager))
            let w = NSWindow(contentViewController: hosting)
            w.title = "co/core — Models"
            w.styleMask = [.titled, .closable, .miniaturizable]
            w.isReleasedWhenClosed = false
            w.center()
            window = w
        }
        if let w = window { WindowActivation.present(w) }
        Task { await manager.refresh() }
    }
}
