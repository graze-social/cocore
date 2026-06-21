// ModelsView: a window to manage which inference models this machine
// loads + advertises. Backed by the `cocore agent models` CLI, which
// edits the LaunchAgent's COCORE_INFERENCE_MODELS and bounces the
// daemon — the bounced agent re-publishes its provider record, so the
// change is visible on PDS + the AppView within seconds.

import AppKit
import SwiftUI

@MainActor
final class ModelManager: ObservableObject {
    @Published var models: [String] = [] { didSet { recomputeActive() } }
    /// `models` minus anything currently downloading — the Active list binds to
    /// this *stored* array (not a computed filter) because a grouped Form's
    /// ForEach mis-renders its last row when fed a freshly-built array each
    /// pass. Kept in sync via `didSet` on `models`/`downloadingModels`.
    @Published var activeModels: [String] = []
    @Published var busy = false
    @Published var error: String?
    /// Non-fatal feedback about the most recent add: whether the model
    /// actually loaded, failed, or is still downloading. Distinct from
    /// `error` (which is a hard command failure) — this is rendered in a
    /// softer style. Cleared at the start of each mutation.
    @Published var loadStatus: LoadStatus?
    /// Live weight-download progress while the agent provisions a model,
    /// read from `~/.cocore/provision-status.json` (which the agent writes
    /// for BOTH LaunchAgent and app-managed installs). nil when nothing is
    /// downloading. Polled by `startDownloadMonitor` while the Models tab
    /// is visible. See [[DownloadInfo]].
    @Published var download: DownloadInfo?
    /// Just the *set* of model ids currently downloading — changes only when a
    /// model starts/finishes, not on every byte update. The Active list keys
    /// off this (to exclude in-flight models) so it doesn't re-render — and
    /// glitch its grouped-Form row backgrounds — twice a second as `download`
    /// republishes progress.
    @Published var downloadingModels: Set<String> = [] { didSet { recomputeActive() } }

    private func recomputeActive() {
        let next = models.filter { !downloadingModels.contains($0) }
        if next != activeModels { activeModels = next }
    }

    /// A snapshot of the in-flight weight download. Byte counts come from the
    /// agent's provisioning marker (sum of the provisioning models' HF cache
    /// dirs); `total` is fetched once per model from the HuggingFace tree API
    /// so we can show a real percentage and ETA instead of a raw byte count.
    struct DownloadInfo: Equatable {
        /// Per-model progress. The marker reports a single aggregate byte
        /// count, so per-model `downloaded` is estimated by filling the
        /// aggregate across the models in order (a later model only starts
        /// counting once the earlier ones are complete). Exact for the common
        /// single-model case; a reasonable approximation for a batch.
        struct Item: Equatable, Identifiable {
            var model: String
            var downloaded: UInt64
            var total: UInt64?  // nil → size unknown (indeterminate bar)
            var id: String { model }
            var fraction: Double? {
                guard let total, total > 0 else { return nil }
                return min(1, Double(downloaded) / Double(total))
            }
        }
        var items: [Item]
        var downloaded: UInt64        // aggregate, for the overall rate/ETA
        var total: UInt64?            // aggregate sum, nil if any size unknown
        var bytesPerSec: Double?

        /// Seconds remaining, only when we have both a total and a non-trivial
        /// rate (a near-zero rate would project an absurd ETA).
        var eta: TimeInterval? {
            guard let total, total > downloaded, let r = bytesPerSec, r > 1024 else { return nil }
            return Double(total - downloaded) / r
        }
    }

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
    init(supervisor: AgentSupervisor? = nil) {
        self.supervisor = supervisor
        // Seed the model lists synchronously so the Active section has its rows
        // at first render. `refresh()` (async, kicked from the view's `.task`)
        // reconciles immediately after. Without a synchronous seed the list
        // goes empty → loaded, and that transition makes the first grouped-Form
        // section render its last row outside the rounded box.
        let seeded = Self.seededModels()
        models = seeded
        activeModels = seeded
    }

    /// Best-effort synchronous read of the configured models: the app-managed
    /// UserDefaults list, falling back to the LaunchAgent plist's
    /// `COCORE_INFERENCE_MODELS`. Used only to seed first render (`refresh()`
    /// is authoritative). Stub excluded, like the live path.
    private static func seededModels() -> [String] {
        let stored = storedModels().filter { $0 != stubModel }
        if !stored.isEmpty { return stored }
        let plist = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/LaunchAgents/dev.cocore.provider.plist")
        guard let dict = NSDictionary(contentsOf: plist),
            let env = dict["EnvironmentVariables"] as? [String: Any],
            let csv = env["COCORE_INFERENCE_MODELS"] as? String
        else { return [] }
        return csv.split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && $0 != stubModel }
    }
    private var appManaged: Bool { supervisor.map { !$0.isLaunchAgentManaged } ?? false }

    // MARK: download progress

    /// Polls the agent's provisioning marker once a second while the Models
    /// tab is on screen. The marker only carries downloaded bytes, so we
    /// also derive a smoothed rate here and (lazily, once per model) fetch
    /// each repo's total size from HuggingFace for a real percentage + ETA.
    private var downloadPollTask: Task<Void, Never>?
    private var lastSample: (bytes: UInt64, at: Date)?
    private var smoothedRate: Double?
    private var repoSizes: [String: UInt64] = [:]  // model → total bytes (HF tree)
    private var repoSizeFailed: Set<String> = []  // models whose size fetch 404'd / failed
    private var repoSizeInFlight: Set<String> = []

    func startDownloadMonitor() {
        guard downloadPollTask == nil else { return }
        downloadPollTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.pollDownload()
                // Poll twice a second so the card appears (and its bytes/rate
                // update) promptly once the agent starts writing the marker.
                try? await Task.sleep(nanoseconds: 500_000_000)
            }
        }
    }

    func stopDownloadMonitor() {
        downloadPollTask?.cancel()
        downloadPollTask = nil
        lastSample = nil
        smoothedRate = nil
        download = nil
        downloadingModels = []
    }

    /// One poll tick: read the marker, update the smoothed rate, and publish
    /// a `DownloadInfo`. Cheap and non-blocking — the (network) size fetch
    /// runs in a detached task and only feeds the cache.
    private func pollDownload() async {
        guard let s = MenuBarController.provisionStatus(), s.phase == "provisioning" else {
            // Only write when something actually changes — @Published fires on
            // every assignment, and an unconditional `download = nil` here would
            // re-render the whole Form twice a second (which glitches the
            // grouped section backgrounds).
            if download != nil { download = nil }
            if !downloadingModels.isEmpty { downloadingModels = [] }
            lastSample = nil
            smoothedRate = nil
            return
        }
        let now = Date()
        // Smoothed download rate from the change in total bytes between ticks.
        // An EMA keeps the number from jittering on HF's bursty transfers.
        if let prev = lastSample, now > prev.at, s.bytesDownloaded >= prev.bytes {
            let inst = Double(s.bytesDownloaded - prev.bytes) / now.timeIntervalSince(prev.at)
            smoothedRate = smoothedRate.map { 0.6 * $0 + 0.4 * inst } ?? inst
        }
        lastSample = (s.bytesDownloaded, now)

        ensureRepoSizes(for: s.models)

        // Accurate per-model progress: read each model's HF cache dir directly
        // (off the main actor) rather than splitting the aggregate, so we can
        // reliably tell which models are still downloading vs already complete.
        // The marker lists every provisioning model — most are usually already
        // on disk — so we keep only the ones still in flight.
        let models = s.models
        let perModel: [(String, UInt64, Bool)] = await Task.detached(priority: .utility) {
            models.map { ($0, Self.cacheBytes($0), Self.isDownloading($0)) }
        }.value

        var items: [DownloadInfo.Item] = []
        for (m, got, downloading) in perModel {
            // Show only models with an in-flight `.incomplete` blob. Comparing
            // bytes-on-disk to HF's repo total is unreliable for "done": mlx
            // fetches only the subset of files it needs, so a finished model
            // still reads ~99% of the full-repo total.
            guard downloading else { continue }
            items.append(DownloadInfo.Item(model: m, downloaded: got, total: repoSizes[m]))
        }
        guard !items.isEmpty else {
            // Nothing has an in-flight download right now.
            if download != nil { download = nil }
            if !downloadingModels.isEmpty { downloadingModels = [] }
            return
        }

        // Publish the downloading set only when it actually changes, so the
        // Active list (which excludes these) stays stable across progress ticks.
        let names = Set(items.map(\.model))
        if names != downloadingModels { downloadingModels = names }

        // Overall (in-progress only) totals drive the ETA; the rate is already
        // sampled from the marker's aggregate above.
        let aggDownloaded = items.reduce(0) { $0 + $1.downloaded }
        let aggTotal: UInt64? =
            items.allSatisfy { $0.total != nil } ? items.reduce(0) { $0 + ($1.total ?? 0) } : nil

        let next = DownloadInfo(
            items: items,
            downloaded: aggDownloaded,
            total: aggTotal,
            bytesPerSec: smoothedRate
        )
        if next != download { download = next }
    }

    /// The HuggingFace hub cache directory for `model`
    /// (`$HOME/.cache/huggingface/hub/models--org--name`; the agent sets no HF
    /// cache override — see `subprocess::hf_cache_size`).
    nonisolated static func weightCacheURL(_ model: String) -> URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".cache/huggingface/hub")
            .appendingPathComponent("models--\(model.replacingOccurrences(of: "/", with: "--"))")
    }

    /// Bytes a model's weights currently occupy on disk (completed +
    /// `.incomplete` blobs). 0 if nothing's downloaded yet.
    nonisolated static func cacheBytes(_ model: String) -> UInt64 {
        dirBytes(weightCacheURL(model))
    }

    /// Whether a model has an in-flight download: HuggingFace writes each blob
    /// to `blobs/<etag>.incomplete` and renames it on completion, so a leftover
    /// `.incomplete` file means bytes are still arriving. Reliable where a
    /// byte-count comparison isn't (mlx fetches only part of a repo).
    nonisolated static func isDownloading(_ model: String) -> Bool {
        let blobs = weightCacheURL(model).appendingPathComponent("blobs")
        let names = (try? FileManager.default.contentsOfDirectory(atPath: blobs.path)) ?? []
        return names.contains { $0.hasSuffix(".incomplete") }
    }

    /// Recursively sum regular-file sizes under `url`, skipping symlinks so
    /// HF's `snapshots/*` links into `blobs/` aren't double-counted (mirrors
    /// the agent's `subprocess::dir_size_bytes`).
    nonisolated static func dirBytes(_ url: URL) -> UInt64 {
        let keys: [URLResourceKey] = [.isSymbolicLinkKey, .isDirectoryKey, .isRegularFileKey, .fileSizeKey]
        guard let entries = try? FileManager.default.contentsOfDirectory(
            at: url, includingPropertiesForKeys: keys)
        else { return 0 }
        var total: UInt64 = 0
        for e in entries {
            guard let rv = try? e.resourceValues(forKeys: Set(keys)) else { continue }
            if rv.isSymbolicLink == true { continue }
            if rv.isDirectory == true {
                total &+= dirBytes(e)
            } else if rv.isRegularFile == true {
                total &+= UInt64(rv.fileSize ?? 0)
            }
        }
        return total
    }

    /// Kick off (at most once per model) a HuggingFace tree fetch for each
    /// model's total download size. Results land in `repoSizes`; failures are
    /// remembered in `repoSizeFailed` so we never refetch on every tick.
    private func ensureRepoSizes(for models: [String]) {
        for m in models
        where repoSizes[m] == nil && !repoSizeFailed.contains(m) && !repoSizeInFlight.contains(m) {
            repoSizeInFlight.insert(m)
            Task { [weak self] in
                let size = await Self.fetchRepoSize(m)
                guard let self else { return }
                if let size { self.repoSizes[m] = size } else { self.repoSizeFailed.insert(m) }
                self.repoSizeInFlight.remove(m)
            }
        }
    }

    /// Total download size of `model` via the HuggingFace tree API. Sums the
    /// LFS object sizes (the real weight bytes) plus small plain files. nil on
    /// any error — the UI then shows an indeterminate bar instead of a wrong %.
    nonisolated static func fetchRepoSize(_ model: String) async -> UInt64? {
        guard let url = URL(string: "https://huggingface.co/api/models/\(model)/tree/main?recursive=true")
        else { return nil }
        var req = URLRequest(url: url)
        req.timeoutInterval = 10
        guard let (data, resp) = try? await URLSession.shared.data(for: req),
            (resp as? HTTPURLResponse)?.statusCode == 200,
            let arr = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]]
        else { return nil }
        var total: UInt64 = 0
        for item in arr where (item["type"] as? String) == "file" {
            // For LFS weights the top-level `size` is the pointer (~130 B);
            // the real size lives under `lfs.size`. Prefer it when present.
            let lfs = (item["lfs"] as? [String: Any])?["size"] as? NSNumber
            let size = lfs ?? (item["size"] as? NSNumber)
            total += size?.uint64Value ?? 0
        }
        return total > 0 ? total : nil
    }

    /// A HuggingFace model-search hit, enriched with the size + descriptor we
    /// fetch per-model so the row can show RAM needs and what the model is.
    struct CatalogResult: Identifiable, Equatable {
        let id: String       // the `org/name` NSID
        let downloads: Int
        let weightBytes: UInt64?  // exact weight size (HF tree LFS sum); nil if unknown
        let pipelineTag: String?  // raw HF pipeline tag (e.g. "text-generation")
        let quant: String?        // e.g. "4-bit" / "8-bit", parsed from tags

        /// The model's resident weight footprint in GB — the deterministic,
        /// dominant term of its memory use (exact LFS bytes from the HF tree,
        /// no fudge factor). The KV cache rides on top of this at serve time
        /// and scales with context length. nil when the size is unknown (we
        /// don't guess). Rounded up so we never under-report.
        var weightGB: Int? {
            guard let b = weightBytes, b > 0 else { return nil }
            return max(1, Int((Double(b) / 1_073_741_824.0).rounded(.up)))
        }

        /// True when this model's weights fit the resource budget — or when its
        /// size is unknown (we can't prove it won't, so we don't disable it).
        var fitsBudget: Bool {
            guard ModelManager.budgetGB > 0, let w = weightGB else { return true }
            return w <= ModelManager.budgetGB
        }

        /// A short human descriptor from the model's HF metadata: the friendly
        /// task name plus the quantization (e.g. "Text generation · 4-bit").
        var subtitle: String? {
            let parts = [pipelineTag.map(ModelManager.friendlyTask), quant].compactMap { $0 }
            return parts.isEmpty ? nil : parts.joined(separator: " · ")
        }
    }

    /// Map an HF `pipeline_tag` to friendlier prose for the search row.
    nonisolated static func friendlyTask(_ tag: String) -> String {
        switch tag {
        case "text-generation": return "Text generation"
        case "text2text-generation": return "Text-to-text"
        case "image-text-to-text": return "Vision + text"
        case "image-to-text": return "Image captioning"
        case "automatic-speech-recognition": return "Speech-to-text"
        case "feature-extraction": return "Embeddings"
        default: return tag.replacingOccurrences(of: "-", with: " ").capitalized
        }
    }

    /// Search HuggingFace for MLX models matching `query`, most-downloaded
    /// first. `filter=mlx` restricts to the MLX library tag so every hit is
    /// loadable by the agent. Each hit is then enriched (concurrently) with
    /// its exact weight size (`fetchRepoSize`, the HF tree LFS sum) so the row
    /// can show a real weight footprint; results whose weights exceed the
    /// resource budget are sorted to the bottom (the UI disables them) rather
    /// than dropped. Empty on any error (the UI shows "no results").
    nonisolated static func searchModels(_ query: String) async -> [CatalogResult] {
        let q = query.trimmingCharacters(in: .whitespaces)
        guard !q.isEmpty,
            let encoded = q.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed),
            let url = URL(
                string: "https://huggingface.co/api/models?search=\(encoded)"
                    + "&filter=mlx&sort=downloads&direction=-1&limit=20")
        else { return [] }
        var req = URLRequest(url: url)
        req.timeoutInterval = 10
        guard let (data, resp) = try? await URLSession.shared.data(for: req),
            (resp as? HTTPURLResponse)?.statusCode == 200,
            let arr = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]]
        else { return [] }

        // Base hits, preserving HF's download-desc order.
        struct Hit { let id: String; let downloads: Int; let pipelineTag: String?; let quant: String? }
        let bitWidths = ["2-bit", "3-bit", "4-bit", "5-bit", "6-bit", "8-bit", "16-bit"]
        let hits: [Hit] = arr.compactMap { item in
            guard let id = item["id"] as? String else { return nil }
            let tags = (item["tags"] as? [String]) ?? []
            return Hit(
                id: id,
                downloads: (item["downloads"] as? NSNumber)?.intValue ?? 0,
                pipelineTag: item["pipeline_tag"] as? String,
                quant: bitWidths.first { tags.contains($0) })
        }

        // Enrich each hit with its exact weight size concurrently (one extra
        // tree call per model). Order is non-deterministic from the group, so
        // we re-sort.
        let enriched: [CatalogResult] = await withTaskGroup(of: CatalogResult.self) { group in
            for h in hits {
                group.addTask {
                    let bytes = await fetchRepoSize(h.id)
                    return CatalogResult(
                        id: h.id, downloads: h.downloads, weightBytes: bytes,
                        pipelineTag: h.pipelineTag, quant: h.quant)
                }
            }
            var out: [CatalogResult] = []
            for await r in group { out.append(r) }
            return out
        }

        // Runnable hits first (by downloads), then the over-budget ones at the
        // bottom — also by downloads. The UI renders the tail disabled.
        return enriched.sorted { a, b in
            if a.fitsBudget != b.fitsBudget { return a.fitsBudget }
            return a.downloads > b.downloads
        }
    }

    /// A quick-add catalog entry. `minRamGB` floors mirror the agent's
    /// `pricing::min_ram_gb`; `recommended` mirrors `pricing::RATES`'s
    /// `recommended` flag (the latest-&-greatest rotation we surface first).
    struct CatalogEntry {
        let nsid: String
        let label: String
        let minRamGB: Int
        let recommended: Bool
        let blurb: String
    }

    /// Curated quick-add catalog. `minRamGB` floors mirror the agent's
    /// `pricing::min_ram_gb`. These are suggestions, not an allowlist — any
    /// MLX-format HuggingFace `org/model` NSID works via the custom field.
    /// The `recommended` set is the current latest-&-greatest rotation
    /// (mirrors the Rust `RATES` `recommended: true` entries); the rest are
    /// kept as legacy choices. This is the OFFLINE fallback for the live
    /// `/v1/recommended-models` fetch.
    static let catalog: [CatalogEntry] = [
        // Recommended rotation (latest & greatest) — mirrors Rust RATES.
        CatalogEntry(nsid: "mlx-community/Qwen3.5-0.8B-MLX-4bit", label: "Qwen 3.5 0.8B", minRamGB: 4, recommended: true, blurb: "Tiny & fast — fits almost any Mac."),
        CatalogEntry(nsid: "mlx-community/Qwen3.5-2B-MLX-4bit", label: "Qwen 3.5 2B", minRamGB: 6, recommended: true, blurb: "Small, snappy general chat model."),
        CatalogEntry(nsid: "mlx-community/Qwen3.5-4B-MLX-4bit", label: "Qwen 3.5 4B", minRamGB: 8, recommended: true, blurb: "Solid all-rounder for everyday work."),
        CatalogEntry(nsid: "mlx-community/gemma-4-e4b-it-4bit", label: "Gemma 4 E4B", minRamGB: 8, recommended: true, blurb: "Google's compact instruct model."),
        CatalogEntry(nsid: "mlx-community/Qwen3.5-9B-MLX-4bit", label: "Qwen 3.5 9B", minRamGB: 16, recommended: true, blurb: "Strong mid-size reasoning."),
        CatalogEntry(nsid: "mlx-community/Qwen3.6-27B-4bit", label: "Qwen 3.6 27B", minRamGB: 24, recommended: true, blurb: "High-quality dense model."),
        CatalogEntry(nsid: "mlx-community/Qwen3.6-35B-A3B-4bit", label: "Qwen 3.6 35B A3B", minRamGB: 32, recommended: true, blurb: "MoE — big quality at modest active cost."),
        CatalogEntry(nsid: "mlx-community/Llama-4-Scout-17B-16E-Instruct-4bit", label: "Llama 4 Scout 17B", minRamGB: 64, recommended: true, blurb: "Meta's mixture-of-experts flagship."),
        CatalogEntry(nsid: "mlx-community/Qwen3.5-122B-A10B-4bit", label: "Qwen 3.5 122B A10B", minRamGB: 96, recommended: true, blurb: "Frontier-class MoE for big rigs."),
        // Legacy choices — still serviceable, no longer the front-runners.
        CatalogEntry(nsid: "mlx-community/Qwen2.5-0.5B-Instruct-4bit", label: "Qwen 2.5 0.5B", minRamGB: 4, recommended: false, blurb: "Legacy tiny model."),
        CatalogEntry(nsid: "mlx-community/Qwen2.5-3B-Instruct-4bit", label: "Qwen 2.5 3B", minRamGB: 8, recommended: false, blurb: "Legacy small model."),
        CatalogEntry(nsid: "mlx-community/gemma-3-4b-it-qat-4bit", label: "Gemma 3 4B", minRamGB: 8, recommended: false, blurb: "Legacy Gemma instruct model."),
        CatalogEntry(nsid: "mlx-community/Qwen2.5-7B-Instruct-4bit", label: "Qwen 2.5 7B", minRamGB: 16, recommended: false, blurb: "Legacy mid-size model."),
        CatalogEntry(nsid: "mlx-community/Qwen2.5-32B-Instruct-4bit", label: "Qwen 2.5 32B", minRamGB: 32, recommended: false, blurb: "Legacy large model."),
        CatalogEntry(nsid: "mlx-community/Llama-3.3-70B-Instruct-4bit", label: "Llama 3.3 70B", minRamGB: 64, recommended: false, blurb: "Legacy flagship model."),
    ]

    /// The recommended (latest & greatest) subset of the catalog mirror.
    static var recommendedCatalog: [CatalogEntry] { catalog.filter { $0.recommended } }

    /// This Mac's physical RAM in GB (rounded), via sysctl `hw.memsize`.
    /// 0 if the probe fails, in which case the picker degrades to showing
    /// every model without a fit judgment.
    nonisolated static let deviceRamGB: Int = {
        var bytes: UInt64 = 0
        var size = MemoryLayout<UInt64>.size
        guard sysctlbyname("hw.memsize", &bytes, &size, nil, 0) == 0, bytes > 0 else { return 0 }
        return Int((Double(bytes) / 1_073_741_824.0).rounded())
    }()

    static func fitsDevice(_ minRamGB: Int) -> Bool {
        deviceRamGB == 0 || minRamGB <= deviceRamGB
    }

    /// Whether a model with this RAM floor fits the resource budget — i.e.
    /// runs comfortably without eating the user reserve. This is the gate
    /// the lists use to decide "runnable on this Mac" (a model can be ≤ total
    /// RAM yet still over budget). True when RAM is unknown.
    static func fitsBudget(_ minRamGB: Int) -> Bool {
        budgetGB == 0 || minRamGB <= budgetGB
    }

    /// RAM (GB) actually available to serve models, after holding back the
    /// user reserve the agent reserves for the OS + the owner's own apps.
    /// This — not raw `deviceRamGB` — is the threshold a model must fit under
    /// to run *comfortably* (the green band in `budgetReport`). 0 when RAM is
    /// unknown.
    nonisolated static var budgetGB: Int {
        guard deviceRamGB > 0 else { return 0 }
        return deviceRamGB - userReserveGB(deviceRamGB)
    }

    /// The biggest *recommended* catalog model that fits this Mac's resource
    /// budget — the suggested default. "Fits" here means it lands in the
    /// comfortable band (`minRamGB <= budgetGB`), i.e. it leaves the reserve
    /// intact rather than consuming all of RAM; this mirrors what
    /// `budgetReport` would classify green. Prefers the latest-&-greatest
    /// rotation; falls back to any budget-fitting catalog model if no
    /// recommended one fits. nil when RAM is unknown or nothing fits.
    static var recommendedNSID: String? {
        guard budgetGB > 0 else { return nil }
        let fitting = catalog.filter { $0.minRamGB <= budgetGB }
        if let best = fitting.filter({ $0.recommended }).max(by: { $0.minRamGB < $1.minRamGB }) {
            return best.nsid
        }
        return fitting.max(by: { $0.minRamGB < $1.minRamGB })?.nsid
    }

    /// Catalog ordered best-for-this-device first: budget-fitting models by
    /// descending size (the biggest comfortable pick on top), then the ones
    /// that need more RAM than this Mac's budget — those trail at the bottom
    /// and the UI renders them disabled. Falls back to declaration order when
    /// RAM is unknown.
    static var catalogForDevice: [CatalogEntry] {
        guard budgetGB > 0 else { return catalog }
        let fits = catalog.filter { fitsBudget($0.minRamGB) }.sorted { $0.minRamGB > $1.minRamGB }
        let tooBig = catalog.filter { !fitsBudget($0.minRamGB) }.sorted { $0.minRamGB < $1.minRamGB }
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

    // MARK: resource budget (mirrors Rust `pricing::budget_report`)

    /// RAM (GB) to hold back for the OS + the owner's own apps so a personal
    /// Mac stays usable while it serves. `ceil(total/5)` (20%), clamped to
    /// [2, 12]. Byte-for-byte the same as Rust `pricing::user_reserve_gb`.
    nonisolated static func userReserveGB(_ total: Int) -> Int {
        guard total > 0 else { return 0 }
        return min(max(Int(ceil(Double(total) / 5.0)), 2), 12)
    }

    /// Traffic-light verdict for a pinned set on this machine. Mirrors Rust
    /// `pricing::BudgetStatus`.
    enum BudgetStatus {
        case comfortable  // green — fits with headroom for you
        case tight        // yellow — fits, but little left for your own work
        case oversubscribed  // red — exceeds RAM; agent drops the largest to fit
    }

    /// A computed budget verdict for a pinned model set, driving the meter +
    /// traffic-light. Mirrors Rust `pricing::BudgetReport`. `used` sums the
    /// worst overlapping SCHEDULED hour's catalog floors (off-catalog/unknown
    /// models contribute 0); the agent enforces the same budget by pruning
    /// largest-first.
    struct BudgetReport {
        let usedGB: Int
        let reserveGB: Int
        let totalGB: Int
        let status: BudgetStatus
        /// The worst overlapping hour (0–23) the `used` total comes from.
        let worstHour: Int
    }

    /// Classify a pinned set against this machine's RAM, respecting per-model
    /// schedules: `used` is the largest sum over any single hour's active set.
    /// The single source of truth for the meter, the warning copy, and the
    /// agent's startup budget — green/yellow/red is identical everywhere.
    static func budgetReport(models: [String], schedules: [String: Window]) -> BudgetReport {
        let total = deviceRamGB
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
        let reserve = userReserveGB(total)
        let status: BudgetStatus
        if total > 0, worstSum > total {
            status = .oversubscribed
        } else if total > 0, worstSum + reserve > total {
            status = .tight
        } else {
            status = .comfortable
        }
        return BudgetReport(
            usedGB: worstSum, reserveGB: reserve, totalGB: total,
            status: status, worstHour: worstHour)
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

    /// The always-loaded in-process fallback engine. Every agent serves it
    /// implicitly (and `agent models list` reports it), but it isn't a
    /// user-managed model — you can't remove it and you wouldn't schedule it —
    /// so we hide it from the Active list. See `models_cli` on the Rust side.
    static let stubModel = "stub"

    func refresh() async {
        if appManaged {
            setModels(Self.storedModels().filter { $0 != Self.stubModel })
            if error != nil { error = nil }
            return
        }
        let (status, out) = await Self.run(["agent", "models", "list"])
        if status == 0 {
            setModels(
                out.split(whereSeparator: \.isNewline)
                    .map { $0.trimmingCharacters(in: .whitespaces) }
                    // Drop the stub, and anything that isn't a model id. `models
                    // list` prints a human sentence ("No models configured … the
                    // stub engine.") when nothing is set; a real NSID never
                    // contains spaces, so this rejects the message and leaves the
                    // empty state rather than rendering the sentence as a row.
                    .filter { !$0.isEmpty && $0 != Self.stubModel && !$0.contains(" ") })
            if error != nil { error = nil }
        } else {
            let e = out.isEmpty ? "`models list` failed (exit \(status))" : out
            if error != e { error = e }
        }
    }

    /// Assign `models` only when it actually changed, so a refresh that returns
    /// the same list (e.g. matching the synchronous seed) doesn't re-publish
    /// and trigger a Form re-layout that glitches the grouped section.
    private func setModels(_ next: [String]) {
        if next != models { models = next }
    }

    func add(_ nsid: String) async {
        if appManaged { await applyAppManaged(adding: nsid) } else { await mutate(["agent", "models", "add", nsid], model: nsid) }
    }
    func remove(_ nsid: String) async {
        // Optimistic: drop it from the visible list immediately so the row
        // disappears on click — the agent bounce below takes a few seconds and
        // we don't want every trash button greyed out (via `busy`) while it
        // runs. refresh() at the end reconciles.
        models.removeAll { $0 == nsid }
        if appManaged { await applyAppManaged(removing: nsid) } else { await mutate(["agent", "models", "remove", nsid]) }
        // Removing a model from the serving list leaves its (often multi-GB)
        // weights in the HuggingFace cache. The agent has been bounced above
        // (so nothing holds the files open and the dropped model isn't
        // reloaded), so now actually free the disk. Runs off the main actor —
        // deleting a large tree shouldn't block the UI.
        await Self.deleteWeightCache(nsid)
    }

    /// Delete a model's downloaded weights from the HuggingFace hub cache so a
    /// remove frees the disk. Mirrors the agent's cache layout
    /// (`$HOME/.cache/huggingface/hub/models--org--name`; the agent sets no HF
    /// cache override — see `subprocess::hf_cache_size`). Best-effort: a
    /// missing dir is fine.
    nonisolated static func deleteWeightCache(_ nsid: String) async {
        await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
            DispatchQueue.global(qos: .utility).async {
                try? FileManager.default.removeItem(at: weightCacheURL(nsid))
                cont.resume()
            }
        }
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

    /// Fetch the live recommended-models set from the console
    /// (`GET {consoleURL}/v1/recommended-models`, shape
    /// `[{id, minRamGb, blurb}]`). Falls back to the hardcoded mirror
    /// (`recommendedCatalog`) on any failure, so the picker still works
    /// offline. Best-effort, no throw.
    static func fetchRecommended() async -> [CatalogEntry] {
        struct Wire: Decodable {
            let id: String
            let minRamGb: Int?
            let blurb: String?
        }
        guard let url = URL(string: "\(Endpoints.consoleURL)/v1/recommended-models") else {
            return recommendedCatalog
        }
        var req = URLRequest(url: url)
        req.timeoutInterval = 8
        guard let (data, resp) = try? await URLSession.shared.data(for: req),
            (resp as? HTTPURLResponse)?.statusCode == 200,
            let wire = try? JSONDecoder().decode([Wire].self, from: data),
            !wire.isEmpty
        else { return recommendedCatalog }
        return wire.map { w in
            // Keep the friendly label/blurb from the mirror when we know the
            // id, so live entries still render nicely; else derive a label.
            let known = catalog.first { $0.nsid == w.id }
            return CatalogEntry(
                nsid: w.id,
                label: known?.label ?? friendlyLabel(for: w.id),
                minRamGB: w.minRamGb ?? known?.minRamGB ?? 0,
                recommended: true,
                blurb: w.blurb ?? known?.blurb ?? "")
        }
    }

    /// Derive a human label from an `org/model` NSID when it isn't in the
    /// mirror (live recommended entries the app doesn't know yet).
    nonisolated static func friendlyLabel(for nsid: String) -> String {
        let tail = nsid.split(separator: "/").last.map(String.init) ?? nsid
        return tail.replacingOccurrences(of: "-", with: " ")
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
    @State private var venvInstalled = VenvBootstrapper.isInstalled
    /// Editor state for per-model schedules; source of truth while editing.
    /// Loaded from UserDefaults on appear, applied (debounced) on change.
    @State private var schedules: [String: ModelManager.Window] = [:]
    @State private var scheduleApplyTask: Task<Void, Never>?

    /// HuggingFace model search (the "Add a model" section).
    @State private var searchQuery = ""
    @State private var searchResults: [ModelManager.CatalogResult] = []
    @State private var searching = false
    @State private var searchTask: Task<Void, Never>?
    /// Live recommended set from the console (falls back to the mirror).
    /// Drives the "Latest" badges; loaded once on appear.
    @State private var recommendedNSIDs: Set<String> = Set(ModelManager.recommendedCatalog.map { $0.nsid })

    /// Debounced HuggingFace search: the field updates instantly, the network
    /// query waits ~350ms after the last keystroke.
    private func runSearch(_ raw: String) {
        searchTask?.cancel()
        let query = raw.trimmingCharacters(in: .whitespaces)
        guard !query.isEmpty else {
            searchResults = []
            searching = false
            return
        }
        searching = true
        searchTask = Task {
            try? await Task.sleep(nanoseconds: 350_000_000)
            if Task.isCancelled { return }
            let results = await ModelManager.searchModels(query)
            if Task.isCancelled { return }
            searchResults = results
            searching = false
        }
    }


    /// Grouped Form footnotes: footnote-sized and secondary-colored like
    /// Settings explanatory text. Let the Form place the footer so its leading
    /// edge matches the section header above (custom insets break that).
    private func sectionFooter(_ text: String) -> some View {
        Text(text)
            .font(.footnote)
            .foregroundStyle(.secondary)
            .multilineTextAlignment(.leading)
            .fixedSize(horizontal: false, vertical: true)
    }

    var body: some View {
        // A native grouped Form — the same shape as the Status/Settings/About
        // tabs — so the Models tab reads as standard macOS settings: section
        // headers, footnote footers, and automatic row insets instead of
        // hand-tuned padding. The tab host (MainWindowController.tab) sizes the
        // pane; the Form scrolls its own overflow.
        Form {
            if !venvInstalled {
                Section { runtimeRows }
            }

            Section {
                if manager.activeModels.isEmpty {
                    Text(manager.downloadingModels.isEmpty
                        ? "No models configured — the agent serves the stub engine only."
                        : "No models are serving yet — see Downloading below.")
                        .foregroundStyle(.secondary)
                } else {
                    // Render the whole list inside ONE Form row (a VStack with
                    // manual dividers). A grouped Form section made of multiple
                    // dynamic ForEach rows hits a macOS rendering bug where the
                    // section background only covers the first row; collapsing
                    // it to a single row sidesteps that entirely.
                    VStack(spacing: 0) {
                        ForEach(Array(manager.activeModels.enumerated()), id: \.element) { index, m in
                            // Space lives around the divider (between items),
                            // not on the rows — so the box edges stay tight and
                            // the text isn't crowding the separators.
                            if index > 0 { Divider().padding(.vertical, 9) }
                            activeRow(m)
                        }
                    }
                }
            } header: {
                Text("Active models")
            } footer: {
                sectionFooter(
                    "Models this machine loads and advertises. Changes bounce the agent and re-publish your provider record within seconds."
                )
            }

            if let items = manager.download?.items, !items.isEmpty {
                Section {
                    VStack(spacing: 0) {
                        ForEach(Array(items.enumerated()), id: \.element.id) { index, item in
                            if index > 0 { Divider().padding(.vertical, 9) }
                            downloadRow(item)
                        }
                    }
                } header: {
                    Text("Downloading")
                } footer: {
                    sectionFooter(
                        "First-time downloads can take a while — you can close this window; it keeps going in the background."
                    )
                }
            }

            if ModelManager.deviceRamGB > 0 {
                Section {
                    budgetMeter
                } header: {
                    Text("Resource budget")
                }
            }

            Section {
                VStack(alignment: .leading, spacing: 0) {
                    // Oversubscription is surfaced by the Resource budget meter
                    // above (WS-E: the 3-state Comfortable/Tight/Oversubscribed
                    // headroom report), so no separate inline warning here.
                    if manager.models.isEmpty {
                        Text("Add a model above to schedule it.")
                            .foregroundStyle(.secondary)
                    } else {
                        ForEach(Array(manager.models.enumerated()), id: \.element) { index, m in
                            if index > 0 { Divider().padding(.vertical, 9) }
                            scheduleRow(m)
                        }
                    }
                }
            } header: {
                Text("Per-model schedule")
            } footer: {
                sectionFooter(
                    "Give a model its own hours so it only loads (and uses RAM) part of the day. A model with no schedule is always on while the agent serves."
                )
            }

            Section {
                HStack(spacing: 8) {
                    // labelsHidden + prompt: a plain full-width search box with
                    // an in-field placeholder, not a Form label/value row (which
                    // would push the typed text to the right and wrap the
                    // placeholder).
                    TextField(
                        "Search", text: $searchQuery,
                        prompt: Text("Search HuggingFace for MLX models…")
                    )
                    .labelsHidden()
                    .textFieldStyle(.roundedBorder)
                    if searching { ProgressView().controlSize(.small) }
                }

                if searchQuery.trimmingCharacters(in: .whitespaces).isEmpty {
                    // No query: the curated, device-fit suggestions. Already-added
                    // models are dropped — they live in "Active models" above.
                    let suggestions = ModelManager.catalogForDevice.filter {
                        !manager.models.contains($0.nsid)
                    }
                    ForEach(suggestions, id: \.nsid) { catalogRow($0) }
                } else if searchResults.isEmpty && !searching {
                    Text("No MLX models found for “\(searchQuery.trimmingCharacters(in: .whitespaces))”.")
                        .foregroundStyle(.secondary)
                } else {
                    // Already-added models are dropped (shown in "Active models").
                    let hits = searchResults.filter { !manager.models.contains($0.id) }
                    ForEach(hits) { searchRow($0) }
                    // Power-user escape hatch: add an exact `org/name` that the
                    // search didn't surface.
                    let q = searchQuery.trimmingCharacters(in: .whitespaces)
                    if q.contains("/"), !searchResults.contains(where: { $0.id == q }) {
                        HStack {
                            Text(q)
                                .font(.system(.callout, design: .monospaced))
                                .lineLimit(1).truncationMode(.middle)
                            Spacer()
                            Button("Add exactly") { Task { await manager.add(q) } }
                                .disabled(manager.busy || manager.models.contains(q))
                        }
                    }
                }
            } header: {
                Text("Add a model")
            } footer: {
                sectionFooter(
                    "Search any MLX model on HuggingFace, or pick a suggestion. co/core runs MLX weights (mlx-community/… or another 4-bit MLX conversion); a stock PyTorch repo won't load."
                )
            }
            .onChange(of: searchQuery) { query in runSearch(query) }

            if manager.busy || manager.error != nil || manager.loadStatus != nil {
                Section {
                    if manager.busy {
                        HStack(spacing: 6) {
                            ProgressView().controlSize(.small)
                            Text("Applying… (bouncing the agent)")
                                .foregroundStyle(.secondary)
                        }
                    }
                    if let e = manager.error {
                        Text(e).foregroundStyle(.red).lineLimit(4)
                    }
                    if let s = manager.loadStatus {
                        Text(s.text)
                            .foregroundStyle(s.isFailure ? .red : .secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
        }
        .formStyle(.grouped)
        .frame(minWidth: 460, maxWidth: .infinity, maxHeight: .infinity)
        .brandStyled()
        .task { await manager.refresh() }
        .task {
            // Pull the live recommended set (falls back to the mirror); drives
            // the "Latest" badges. Best-effort, never blocks the UI.
            let live = await ModelManager.fetchRecommended()
            recommendedNSIDs = Set(live.map { $0.nsid })
        }
        .onAppear {
            schedules = ModelManager.loadSchedules()
            manager.startDownloadMonitor()
        }
        .onDisappear { manager.stopDownloadMonitor() }
    }

    // MARK: active / download rows

    /// A ready model: name + a red trash that frees the disk. No global
    /// `busy` disable — removal is optimistic (the row vanishes on click), so
    /// the other trashes stay live.
    @ViewBuilder private func activeRow(_ m: String) -> some View {
        let ram = ModelManager.minRamGB(for: m)
        HStack {
            Text(m)
                .font(.system(.callout, design: .monospaced))
                .lineLimit(1).truncationMode(.middle)
            // Small neutral pill with this model's RAM footprint (the same
            // per-model figure the budget meter sums). Omitted for off-catalog
            // models whose floor we don't know.
            if ram > 0 {
                Text("~\(ram) GB")
                    .font(.caption2)
                    .padding(.horizontal, 5)
                    .padding(.vertical, 1)
                    .background(Color.secondary.opacity(0.15))
                    .foregroundStyle(.secondary)
                    .clipShape(Capsule())
                    .help("Approximate RAM this model needs while serving")
            }
            Spacer()
            Button(role: .destructive) {
                Task { await manager.remove(m) }
            } label: {
                Image(systemName: "trash")
            }
            .buttonStyle(.borderless)
            .tint(.red)
            .help("Remove this model")
        }
    }

    /// A still-downloading model (own "Downloading" section): the name dimmed
    /// (it isn't serving yet), its size/percent on the same row, a trash to
    /// cancel + free the partial download, and its progress bar below.
    @ViewBuilder private func downloadRow(_ item: ModelManager.DownloadInfo.Item) -> some View {
        HStack(spacing: 14) {
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    Text(item.model)
                        .font(.system(.callout, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .lineLimit(1).truncationMode(.middle)
                    // A wide minimum gap so the size never crowds the name.
                    Spacer(minLength: 24)
                    Text(sizeLabel(item))
                        .font(.footnote).foregroundStyle(.secondary)
                        .layoutPriority(1)
                }
                if let frac = item.fraction {
                    ProgressView(value: frac)
                } else {
                    // Size unknown — indeterminate bar so it still reads as
                    // "in progress".
                    ProgressView().progressViewStyle(.linear)
                }
            }
            // Trash sits to the right of the whole block (name/size + bar),
            // vertically centered.
            Button(role: .destructive) {
                Task { await manager.remove(item.model) }
            } label: {
                Image(systemName: "trash")
            }
            .buttonStyle(.borderless)
            .tint(.red)
            .help("Cancel download and remove this model")
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    /// The per-model size label shown on the name row: "1.2 GB of 1.6 GB · 73%"
    /// when the repo size is known, else a plain downloaded count. The
    /// numerator is clamped to the total (our cache-dir byte count can slightly
    /// exceed HF's estimate, which would otherwise read "1.7 GB of 1.6 GB").
    private func sizeLabel(_ item: ModelManager.DownloadInfo.Item) -> String {
        if let total = item.total, let frac = item.fraction {
            return "\(MenuBarController.humanBytes(min(item.downloaded, total))) of "
                + "\(MenuBarController.humanBytes(total)) · \(Int(frac * 100))%"
        }
        return "\(MenuBarController.humanBytes(item.downloaded)) downloaded"
    }

    // MARK: resource budget meter + traffic light

    /// A horizontal meter showing pinned RAM vs this Mac's total, with the
    /// owner-reserve band marked, plus a traffic-light status line. Mirrors
    /// the Rust `pricing::budget_report` verdict exactly. Hosted inside the
    /// Form's "Resource budget" Section (which provides the heading), so this
    /// draws just the bar + labels + status line.
    @ViewBuilder private var budgetMeter: some View {
        let report = ModelManager.budgetReport(models: manager.models, schedules: schedules)
        let total = report.totalGB
        let used = report.usedGB
        let reserve = report.reserveGB
        let (color, title, detail): (Color, String, String?) = {
            switch report.status {
            case .comfortable:
                return (Brand.success, "Comfortable", nil)
            case .tight:
                return (
                    .orange, "Tight",
                    "Your in-use models fit, but leave little for you — this Mac may get "
                        + "sluggish while you work. Drop one or stagger their hours.")
            case .oversubscribed:
                return (
                    .red, "Oversubscribed",
                    "Your in-use models need more RAM than this Mac has. The agent will drop "
                        + "the largest to fit; remove one or schedule them at different hours.")
            }
        }()
        VStack(alignment: .leading, spacing: 8) {
            GeometryReader { geo in
                let w = geo.size.width
                let denom = CGFloat(max(total, max(used, 1)))
                let usedW = min(w, w * CGFloat(used) / denom)
                // Reserve band sits at the top end of total RAM.
                let reserveStart = w * CGFloat(max(total - reserve, 0)) / denom
                let reserveW = min(w - reserveStart, w * CGFloat(reserve) / denom)
                ZStack(alignment: .leading) {
                    RoundedRectangle(cornerRadius: 5)
                        .fill(Color.secondary.opacity(0.18))
                    // Reserve band (held back for the owner).
                    RoundedRectangle(cornerRadius: 0)
                        .fill(Color.secondary.opacity(0.28))
                        .frame(width: max(0, reserveW))
                        .offset(x: reserveStart)
                    // Used (pinned models) fill.
                    RoundedRectangle(cornerRadius: 5)
                        .fill(color.opacity(0.85))
                        .frame(width: max(0, usedW))
                }
            }
            .frame(height: 14)

            Text(
                "In use \(used) GB · Reserved for you \(reserve) GB · This Mac \(total) GB"
            )
            .font(.caption).foregroundStyle(.secondary)

            HStack(spacing: 6) {
                Circle().fill(color).frame(width: 9, height: 9)
                Text(title).font(.footnote.weight(.semibold)).foregroundStyle(color)
            }
            if let detail {
                Text(detail)
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                Text("Comfortable headroom for your own work while you serve.")
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    // MARK: catalog row

    /// One row in the "Add from catalog" section: label (+ a green "Latest"
    /// badge for models in the recommended rotation, + a "recommended for this
    /// Mac" accent tag for the best fit), the monospaced NSID, the RAM-fit
    /// line, and a standard Add button. The model's blurb sits under the name.
    @ViewBuilder private func catalogRow(_ item: ModelManager.CatalogEntry) -> some View {
        let fits = ModelManager.fitsBudget(item.minRamGB)
        let suggested = item.nsid == ModelManager.recommendedNSID
        let isLatest = recommendedNSIDs.contains(item.nsid)
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(item.label)
                        .fontWeight(suggested ? .semibold : .regular)
                    if isLatest {
                        Text("Latest")
                            .font(.caption2.weight(.semibold))
                            .padding(.horizontal, 5)
                            .padding(.vertical, 1)
                            .background(Brand.success.opacity(0.18))
                            .foregroundStyle(Brand.success)
                            .clipShape(Capsule())
                    }
                    if suggested {
                        Text("recommended for this Mac")
                            .font(.caption)
                            .foregroundStyle(.tint)
                    }
                }
                if !item.blurb.isEmpty {
                    Text(item.blurb)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .lineLimit(1).truncationMode(.tail)
                }
                Text(item.nsid)
                    .font(.system(.callout, design: .monospaced))
                    .lineLimit(1).truncationMode(.middle)
                    .foregroundStyle(.secondary)
                Text(
                    ModelManager.deviceRamGB == 0
                        ? "needs ~\(item.minRamGB)GB"
                        : (fits
                            ? "needs ~\(item.minRamGB)GB · fits this Mac (\(ModelManager.deviceRamGB)GB)"
                            : "needs ~\(item.minRamGB)GB — over this Mac's \(ModelManager.budgetGB)GB budget")
                )
                .font(.footnote)
                .foregroundStyle(fits ? AnyShapeStyle(.secondary) : AnyShapeStyle(.orange))
            }
            Spacer()
            Button("Add") { Task { await manager.add(item.nsid) } }
                .disabled(manager.busy || !fits || manager.models.contains(item.nsid))
        }
        .opacity(fits ? 1 : 0.65)
    }

    /// One HuggingFace search result: the NSID, its download count, and Add.
    @ViewBuilder private func searchRow(_ r: ModelManager.CatalogResult) -> some View {
        let fits = r.fitsBudget
        // "needs ~14 GB (weights) · 12.3K downloads" — weight footprint omitted
        // when the size is unknown. KV cache rides on top at serve time.
        let ram: String? = r.weightGB.map { "needs ~\($0) GB (weights)" }
        let stats = [ram, "\(Self.formatDownloads(r.downloads)) downloads"]
            .compactMap { $0 }.joined(separator: " · ")
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(r.id)
                    .font(.system(.callout, design: .monospaced))
                    .lineLimit(1).truncationMode(.middle)
                if let subtitle = r.subtitle {
                    Text(subtitle)
                        .font(.footnote).foregroundStyle(.secondary)
                        .lineLimit(1).truncationMode(.tail)
                }
                Text(stats)
                    .font(.footnote)
                    .foregroundStyle(fits ? AnyShapeStyle(.secondary) : AnyShapeStyle(.orange))
            }
            Spacer()
            Button("Add") { Task { await manager.add(r.id) } }
                .disabled(manager.busy || !fits || manager.models.contains(r.id))
        }
        .opacity(fits ? 1 : 0.65)
    }

    /// Compact download count, e.g. 1_234_567 → "1.2M", 9_400 → "9.4K".
    private static func formatDownloads(_ n: Int) -> String {
        switch n {
        case 1_000_000...: return String(format: "%.1fM", Double(n) / 1_000_000)
        case 1_000...: return String(format: "%.1fK", Double(n) / 1_000)
        default: return "\(n)"
        }
    }

    @ViewBuilder private func scheduleRow(_ m: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(m)
                    .font(.system(.callout, design: .monospaced))
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
                    Text("from").font(.footnote).foregroundStyle(.secondary)
                    hourPicker(m, isStart: true)
                    Text("to").font(.footnote).foregroundStyle(.secondary)
                    hourPicker(m, isStart: false)
                    Spacer()
                }
            }
        }
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

    /// Rows prompting to install the Python runtime real models need, with
    /// live progress. The body only renders this section while the runtime is
    /// absent (e.g. headless/curl installs that bootstrapped it already).
    @ViewBuilder
    private var runtimeRows: some View {
        switch venv.state {
        case .running(let line):
            HStack(spacing: 6) {
                ProgressView().controlSize(.small)
                Text("Setting up the Python runtime… \(line)")
                    .foregroundStyle(.secondary)
                    .lineLimit(1).truncationMode(.middle)
            }
        case .failed(let msg):
            Text(msg).foregroundStyle(.red).lineLimit(3)
            Button("Retry runtime setup") { runBootstrap() }
        default:
            Text("Real models need a one-time Python runtime (~280MB). Until it's installed the agent serves the stub engine only.")
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Button("Set up real-model runtime") { runBootstrap() }
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
