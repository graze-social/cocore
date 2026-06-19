// PreferencesView: SwiftUI settings window.
//
// Single source of truth for: console URL, advisor URL, AppView URL,
// schedule (idle windows), and price list. Bound to UserDefaults with
// @AppStorage so changes persist immediately and are picked up by the
// agent on its next launch.

import AppKit
import SwiftUI

/// Hosts PreferencesView in a real NSWindow opened from the menu bar.
/// The SwiftUI `Settings` scene's `showSettingsWindow:` action no-ops
/// for an `.accessory` app with no responder, so we own the window
/// ourselves (same pattern as ModelsWindowController).
@MainActor
final class PreferencesWindowController {
    private var window: NSWindow?
    private let state: AppState
    private let supervisor: AgentSupervisor

    init(state: AppState, supervisor: AgentSupervisor) {
        self.state = state
        self.supervisor = supervisor
    }

    func show() {
        if window == nil {
            let hosting = NSHostingController(
                rootView: PreferencesView(supervisor: supervisor).environmentObject(state))
            let w = NSWindow(contentViewController: hosting)
            w.title = "co/core — Settings"
            w.styleMask = [.titled, .closable, .miniaturizable]
            w.isReleasedWhenClosed = false
            w.center()
            window = w
        }
        if let w = window { WindowActivation.present(w) }
    }
}

struct PreferencesView: View {
    @EnvironmentObject private var state: AppState

    /// The agent we restart so an applied Network/Schedule change actually
    /// reaches the running agent — including on a self-contained app where
    /// there's no LaunchAgent plist to edit.
    let supervisor: AgentSupervisor

    @AppStorage("consoleBaseUrl") private var consoleBaseUrl = "https://console.cocore.dev"
    @AppStorage("advisorUrl") private var advisorUrl = "wss://advisor.cocore.dev/v1/agent"
    @AppStorage("machineLabel") private var machineName = ""
    @AppStorage("scheduleLimited") private var scheduleLimited = false
    @AppStorage("idleStart") private var idleStart = 22
    @AppStorage("idleEnd") private var idleEnd = 8

    @State private var networkApplied = false
    @State private var nameApplied = false
    @State private var scheduleApplied = false

    // One grouped settings form. (Was its own nested TabView with a Status
    // sub-tab; that sub-tab is now the main window's Status tab, and tabs
    // inside a tab read badly — so this is flat now.)
    var body: some View {
        Form {
            Section("This machine") {
                TextField("Machine name", text: $machineName, prompt: Text("My Mac"))
                HStack {
                    Button("Rename & restart agent") {
                        Task {
                            await supervisor.applyMachineNameAndReconnect()
                            nameApplied = true
                        }
                    }
                    if nameApplied {
                        Text("Renamed — agent restarted")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                }
                Text("How this machine appears to requesters. Leave blank to use the system hostname.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Section("Network") {
                TextField("Console URL", text: $consoleBaseUrl)
                TextField("Advisor URL", text: $advisorUrl)
                HStack {
                    Button("Apply & restart agent") {
                        Task {
                            await supervisor.applyNetworkAndReconnect()
                            networkApplied = true
                        }
                    }
                    if networkApplied {
                        Text("Applied — agent restarted")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                }
                Text("The federable services this machine talks to — you can run your own; none is authoritative. Applying writes these into the LaunchAgent and reconnects the agent.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Section("Schedule") {
                Toggle("Only serve during set hours", isOn: $scheduleLimited)
                    .toggleStyle(.switch)
                if scheduleLimited {
                    HStack(spacing: 12) {
                        Picker("From", selection: $idleStart) {
                            ForEach(0..<24, id: \.self) { Text(Self.hourLabel($0)).tag($0) }
                        }
                        .frame(width: 170)
                        Picker("To", selection: $idleEnd) {
                            ForEach(0..<24, id: \.self) { Text(Self.hourLabel($0)).tag($0) }
                        }
                        .frame(width: 170)
                    }
                    Text(scheduleSummary)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                    Text("Outside this window the agent disconnects and frees its inference engine.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                } else {
                    Text("Serving 24/7 — the agent stays connected whenever this Mac is awake.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                HStack {
                    Button("Apply & restart agent") {
                        Task {
                            await supervisor.applyScheduleAndReconnect()
                            scheduleApplied = true
                        }
                    }
                    if scheduleApplied {
                        Text("Applied — agent restarted")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                }
            }
        }
        .formStyle(.grouped)
    }

    private var scheduleSummary: String {
        let hours = (idleEnd - idleStart + 24) % 24
        let span = hours == 0 ? 24 : hours
        return "Serving \(Self.hourLabel(idleStart)) → \(Self.hourLabel(idleEnd)) · \(span) hour\(span == 1 ? "" : "s")/day"
    }

    /// Format a 0–23 hour as a friendly 12-hour clock label, e.g. `10:00 PM`.
    static func hourLabel(_ h: Int) -> String {
        let period = h < 12 ? "AM" : "PM"
        let h12 = h % 12 == 0 ? 12 : h % 12
        return "\(h12):00 \(period)"
    }
}
