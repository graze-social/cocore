import XCTest

@testable import CoCoreShell

/// Unit coverage for `AgentSupervisor.classifyExit` — the pure decision that
/// keeps a LATE exit from a superseded agent child from being applied to the
/// live one.
///
/// Bug report br_57cef8d6 (new M5 Air, tray 0.9.52): the agent's graceful
/// shutdown gives its offline-marker PDS publish a full 5s of its own, so
/// `stop()`'s 5s wait routinely expired an instant before the child was gone.
/// `stop()` then abandoned it, `start()` spawned a replacement, and the old
/// child's `terminationHandler` fired late — nil'ing `process` (so the tray
/// believed a healthy, serving agent was down: `isServing()` false forever) and
/// charging the exit to the new child ("ran 0s", status 15/9 from the reaper).
/// The 30s liveness reconciler then respawned every tick, each spawn reaping the
/// live worker, until the circuit breaker parked the machine for 15 minutes —
/// 279 spawns and 59 circuit trips in a single day, zero jobs served.
///
/// The generation check is what breaks that loop, so pin its three outcomes.
final class StaleExitTests: XCTestCase {
    /// The common case: the child we own crashed or was killed → respawn.
    func testCurrentGenerationUnexpectedExitRespawns() {
        XCTAssertEqual(
            AgentSupervisor.classifyExit(
                generation: 7, currentGeneration: 7, intentionalStop: false),
            .unexpected)
    }

    /// We asked it to stop and nothing superseded it → stay down.
    func testCurrentGenerationIntentionalStopStaysDown() {
        XCTAssertEqual(
            AgentSupervisor.classifyExit(
                generation: 7, currentGeneration: 7, intentionalStop: true),
            .intentional)
    }

    /// The regression: an abandoned child exits AFTER its replacement was
    /// spawned. `intentionalStop` has already been cleared by that spawn, so
    /// the old `intentionalStop` guard alone read this as a crash of the live
    /// child. Generation mismatch must win over the latch either way.
    func testSupersededExitIsStaleEvenWithStopLatchCleared() {
        XCTAssertEqual(
            AgentSupervisor.classifyExit(
                generation: 7, currentGeneration: 8, intentionalStop: false),
            .stale)
        XCTAssertEqual(
            AgentSupervisor.classifyExit(
                generation: 7, currentGeneration: 8, intentionalStop: true),
            .stale)
    }

    /// Several spawns can land while an old child lingers (the 30s reconciler
    /// ticking through a storm); every one of those exits is still stale.
    func testFarBehindGenerationIsStale() {
        XCTAssertEqual(
            AgentSupervisor.classifyExit(
                generation: 1, currentGeneration: 42, intentionalStop: false),
            .stale)
    }
}
