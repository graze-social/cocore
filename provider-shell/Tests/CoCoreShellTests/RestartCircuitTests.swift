import XCTest

@testable import CoCoreShell

/// Unit coverage for the restart circuit breaker's pure decision function
/// (`AgentSupervisor.evaluateCircuit`). The breaker is the choke-point backstop
/// for the confidential-restart loop in bug report br_ed8f257c: no matter which
/// caller drives a respawn, it funnels through here, so this is where "stop the
/// ~1/min churn" is enforced. The timing is easy to get subtly wrong (the
/// original threshold was too high to catch a 62–68s cycle), so pin it.
final class RestartCircuitTests: XCTestCase {
    private let threshold = 5
    private let window: TimeInterval = 360

    private func eval(now: Date, spawns: [Date], openUntil: Date? = nil)
        -> AgentSupervisor.CircuitEval
    {
        AgentSupervisor.evaluateCircuit(
            now: now, spawnTimes: spawns, circuitOpenUntil: openUntil,
            threshold: threshold, window: window)
    }

    /// A cold start (no prior spawns) is allowed.
    func testFirstSpawnAllowed() {
        let now = Date(timeIntervalSince1970: 10_000)
        XCTAssertEqual(eval(now: now, spawns: []).action, .allow)
    }

    /// Four prior spawns in-window is still under threshold → allow the fifth.
    func testUnderThresholdAllows() {
        let now = Date(timeIntervalSince1970: 10_000)
        let spawns = (1...4).map { now.addingTimeInterval(-Double($0) * 64) }
        let e = eval(now: now, spawns: spawns)
        XCTAssertEqual(e.action, .allow)
        // The returned prune keeps all four (all inside the 360s window).
        XCTAssertEqual(e.prunedSpawnTimes.count, 4)
    }

    /// The observed ~64s loop: five prior spawns land inside the 6-minute
    /// window, so the sixth attempt trips the breaker instead of respawning.
    func testLoopCadenceTrips() {
        let now = Date(timeIntervalSince1970: 10_000)
        let spawns = (1...5).map { now.addingTimeInterval(-Double($0) * 64) }  // -64…-320s
        let e = eval(now: now, spawns: spawns)
        XCTAssertEqual(e.action, .trip)
        XCTAssertEqual(e.prunedSpawnTimes, [])
    }

    /// Spawns older than the window don't count — a machine that restarts a few
    /// times an hour (well spaced) never trips.
    func testOldSpawnsPrunedDoNotTrip() {
        let now = Date(timeIntervalSince1970: 10_000)
        // Five spawns, but each ~10 min apart → only the most recent is in-window.
        let spawns = (1...5).map { now.addingTimeInterval(-Double($0) * 600) }
        let e = eval(now: now, spawns: spawns)
        XCTAssertEqual(e.action, .allow)
        XCTAssertEqual(e.prunedSpawnTimes.count, 0)
    }

    /// While the circuit is open (deadline in the future) every spawn is refused,
    /// regardless of the spawn history.
    func testOpenCircuitRefuses() {
        let now = Date(timeIntervalSince1970: 10_000)
        let e = eval(now: now, spawns: [], openUntil: now.addingTimeInterval(300))
        XCTAssertEqual(e.action, .refuse)
    }

    /// Once the cooldown deadline passes, the next attempt is a half-open probe:
    /// treated as closed, so a machine whose problem cleared recovers on its own.
    func testLapsedCircuitAllowsHalfOpenProbe() {
        let now = Date(timeIntervalSince1970: 10_000)
        let e = eval(now: now, spawns: [], openUntil: now.addingTimeInterval(-1))
        XCTAssertEqual(e.action, .allow)
    }
}
