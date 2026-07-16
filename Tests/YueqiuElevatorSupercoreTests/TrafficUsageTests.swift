import XCTest
@testable import YueqiuElevatorSupercore

final class TrafficUsageTests: XCTestCase {
    func testProfileTrafficUsageAccumulatesRuntimeDeltas() {
        var usage = ProfileTrafficUsage.zero

        XCTAssertEqual(usage.record(snapshot: ConnectionTrafficSnapshot(upTotal: 100, downTotal: 300)), TrafficTotals(up: 100, down: 300))
        XCTAssertEqual(usage.record(snapshot: ConnectionTrafficSnapshot(upTotal: 150, downTotal: 450)), TrafficTotals(up: 150, down: 450))
        XCTAssertEqual(usage.record(snapshot: ConnectionTrafficSnapshot(upTotal: 140, downTotal: 420)), TrafficTotals(up: 150, down: 450))
    }

    func testProfileTrafficUsageKeepsTotalsAfterRuntimeBaselineReset() {
        var usage = ProfileTrafficUsage.zero

        usage.record(snapshot: ConnectionTrafficSnapshot(upTotal: 100, downTotal: 300))
        usage.resetRuntimeBaseline()
        XCTAssertEqual(usage.totals, TrafficTotals(up: 100, down: 300))

        usage.record(snapshot: ConnectionTrafficSnapshot(upTotal: 20, downTotal: 40))
        XCTAssertEqual(usage.totals, TrafficTotals(up: 120, down: 340))
    }

    func testTrafficUsageStorePersistsPerProfileUsage() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let paths = AppPaths(root: root)
        let store = TrafficUsageStore(paths: paths)

        var profileA = ProfileTrafficUsage.zero
        profileA.record(snapshot: ConnectionTrafficSnapshot(upTotal: 1024, downTotal: 2048))
        var profileB = ProfileTrafficUsage.zero
        profileB.record(snapshot: ConnectionTrafficSnapshot(upTotal: 10, downTotal: 20))

        try store.save(profileA, profileID: "a")
        try store.save(profileB, profileID: "b")

        XCTAssertEqual(store.load(profileID: "a").totals, TrafficTotals(up: 1024, down: 2048))
        XCTAssertEqual(store.load(profileID: "b").totals, TrafficTotals(up: 10, down: 20))
        XCTAssertEqual(store.load(profileID: "missing").totals, .zero)
    }
}
