import XCTest
@testable import YueqiuElevatorSupercore

final class AppPathsTests: XCTestCase {
    func testProfileSpecificPathsDoNotCollide() {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let paths = AppPaths(root: root)

        XCTAssertNotEqual(paths.originalProfile(id: "a"), paths.originalProfile(id: "b"))
        XCTAssertNotEqual(paths.supercoreRuntimeProfile(id: "a"), paths.supercoreRuntimeProfile(id: "b"))
        XCTAssertNotEqual(paths.providerNodesCache(id: "a"), paths.providerNodesCache(id: "b"))
        XCTAssertNotEqual(paths.trafficUsage(id: "a"), paths.trafficUsage(id: "b"))
        XCTAssertNotEqual(paths.smartRules(id: "a"), paths.smartRules(id: "b"))
        XCTAssertNotEqual(paths.supercoreSmartState(id: "a"), paths.supercoreSmartState(id: "b"))
        XCTAssertTrue(paths.supercoreDaemonRuntimeProfile.path.contains("/state/supercore-daemon-runtime.yaml"))
        XCTAssertTrue(paths.originalProfile(id: "a").path.contains("/profiles/a/original.yaml"))
        XCTAssertTrue(paths.supercoreRuntimeProfile(id: "b").path.contains("/profiles/b/supercore-runtime.yaml"))
        XCTAssertTrue(paths.supercoreSubscriptionSource(id: "b").path.contains("/profiles/b/supercore-subscription-source.yaml"))
        XCTAssertTrue(paths.providerNodesCache(id: "b").path.contains("/profiles/b/provider-nodes.json"))
        XCTAssertTrue(paths.providerPayload(id: "b", providerName: "yt/main").path.contains("/profiles/b/provider-payloads/yt_main.txt"))
        XCTAssertTrue(paths.trafficUsage(id: "b").path.contains("/profiles/b/traffic-usage.json"))
        XCTAssertTrue(paths.smartRules(id: "b").path.contains("/profiles/b/smart-rules.json"))
        XCTAssertTrue(paths.supercoreSmartState(id: "b").path.contains("/profiles/b/supercore-smart-state.json"))
    }
}
