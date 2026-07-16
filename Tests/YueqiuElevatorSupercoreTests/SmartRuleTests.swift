import XCTest
@testable import YueqiuElevatorSupercore

final class SmartRuleTests: XCTestCase {
    func testSmartRuleStatsCountsProxyRulesThatCanUseDirect() {
        let candidates = [
            SmartRuleCandidate(
                target: .domain,
                value: "example.com",
                endpointHost: "example.com",
                port: 443,
                observedRoute: .proxy,
                directState: .reachable,
                proxyState: .reachable
            ),
            SmartRuleCandidate(
                target: .domain,
                value: "blocked.example",
                endpointHost: "blocked.example",
                port: 443,
                observedRoute: .proxy,
                directState: .failed,
                proxyState: .reachable
            ),
            SmartRuleCandidate(
                target: .domain,
                value: "direct.example",
                endpointHost: "direct.example",
                port: 443,
                observedRoute: .direct,
                directState: .reachable,
                proxyState: .unknown
            )
        ]

        let stats = SmartRuleStats(candidates: candidates)

        XCTAssertEqual(stats.proxyComparedCount, 2)
        XCTAssertEqual(stats.proxyDirectReachableCount, 1)
        XCTAssertEqual(stats.proxyDirectReachableRatioTitle, "50%")
        XCTAssertEqual(stats.directRecommendationCount, 1)
        XCTAssertEqual(stats.proxyRecommendationCount, 1)
    }

    func testSmartRuleStorePersistsPerProfile() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let paths = AppPaths(root: root)
        try paths.prepareDirectories()
        let store = SmartRuleStore(paths: paths)
        let candidate = SmartRuleCandidate(
            id: UUID(uuidString: "00000000-0000-0000-0000-000000000002")!,
            target: .ipCIDR,
            value: "8.8.8.8/32",
            endpointHost: "8.8.8.8",
            port: 443,
            observedRoute: .proxy,
            directState: .reachable,
            proxyState: .reachable,
            firstSeenAt: Date(timeIntervalSince1970: 0),
            lastSeenAt: Date(timeIntervalSince1970: 1)
        )

        try store.save([candidate], profileID: "a")

        XCTAssertEqual(store.load(profileID: "a"), [candidate])
        XCTAssertEqual(store.load(profileID: "b"), [])
        try? FileManager.default.removeItem(at: root)
    }

    func testEndpointClassifierSkipsPrivateFakeIPAndClassifiesPublicTargets() {
        XCTAssertNil(SmartRuleEndpointClassifier.classify(host: "198.18.0.1"))
        XCTAssertNil(SmartRuleEndpointClassifier.classify(host: "localhost"))

        let domain = SmartRuleEndpointClassifier.classify(host: "Example.COM.")
        XCTAssertEqual(domain?.target, .domain)
        XCTAssertEqual(domain?.value, "example.com")

        let ipv4 = SmartRuleEndpointClassifier.classify(host: "8.8.8.8")
        XCTAssertEqual(ipv4?.target, .ipCIDR)
        XCTAssertEqual(ipv4?.value, "8.8.8.8/32")
    }
}
