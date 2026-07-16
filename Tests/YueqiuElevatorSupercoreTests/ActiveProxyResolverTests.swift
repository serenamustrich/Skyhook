import XCTest
@testable import YueqiuElevatorSupercore

final class ActiveProxyResolverTests: XCTestCase {
    func testResolvesNestedSelectedProxyGroupToConcreteNode() {
        let groups = [
            ProxyGroup(name: "🚀 节点选择", type: "select", now: "👋 手动选择节点", all: ["👋 手动选择节点", "DIRECT"]),
            ProxyGroup(name: "👋 手动选择节点", type: "select", now: "🇭🇰 香港 02", all: ["🇭🇰 香港 02", "🇸🇬 新加坡 01"]),
            ProxyGroup(name: "亚洲", type: "select", now: "🇸🇬 新加坡 01", all: ["🇸🇬 新加坡 01"])
        ]

        XCTAssertEqual(
            ActiveProxyResolver.concreteNodeName(in: groups, mode: .rule),
            "🇭🇰 香港 02"
        )
    }

    func testDirectModeReportsDirect() {
        XCTAssertEqual(
            ActiveProxyResolver.concreteNodeName(in: [], mode: .direct),
            "DIRECT"
        )
    }
}
