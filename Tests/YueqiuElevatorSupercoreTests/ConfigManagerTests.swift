import XCTest
@testable import YueqiuElevatorSupercore

final class ConfigManagerTests: XCTestCase {
    func testParseProxyGroupsFromSubscriptionYAML() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let paths = AppPaths(root: root)
        try paths.prepareDirectories()
        let manager = ConfigManager(paths: paths, keychain: KeychainStore(service: "YueqiuElevatorSupercoreTests"))

        let yaml = """
        proxies:
          - name: HK 01
            type: ss
          - name: JP/02
            type: ss
        proxy-groups:
          - name: Proxy
            type: select
            proxies:
              - HK 01
              - JP/02
              - DIRECT
          - name: Region
            type: select
            proxies:
              [HK 01, JP/02, DIRECT]
          - name: Dynamic
            type: url-test
            include-all: true
            filter: "香港|日本"
          - { name: Auto, type: url-test, proxies: [HK 01, JP/02] }
        rules:
          - MATCH,Proxy
        """

        let groups = manager.parseProxyGroups(from: yaml, selectedNodes: ["Proxy": "JP/02"])

        XCTAssertEqual(groups.count, 4)
        XCTAssertEqual(groups[0].name, "Proxy")
        XCTAssertEqual(groups[0].now, "JP/02")
        XCTAssertEqual(groups[0].all, ["HK 01", "JP/02", "DIRECT"])
        XCTAssertEqual(groups[1].name, "Region")
        XCTAssertEqual(groups[1].all, ["HK 01", "JP/02", "DIRECT"])
        XCTAssertEqual(groups[2].name, "Dynamic")
        XCTAssertTrue(groups[2].includeAll)
        XCTAssertEqual(groups[2].filter, "香港|日本")
        XCTAssertEqual(groups[2].all, [])
        XCTAssertEqual(groups[3].name, "Auto")
        XCTAssertEqual(groups[3].all, ["HK 01", "JP/02"])
        try? FileManager.default.removeItem(at: root)
    }

    func testSupercoreRuntimeConfigUsesStorePortsTunAndCustomRules() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let paths = AppPaths(root: root)
        try paths.prepareDirectories()
        let manager = ConfigManager(paths: paths, keychain: KeychainStore(service: "YueqiuElevatorSupercoreTests"))

        let runtime = manager.makeSupercoreRuntimeYAML(
            profileID: "profile-a",
            tunEnabled: true,
            runtimeOptions: RuntimeOptions(mixedPort: 7897, controllerPort: 9197, tunEnabled: true),
            customRules: [
                CustomRule(target: .domainSuffix, value: "example.com", action: .proxy),
                CustomRule(target: .ipCIDR, value: "8.8.8.8/32", action: .direct),
                CustomRule(target: .domain, value: "blocked.example", action: .reject),
                CustomRule(
                    target: .appBundle,
                    value: "com.apple.Safari",
                    action: .outbound,
                    outboundName: "HK 01"
                )
            ],
            proxyOutboundName: "节点选择"
        )

        XCTAssertTrue(runtime.contains("mixed_listen: 127.0.0.1:7897"))
        XCTAssertTrue(runtime.contains("control_listen: 127.0.0.1:9197"))
        XCTAssertTrue(runtime.contains("probe_url: http://www.gstatic.com/generate_204"))
        XCTAssertTrue(runtime.contains("probe_timeout_ms: 500"))
        XCTAssertTrue(runtime.contains("probe_concurrency: 50"))
        XCTAssertTrue(runtime.contains("enabled: true"))
        XCTAssertTrue(runtime.contains("setup: true"))
        XCTAssertTrue(runtime.contains("store_path: \"\(paths.supercoreSubscriptionStore.path)\""))
        XCTAssertTrue(runtime.contains("type: reject"))
        XCTAssertTrue(runtime.contains("name: reject"))
        XCTAssertTrue(runtime.contains("target: domain-suffix"))
        XCTAssertTrue(runtime.contains("outbound: \"节点选择\""))
        XCTAssertTrue(runtime.contains("target: ip-cidr"))
        XCTAssertTrue(runtime.contains("blocked.example"))
        XCTAssertTrue(runtime.contains("outbound: \"reject\""))
        XCTAssertTrue(runtime.contains("target: app-bundle"))
        XCTAssertTrue(runtime.contains("value: \"com.apple.Safari\""))
        XCTAssertTrue(runtime.contains("outbound: \"HK 01\""))
        try? FileManager.default.removeItem(at: root)
    }

    func testSupercoreRuntimeConfigDoesNotForceDirectFallbackWithoutCustomRules() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let paths = AppPaths(root: root)
        try paths.prepareDirectories()
        let manager = ConfigManager(paths: paths, keychain: KeychainStore(service: "YueqiuElevatorSupercoreTests"))

        let runtime = manager.makeSupercoreRuntimeYAML(
            profileID: "profile-a",
            tunEnabled: false,
            customRules: [],
            proxyOutboundName: "节点选择"
        )

        XCTAssertTrue(runtime.contains("rules: []"))
        XCTAssertFalse(runtime.contains("target: match"))
        try? FileManager.default.removeItem(at: root)
    }

    func testCustomRulesPersistPerProfile() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let paths = AppPaths(root: root)
        try paths.prepareDirectories()
        let manager = ConfigManager(paths: paths, keychain: KeychainStore(service: "YueqiuElevatorSupercoreTests"))
        let rules = [
            CustomRule(
                id: UUID(uuidString: "00000000-0000-0000-0000-000000000001")!,
                target: .domainKeyword,
                value: "openai",
                action: .proxy,
                createdAt: Date(timeIntervalSince1970: 0)
            )
        ]

        try manager.saveCustomRules(rules, profileID: "a")

        XCTAssertEqual(manager.loadCustomRules(profileID: "a"), rules)
        XCTAssertEqual(manager.loadCustomRules(profileID: "b"), [])
        try? FileManager.default.removeItem(at: root)
    }
}
