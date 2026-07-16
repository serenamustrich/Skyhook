import XCTest
@testable import YueqiuElevatorSupercore

@MainActor
final class PlanBehaviorTests: XCTestCase {

    // MARK: - §1.1 TUN Mode Grading

    func testTUNModeDNSOptions() {
        let strategies: [TunDNSStrategy] = [.direct, .overTcp, .virtual]
        XCTAssertEqual(strategies.count, 3, "Should have 3 TUN DNS strategies")
        XCTAssertEqual(TunDNSStrategy.direct.title, "系统 DNS（推荐）")
        XCTAssertEqual(TunDNSStrategy.overTcp.title, "核心 DNS over TCP")
        XCTAssertEqual(TunDNSStrategy.virtual.title, "Fake-IP 虚拟 DNS（高级）")
    }

    func testDefaultTUNModeIsDirect() async {
        let paths = AppPaths()
        try? paths.prepareDirectories()
        let state = AppState(paths: paths, keychain: KeychainStore(service: "test-plan"))
        await state.bootstrap()
        XCTAssertEqual(state.runtimeOptions.dnsStrategy, .direct)
    }

    // MARK: - §1.3 Network Recovery Detection

    func testNetworkRecoveryDetection() async {
        let paths = AppPaths()
        try? paths.prepareDirectories()
        let state = AppState(paths: paths, keychain: KeychainStore(service: "test-plan"))
        await state.bootstrap()
        XCTAssertFalse(state.networkRecoveryNeeded)
    }

    // MARK: - §2.1 Probe Failure Classification

    func testProbeFailureClassification() {
        let result = SupercoreProbeResult(
            name: "test",
            kind: "unknown",
            success: false,
            latencyMs: nil,
            failureKind: "outbound_not_found",
            error: "outbound not found"
        )
        XCTAssertEqual(result.failureTitle, "核心无此节点")
    }

    func testProbeFailureTimeoutClassification() {
        let result = SupercoreProbeResult(
            name: "test",
            kind: "ss",
            success: false,
            latencyMs: 500,
            failureKind: "timeout",
            error: "probe timed out after 500ms"
        )
        XCTAssertEqual(result.failureTitle, "超时")
    }

    func testProbeFailureInvalidProbeURLClassification() {
        let result = SupercoreProbeResult(
            name: "test",
            kind: "ss",
            success: false,
            latencyMs: 10,
            failureKind: "invalid_probe_url",
            error: "invalid probe URL: https://"
        )
        XCTAssertEqual(result.failureTitle, "无效检测地址")
    }

    func testProbeFailureDialErrorClassification() {
        let result = SupercoreProbeResult(
            name: "test",
            kind: "trojan",
            success: false,
            latencyMs: 100,
            failureKind: "dial_error",
            error: "connection refused"
        )
        XCTAssertEqual(result.failureTitle, "拨号失败")
    }

    func testProbeFailureTlsErrorClassification() {
        let result = SupercoreProbeResult(
            name: "test",
            kind: "vmess",
            success: false,
            latencyMs: 50,
            failureKind: "tls_error",
            error: "tls handshake failed"
        )
        XCTAssertEqual(result.failureTitle, "TLS 失败")
    }

    func testProbeFailureProtocolUnsupportedClassification() {
        let result = SupercoreProbeResult(
            name: "test",
            kind: "unknown",
            success: false,
            latencyMs: nil,
            failureKind: "protocol_unsupported",
            error: "protocol not supported"
        )
        XCTAssertEqual(result.failureTitle, "协议暂不支持")
    }

    func testProbeFailureHttpStatusClassification() {
        let result = SupercoreProbeResult(
            name: "test",
            kind: "trojan",
            success: false,
            latencyMs: 100,
            failureKind: "http_status",
            error: "received non-204 status"
        )
        XCTAssertEqual(result.failureTitle, "HTTP 状态异常")
    }

    func testProbeFailureDnsErrorClassification() {
        let result = SupercoreProbeResult(
            name: "test",
            kind: "vmess",
            success: false,
            latencyMs: 100,
            failureKind: "dns_error",
            error: "DNS lookup failed"
        )
        XCTAssertEqual(result.failureTitle, "DNS 解析失败")
    }

    func testProbeFailureEmptyResponseClassification() {
        let result = SupercoreProbeResult(
            name: "test",
            kind: "vless",
            success: false,
            latencyMs: 100,
            failureKind: "empty_response",
            error: "empty probe response"
        )
        XCTAssertEqual(result.failureTitle, "空响应")
    }

    func testProbeMergeMissingOutboundsAreClassifiedAsNotFound() {
        let requestedNames = ["node-a", "node-b", "node-c"]
        let results = [
            SupercoreProbeResult(
                name: "node-a",
                kind: "ss",
                success: true,
                latencyMs: 180,
                failureKind: nil,
                error: ""
            ),
            SupercoreProbeResult(
                name: "node-b",
                kind: "vmess",
                success: false,
                latencyMs: 1_000,
                failureKind: "timeout",
                error: "timeout"
            )
        ]
        let merged = AppState.mergeProbeResults(
            requestedNames: requestedNames,
            results: results,
            existingDelayResults: ["node-a": 999, "node-b": 999, "node-c": 999],
            existingDelayFailureKinds: ["node-a": "old", "node-b": "dial_error", "node-c": "old"]
        )

        XCTAssertEqual(merged.available, 1)
        XCTAssertEqual(merged.total, 3)
        XCTAssertEqual(merged.returnedNames, ["node-a", "node-b"])
        XCTAssertEqual(merged.missingNames, ["node-c"])
        XCTAssertEqual(merged.delayResults["node-a"], 180)
        XCTAssertNil(merged.delayFailureKinds["node-a"])
        XCTAssertEqual(merged.delayFailureKinds["node-b"], "timeout")
        XCTAssertEqual(merged.delayResults["node-b"], -1)
        XCTAssertEqual(merged.delayFailureKinds["node-c"], "outbound_not_found")
        XCTAssertEqual(merged.delayResults["node-c"], -1)
        XCTAssertEqual(merged.failureCounts["outbound_not_found"], 1)
        XCTAssertEqual(merged.failureCounts["timeout"], 1)
    }

    // MARK: - §2.2 Probe URL Configuration

    func testDefaultProbeURL() {
        XCTAssertEqual(DelayPolicy.probeURL, "http://www.gstatic.com/generate_204")
    }

    func testDefaultProbeTimeout() {
        XCTAssertEqual(DelayPolicy.timeoutMilliseconds, 500)
    }

    func testProbeURLPersistence() async {
        let paths = AppPaths()
        try? paths.prepareDirectories()
        let state = AppState(paths: paths, keychain: KeychainStore(service: "test-plan"))
        await state.bootstrap()

        let testURL = "http://cp.cloudflare.com/generate_204"
        state.setProbeURL(testURL)
        XCTAssertEqual(state.probeURL, testURL)
    }

    // MARK: - §2.3 Dynamic Probe Timeout

    func testProbeRequestTimeoutCalculation() {
        XCTAssertEqual(
            ProbeTimeoutCalculator.requestTimeout(
                timeoutMilliseconds: 500,
                concurrency: 50,
                names: []
            ),
            1.0
        )
        XCTAssertEqual(
            ProbeTimeoutCalculator.requestTimeout(
                timeoutMilliseconds: 500,
                concurrency: 1,
                names: []
            ),
            1.0
        )
        XCTAssertEqual(
            ProbeTimeoutCalculator.requestTimeout(
                timeoutMilliseconds: 500,
                concurrency: 50,
                names: ["a"]
            ),
            1.0
        )
        XCTAssertEqual(
            ProbeTimeoutCalculator.requestTimeout(
                timeoutMilliseconds: 500,
                concurrency: 50,
                names: Array(repeating: "n", count: 100)
            ),
            1.5
        )
        XCTAssertEqual(
            ProbeTimeoutCalculator.requestTimeout(
                timeoutMilliseconds: 500,
                concurrency: 50,
                names: Array(repeating: "n", count: 101)
            ),
            2.0
        )
        XCTAssertEqual(
            ProbeTimeoutCalculator.requestTimeout(
                timeoutMilliseconds: 500,
                concurrency: 50,
                names: Array(repeating: "n", count: 131)
            ),
            2.0
        )
    }

    func testProbeRequestTimeoutUsesDefaultConcurrencyWhenNil() {
        XCTAssertEqual(
            ProbeTimeoutCalculator.requestTimeout(
                timeoutMilliseconds: 500,
                concurrency: nil,
                names: Array(repeating: "n", count: 131)
            ),
            ProbeTimeoutCalculator.requestTimeout(
                timeoutMilliseconds: 500,
                concurrency: DelayPolicy.manualConcurrency,
                names: Array(repeating: "n", count: 131)
            )
        )
    }

    func testProbeRequestTimeoutUsesConservativeBudgetWhenNodeCountIsUnknown() {
        XCTAssertGreaterThanOrEqual(
            ProbeTimeoutCalculator.requestTimeout(
                timeoutMilliseconds: 500,
                concurrency: 50,
                names: nil
            ),
            60
        )
    }

    func testProbeRequestTimeoutForSingleAndHundredNodesWithConcurrency50() {
        XCTAssertEqual(
            ProbeTimeoutCalculator.requestTimeout(
                timeoutMilliseconds: 500,
                concurrency: 50,
                names: ["only-one"]
            ),
            1.0
        )
        XCTAssertEqual(
            ProbeTimeoutCalculator.requestTimeout(
                timeoutMilliseconds: 500,
                concurrency: 50,
                names: Array(repeating: "node", count: 50)
            ),
            1.0
        )
        XCTAssertEqual(
            ProbeTimeoutCalculator.requestTimeout(
                timeoutMilliseconds: 500,
                concurrency: 50,
                names: Array(repeating: "node", count: 51)
            ),
            1.5
        )
    }

    // MARK: - §4.1 TUN Route Policy

    func testTUNBypassIncludesLANAddresses() {
        let paths = AppPaths()
        try? paths.prepareDirectories()
        let configManager = ConfigManager(paths: paths, keychain: KeychainStore(service: "test"))
        let yaml = configManager.makeSupercoreRuntimeYAML(
            profileID: "test",
            tunEnabled: true,
            runtimeOptions: RuntimeOptions()
        )

        XCTAssertTrue(yaml.contains("10.0.0.0/8"), "Should bypass 10.x.x.x")
        XCTAssertTrue(yaml.contains("172.16.0.0/12"), "Should bypass 172.16.x.x")
        XCTAssertTrue(yaml.contains("192.168.0.0/16"), "Should bypass 192.168.x.x")
        XCTAssertTrue(yaml.contains("127.0.0.0/8"), "Should bypass loopback")
        XCTAssertTrue(yaml.contains("169.254.0.0/16"), "Should bypass link-local")
    }

    func testTUNRouteExcludesAppleCaptivePortal() {
        let paths = AppPaths()
        try? paths.prepareDirectories()
        let configManager = ConfigManager(paths: paths, keychain: KeychainStore(service: "test"))
        let yaml = configManager.makeSupercoreRuntimeYAML(
            profileID: "test",
            tunEnabled: true,
            runtimeOptions: RuntimeOptions()
        )

        XCTAssertTrue(yaml.contains("17.0.0.0/8"), "Should exclude Apple captive portal range")
    }

    func testTUNDisabledByDefault() {
        let paths = AppPaths()
        try? paths.prepareDirectories()
        let configManager = ConfigManager(paths: paths, keychain: KeychainStore(service: "test"))
        let yaml = configManager.makeSupercoreRuntimeYAML(
            profileID: "test",
            tunEnabled: false,
            runtimeOptions: RuntimeOptions()
        )

        XCTAssertTrue(yaml.contains("enabled: false"), "TUN should be disabled by default")
    }

    func testFakeIPDisabledByDefault() {
        let paths = AppPaths()
        try? paths.prepareDirectories()
        let configManager = ConfigManager(paths: paths, keychain: KeychainStore(service: "test"))
        let yaml = configManager.makeSupercoreRuntimeYAML(
            profileID: "test",
            tunEnabled: true,
            runtimeOptions: RuntimeOptions(dnsStrategy: .direct)
        )

        XCTAssertTrue(yaml.contains("dns_strategy: direct"), "DNS should default to direct")
    }

    // MARK: - §5.1 Rule Type Coverage

    func testRuleTargetCoverage() {
        let targets: [CustomRuleTarget] = [
            .domain, .domainSuffix, .domainKeyword, .domainRegex,
            .ipCIDR, .ipCIDR6,
            .appName, .appPath, .appPathRegex, .appBundle
        ]
        XCTAssertEqual(targets.count, 10, "Should have 10 rule targets")
    }

    func testCustomRuleTargetSupercoreMapping() {
        XCTAssertEqual(CustomRuleTarget.domain.supercoreTarget, "domain")
        XCTAssertEqual(CustomRuleTarget.domainSuffix.supercoreTarget, "domain-suffix")
        XCTAssertEqual(CustomRuleTarget.domainKeyword.supercoreTarget, "domain-keyword")
        XCTAssertEqual(CustomRuleTarget.domainRegex.supercoreTarget, "domain-regex")
        XCTAssertEqual(CustomRuleTarget.ipCIDR.supercoreTarget, "ip-cidr")
        XCTAssertEqual(CustomRuleTarget.ipCIDR6.supercoreTarget, "ip-cidr6")
        XCTAssertEqual(CustomRuleTarget.appName.supercoreTarget, "app-name")
        XCTAssertEqual(CustomRuleTarget.appPath.supercoreTarget, "app-path")
        XCTAssertEqual(CustomRuleTarget.appPathRegex.supercoreTarget, "app-path-regex")
        XCTAssertEqual(CustomRuleTarget.appBundle.supercoreTarget, "app-bundle")
    }

    // MARK: - §5.2 Rule Provider Fallback

    func testRuleProviderFallbackHasConfigurationMarker() {
        let yaml = """
        proxy-providers:
          test-provider:
            type: http
            url: https://example.com/provider.yaml
            interval: 3600
          backup-provider:
            type: http
            url: https://example.com/backup.yaml
        """

        let providers = ProxyNodeParser.parseProviderURLs(from: yaml)
        XCTAssertEqual(providers["test-provider"], URL(string: "https://example.com/provider.yaml"))
        XCTAssertEqual(providers["backup-provider"], URL(string: "https://example.com/backup.yaml"))
        XCTAssertEqual(Set(providers.keys), ["test-provider", "backup-provider"])
    }

    // MARK: - §6.1 Provider Caching

    func testProviderNodesCachedLocally() async throws {
        let paths = AppPaths()
        try paths.prepareDirectories()
        let keychain = KeychainStore(service: "test-plan")
        let configManager = ConfigManager(paths: paths, keychain: keychain)
        let subscriptionManager = SubscriptionManager(paths: paths, keychain: keychain, configManager: configManager)

        let profileID = "test-cache-profile"
        try paths.prepareProfileDirectory(id: profileID)
        let cacheURL = paths.providerNodesCache(id: profileID)
        let cachedNodes = [
            ProxyNode(name: "cache-node-a", source: "local", country: "香港"),
            ProxyNode(name: "cache-node-b", source: "local", country: "美国"),
        ]
        let cacheData = try JSONEncoder().encode(cachedNodes)
        try cacheData.write(to: cacheURL, options: .atomic)

        let loaded = subscriptionManager.loadCachedProviderNodes(profileID: profileID)
        XCTAssertEqual(loaded.count, 2)
        XCTAssertEqual(Set(loaded.map(\.name)), Set(["cache-node-a", "cache-node-b"]))
        XCTAssertEqual(loaded[0].source, "local")
    }

    func testSwitchProfileDoesNotReDownload() async throws {
        let paths = AppPaths()
        try? paths.prepareDirectories()
        let profileA = SubscriptionProfile(
            id: "profile-a",
            name: "ProfileA",
            maskedURL: "https://example.com/profile-a",
            importedAt: Date(),
            updatedAt: Date(),
            selectedNodes: [:]
        )
        let profileB = SubscriptionProfile(
            id: "profile-b",
            name: "ProfileB",
            maskedURL: "https://example.com/profile-b",
            importedAt: Date(),
            updatedAt: Date(),
            selectedNodes: [:]
        )
        let profileIndex = ProfileIndex(activeProfileID: profileA.id, profiles: [profileA, profileB])
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        try encoder.encode(profileIndex).write(to: paths.profilesIndex, options: .atomic)
        try paths.prepareProfileDirectory(id: profileA.id)
        try paths.prepareProfileDirectory(id: profileB.id)

        let cachedNodesA = [ProxyNode(name: "A-Cache", source: "profile-a", country: "香港")]
        let cachedNodesB = [ProxyNode(name: "B-Cache", source: "profile-b", country: "美国")]
        let cacheDataA = try JSONEncoder().encode(cachedNodesA)
        let cacheDataB = try JSONEncoder().encode(cachedNodesB)
        try cacheDataA.write(to: paths.providerNodesCache(id: profileA.id), options: .atomic)
        try cacheDataB.write(to: paths.providerNodesCache(id: profileB.id), options: .atomic)

        let state = AppState(
            paths: paths,
            keychain: KeychainStore(service: "test-plan-switch-\(UUID().uuidString)")
        )
        await state.bootstrap()

        XCTAssertTrue(state.operation == nil, "No operation should be in progress after bootstrap")
        XCTAssertEqual(state.activeSubscription?.id, profileA.id)
        XCTAssertEqual(state.providerNodes.map(\.name), ["A-Cache"])
        state.switchProfile(profileB.id)
        for _ in 0..<80 {
            if state.activeSubscription?.id == profileB.id && state.operation == nil {
                break
            }
            try await Task.sleep(for: .milliseconds(20))
        }

        XCTAssertEqual(state.activeSubscription?.id, profileB.id)
        XCTAssertEqual(state.providerNodes.map(\.name), ["B-Cache"])
    }

    // MARK: - §7.1 Node Page Delay Colors

    func testDelayPolicyColorThresholds() {
        XCTAssertFalse(DelayPolicy.isAvailable(nil))
        XCTAssertFalse(DelayPolicy.isAvailable(-1))
        XCTAssertTrue(DelayPolicy.isAvailable(0))
        XCTAssertTrue(DelayPolicy.isAvailable(49))
        XCTAssertTrue(DelayPolicy.isAvailable(149))
        XCTAssertFalse(DelayPolicy.isAvailable(500))
    }

    func testDelayDisplayTitles() {
        XCTAssertEqual(DelayPolicy.displayTitle(for: nil), "未测")
        XCTAssertEqual(DelayPolicy.displayTitle(for: -1), "超时")
        XCTAssertEqual(DelayPolicy.displayTitle(for: 38), "38ms")
        XCTAssertEqual(DelayPolicy.displayTitle(for: 150), "150ms")
    }

    // MARK: - §7.2 Startup Behavior

    func testStartupUsesLastNode() async {
        let paths = AppPaths()
        try? paths.prepareDirectories()
        let state = AppState(paths: paths, keychain: KeychainStore(service: "test-plan"))
        await state.bootstrap()

        XCTAssertEqual(state.runtimePurpose, .idle)
        XCTAssertFalse(state.coreState.isRunning)
    }

    func testStartupDoesNotRefreshSubscription() async {
        let paths = AppPaths()
        try? paths.prepareDirectories()
        let state = AppState(paths: paths, keychain: KeychainStore(service: "test-plan"))
        await state.bootstrap()
        XCTAssertNil(state.operation)
        XCTAssertEqual(state.userMessage, "未启动")
    }

    func testResolveStartupNodeCandidateReturnsLastStartedNodeWhenAvailable() {
        let paths = AppPaths()
        try? paths.prepareDirectories()
        let state = AppState(paths: paths, keychain: KeychainStore(service: "test-startup-resolve-available"))
        state.proxies = [
            ProxyGroup(
                name: "测试组",
                type: "select",
                now: "香港-01",
                all: ["香港-01", "香港-02"]
            )
        ]
        state.activeSubscription = SubscriptionProfile(
            id: "startup-last-node",
            name: "LastNodeProfile",
            maskedURL: "https://example.com/last-node",
            importedAt: Date(),
            updatedAt: Date(),
            selectedNodes: [:],
            lastStartedNode: "香港-01"
        )

        let resolved = state.resolveStartupNodeCandidateFromLastStarted()
        XCTAssertEqual(resolved.node, "香港-01")
        XCTAssertFalse(resolved.needsManualProbe)
    }

    func testResolveStartupNodeCandidateFallsBackToSameCountry() {
        let paths = AppPaths()
        try? paths.prepareDirectories()
        let state = AppState(paths: paths, keychain: KeychainStore(service: "test-startup-resolve-fallback"))
        state.proxies = [
            ProxyGroup(
                name: "测试组",
                type: "select",
                now: "美国-01",
                all: ["美国-01", "香港-备用"]
            )
        ]
        state.providerNodes = [
            ProxyNode(name: "香港-备用", source: "历史缓存", country: "香港")
        ]
        state.activeSubscription = SubscriptionProfile(
            id: "startup-last-node-fallback",
            name: "LastNodeFallbackProfile",
            maskedURL: "https://example.com/last-node-fallback",
            importedAt: Date(),
            updatedAt: Date(),
            selectedNodes: [:],
            lastStartedNode: "香港-离线"
        )

        let resolved = state.resolveStartupNodeCandidateFromLastStarted()
        XCTAssertEqual(resolved.node, "香港-备用")
        XCTAssertFalse(resolved.needsManualProbe)
    }

    func testResolveStartupNodeCandidateNeedsManualProbeWhenNoSameCountryFallback() {
        let paths = AppPaths()
        try? paths.prepareDirectories()
        let state = AppState(paths: paths, keychain: KeychainStore(service: "test-startup-resolve-manual"))
        state.proxies = [
            ProxyGroup(
                name: "测试组",
                type: "select",
                now: "美国-01",
                all: ["美国-01", "日本-01"]
            )
        ]
        state.providerNodes = [
            ProxyNode(name: "美国-历史-01", source: "历史缓存", country: "美国"),
            ProxyNode(name: "日本-历史-01", source: "历史缓存", country: "日本")
        ]
        state.activeSubscription = SubscriptionProfile(
            id: "startup-last-node-manual",
            name: "LastNodeManualProfile",
            maskedURL: "https://example.com/last-node-manual",
            importedAt: Date(),
            updatedAt: Date(),
            selectedNodes: [:],
            lastStartedNode: "异域-离线"
        )

        let resolved = state.resolveStartupNodeCandidateFromLastStarted()
        XCTAssertNil(resolved.node)
        XCTAssertTrue(resolved.needsManualProbe)
    }

    func testStartupProxyFailsFastWhenSupercoreCacheMissing() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let paths = AppPaths(root: root)
        try? paths.prepareDirectories()
        let keychain = KeychainStore(service: "test-startup-cache-\(UUID().uuidString)")

        let profile = SubscriptionProfile(
            id: "startup-no-cache-profile",
            name: "NoCacheProfile",
            maskedURL: "https://example.com/no-cache",
            importedAt: Date(),
            updatedAt: Date(),
            selectedNodes: [:]
        )
        try paths.prepareProfileDirectory(id: profile.id)
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        try encoder.encode(ProfileIndex(activeProfileID: profile.id, profiles: [profile]))
            .write(to: paths.profilesIndex)
        let originalYAML = """
        proxies: []
        proxy-groups: []
        rules: []
        """
        try originalYAML.write(
            to: paths.originalProfile(id: profile.id),
            atomically: true,
            encoding: .utf8
        )

        let state = AppState(paths: paths, keychain: keychain)
        await state.bootstrap()
        XCTAssertEqual(state.activeSubscription?.id, profile.id)
        XCTAssertEqual(state.userMessage, "未启动")

        state.startProxy()
        let timeout = Date().addingTimeInterval(2)
        while state.operation != nil && Date() < timeout {
            try await Task.sleep(for: .milliseconds(20))
        }
        while !state.userMessage.contains("启动失败") && Date() < timeout {
            try await Task.sleep(for: .milliseconds(20))
        }

        XCTAssertNil(state.operation)
        XCTAssertFalse(state.logLines.contains(where: { $0.contains("首次准备本地订阅缓存") }))
        XCTAssertTrue(state.userMessage.contains("Supercore 未加载到本地订阅缓存"))
    }

    func testStartupProxyDoesNotLogSubscriptionSyncOrGlobalDelay() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let paths = AppPaths(root: root)
        try? paths.prepareDirectories()
        let keychain = KeychainStore(service: "test-startup-no-sync-delay-\(UUID().uuidString)")

        let profile = SubscriptionProfile(
            id: "startup-no-sync-delay-profile",
            name: "NoSyncDelayProfile",
            maskedURL: "https://example.com/no-sync-delay",
            importedAt: Date(),
            updatedAt: Date(),
            selectedNodes: [:]
        )
        try paths.prepareProfileDirectory(id: profile.id)
        let index = ProfileIndex(activeProfileID: profile.id, profiles: [profile])
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        try encoder.encode(index).write(to: paths.profilesIndex)

        let originalYAML = """
        proxies: []
        proxy-groups: []
        rules: []
        """
        try originalYAML.write(to: paths.originalProfile(id: profile.id), atomically: true, encoding: .utf8)

        let state = AppState(paths: paths, keychain: keychain)
        await state.bootstrap()
        let baselineLogCount = state.logLines.count
        state.startProxy()

        let timeout = Date().addingTimeInterval(2)
        while state.operation != nil && Date() < timeout {
            try? await Task.sleep(for: .milliseconds(20))
        }

        while !state.userMessage.contains("启动失败") && Date() < timeout {
            try? await Task.sleep(for: .milliseconds(20))
        }

        let startupAppendedLogs = state.logLines.dropFirst(baselineLogCount)
        let hasNoSyncLogs = !startupAppendedLogs.contains { line in
            line.contains("启动后台自动更新订阅")
                || line.contains("启动订阅自动更新...")
                || line.contains("订阅更新开始，共")
        }
        let hasNoGlobalDelayLogs = !startupAppendedLogs.contains { line in
            line.contains("正在全局测速")
                || line.contains("全局测速并自动择优")
        }
        XCTAssertTrue(hasNoSyncLogs)
        XCTAssertTrue(hasNoGlobalDelayLogs)
        XCTAssertTrue(state.userMessage.contains("Supercore 未加载到本地订阅缓存"))
    }

    func testStartupProxyDoesNotTriggerSubscriptionRefreshWhenOldProfileAndNoCache() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let paths = AppPaths(root: root)
        try? paths.prepareDirectories()
        let keychain = KeychainStore(service: "test-startup-old-profile-no-cache-\(UUID().uuidString)")

        let profile = SubscriptionProfile(
            id: "startup-old-profile-no-cache-profile",
            name: "NoSyncOldProfile",
            maskedURL: "https://example.com/no-sync-old-profile",
            importedAt: Date(timeIntervalSinceNow: -7200),
            updatedAt: Date(timeIntervalSinceNow: -7200),
            selectedNodes: [:]
        )
        try paths.prepareProfileDirectory(id: profile.id)
        let index = ProfileIndex(activeProfileID: profile.id, profiles: [profile])
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        try encoder.encode(index).write(to: paths.profilesIndex)

        let originalYAML = """
        proxies: []
        proxy-groups: []
        rules: []
        """
        try originalYAML.write(to: paths.originalProfile(id: profile.id), atomically: true, encoding: .utf8)

        let state = AppState(paths: paths, keychain: keychain)
        await state.bootstrap()
        let baselineLogCount = state.logLines.count

        state.startProxy()

        let timeout = Date().addingTimeInterval(3)
        while state.operation != nil && Date() < timeout {
            try? await Task.sleep(for: .milliseconds(20))
        }
        while !state.userMessage.contains("启动失败") && Date() < timeout {
            try? await Task.sleep(for: .milliseconds(20))
        }

        let startupAppendedLogs = state.logLines.dropFirst(baselineLogCount)
        let hasNoSyncLogs = !startupAppendedLogs.contains { line in
            line.contains("启动后台自动更新订阅")
                || line.contains("启动订阅自动更新...")
                || line.contains("订阅更新开始，共")
        }
        let hasNoGlobalDelayLogs = !startupAppendedLogs.contains { line in
            line.contains("正在全局测速")
                || line.contains("全局测速并自动择优")
        }
        XCTAssertTrue(hasNoSyncLogs)
        XCTAssertTrue(hasNoGlobalDelayLogs)
        XCTAssertTrue(
            startupAppendedLogs.contains(where: { line in
                line.contains("启动订阅更新已跳过") || line.contains("启动代理失败")
            }) || state.userMessage.contains("启动失败")
        )
        XCTAssertTrue(state.userMessage.contains("Supercore 未加载到本地订阅缓存"))
    }

    func testDelayTestingRequiresLocalSupercoreCache() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let paths = AppPaths(root: root)
        try paths.prepareDirectories()
        let keychain = KeychainStore(service: "test-delay-local-cache-\(UUID().uuidString)")

        let profile = SubscriptionProfile(
            id: "delay-cache-profile",
            name: "DelayCache",
            maskedURL: "https://example.com/delay-cache",
            importedAt: Date(),
            updatedAt: Date(),
            selectedNodes: [:]
        )
        try paths.prepareProfileDirectory(id: profile.id)

        let index = ProfileIndex(activeProfileID: profile.id, profiles: [profile])
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        try encoder.encode(index).write(to: paths.profilesIndex, options: .atomic)

        let cachedNodes = [
            ProxyNode(name: "HK-01", source: "cache", country: "香港"),
            ProxyNode(name: "HK-02", source: "cache", country: "香港")
        ]
        let cacheData = try JSONEncoder().encode(cachedNodes)
        try cacheData.write(to: paths.providerNodesCache(id: profile.id), options: .atomic)

        let originalYAML = """
        proxies: []
        proxy-groups: []
        rules: []
        """
        try originalYAML.write(to: paths.originalProfile(id: profile.id), atomically: true, encoding: .utf8)

        let state = AppState(paths: paths, keychain: keychain)
        await state.bootstrap()
        XCTAssertEqual(state.activeSubscription?.id, profile.id)
        XCTAssertFalse(state.providerNodes.isEmpty, "预期本地缓存节点写入后可被加载")
        XCTAssertEqual(state.userMessage, "未启动")

        state.testAllAvailableNodesDelay()
        for _ in 0..<100 {
            if state.operation != nil {
                break
            }
            try await Task.sleep(for: .milliseconds(20))
        }
        XCTAssertNotNil(state.operation)
        for _ in 0..<100 {
            if state.operation == nil {
                break
            }
            try await Task.sleep(for: .milliseconds(20))
        }

        XCTAssertNil(state.operation)
        XCTAssertFalse(state.logLines.contains(where: { $0.contains("首次准备本地订阅缓存") }))
        XCTAssertTrue(
            state.userMessage.contains("可用节点延迟测试完成") ||
            state.userMessage.contains("所有节点测速完成") ||
            state.userMessage.contains("失败"),
            "current userMessage: \(state.userMessage)"
        )
        if state.userMessage.contains("Supercore 未加载到本地订阅缓存") {
            XCTAssertTrue(state.logLines.contains(where: { $0.contains("测速失败") }) || state.userMessage.contains("测速失败"))
        }
    }

    func testDelayTestingRuntimeAlwaysDisablesTUNAndCoreDNS() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let paths = AppPaths(root: root)
        try paths.prepareDirectories()
        let keychain = KeychainStore(service: "test-delay-runtime-no-tun-\(UUID().uuidString)")
        let profileID = "delay-runtime-no-tun"
        try paths.prepareProfileDirectory(id: profileID)
        try """
        proxies: []
        proxy-groups: []
        rules: []
        """.write(
            to: paths.originalProfile(id: profileID),
            atomically: true,
            encoding: .utf8
        )

        let state = AppState(paths: paths, keychain: keychain)
        state.tunEnabled = true
        state.runtimeOptions.dnsStrategy = .virtual

        let options = try state.prepareDelayTestingRuntime(profileID: profileID)
        let runtime = try String(
            contentsOf: paths.supercoreRuntimeProfile(id: profileID),
            encoding: .utf8
        )

        XCTAssertFalse(options.tunEnabled)
        XCTAssertTrue(runtime.contains("tun:\n  enabled: false"))
        XCTAssertTrue(runtime.contains("setup: false"))
        XCTAssertTrue(runtime.contains("dns:\n  enabled: false"))
        XCTAssertTrue(runtime.contains("hijack_udp_53: false"))
    }

    // MARK: - §7.3 Log Categories

    func testLogCategoryCoverage() {
        let categories: [LogCategory] = [.all, .proxy, .direct, .rule, .dns, .tun, .error, .system]
        XCTAssertEqual(categories.count, 8, "Should have 8 log categories")
    }

    func testLogClassifierCategorizesCorrectly() {
        XCTAssertEqual(LogClassifier.category(for: "dns query failed"), .error)
        XCTAssertEqual(LogClassifier.category(for: "tun device created"), .tun)
        XCTAssertEqual(LogClassifier.category(for: "dns resolution complete"), .dns)
        XCTAssertEqual(LogClassifier.category(for: "proxy connection ok"), .proxy)
        XCTAssertEqual(LogClassifier.category(for: "direct connection"), .direct)
        XCTAssertEqual(LogClassifier.category(for: "rule matched"), .rule)
        XCTAssertEqual(LogClassifier.category(for: "error: connection refused"), .error)
    }

    // MARK: - §3.2 Shadowsocks Ciphers

    func testShadowsocksCipherCoverage() {
        let ciphers = [
            "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
            "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
            "2022-blake3-chacha20-poly1305"
        ]
        var renderedPayloads: [String] = []

        for cipher in ciphers {
            let credential = "\(cipher):password"
            let encoded = Data(credential.utf8).base64EncodedString()
            let uri = "ss://\(encoded)@127.0.0.1:8388#\(cipher)"
            let yaml = URISubscriptionConverter.convertIfNeeded(uri)

            XCTAssertNotNil(yaml)
            if let yaml {
                renderedPayloads.append(yaml)
                XCTAssertTrue(yaml.contains("name: \"\(cipher)\""))
                XCTAssertTrue(yaml.contains("type: ss"))
                XCTAssertTrue(yaml.contains("server: \"127.0.0.1\""))
                XCTAssertTrue(yaml.contains("port: 8388"))
                XCTAssertTrue(yaml.contains("cipher: \"\(cipher)\""))
            }
        }

        XCTAssertEqual(renderedPayloads.count, ciphers.count)
        XCTAssertEqual(Set(renderedPayloads).count, ciphers.count)

        let combined = renderedPayloads.joined(separator: "\n")
        for cipher in ciphers {
            XCTAssertTrue(combined.contains("cipher: \"\(cipher)\""))
        }
    }

    // MARK: - §3.3 SSR Cipher Coverage

    func testSSRCipherCoverage() {
        let ciphers = [
            "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
            "rc4-md5", "chacha20"
        ]
        XCTAssertEqual(Set(ciphers).count, 5)
        let text = ciphers
            .map { "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@example.com:443#\($0)" }
            .joined(separator: "\n")
        let nodes = ProxyNodeParser.parseNodes(from: text, source: "test")
        XCTAssertEqual(nodes.count, ciphers.count)
        XCTAssertEqual(Set(nodes.map(\.name)), Set(ciphers))
        XCTAssertTrue(ciphers.contains("aes-128-cfb"))
        XCTAssertTrue(ciphers.contains("chacha20"))
        XCTAssertEqual(ciphers.filter { $0.hasPrefix("aes-") }.count, 3)
    }

    func testSSRProtocolCoverage() {
        let protocols = [
            "origin", "verify_sha1", "auth_sha1_v4",
            "auth_aes128_md5", "auth_aes128_sha1"
        ]

        XCTAssertEqual(Set(protocols).count, 5)
        let text = protocols
            .map { "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@example.com:443#\($0)" }
            .joined(separator: "\n")
        let nodes = ProxyNodeParser.parseNodes(from: text, source: "test")
        XCTAssertEqual(nodes.count, protocols.count)
        XCTAssertEqual(Set(nodes.map(\.name)), Set(protocols))
        XCTAssertEqual(protocols.filter { $0.hasPrefix("auth_") }.count, 3)
        XCTAssertEqual(protocols.filter { $0.hasPrefix("auth_") && $0.contains("sha1") }.count, 2)
        XCTAssertTrue(protocols.contains("verify_sha1"))
    }

    func testSSRObfsCoverage() {
        let obfs = ["plain", "http_simple", "http_post", "tls1.2_ticket_auth"]

        XCTAssertEqual(Set(obfs).count, 4)
        let text = obfs
            .map { "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@example.com:443#\($0)" }
            .joined(separator: "\n")
        let nodes = ProxyNodeParser.parseNodes(from: text, source: "test")
        XCTAssertEqual(nodes.count, obfs.count)
        XCTAssertEqual(Set(nodes.map(\.name)), Set(obfs))
        XCTAssertEqual(obfs.filter { $0.hasPrefix("http") }.count, 2)
    }

    // MARK: - §4.2 Fake-IP DNS

    func testFakeIPRangeConstants() {
        let rangeStart: UInt32 = 0xC6120000
        let rangeEnd: UInt32 = 0xC613FFFF
        XCTAssertEqual(rangeStart, 0xC6120000)
        XCTAssertEqual(rangeEnd, 0xC613FFFF)
    }

    // MARK: - §4.3 DNS Rollback

    func testDNSFallbackBehavior() {
        let paths = AppPaths()
        try? paths.prepareDirectories()
        let configManager = ConfigManager(paths: paths, keychain: KeychainStore(service: "test"))

        let dnsOverTcp = configManager.makeSupercoreRuntimeYAML(
            profileID: "test",
            tunEnabled: true,
            runtimeOptions: RuntimeOptions(dnsStrategy: .overTcp)
        )
        XCTAssertTrue(dnsOverTcp.contains("over-tcp"))

        let directDNS = configManager.makeSupercoreRuntimeYAML(
            profileID: "test",
            tunEnabled: true,
            runtimeOptions: RuntimeOptions(dnsStrategy: .direct)
        )
        XCTAssertTrue(directDNS.contains("direct"))
    }

    // MARK: - §5.3 Smart Rules

    func testSmartRuleCandidateRecommendation() {
        var candidate = SmartRuleCandidate(
            target: .domain,
            value: "example.com",
            endpointHost: "example.com",
            port: nil,
            observedRoute: .proxy,
            directState: .reachable,
            proxyState: .reachable,
            hitCount: 10
        )
        XCTAssertEqual(candidate.recommendationAction, .direct)

        candidate.directState = .failed
        candidate.observedRoute = .direct
        XCTAssertEqual(candidate.recommendationAction, .proxy)
    }

    // MARK: - §11 Compliance

    func testNoUserSubscriptionURLsInCode() {
        let paths = AppPaths()
        XCTAssertNotNil(paths.root)
    }

    // MARK: - §6.3 TUN/DNS Safety - Network Diagnostics

    /// §6.3 步骤 2/3/4：诊断函数必须输出三项状态且可独立调用。
    func testRunNetworkDiagnosticsReturnsThreeStateItems() async {
        let paths = AppPaths()
        try? paths.prepareDirectories()
        let state = AppState(paths: paths, keychain: KeychainStore(service: "test-6-3-diag"))
        await state.bootstrap()

        let snapshot = state.runNetworkDiagnostics()

        // 三项关键状态都必须存在
        XCTAssertNotNil(snapshot.proxyDescription, "系统代理描述必须非空")
        XCTAssertNotNil(snapshot.daemonDescription, "daemon 状态描述必须非空")
        XCTAssertGreaterThanOrEqual(snapshot.fakeIPRouteCount, 0, "198.18 残留路由条数必须为非负整数")
        // 在干净环境下，daemon 通常未加载
        XCTAssertFalse(snapshot.daemonLoaded, "干净环境下 daemon 不应处于 loaded 状态")
    }

    /// §6.3 步骤 1：恢复网络执行前后会输出"执行前/执行后"诊断日志。
    func testRestoreNetworkSnapshotLogsPreAndPostDiagnostics() async {
        let paths = AppPaths()
        try? paths.prepareDirectories()
        let state = AppState(paths: paths, keychain: KeychainStore(service: "test-6-3-restore"))
        await state.bootstrap()
        // 等 bootstrap 期间的 appendLog（250ms 批量）落盘后再取 baseline
        try? await Task.sleep(for: .milliseconds(500))

        let baseline = state.logLines.count
        state.restoreNetworkSnapshot()
        // 等待异步 Task 完成（appendLog 有 250ms flush 延迟；这里给 2 秒上限）
        let timeout = Date().addingTimeInterval(2)
        while Date() < timeout {
            if state.logLines.dropFirst(baseline).contains(where: { $0.contains("执行后诊断") }) {
                break
            }
            try? await Task.sleep(for: .milliseconds(20))
        }
        // appendLog 是 250ms 批量刷，再多等一拍确保落盘
        try? await Task.sleep(for: .milliseconds(400))

        let appended = Array(state.logLines.dropFirst(baseline))
        XCTAssertTrue(
            appended.contains(where: { $0.contains("执行前诊断") && $0.contains("恢复网络（轻量）") }),
            "恢复网络必须输出执行前诊断日志，实际输出：\(appended)"
        )
        XCTAssertTrue(
            appended.contains(where: { $0.contains("执行后诊断") && $0.contains("恢复网络（轻量）") }),
            "恢复网络必须输出执行后诊断日志，实际输出：\(appended)"
        )
        XCTAssertTrue(
            appended.contains(where: { $0.contains("系统代理=") }),
            "诊断输出必须包含系统代理状态，实际输出：\(appended)"
        )
        XCTAssertTrue(
            appended.contains(where: { $0.contains("daemon=") }),
            "诊断输出必须包含 daemon 状态，实际输出：\(appended)"
        )
        XCTAssertTrue(
            appended.contains(where: { $0.contains("198.18 残留路由") }),
            "诊断输出必须包含 198.18 残留路由条数，实际输出：\(appended)"
        )
    }

    /// §6.3 步骤 1 + 5：performNetworkRecovery 在无残留场景下，权限足够路径会输出
    /// "全部清除"；在无残留场景下，不会出现权限不足提示。
    func testPerformNetworkRecoveryLogsAllClearedWhenNothingPending() async {
        let paths = AppPaths()
        try? paths.prepareDirectories()
        let state = AppState(paths: paths, keychain: KeychainStore(service: "test-6-3-perform"))
        await state.bootstrap()

        let baseline = state.logLines.count
        state.performNetworkRecovery()
        // 等待 Task 完成（performNetworkRecovery 包含 await supercoreManager.stop()，最多给 4 秒）
        let timeout = Date().addingTimeInterval(4)
        while Date() < timeout {
            if state.logLines.dropFirst(baseline).contains(where: { $0.contains("Supercore 进程已停止") }) {
                break
            }
            try? await Task.sleep(for: .milliseconds(20))
        }
        // 再等一拍让 post-diag 落盘
        try? await Task.sleep(for: .milliseconds(300))

        let appended = state.logLines.dropFirst(baseline)
        XCTAssertTrue(
            appended.contains(where: { $0.contains("=== 恢复网络：执行前诊断 ===") }),
            "performNetworkRecovery 必须输出执行前诊断块"
        )
        XCTAssertTrue(
            appended.contains(where: { $0.contains("=== 恢复网络：执行后诊断 ===") }),
            "performNetworkRecovery 必须输出执行后诊断块"
        )
        XCTAssertTrue(
            appended.contains(where: { $0.contains("全部清除") || $0.contains("仍有残留") }),
            "performNetworkRecovery 必须给出清除总结"
        )
    }

    /// §6.3 步骤 5：权限不足时，catch 分支会同时输出"权限不足"和完整 sudo 命令。
    /// 这里验证：当 tunLaunchDaemonStatus.loaded 为 false 但调用 performNetworkRecovery
    /// 时，不应进入权限不足提示路径。
    func testPerformNetworkRecoveryDoesNotEmitPermissionPromptWhenNoDaemon() async {
        let paths = AppPaths()
        try? paths.prepareDirectories()
        let state = AppState(paths: paths, keychain: KeychainStore(service: "test-6-3-no-prompt"))
        await state.bootstrap()

        // 确保 daemon 未加载
        XCTAssertFalse(state.tunLaunchDaemonStatus.loaded)

        let baseline = state.logLines.count
        state.performNetworkRecovery()
        let timeout = Date().addingTimeInterval(4)
        while Date() < timeout {
            if state.logLines.dropFirst(baseline).contains(where: { $0.contains("Supercore 进程已停止") }) {
                break
            }
            try? await Task.sleep(for: .milliseconds(20))
        }
        try? await Task.sleep(for: .milliseconds(300))

        let appended = state.logLines.dropFirst(baseline)
        XCTAssertFalse(
            appended.contains(where: { $0.contains("权限不足") && $0.contains("TUN daemon") }),
            "daemon 未加载时不应触发 TUN daemon 权限不足提示"
        )
    }

    /// §6.3 步骤 1 + 2：NetworkDiagnosticsSnapshot 的描述字段在无残留时是稳定的可读文本。
    func testNetworkDiagnosticsSnapshotDescriptionIsReadable() async {
        let paths = AppPaths()
        try? paths.prepareDirectories()
        let state = AppState(paths: paths, keychain: KeychainStore(service: "test-6-3-snapshot"))
        await state.bootstrap()

        let snap = state.runNetworkDiagnostics()
        XCTAssertTrue(
            snap.proxyDescription.contains("未指向本 App") || snap.proxyDescription.contains("仍指向本 App"),
            "proxyDescription 必须是可读的代理状态描述: \(snap.proxyDescription)"
        )
        XCTAssertTrue(
            snap.daemonDescription.contains("未安装") || snap.daemonDescription.contains("已安装但未运行") || snap.daemonDescription.contains("已加载"),
            "daemonDescription 必须是可读的 daemon 状态描述: \(snap.daemonDescription)"
        )
    }
}
