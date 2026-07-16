import AppKit
import Darwin
import Foundation

@MainActor
final class AppState: ObservableObject {
    struct ProbeResultMergeSummary {
        let available: Int
        let total: Int
        let delayResults: [String: Int]
        let delayFailureKinds: [String: String]
        let failureCounts: [String: Int]
        let missingNames: [String]
        let returnedNames: [String]
    }

    struct StartupNodeRestoreResult {
        let nodes: [String]
        let needsManualProbe: Bool
    }

    static func mergeProbeResults(
        requestedNames: [String],
        results: [SupercoreProbeResult],
        existingDelayResults: [String: Int],
        existingDelayFailureKinds: [String: String]
    ) -> ProbeResultMergeSummary {
        let requested = Set(requestedNames)
        var nextPublishedFailureKinds = existingDelayFailureKinds
        var nextPublishedResults = existingDelayResults
        var returnedNames: [String] = []
        var available = 0
        for result in results where requested.contains(result.name) {
            returnedNames.append(result.name)
            let resolvedFailureKind = result.failureKind ?? (result.success ? nil : "unknown")
            if result.success, let latency = result.latencyMs {
                let delay = Int(clamping: latency)
                nextPublishedResults[result.name] = delay
                nextPublishedFailureKinds[result.name] = nil
                if DelayPolicy.isAvailable(delay, failureKind: resolvedFailureKind) {
                    available += 1
                }
            } else {
                nextPublishedResults[result.name] = -1
                nextPublishedFailureKinds[result.name] = resolvedFailureKind
            }
        }
        let missingNames = requestedNames.filter { !returnedNames.contains($0) }
        for name in missingNames {
            nextPublishedFailureKinds[name] = "outbound_not_found"
            nextPublishedResults[name] = -1
        }
        var failureCounts: [String: Int] = Dictionary(
            grouping: results.filter { requested.contains($0.name) && !$0.success }
        ) { $0.failureKind ?? "unknown" }
            .mapValues(\.count)
        if !missingNames.isEmpty {
            failureCounts["outbound_not_found", default: 0] = (failureCounts["outbound_not_found"] ?? 0) + missingNames.count
        }
        return .init(
            available: available,
            total: requestedNames.count,
            delayResults: nextPublishedResults,
            delayFailureKinds: nextPublishedFailureKinds,
            failureCounts: failureCounts,
            missingNames: missingNames,
            returnedNames: returnedNames
        )
    }

    @Published var coreState: CoreState = .notPrepared
    @Published var tunEnabled = false
    @Published var runtimePurpose: RuntimePurpose = .idle
    @Published var selectedMode: ProxyMode = .rule
    @Published var traffic = TrafficFrame(up: 0, down: 0)
    @Published var trafficTotals = TrafficTotals.zero
    @Published var runtimeOptions = RuntimeOptions()
    @Published var proxies: [ProxyGroup] = []
    @Published var providerNodes: [ProxyNode] = []
    @Published var countryGroups: [CountryNodeGroup] = []
    @Published var selectedCountry: String?
    @Published var autoCountrySwitchEnabled = false
    @Published var showOnlyAvailableNodes = false
    @Published var delayResults: [String: Int] = [:]
    @Published var delayFailureKinds: [String: String] = [:]
    @Published var delayTestingGroups: Set<String> = []
    @Published var logLines: [String] = []
    @Published var logEntries: [AppLogEntry] = []
    @Published var profiles: [SubscriptionProfile] = []
    @Published var activeSubscription: SubscriptionProfile?
    @Published var customRules: [CustomRule] = []
    @Published var smartRuleCandidates: [SmartRuleCandidate] = []
    @Published var profileTrafficTotals: [String: TrafficTotals] = [:]
    @Published var userMessage = "未启动"
    @Published var operation: OperationState?
    @Published var isBackgroundDelayTesting = false
    @Published var tunLaunchDaemonStatus = TunLaunchDaemonStatus()
    @Published var networkRecoveryNeeded = false
    @Published var probeURL = DelayPolicy.probeURL

    var currentNodeStatus: CurrentNodeStatus {
        let name = ActiveProxyResolver.concreteNodeName(in: proxies, mode: selectedMode)
        let delay = name.flatMap { delayResults[$0] }
        let failureKind = name.flatMap { delayFailureKinds[$0] }
        return CurrentNodeStatus(name: name, delay: delay, failureKind: failureKind)
    }

    func delayFailureKind(for node: String) -> String? {
        delayFailureKinds[node]
    }

    func delayTitle(for node: String) -> String {
        guard let delay = delayResults[node] else { return "\(node) · 未测" }
        return "\(node) · \(DelayPolicy.displayTitle(for: delay, failureKind: delayFailureKinds[node]))"
    }

    func delayDisplayTitle(for node: String) -> String {
        guard let delay = delayResults[node] else { return "未测" }
        return DelayPolicy.displayTitle(for: delay, failureKind: delayFailureKinds[node])
    }

    func isDelayAvailable(_ node: String) -> Bool {
        DelayPolicy.isAvailable(delayResults[node], failureKind: delayFailureKinds[node])
    }

    var smartRuleStats: SmartRuleStats {
        SmartRuleStats(candidates: smartRuleCandidates)
    }

    let paths: AppPaths
    let keychain: KeychainStore
    let configManager: ConfigManager
    let subscriptionManager: SubscriptionManager
    let trafficUsageStore: TrafficUsageStore
    let smartRuleStore: SmartRuleStore
    let supercoreManager: SupercoreManager
    let supercoreAPIClient: SupercoreAPIClient
    let tunLaunchDaemonManager: TunLaunchDaemonManager
    let proxyManager: SystemProxyManager

    private var settingsWindow: NSWindow?
    private var trafficPollingTask: Task<Void, Never>?
    private var logsTask: Task<Void, Never>?
    private var autoDelayTask: Task<Void, Never>?
    private var launchRefreshTask: Task<Void, Never>?
    private var backgroundSubscriptionTask: Task<Void, Never>?
    private var smartRuleLearningTask: Task<Void, Never>?
    private var startupNodeHealthTask: Task<Void, Never>?
    private var smartRuleProbeTasks: [String: Task<Void, Never>] = [:]
    private var recentSmartRuleConnectionIDs: Set<String> = []
    private var pendingLogLines: [String] = []
    private var pendingLogEntries: [AppLogEntry] = []
    private var logFlushTask: Task<Void, Never>?
    private var isStartingSupercoreProxy = false
    private var activeTrafficUsage = ProfileTrafficUsage.zero
    private var activeTrafficProfileID: String?
    private var usingTunLaunchDaemon = false
    private var lastTrafficUsageFlushAt = Date.distantPast
    private let launchAutoUpdateMinimumInterval: TimeInterval = 60 * 60
    private let launchNetworkTimeout: TimeInterval = 10
    private let backgroundSubscriptionRefreshInterval: TimeInterval = 30 * 60
    private let trafficUsageFlushInterval: TimeInterval = 5
    private static let supercoreDateFormatterWithFractions: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter
    }()
    private static let supercoreDateFormatter: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter
    }()

    init(paths: AppPaths, keychain: KeychainStore) {
        self.paths = paths
        self.keychain = keychain
        self.configManager = ConfigManager(paths: paths, keychain: keychain)
        self.supercoreAPIClient = SupercoreAPIClient(baseURL: URL(string: "http://127.0.0.1:9197")!)
        self.supercoreManager = SupercoreManager(paths: paths, apiClient: supercoreAPIClient)
        self.subscriptionManager = SubscriptionManager(paths: paths, keychain: keychain, configManager: configManager)
        self.trafficUsageStore = TrafficUsageStore(paths: paths)
        self.smartRuleStore = SmartRuleStore(paths: paths)
        self.tunLaunchDaemonManager = TunLaunchDaemonManager()
        self.proxyManager = SystemProxyManager(paths: paths)
        self.supercoreManager.onStateChanged = { [weak self] state in
            Task { @MainActor in
                self?.coreState = state
                if !state.isRunning {
                    self?.runtimePurpose = .idle
                }
            }
        }
        self.supercoreManager.onLogLine = { [weak self] line in
            Task { @MainActor in self?.appendLog(line) }
        }
    }

    func bootstrap() async {
        profiles = subscriptionManager.loadProfiles()
        activeSubscription = subscriptionManager.loadActiveProfile()
        reloadProfileTrafficTotals()
        loadTrafficUsageForActiveProfile()
        loadCustomRulesForActiveProfile()
        loadSmartRulesForActiveProfile()
        loadLocalProxyGroupsForActiveProfile()
        selectedCountry = UserDefaults.standard.string(forKey: "selectedCountry")
        autoCountrySwitchEnabled = UserDefaults.standard.bool(forKey: "autoCountrySwitchEnabled")
        showOnlyAvailableNodes = UserDefaults.standard.bool(forKey: "showOnlyAvailableNodes")
        tunEnabled = UserDefaults.standard.bool(forKey: "tunEnabled")
        if let rawDNSStrategy = UserDefaults.standard.string(forKey: "tunDNSStrategy"),
           let dnsStrategy = TunDNSStrategy(rawValue: rawDNSStrategy) {
            let resetKey = "didResetUnsafeTunDNSDefaults"
            if dnsStrategy != .direct && !UserDefaults.standard.bool(forKey: resetKey) {
                runtimeOptions.dnsStrategy = .direct
                UserDefaults.standard.set(TunDNSStrategy.direct.rawValue, forKey: "tunDNSStrategy")
                UserDefaults.standard.set(true, forKey: resetKey)
                appendLog("已将旧 TUN DNS 设置重置为直连 DNS，避免退出后网络残留")
            } else {
                runtimeOptions.dnsStrategy = dnsStrategy
            }
        }
        if let dnsServer = UserDefaults.standard.string(forKey: "tunDNSServer"), !dnsServer.isEmpty {
            runtimeOptions.dnsServer = dnsServer
        }
        if let savedProbeURL = UserDefaults.standard.string(forKey: "probeURL"), !savedProbeURL.isEmpty {
            probeURL = savedProbeURL
        }
        if let mode = UserDefaults.standard.string(forKey: "selectedMode").flatMap(ProxyMode.init(rawValue:)) {
            selectedMode = mode
        }
        if proxyManager.hasSavedSnapshot {
            userMessage = "检测到上次代理快照，可在设置中恢复网络"
        }
        refreshTunLaunchDaemonStatus()
        loadCachedProviderNodesForActiveProfile()
        await attachExistingCoreIfNeeded()
        checkNetworkRecoveryNeeded()
        configureAutoDelayTask(runImmediately: false)
        startLaunchBackgroundRefresh()
        startBackgroundSubscriptionRefresh()
    }

    func showSettings() {
        if settingsWindow == nil {
            settingsWindow = SettingsWindow.make(appState: self)
        }
        settingsWindow?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    func importSubscription(urlString: String) {
        guard operation == nil else { return }
        Task {
            do {
                setOperation(.importingSubscription, "正在直连下载订阅...")
                let importedProfile = try await subscriptionManager.importSubscription(urlString: urlString, tunEnabled: tunEnabled)
                setOperation(.importingSubscription, "正在保存订阅信息...")
                profiles = subscriptionManager.loadProfiles()
                reloadProfileTrafficTotals()
                let activeProfile = subscriptionManager.loadActiveProfile()
                activeSubscription = activeProfile
                loadTrafficUsageForActiveProfile()
                loadCustomRulesForActiveProfile()
                loadSmartRulesForActiveProfile()
                if activeProfile?.id == importedProfile.id {
                    loadLocalProxyGroupsForActiveProfile()
                    setOperation(.importingSubscription, "正在直连拉取 provider 节点...")
                    await refreshProviderNodesForActiveProfile(timeout: 30, silent: false)
                    setOperation(.importingSubscription, "正在准备本地运行缓存...")
                    do {
                        try await supercoreManager.syncSubscription(
                            profile: importedProfile,
                            sourcePath: try subscriptionManager.coreSubscriptionSourceURL(profileID: importedProfile.id)
                        )
                    } catch {
                        appendLog("准备 Supercore 本地订阅缓存失败：\(error.localizedDescription)")
                    }
                    userMessage = "订阅已保存并设为当前：\(importedProfile.name)"
                } else {
                    userMessage = "订阅已保存：\(importedProfile.name)，当前仍使用：\(activeProfile?.name ?? "未选择订阅")"
                }
            } catch {
                userMessage = "订阅导入失败：\(error.localizedDescription)"
                appendLog(userMessage)
            }
            clearOperation()
        }
    }

    func updateSubscription() {
        guard operation == nil else { return }
        Task {
            let snapshotProfiles = profiles
            guard !snapshotProfiles.isEmpty else {
                userMessage = "还没有可更新的订阅"
                return
            }

            setOperation(.updatingSubscription, "正在更新全部订阅 0/\(snapshotProfiles.count)...")
            var successCount = 0
            var failures: [String] = []
            let activeProfileID = activeSubscription?.id

            for (index, profile) in snapshotProfiles.enumerated() {
                guard !Task.isCancelled else { break }
                updateOperation("正在更新 \(profile.name)（\(index + 1)/\(snapshotProfiles.count)）...")
                do {
                    _ = try await subscriptionManager.updateSubscription(
                        profileID: profile.id,
                        tunEnabled: tunEnabled,
                        timeout: 30
                    )
                    _ = try? await subscriptionManager.downloadProviderNodes(for: profile.id, timeout: 15)
                    if profile.id == activeProfileID {
                        do {
                            try await supercoreManager.syncSubscription(
                                profile: profile,
                                sourcePath: try subscriptionManager.coreSubscriptionSourceURL(profileID: profile.id)
                            )
                        } catch {
                            appendLog("准备 Supercore 本地订阅缓存失败：\(profile.name)：\(error.localizedDescription)")
                        }
                    }
                    successCount += 1
                } catch {
                    failures.append("\(profile.name)：\(error.localizedDescription)")
                    appendLog("订阅更新失败：\(profile.name)：\(error.localizedDescription)")
                }
            }

            setOperation(.updatingSubscription, "正在刷新订阅列表...")
            profiles = subscriptionManager.loadProfiles()
            activeSubscription = activeProfileID.flatMap { id in profiles.first(where: { $0.id == id }) }
                ?? subscriptionManager.loadActiveProfile()
            reloadProfileTrafficTotals()
            loadTrafficUsageForActiveProfile()
            loadCustomRulesForActiveProfile()
            loadSmartRulesForActiveProfile()
            loadLocalProxyGroupsForActiveProfile()
            loadCachedProviderNodesForActiveProfile()

            if coreState.isRunning,
               let activeProfile = activeSubscription {
                do {
                    try await supercoreManager.syncSubscription(
                        profile: activeProfile,
                        sourcePath: try subscriptionManager.coreSubscriptionSourceURL(profileID: activeProfile.id)
                    )
                    try await supercoreAPIClient.reloadActiveSubscription()
                    try await refreshRuntimeState()
                    mergeRuntimeNodesIntoProviderCatalog()
                    appendLog("Supercore 已重载更新后的当前订阅")
                } catch {
                    appendLog("Supercore 重载当前订阅失败：\(error.localizedDescription)")
                }
            }

            if failures.isEmpty {
                userMessage = "全部订阅已更新：\(successCount)/\(snapshotProfiles.count)"
            } else {
                userMessage = "订阅更新完成：成功 \(successCount)/\(snapshotProfiles.count)，失败 \(failures.count)"
            }
            clearOperation()
        }
    }

    func startProxy() {
        guard operation == nil else { return }
        isStartingSupercoreProxy = true
        startSupercoreProxy()
    }

    func stopProxy() {
        stopSupercoreProxy()
    }

    private func startSupercoreProxy() {
        guard operation == nil else {
            isStartingSupercoreProxy = false
            return
        }
        Task {
            defer { isStartingSupercoreProxy = false }
            do {
                autoDelayTask?.cancel()
                autoDelayTask = nil
                setOperation(.startingCore, "正在准备 Supercore runtime...")
                guard let profile = activeSubscription else {
                    throw AppError.missingSubscription
                }
                let daemonStatus = tunLaunchDaemonManager.status()
                tunLaunchDaemonStatus = daemonStatus
                let shouldUseTunDaemon = daemonStatus.installed
                if tunEnabled && !daemonStatus.installed && getuid() != 0 {
                    appendLog("Supercore TUN 需要先安装 LaunchDaemon 权限服务；当前从 App 启动将尝试普通用户模式")
                }
                let options = try makeRuntimeOptions(tunEnabled: tunEnabled, useLaunchDaemon: shouldUseTunDaemon)
                runtimeOptions = options
                supercoreAPIClient.setControlPort(options.controllerPort)
                try configManager.regenerateSupercoreRuntime(
                    profileID: profile.id,
                    tunEnabled: tunEnabled,
                    runtimeOptions: options
                )
                guard !subscriptionManager.needsProviderPayloadCache(profileID: profile.id) else {
                    throw AppError.processFailed("provider 本地缓存未准备好，请先在节点页测速一次或更新订阅")
                }
                guard try supercoreManager.activateCachedSubscription(profileID: profile.id) else {
                    throw AppError.processFailed("Supercore 未加载到本地订阅缓存，请先在导入/更新订阅后再启动代理")
                }
                appendLog("启动使用本地 Supercore 订阅缓存：\(profile.name)")
                resetRuntimeTrafficBaselineForActiveProfile(flushImmediately: true)
                setOperation(.startingCore, "正在启动 Supercore...")
                if shouldUseTunDaemon {
                    try copyRuntimeToDaemonRuntime(profileID: profile.id)
                    setOperation(.startingCore, "正在热重载 TUN 权限服务...")
                    try await supercoreAPIClient.reloadConfig(path: paths.supercoreDaemonRuntimeProfile)
                    let version = try await supercoreAPIClient.getVersion(timeoutInterval: 1.5).version
                    coreState = .running(version: version)
                    usingTunLaunchDaemon = true
                    refreshTunLaunchDaemonStatus()
                } else {
                    usingTunLaunchDaemon = false
                    try await supercoreManager.start(configPath: paths.supercoreRuntimeProfile(id: profile.id))
                }
                try await LocalPortAllocator.waitUntilLocalPortAcceptsConnections(options.mixedPort)
                runtimePurpose = .proxy
                startStreams()
                setOperation(.startingCore, "正在读取 Supercore 代理组...")
                try await refreshRuntimeState()
                mergeRuntimeNodesIntoProviderCatalog()
                let restoredNodeResult = await restoreStartupNodePreference()
                setOperation(.startingCore, "正在启用系统代理 \(options.mixedPort)...")
                try proxyManager.enableSystemProxy(port: options.mixedPort)
                await refreshTrafficSnapshot(flushImmediately: true)
                if let startedNode = restoredNodeResult.nodes.first ?? currentNodeStatus.name,
                   isConcreteProxyNode(startedNode, groupNames: Set(proxies.map(\.name))) {
                    saveLastStartedNode(startedNode)
                }
                configureAutoDelayTask(runImmediately: false)
                if !restoredNodeResult.nodes.isEmpty {
                    userMessage = "代理运行中：\(currentNodeStatus.summary) · \(options.mixedPort)"
                } else {
                    userMessage = "代理运行中：\(profile.name) · \(options.mixedPort)"
                    if restoredNodeResult.needsManualProbe {
                        let prompt = "代理运行中：未能恢复上次节点，建议先在节点页测速再重启"
                        appendLog(prompt)
                        userMessage = prompt
                    }
                }
                if let restoredNode = restoredNodeResult.nodes.first {
                    scheduleStartupNodeHealthCheck(restoredNode)
                }
            } catch {
                try? proxyManager.restoreIfOwned()
                userMessage = "Supercore 启动失败：\(error.localizedDescription)"
                appendLog(userMessage)
            }
            clearOperation()
        }
    }

    private func stopSupercoreProxy() {
        Task {
            await persistFinalTrafficSnapshot(resetRuntimeBaseline: true)
            startupNodeHealthTask?.cancel()
            startupNodeHealthTask = nil
            stopStreams()
            do {
                try proxyManager.restoreIfOwned()
            } catch {
                appendLog("恢复系统代理失败：\(error.localizedDescription)")
            }
            if usingTunLaunchDaemon, let profileID = activeSubscription?.id {
                do {
                    try configManager.regenerateSupercoreRuntime(
                        profileID: profileID,
                        tunEnabled: false,
                        runtimeOptions: runtimeOptions,
                        probeURL: probeURL
                    )
                    try copyRuntimeToDaemonRuntime(profileID: profileID)
                    try await supercoreAPIClient.reloadConfig(path: paths.supercoreDaemonRuntimeProfile)
                    refreshTunLaunchDaemonStatus()
                } catch {
                    appendLog("关闭 TUN daemon 配置失败：\(error.localizedDescription)")
                }
            } else {
                await supercoreManager.stop()
            }
            usingTunLaunchDaemon = false
            resetRuntimeTrafficBaselineForActiveProfile(flushImmediately: true)
            runtimePurpose = .idle
            traffic = TrafficFrame(up: 0, down: 0)
            userMessage = tunLaunchDaemonStatus.loaded ? "已停止代理，TUN 权限服务保持待命" : "已停止 Supercore"
        }
    }

    func setSelectedCountry(_ country: String?) {
        selectedCountry = country
        if let country {
            UserDefaults.standard.set(country, forKey: "selectedCountry")
            userMessage = "已选择国家：\(country)"
        } else {
            UserDefaults.standard.removeObject(forKey: "selectedCountry")
            userMessage = "已清除国家自动选择"
        }
        configureAutoDelayTask(runImmediately: true)
    }

    func setAutoCountrySwitchEnabled(_ enabled: Bool) {
        autoCountrySwitchEnabled = enabled
        UserDefaults.standard.set(enabled, forKey: "autoCountrySwitchEnabled")
        configureAutoDelayTask(runImmediately: true)
        if enabled {
            userMessage = coreState.isRunning ? "已开启国家自动择优" : "已开启国家自动择优，启动代理后生效"
        } else {
            userMessage = "已关闭国家自动择优"
        }
    }

    func setShowOnlyAvailableNodes(_ enabled: Bool) {
        showOnlyAvailableNodes = enabled
        UserDefaults.standard.set(enabled, forKey: "showOnlyAvailableNodes")
        rebuildCountryGroups()
        userMessage = enabled ? "只显示可测速节点" : "显示全部节点"
    }

    func trafficTotals(for profile: SubscriptionProfile) -> TrafficTotals {
        profileTrafficTotals[profile.id] ?? .zero
    }

    func setTunEnabled(_ enabled: Bool) {
        tunEnabled = enabled
        UserDefaults.standard.set(enabled, forKey: "tunEnabled")
        Task {
            do {
                if let profileID = activeSubscription?.id {
                    try configManager.regenerateSupercoreRuntime(
                        profileID: profileID,
                        tunEnabled: enabled,
                        runtimeOptions: runtimeOptions
                    )
                }
                userMessage = enabled ? "已生成 TUN runtime 配置，重启代理后生效" : "已关闭 TUN 配置，重启代理后生效"
            } catch {
                userMessage = "TUN 配置更新失败：\(error.localizedDescription)"
            }
        }
    }

    func setTunDNSStrategy(_ strategy: TunDNSStrategy) {
        runtimeOptions.dnsStrategy = strategy
        UserDefaults.standard.set(strategy.rawValue, forKey: "tunDNSStrategy")
        Task {
            do {
                if let profileID = activeSubscription?.id {
                    try configManager.regenerateSupercoreRuntime(
                        profileID: profileID,
                        tunEnabled: tunEnabled,
                        runtimeOptions: runtimeOptions
                    )
                    if coreState.isRunning {
                        if usingTunLaunchDaemon {
                            try copyRuntimeToDaemonRuntime(profileID: profileID)
                            try await supercoreAPIClient.reloadConfig(path: paths.supercoreDaemonRuntimeProfile)
                        } else {
                            try await supercoreAPIClient.reloadConfig(path: paths.supercoreRuntimeProfile(id: profileID))
                        }
                    }
                }
                userMessage = "DNS 策略已切换为 \(strategy.title)"
            } catch {
                userMessage = "DNS 策略更新失败：\(error.localizedDescription)"
                appendLog(userMessage)
            }
        }
    }

    func setProbeURL(_ url: String) {
        let trimmed = url.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        probeURL = trimmed
        UserDefaults.standard.set(trimmed, forKey: "probeURL")
        userMessage = "测速 URL 已更新：\(trimmed)"
    }

    func refreshTunLaunchDaemonStatus() {
        tunLaunchDaemonStatus = tunLaunchDaemonManager.status()
    }

    func installTunLaunchDaemon() {
        guard operation == nil else { return }
        guard let profile = activeSubscription else {
            userMessage = "请先导入并选择订阅"
            return
        }
        Task {
            setOperation(.tunDaemon, "正在准备 TUN 权限服务...")
            do {
                try supercoreManager.ensureCoreInstalled()
                let options = try makeRuntimeOptions(tunEnabled: tunEnabled, useLaunchDaemon: true)
                runtimeOptions = options
                supercoreAPIClient.setControlPort(options.controllerPort)
                try configManager.regenerateSupercoreRuntime(
                    profileID: profile.id,
                    tunEnabled: tunEnabled,
                    runtimeOptions: options
                )
                try copyRuntimeToDaemonRuntime(profileID: profile.id)
                setOperation(.tunDaemon, "需要 macOS 管理员授权安装 LaunchDaemon...")
                try tunLaunchDaemonManager.installOrUpdate(
                    binaryURL: paths.supercoreBinary,
                    configURL: paths.supercoreDaemonRuntimeProfile
                )
                refreshTunLaunchDaemonStatus()
                userMessage = "TUN 权限服务已安装，之后可免重复输密码"
            } catch {
                userMessage = "安装 TUN 权限服务失败：\(error.localizedDescription)"
                appendLog(userMessage)
            }
            clearOperation()
        }
    }

    func uninstallTunLaunchDaemon() {
        guard operation == nil else { return }
        Task {
            setOperation(.tunDaemon, "正在卸载 TUN 权限服务...")
            do {
                try tunLaunchDaemonManager.uninstall()
                usingTunLaunchDaemon = false
                refreshTunLaunchDaemonStatus()
                userMessage = "TUN 权限服务已卸载"
            } catch {
                userMessage = "卸载 TUN 权限服务失败：\(error.localizedDescription)"
                appendLog(userMessage)
            }
            clearOperation()
        }
    }

    func setMode(_ mode: ProxyMode) {
        Task {
            do {
                if coreState.isRunning, mode == .direct {
                    try await supercoreAPIClient.useOutbound(name: "direct")
                }
                selectedMode = mode
                UserDefaults.standard.set(mode.rawValue, forKey: "selectedMode")
                userMessage = coreState.isRunning ? "已切换模式：\(mode.title)" : "已保存模式：\(mode.title)，启动后生效"
            } catch {
                userMessage = "切换模式失败：\(error.localizedDescription)"
            }
        }
    }

    func selectProxy(group: String, node: String) {
        Task {
            do {
                if proxies.contains(where: { $0.name == node }) {
                    userMessage = "代理组仅用于查看节点，请选择里面的具体节点"
                    return
                }
                if let profileID = activeSubscription?.id {
                    subscriptionManager.saveSelectedNode(profileID: profileID, group: group, node: node)
                    profiles = subscriptionManager.loadProfiles()
                    activeSubscription = profiles.first(where: { $0.id == profileID })
                }
                ensureProxyModeForConcreteSelection()
                if coreState.isRunning {
                    try await supercoreAPIClient.useOutbound(name: node)
                    try await refreshRuntimeState()
                    saveLastStartedNode(node)
                    userMessage = "已选择节点：\(currentNodeStatus.summary)"
                } else {
                    setLocalSelectedNode(group: group, node: node)
                    saveLastStartedNode(node)
                    userMessage = "已保存节点选择，启动代理后生效：\(node)"
                }
            } catch {
                userMessage = "选择节点失败：\(error.localizedDescription)"
            }
        }
    }

    func testAllGroupsDelay() {
        guard operation == nil else { return }
        Task {
            setOperation(.testingDelay, "正在准备测速服务...")
            do {
                try await ensureCoreRunningForDelayTesting()
                updateOperation("正在测试全部代理组延迟...")
                guard !proxies.isEmpty else {
                    userMessage = "当前订阅没有可测速代理组"
                    clearOperation()
                    return
                }
                delayTestingGroups = Set(proxies.map(\.name))
                let names = Array(Set(proxies.flatMap(\.all)))
                    .sorted { $0.localizedStandardCompare($1) == .orderedAscending }
                let result = await testNodeDelays(
                    names: names,
                    timeout: DelayPolicy.timeoutMilliseconds,
                    concurrency: DelayPolicy.manualConcurrency
                )
                delayTestingGroups = []
                userMessage = "全部代理组延迟测试完成：可用 \(result.available)/\(result.total)"
            } catch {
                delayTestingGroups = []
                userMessage = "测速失败：\(error.localizedDescription)"
                appendLog(userMessage)
            }
            clearOperation()
        }
    }

    func testAllAvailableNodesDelay() {
        guard operation == nil else { return }
        Task {
            setOperation(.testingDelay, "正在准备测速服务...")
            do {
                try await ensureCoreRunningForDelayTesting()
                updateOperation("正在测试可用节点延迟...")
                await testCatalogNodeDelays(limit: nil, concurrency: DelayPolicy.manualConcurrency)
                userMessage = "可用节点延迟测试完成"
            } catch {
                userMessage = "测速失败：\(error.localizedDescription)"
                appendLog(userMessage)
            }
            clearOperation()
        }
    }

    func testAllNodesDelay() {
        guard operation == nil else { return }
        Task {
            setOperation(.testingDelay, "正在准备测速服务...")
            do {
                try await ensureCoreRunningForDelayTesting()
                let names = allKnownProxyNodeNames(includeHistoricalDelayResults: true)
                guard !names.isEmpty else {
                    userMessage = "没有可测速节点：订阅未解析出具体节点，请检查 provider 是否下载成功"
                    appendLog(userMessage)
                    clearOperation()
                    return
                }
                updateOperation("正在测试所有节点，包括已超时节点...")
                let result = await testNodeDelays(
                    names: names,
                    timeout: DelayPolicy.timeoutMilliseconds,
                    concurrency: DelayPolicy.manualConcurrency
                )
                userMessage = "所有节点测速完成：可用 \(result.available)/\(result.total)"
            } catch {
                userMessage = "测速失败：\(error.localizedDescription)"
                appendLog(userMessage)
            }
            clearOperation()
        }
    }

    func autoSelectBestNodeNow() {
        guard operation == nil else { return }
        Task {
            setOperation(.testingDelay, "正在准备测速服务...")
            do {
                try await ensureCoreRunningForDelayTesting()
                if let selectedCountry {
                    updateOperation("正在测试 \(selectedCountry) 节点并自动择优...")
                    let countryNames = nodesForCountry(selectedCountry).map(\.name)
                    await testNodeDelays(
                        names: countryNames.isEmpty ? allKnownProxyNodeNames(includeHistoricalDelayResults: true) : countryNames,
                        timeout: DelayPolicy.timeoutMilliseconds,
                        concurrency: DelayPolicy.manualConcurrency
                    )
                    if let group = countryGroups.first(where: { $0.country == selectedCountry }),
                       let best = bestNodeName(in: group.nodes) {
                        await selectBestCountryNode(best)
                    } else if let best = bestSelectableDelayNodeName() {
                        await selectBestAvailableNode(best)
                    } else {
                        userMessage = "没有找到可自动切换的低延迟节点"
                    }
                } else {
                    updateOperation("正在全局测速并自动择优...")
                    await testNodeDelays(
                        names: allKnownProxyNodeNames(includeHistoricalDelayResults: true),
                        timeout: DelayPolicy.timeoutMilliseconds,
                        concurrency: DelayPolicy.manualConcurrency
                    )
                    if let best = bestSelectableDelayNodeName() {
                        await selectBestAvailableNode(best)
                    } else {
                        userMessage = "没有找到可自动切换的低延迟节点"
                    }
                }
            } catch {
                userMessage = "自动择优失败：\(error.localizedDescription)"
                appendLog(userMessage)
            }
            clearOperation()
        }
    }

    func autoSelectBestNode(in groupName: String) {
        guard operation == nil else { return }
        Task {
            setOperation(.testingDelay, "正在准备测速服务...")
            do {
                try await ensureCoreRunningForDelayTesting()
                let names = concreteNodeNames(inGroup: groupName)
                guard !names.isEmpty else {
                    userMessage = "\(groupName) 没有可择优的具体节点"
                    clearOperation()
                    return
                }
                updateOperation("正在测试 \(groupName) 内的节点...")
                await testNodeDelays(
                    names: names,
                    timeout: DelayPolicy.timeoutMilliseconds,
                    concurrency: DelayPolicy.manualConcurrency
                )
                guard let best = names.compactMap({ name -> (String, Int)? in
                    guard isDelayAvailable(name), let delay = delayResults[name] else { return nil }
                    return (name, delay)
                }).min(by: { $0.1 < $1.1 })?.0 else {
                    userMessage = "\(groupName) 没有可用低延迟节点"
                    clearOperation()
                    return
                }
                try await applyBestNode(best, forGroup: groupName)
                userMessage = "\(groupName) 已择优：\(currentNodeStatus.summary)"
            } catch {
                userMessage = "代理组择优失败：\(error.localizedDescription)"
                appendLog(userMessage)
            }
            clearOperation()
        }
    }

    func testDelay(groupName: String) {
        guard operation == nil else { return }
        guard let group = proxies.first(where: { $0.name == groupName }) else {
            userMessage = "未找到代理组：\(groupName)"
            return
        }
        Task {
            setOperation(.testingDelay, "正在准备测速服务...")
            do {
                try await ensureCoreRunningForDelayTesting()
                updateOperation("正在测试 \(group.name) 延迟...")
                let concreteNames = concreteNodeNames(inGroup: groupName)
                guard !concreteNames.isEmpty else {
                    userMessage = "\(groupName) 没有可测速的具体节点"
                    clearOperation()
                    return
                }
                delayTestingGroups.insert(group.name)
                let result = await testSupercoreNodeDelays(
                    names: concreteNames,
                    timeout: DelayPolicy.timeoutMilliseconds,
                    concurrency: DelayPolicy.manualConcurrency,
                    announcesProgress: false
                )
                delayTestingGroups.remove(group.name)
                userMessage = "\(group.name) 测速完成：可用 \(result.available)/\(result.total)"
            } catch {
                delayTestingGroups.remove(group.name)
                userMessage = "测速失败：\(error.localizedDescription)"
                appendLog(userMessage)
            }
            clearOperation()
        }
    }

    func delaySubtitle(for group: ProxyGroup) -> String {
        if delayTestingGroups.contains(group.name) {
            return "测试中..."
        }
        guard let now = group.now, let delay = delayResults[now] else {
            return group.now ?? "-"
        }
        return "\(now) · \(DelayPolicy.displayTitle(for: delay, failureKind: delayFailureKinds[now]))"
    }

    func refreshRuntimeState() async throws {
        selectedMode = selectedMode == .direct ? .direct : .rule
        let runtimeGroups = try await supercoreAPIClient.getGroups()
        proxies = runtimeGroups
            .map { group in
                ProxyGroup(
                    name: group.name,
                    type: group.kind,
                    now: group.selectedMember,
                    all: group.members.map(\.name)
                )
            }
            .filter { !$0.name.isEmpty && !$0.all.isEmpty }
            .sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }

        for member in runtimeGroups.flatMap(\.members) {
            if let latency = member.lastLatencyMs {
                delayResults[member.name] = Int(clamping: latency)
                delayFailureKinds[member.name] = nil
            } else if !member.healthy, member.attempts > 0 {
                delayResults[member.name] = -1
                delayFailureKinds[member.name] = "dial_error"
            }
        }
    }

    func refreshNodeList() {
        Task {
            await refreshProviderNodesForActiveProfile(timeout: 15, silent: false)
            if coreState.isRunning {
                do {
                    try await refreshRuntimeState()
                    mergeRuntimeNodesIntoProviderCatalog()
                    userMessage = "代理组已刷新"
                } catch {
                    loadLocalProxyGroupsForActiveProfile()
                    userMessage = "已显示订阅本地代理组，API 刷新失败：\(error.localizedDescription)"
                }
            } else {
                loadLocalProxyGroupsForActiveProfile()
                userMessage = proxies.isEmpty ? "当前订阅没有解析到代理组" : "已显示当前订阅代理组"
            }
        }
    }

    func switchProfile(_ profileID: String) {
        guard operation == nil else { return }
        switchSupercoreProfile(profileID)
    }

    private func switchSupercoreProfile(_ profileID: String) {
        Task {
            do {
                setOperation(.switchingProfile, "正在切换本地订阅...")
                let wasRunning = coreState.isRunning
                let previousPurpose = runtimePurpose
                if wasRunning {
                    await persistFinalTrafficSnapshot(resetRuntimeBaseline: true)
                    stopStreams()
                }
                let profile = try subscriptionManager.setActiveProfile(profileID)
                activeSubscription = profile
                profiles = subscriptionManager.loadProfiles()
                reloadProfileTrafficTotals()
                loadTrafficUsageForActiveProfile()
                loadCustomRulesForActiveProfile()
                loadSmartRulesForActiveProfile()
                loadLocalProxyGroupsForActiveProfile()
                loadCachedProviderNodesForActiveProfile()
                filterDelayResultsForActiveProfile()

                if wasRunning {
                    guard !subscriptionManager.needsProviderPayloadCache(profileID: profile.id) else {
                        appendLog("已切换本地订阅，跳过运行中热切换：provider 本地缓存尚未准备")
                        userMessage = "已切换订阅：\(profile.name)，provider 缓存将在下次启动代理时准备"
                        clearOperation()
                        return
                    }
                    do {
                        setOperation(.switchingProfile, "正在热切换运行中的代理...")
                        let shouldUseTun = previousPurpose == .delayTesting ? false : tunEnabled
                        var options = runtimeOptions
                        options.tunEnabled = shouldUseTun
                        runtimeOptions = options
                supercoreAPIClient.setControlPort(options.controllerPort)
                try configManager.regenerateSupercoreRuntime(
                    profileID: profile.id,
                    tunEnabled: tunEnabled,
                    runtimeOptions: options,
                    probeURL: probeURL
                )
                        resetRuntimeTrafficBaselineForActiveProfile(flushImmediately: true)
                        let sourcePath = try subscriptionManager.coreSubscriptionSourceURL(profileID: profile.id)
                        if !(try supercoreManager.activateCachedSubscription(profileID: profile.id)) {
                            try await supercoreManager.syncSubscription(profile: profile, sourcePath: sourcePath)
                        }
                        try await supercoreAPIClient.useSubscription(id: profile.id)
                        if usingTunLaunchDaemon {
                            try copyRuntimeToDaemonRuntime(profileID: profile.id)
                            try await supercoreAPIClient.reloadConfig(path: paths.supercoreDaemonRuntimeProfile)
                            let version = try await supercoreAPIClient.getVersion(timeoutInterval: 1.5).version
                            coreState = .running(version: version)
                            usingTunLaunchDaemon = true
                            refreshTunLaunchDaemonStatus()
                        } else {
                            try await supercoreAPIClient.reloadConfig(path: paths.supercoreRuntimeProfile(id: profile.id))
                        }
                        runtimePurpose = previousPurpose == .delayTesting ? .delayTesting : .proxy
                        try await refreshRuntimeState()
                        mergeRuntimeNodesIntoProviderCatalog()
                        await restoreSavedSelections()
                        startStreams()
                        await refreshTrafficSnapshot(flushImmediately: true)
                        userMessage = "已切换订阅并热重载代理：\(profile.name)"
                    } catch {
                        appendLog("运行中的代理热切换失败：\(error.localizedDescription)")
                        userMessage = "已切换订阅：\(profile.name)，运行中的代理重载失败，停止后再启动会使用新订阅"
                    }
                } else {
                    _ = try? supercoreManager.activateCachedSubscription(profileID: profile.id)
                    userMessage = "已切换订阅：\(profile.name)"
                }
            } catch {
                userMessage = "切换 Supercore 订阅失败：\(error.localizedDescription)"
                appendLog(userMessage)
            }
            clearOperation()
        }
    }

    func restoreNetworkSnapshot() {
        Task {
            appendLog("=== 恢复网络（轻量）：执行前诊断 ===")
            let preDiag = runNetworkDiagnostics()
            appendLog("诊断完成：系统代理=\(preDiag.proxyDescription)，daemon=\(preDiag.daemonDescription)，198.18 残留路由 \(preDiag.fakeIPRouteCount) 条")
            var postDiag: NetworkDiagnosticsSnapshot? = nil
            do {
                try proxyManager.restoreIfOwned()
                appendLog("系统代理快照已恢复")
                userMessage = "网络代理快照已恢复"
            } catch {
                appendLog("恢复网络失败：\(error.localizedDescription)")
                userMessage = "恢复网络失败：\(error.localizedDescription)"
            }
            // §6.3 步骤 1：恢复网络结束后再次诊断，确保 post 状态始终被记录
            appendLog("=== 恢复网络（轻量）：执行后诊断 ===")
            postDiag = runNetworkDiagnostics()
            if let postDiag {
                appendLog("诊断完成：系统代理=\(postDiag.proxyDescription)，daemon=\(postDiag.daemonDescription)，198.18 残留路由 \(postDiag.fakeIPRouteCount) 条")
                if postDiag.fakeIPRouteCount > 0 {
                    appendLog("注意：198.18.0.0/15 仍有 \(postDiag.fakeIPRouteCount) 条残留路由，如需清理请使用「一键恢复网络」或在终端执行：sudo route delete -net 198.18.0.0/15")
                }
                if postDiag.daemonLoaded {
                    appendLog("注意：TUN LaunchDaemon 仍在运行，如需停止请使用「一键恢复网络」或在终端执行：sudo launchctl bootout system cn.yueqiu.elevator.supercore")
                }
                networkRecoveryNeeded = postDiag.daemonLoaded || postDiag.fakeIPRouteCount > 0 || postDiag.proxyPointsToUs
            }
        }
    }

    func performNetworkRecovery() {
        guard operation == nil else { return }
        Task {
            setOperation(.networkRecovery, "正在恢复网络...")
            appendLog("=== 恢复网络：执行前诊断 ===")
            let preDiag = runNetworkDiagnostics()
            appendLog("诊断完成：系统代理=\(preDiag.proxyDescription)，daemon=\(preDiag.daemonDescription)，198.18 残留路由 \(preDiag.fakeIPRouteCount) 条")

            var recovered = true
            do {
                try proxyManager.restoreIfOwned()
                appendLog("系统代理已恢复")
            } catch {
                appendLog("恢复系统代理失败：\(error.localizedDescription)")
                appendLog("如需手动恢复，请在终端执行：sudo networksetup -setwebproxystate <服务名> off && sudo networksetup -setsecurewebproxystate <服务名> off && sudo networksetup -setsocksfirewallproxystate <服务名> off")
                recovered = false
            }
            if tunLaunchDaemonStatus.loaded {
                if getuid() == 0 {
                    do {
                        if let profileID = activeSubscription?.id {
                            try configManager.regenerateSupercoreRuntime(
                                profileID: profileID,
                                tunEnabled: false,
                                runtimeOptions: runtimeOptions
                            )
                            try copyRuntimeToDaemonRuntime(profileID: profileID)
                            try await supercoreAPIClient.reloadConfig(path: paths.supercoreDaemonRuntimeProfile)
                            appendLog("TUN daemon 已重置为关闭状态")
                        }
                    } catch {
                        appendLog("重置 TUN daemon 失败：\(error.localizedDescription)")
                        appendLog("权限不足：关闭 TUN daemon 需要管理员权限，请在终端执行：sudo launchctl bootout system cn.yueqiu.elevator.supercore")
                        userMessage = "需要管理员权限关闭 TUN daemon，请在终端执行：sudo launchctl bootout system cn.yueqiu.elevator.supercore"
                        recovered = false
                    }
                } else {
                    appendLog("权限不足：TUN daemon 运行中，但当前进程无 root 权限，无法自动关闭")
                    appendLog("请在终端执行：sudo launchctl bootout system cn.yueqiu.elevator.supercore")
                    userMessage = "TUN daemon 需要管理员权限才能关闭，请在终端执行：sudo launchctl bootout system cn.yueqiu.elevator.supercore"
                    recovered = false
                }
            }
            await supercoreManager.stop()
            appendLog("Supercore 进程已停止")

            appendLog("=== 恢复网络：执行后诊断 ===")
            let postDiag = runNetworkDiagnostics()
            appendLog("诊断完成：系统代理=\(postDiag.proxyDescription)，daemon=\(postDiag.daemonDescription)，198.18 残留路由 \(postDiag.fakeIPRouteCount) 条")
            let proxyChanged = preDiag.proxyPointsToUs != postDiag.proxyPointsToUs
            let daemonChanged = preDiag.daemonLoaded != postDiag.daemonLoaded
            let routeChanged = preDiag.fakeIPRouteCount != postDiag.fakeIPRouteCount
            if !recovered {
                appendLog("仍有残留：系统代理=\(postDiag.proxyPointsToUs ? "仍指向本 App" : "已清除")，daemon=\(postDiag.daemonLoaded ? "仍运行" : "已停止")，198.18 路由 \(postDiag.fakeIPRouteCount) 条（变化：代理 \(proxyChanged ? "已变化" : "无变化")，daemon \(daemonChanged ? "已变化" : "无变化")，路由 \(routeChanged ? "已变化" : "无变化")）")
            } else {
                appendLog("全部清除：系统代理已恢复，daemon 已停止，198.18 路由已无残留")
            }

            networkRecoveryNeeded = !recovered
            if recovered {
                userMessage = "网络已恢复"
            }
            clearOperation()
        }
    }

    /// §6.3 TUN/DNS 安全 — 独立诊断函数，输出三项目前状态。
    /// 可在恢复网络前后、日志面板、菜单等任意位置独立调用。
    struct NetworkDiagnosticsSnapshot: Equatable {
        /// 系统代理是否指向本 App 端口（7890 HTTP / 7897 SOCKS）。
        let proxyPointsToUs: Bool
        /// 代理指向说明（用于日志输出）。
        let proxyDescription: String
        /// LaunchDaemon 是否已加载。
        let daemonLoaded: Bool
        /// Daemon 状态说明（用于日志输出）。
        let daemonDescription: String
        /// 198.18.0.0/15 Fake-IP 残留路由条数。
        let fakeIPRouteCount: Int
    }

    /// 收集三项关键状态：系统代理、daemon runtime、198.18 残留路由。
    /// 不修改任何系统状态，仅做只读探测。
    func runNetworkDiagnostics() -> NetworkDiagnosticsSnapshot {
        let proxyToApp = proxyManager.isSystemProxyPointingTo(port: 7890)
            || proxyManager.isSystemProxyPointingTo(port: 7897)
        let proxyDesc: String
        if proxyToApp {
            proxyDesc = "仍指向本 App（7890/7897）"
        } else if proxyManager.hasSavedSnapshot {
            proxyDesc = "未指向本 App，但存在未恢复的代理快照"
        } else {
            proxyDesc = "未指向本 App"
        }

        let daemon = tunLaunchDaemonManager.status()
        let daemonDesc: String
        if daemon.loaded {
            daemonDesc = daemon.pid.map { "已加载（pid \($0)）" } ?? "已加载"
        } else if daemon.installed {
            daemonDesc = "已安装但未运行"
        } else {
            daemonDesc = "未安装"
        }

        let routeCount = countFakeIPRoutes()
        return NetworkDiagnosticsSnapshot(
            proxyPointsToUs: proxyToApp,
            proxyDescription: proxyDesc,
            daemonLoaded: daemon.loaded,
            daemonDescription: daemonDesc,
            fakeIPRouteCount: routeCount
        )
    }

    /// 探测 `198.18.0.0/15` Fake-IP 残留路由条数。
    /// 通过 `netstat -rn -f inet` 只读查询，失败时返回 0 并输出错误。
    private func countFakeIPRoutes() -> Int {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/netstat")
        process.arguments = ["-rn", "-f", "inet"]
        let stdout = Pipe()
        let stderr = Pipe()
        process.standardOutput = stdout
        process.standardError = stderr
        do {
            try process.run()
        } catch {
            appendLog("诊断：执行 netstat 失败：\(error.localizedDescription)")
            return 0
        }
        let data = stdout.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            let errText = String(data: stderr.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            appendLog("诊断：netstat 退出码非零（\(process.terminationStatus)）：\(errText)")
            return 0
        }
        let output = String(data: data, encoding: .utf8) ?? ""
        return output
            .split(separator: "\n")
            .filter { $0.contains("198.18.0.0/15") }
            .count
    }

    private func checkNetworkRecoveryNeeded() {
        let hasSnapshot = proxyManager.hasSavedSnapshot
        let hasDaemon = tunLaunchDaemonStatus.loaded
        let hasCoreProcess = coreState.isRunning
        let proxyPointsToUs = proxyManager.isSystemProxyPointingTo(port: 7890) || proxyManager.isSystemProxyPointingTo(port: 7897)
        networkRecoveryNeeded = hasSnapshot || hasDaemon || hasCoreProcess || proxyPointsToUs
        if networkRecoveryNeeded {
            appendLog("检测到上次网络状态未清理：快照=\(hasSnapshot), daemon=\(hasDaemon), 进程=\(hasCoreProcess), 代理=\(proxyPointsToUs)")
        }
    }

    func openAppSupport() {
        NSWorkspace.shared.open(paths.root)
    }

    func clearLogs() {
        logLines = []
        logEntries = []
        pendingLogLines = []
        pendingLogEntries = []
        userMessage = "日志已清空"
    }

    func addCustomRule(
        target: CustomRuleTarget,
        value: String,
        action: CustomRuleAction,
        outboundName: String? = nil
    ) {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            userMessage = "规则内容不能为空"
            return
        }
        guard !trimmed.contains(","), !trimmed.contains("\n") else {
            userMessage = "规则内容不能包含逗号或换行"
            return
        }
        let outbound = outboundName?.trimmingCharacters(in: .whitespacesAndNewlines)
        if action == .outbound, outbound?.isEmpty != false {
            userMessage = "请选择要指定的节点或代理组"
            return
        }
        customRules.insert(
            CustomRule(
                target: target,
                value: trimmed,
                action: action,
                outboundName: action == .outbound ? outbound : nil
            ),
            at: 0
        )
        saveCustomRulesAndReloadRuntime(successMessage: "规则已添加")
    }

    func removeCustomRule(_ ruleID: UUID) {
        customRules.removeAll { $0.id == ruleID }
        saveCustomRulesAndReloadRuntime(successMessage: "规则已删除")
    }

    func setCustomRuleEnabled(_ ruleID: UUID, enabled: Bool) {
        customRules = customRules.map { rule in
            guard rule.id == ruleID else { return rule }
            var copy = rule
            copy.enabled = enabled
            return copy
        }
        saveCustomRulesAndReloadRuntime(successMessage: enabled ? "规则已启用" : "规则已停用")
    }

    func smartRules(recommendation action: CustomRuleAction) -> [SmartRuleCandidate] {
        smartRuleCandidates
            .filter { $0.recommendationAction == action }
            .sorted { lhs, rhs in
                if lhs.enabledAction == nil, rhs.enabledAction != nil { return true }
                if lhs.enabledAction != nil, rhs.enabledAction == nil { return false }
                if lhs.hitCount != rhs.hitCount { return lhs.hitCount > rhs.hitCount }
                return lhs.lastSeenAt > rhs.lastSeenAt
            }
    }

    func isSmartRuleEnabled(_ candidate: SmartRuleCandidate, action: CustomRuleAction) -> Bool {
        candidate.enabledAction == action ||
            customRules.contains { rule in
                rule.enabled &&
                    rule.target == candidate.target &&
                    rule.action == action &&
                    rule.value.caseInsensitiveCompare(candidate.value) == .orderedSame
            }
    }

    func enableSmartRule(_ candidateID: UUID) {
        guard let candidate = smartRuleCandidates.first(where: { $0.id == candidateID }),
              let action = candidate.recommendationAction else {
            userMessage = "这条学习记录还没有可启用建议"
            return
        }
        enableSmartRules([candidate], action: action)
    }

    func enableAllSmartRules(recommendation action: CustomRuleAction) {
        let candidates = smartRules(recommendation: action)
            .filter { !isSmartRuleEnabled($0, action: action) }
        guard !candidates.isEmpty else {
            userMessage = "没有可启用的\(action.title)建议"
            return
        }
        enableSmartRules(candidates, action: action)
    }

    func toggleProxy() {
        guard operation == nil else { return }
        if runtimePurpose == .proxy, coreState.isRunning {
            stopProxy()
        } else {
            startProxy()
        }
    }

    func prepareForQuit() async {
        await persistFinalTrafficSnapshot(resetRuntimeBaseline: runtimePurpose == .proxy)
        stopStreams()
        autoDelayTask?.cancel()
        startupNodeHealthTask?.cancel()
        launchRefreshTask?.cancel()
        backgroundSubscriptionTask?.cancel()
        smartRuleLearningTask?.cancel()
        smartRuleProbeTasks.values.forEach { $0.cancel() }
        saveSmartRulesForActiveProfile()
        logFlushTask?.cancel()
        persistActiveTrafficUsage(force: true)
        flushPendingLogs()
        try? proxyManager.restoreIfOwned()
        if usingTunLaunchDaemon, let profileID = activeSubscription?.id {
            do {
                try configManager.regenerateSupercoreRuntime(
                    profileID: profileID,
                    tunEnabled: false,
                    runtimeOptions: runtimeOptions
                )
                try copyRuntimeToDaemonRuntime(profileID: profileID)
                try await supercoreAPIClient.reloadConfig(path: paths.supercoreDaemonRuntimeProfile)
            } catch {
                appendLog("退出时关闭 TUN daemon 配置失败：\(error.localizedDescription)")
            }
        } else {
            await supercoreManager.stop()
        }
        usingTunLaunchDaemon = false
        runtimePurpose = .idle
        traffic = TrafficFrame(up: 0, down: 0)
    }

    private func startStreams() {
        stopStreams()
        startSupercoreStreams()
        startSmartRuleLearning()
    }

    private func startSupercoreStreams() {
        trafficPollingTask = Task { [weak self] in
            guard let self else { return }
            var previous: ConnectionTrafficSnapshot?
            var previousAt: Date?
            while !Task.isCancelled {
                do {
                    let snapshot = try await self.supercoreAPIClient.getConnectionsTrafficSnapshot()
                    let now = Date()
                    if let previous, let previousAt {
                        let elapsed = max(0.25, now.timeIntervalSince(previousAt))
                        let frame = TrafficFrame(
                            up: Int(Double(max(0, snapshot.upTotal - previous.upTotal)) / elapsed),
                            down: Int(Double(max(0, snapshot.downTotal - previous.downTotal)) / elapsed)
                        )
                        await MainActor.run {
                            self.recordTrafficSnapshot(snapshot)
                            self.traffic = frame
                        }
                    } else {
                        await MainActor.run {
                            self.recordTrafficSnapshot(snapshot)
                        }
                    }
                    previous = snapshot
                    previousAt = now
                } catch {
                    await MainActor.run {
                        self.handleSupercoreStreamFailure(error, source: "流量")
                    }
                    if self.isSupercoreConnectionFailure(error) {
                        return
                    }
                }
                try? await Task.sleep(nanoseconds: 1_000_000_000)
            }
        }
        logsTask = Task { [weak self] in
            guard let self else { return }
            var seen = Set<String>()
            while !Task.isCancelled {
                do {
                    let lines = try await self.supercoreAPIClient.getLogs()
                    await MainActor.run {
                        for line in lines.reversed() where !seen.contains(line) {
                            seen.insert(line)
                            self.appendLog(line)
                        }
                    }
                } catch {
                    await MainActor.run {
                        self.handleSupercoreStreamFailure(error, source: "日志")
                    }
                    if self.isSupercoreConnectionFailure(error) {
                        return
                    }
                }
                try? await Task.sleep(nanoseconds: 2_000_000_000)
            }
        }
    }

    private func handleSupercoreStreamFailure(_ error: Error, source: String) {
        if isSupercoreConnectionFailure(error) {
            appendLog("Supercore \(source)轮询已暂停：控制端口暂不可用")
            stopStreams()
            return
        }
        appendLog("Supercore \(source)轮询失败：\(error.localizedDescription)")
    }

    private nonisolated func isSupercoreConnectionFailure(_ error: Error) -> Bool {
        let nsError = error as NSError
        guard nsError.domain == NSURLErrorDomain else { return false }
        return [
            NSURLErrorCannotConnectToHost,
            NSURLErrorNetworkConnectionLost,
            NSURLErrorTimedOut,
            NSURLErrorCannotFindHost,
            NSURLErrorNotConnectedToInternet
        ].contains(nsError.code)
    }

    private func startSmartRuleLearning() {
        smartRuleLearningTask?.cancel()
        guard activeSubscription != nil else { return }
        smartRuleLearningTask = Task { [weak self] in
            guard let self else { return }
            while !Task.isCancelled {
                do {
                    let snapshot = try await self.supercoreAPIClient.getSmartRules()
                    await MainActor.run {
                        self.applySupercoreSmartSnapshot(snapshot)
                    }
                } catch {
                    await MainActor.run {
                        self.appendLog("智能规则同步跳过本轮：\(error.localizedDescription)")
                    }
                }
                try? await Task.sleep(nanoseconds: 5_000_000_000)
            }
        }
    }

    private func recordSmartRuleObservations(_ observations: [SmartRuleObservation]) {
        guard activeSubscription != nil else { return }
        var candidatesByKey = Dictionary(uniqueKeysWithValues: smartRuleCandidates.map { ($0.key, $0) })
        var changed = false
        for observation in observations {
            if let connectionID = observation.connectionID {
                guard !recentSmartRuleConnectionIDs.contains(connectionID) else { continue }
                recentSmartRuleConnectionIDs.insert(connectionID)
            }
            if var candidate = candidatesByKey[observation.key] {
                candidate.record(observation)
                candidatesByKey[observation.key] = candidate
            } else {
                candidatesByKey[observation.key] = SmartRuleCandidate(observation: observation)
            }
            changed = true
        }
        guard changed else { return }
        if recentSmartRuleConnectionIDs.count > 1_000 {
            recentSmartRuleConnectionIDs = Set(recentSmartRuleConnectionIDs.suffix(500))
        }
        smartRuleCandidates = candidatesByKey.values.sorted { lhs, rhs in
            if lhs.recommendationAction != nil, rhs.recommendationAction == nil { return true }
            if lhs.recommendationAction == nil, rhs.recommendationAction != nil { return false }
            if lhs.hitCount != rhs.hitCount { return lhs.hitCount > rhs.hitCount }
            return lhs.lastSeenAt > rhs.lastSeenAt
        }
        saveSmartRulesForActiveProfile()
        scheduleDirectProbesIfNeeded()
    }

    private func scheduleDirectProbesIfNeeded() {
        let pending = smartRuleCandidates
            .filter {
                $0.observedRoute == .proxy &&
                    $0.directState == .unknown &&
                    $0.proxyState == .reachable &&
                    smartRuleProbeTasks[$0.key] == nil
            }
            .prefix(max(0, 8 - smartRuleProbeTasks.count))
        for candidate in pending {
            scheduleDirectProbe(for: candidate)
        }
    }

    private func scheduleDirectProbe(for candidate: SmartRuleCandidate) {
        let key = candidate.key
        smartRuleProbeTasks[key] = Task { [weak self] in
            let reachable = await SmartRuleDirectProbe.canConnect(host: candidate.endpointHost, port: candidate.port)
            await MainActor.run {
                self?.finishDirectProbe(key: key, state: reachable ? .reachable : .failed)
            }
        }
    }

    private func finishDirectProbe(key: String, state: SmartRuleProbeState) {
        smartRuleProbeTasks[key] = nil
        guard let index = smartRuleCandidates.firstIndex(where: { $0.key == key }) else { return }
        smartRuleCandidates[index].setDirectProbeResult(state)
        saveSmartRulesForActiveProfile()
        scheduleDirectProbesIfNeeded()
    }

    private func refreshTrafficSnapshot(flushImmediately: Bool = false) async {
        do {
            let snapshot = try await currentTrafficSnapshot()
            recordTrafficSnapshot(snapshot, flushImmediately: flushImmediately)
        } catch {
            appendLog("读取流量统计失败：\(error.localizedDescription)")
        }
    }

    private func persistFinalTrafficSnapshot(resetRuntimeBaseline: Bool) async {
        do {
            let snapshot = try await currentTrafficSnapshot()
            recordTrafficSnapshot(snapshot, flushImmediately: true)
        } catch {
            appendLog("保存最终流量统计失败：\(error.localizedDescription)")
        }
        if resetRuntimeBaseline {
            resetRuntimeTrafficBaselineForActiveProfile(flushImmediately: true)
        }
    }

    private func currentTrafficSnapshot() async throws -> ConnectionTrafficSnapshot {
        try await supercoreAPIClient.getConnectionsTrafficSnapshot()
    }

    private func loadTrafficUsageForActiveProfile() {
        guard let profileID = activeSubscription?.id else {
            activeTrafficUsage = .zero
            activeTrafficProfileID = nil
            trafficTotals = .zero
            return
        }
        activeTrafficUsage = trafficUsageStore.load(profileID: profileID)
        activeTrafficProfileID = profileID
        trafficTotals = activeTrafficUsage.totals
        profileTrafficTotals[profileID] = activeTrafficUsage.totals
        lastTrafficUsageFlushAt = .distantPast
    }

    private func recordTrafficSnapshot(
        _ snapshot: ConnectionTrafficSnapshot,
        flushImmediately: Bool = false
    ) {
        guard let profileID = activeSubscription?.id else {
            trafficTotals = .zero
            return
        }
        if activeTrafficProfileID != profileID {
            loadTrafficUsageForActiveProfile()
        }
        let oldTotals = activeTrafficUsage.totals
        let totals = activeTrafficUsage.record(snapshot: snapshot)
        trafficTotals = totals
        profileTrafficTotals[profileID] = totals
        let changed = totals != oldTotals
        if flushImmediately || (changed && Date().timeIntervalSince(lastTrafficUsageFlushAt) >= trafficUsageFlushInterval) {
            persistActiveTrafficUsage(force: true)
        }
    }

    private func resetRuntimeTrafficBaselineForActiveProfile(flushImmediately: Bool) {
        guard let profileID = activeSubscription?.id else { return }
        if activeTrafficProfileID != profileID {
            loadTrafficUsageForActiveProfile()
        }
        activeTrafficUsage.resetRuntimeBaseline()
        trafficTotals = activeTrafficUsage.totals
        profileTrafficTotals[profileID] = activeTrafficUsage.totals
        if flushImmediately {
            persistActiveTrafficUsage(force: true)
        }
    }

    private func persistActiveTrafficUsage(force: Bool = false) {
        guard let profileID = activeTrafficProfileID else { return }
        guard force || Date().timeIntervalSince(lastTrafficUsageFlushAt) >= trafficUsageFlushInterval else {
            return
        }
        do {
            try trafficUsageStore.save(activeTrafficUsage, profileID: profileID)
            lastTrafficUsageFlushAt = Date()
        } catch {
            appendLog("保存订阅流量统计失败：\(error.localizedDescription)")
        }
    }

    private func reloadProfileTrafficTotals() {
        profileTrafficTotals = Dictionary(
            uniqueKeysWithValues: profiles.map { profile in
                (profile.id, trafficUsageStore.load(profileID: profile.id).totals)
            }
        )
    }

    private func loadCustomRulesForActiveProfile() {
        guard let profileID = activeSubscription?.id else {
            customRules = []
            return
        }
        customRules = configManager.loadCustomRules(profileID: profileID)
    }

    private func copyRuntimeToDaemonRuntime(profileID: String) throws {
        let source = paths.supercoreRuntimeProfile(id: profileID)
        guard FileManager.default.fileExists(atPath: source.path) else {
            throw AppError.missingRuntimeConfig
        }
        try FileManager.default.createDirectory(
            at: paths.supercoreDaemonRuntimeProfile.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        if FileManager.default.fileExists(atPath: paths.supercoreDaemonRuntimeProfile.path) {
            try FileManager.default.removeItem(at: paths.supercoreDaemonRuntimeProfile)
        }
        try FileManager.default.copyItem(at: source, to: paths.supercoreDaemonRuntimeProfile)
    }

    private func makeRuntimeOptions(tunEnabled: Bool, useLaunchDaemon: Bool) throws -> RuntimeOptions {
        var options = RuntimeOptions(mixedPort: 7897, controllerPort: 9197, tunEnabled: tunEnabled)
        options.dnsStrategy = runtimeOptions.dnsStrategy
        options.dnsServer = runtimeOptions.dnsServer
        if useLaunchDaemon {
            options.mixedPort = runtimeOptions.mixedPort == RuntimeOptions().mixedPort ? 7897 : runtimeOptions.mixedPort
            options.controllerPort = 9197
        } else {
            options.mixedPort = try LocalPortAllocator.availablePort(preferred: options.mixedPort)
            options.controllerPort = try LocalPortAllocator.availablePort(
                preferred: options.controllerPort,
                fallbackRange: 9197...9297
            )
        }
        return options
    }

    private func loadSmartRulesForActiveProfile() {
        guard let profileID = activeSubscription?.id else {
            smartRuleCandidates = []
            recentSmartRuleConnectionIDs = []
            return
        }
        smartRuleCandidates = smartRuleStore.load(profileID: profileID)
        recentSmartRuleConnectionIDs = []
    }

    private func saveSmartRulesForActiveProfile() {
        guard let profileID = activeSubscription?.id else { return }
        do {
            try smartRuleStore.save(smartRuleCandidates, profileID: profileID)
        } catch {
            appendLog("保存智能规则失败：\(error.localizedDescription)")
        }
    }

    private func refreshSupercoreSmartRulesSnapshot(silent: Bool) async {
        do {
            let snapshot = try await supercoreAPIClient.getSmartRules()
            applySupercoreSmartSnapshot(snapshot)
        } catch {
            if !silent {
                appendLog("同步 Supercore 智能规则失败：\(error.localizedDescription)")
            }
        }
    }

    private func applySupercoreSmartSnapshot(_ snapshot: SupercoreSmartRulesSnapshot) {
        guard activeSubscription != nil else { return }
        let existingByKey = Dictionary(uniqueKeysWithValues: smartRuleCandidates.map { ($0.key, $0) })
        var recommendationsByKey: [String: SupercoreSmartRecommendation] = [:]
        for recommendation in snapshot.recommendations {
            guard let target = CustomRuleTarget(supercoreTarget: recommendation.target) else { continue }
            recommendationsByKey[SmartRuleCandidate.key(target: target, value: recommendation.value)] = recommendation
        }
        let enabledActionsByKey = smartEnabledActions(from: snapshot)
        let candidates = snapshot.observations.compactMap { observation -> SmartRuleCandidate? in
            guard let target = CustomRuleTarget(supercoreTarget: observation.target) else { return nil }
            let key = SmartRuleCandidate.key(target: target, value: observation.value)
            let recommendation = recommendationsByKey[key]
            let recommendationAction = recommendation.flatMap(smartRecommendationAction)
            let lastSeen = parseSupercoreDate(observation.lastSeenAt)
            var candidate = existingByKey[key] ?? SmartRuleCandidate(
                target: target,
                value: observation.value,
                endpointHost: observation.value,
                port: nil,
                observedRoute: observation.proxyRoutedHits >= observation.directRoutedHits ? .proxy : .direct,
                firstSeenAt: lastSeen,
                lastSeenAt: lastSeen
            )
            candidate.target = target
            candidate.value = observation.value
            candidate.endpointHost = observation.value
            candidate.port = nil
            candidate.observedRoute = smartObservedRoute(for: observation)
            candidate.directState = smartDirectState(for: observation, recommendationAction: recommendationAction)
            candidate.proxyState = smartProxyState(for: observation, recommendationAction: recommendationAction)
            candidate.hitCount = Int(clamping: observation.visits)
            candidate.lastSeenAt = lastSeen
            candidate.enabledAction = enabledActionsByKey[key] ?? enabledCustomRuleAction(target: target, value: observation.value)
            candidate.recommendationActionOverride = recommendationAction
            candidate.recommendationReasonText = recommendation.map(smartRecommendationReason)
            return candidate
        }
        let sorted = candidates.sorted { lhs, rhs in
            if lhs.recommendationAction != nil, rhs.recommendationAction == nil { return true }
            if lhs.recommendationAction == nil, rhs.recommendationAction != nil { return false }
            if lhs.hitCount != rhs.hitCount { return lhs.hitCount > rhs.hitCount }
            return lhs.lastSeenAt > rhs.lastSeenAt
        }
        if sorted != smartRuleCandidates {
            smartRuleCandidates = sorted
            saveSmartRulesForActiveProfile()
        }
    }

    private func smartEnabledActions(from snapshot: SupercoreSmartRulesSnapshot) -> [String: CustomRuleAction] {
        var actions: [String: CustomRuleAction] = [:]
        for rule in snapshot.rules where rule.enabled {
            guard let target = CustomRuleTarget(supercoreTarget: rule.target) else { continue }
            actions[SmartRuleCandidate.key(target: target, value: rule.value)] = smartAction(
                forOutbound: rule.outbound,
                snapshot: snapshot
            )
        }
        return actions
    }

    private func smartAction(forOutbound outbound: String, snapshot: SupercoreSmartRulesSnapshot) -> CustomRuleAction {
        if outbound == snapshot.directOutbound {
            return .direct
        }
        if let proxyOutbound = snapshot.proxyOutbound, outbound == proxyOutbound {
            return .proxy
        }
        if outbound == "reject" {
            return .reject
        }
        return .outbound
    }

    private func enabledCustomRuleAction(target: CustomRuleTarget, value: String) -> CustomRuleAction? {
        customRules.first { rule in
            rule.enabled &&
                rule.target == target &&
                rule.value.caseInsensitiveCompare(value) == .orderedSame
        }?.action
    }

    private func smartRecommendationAction(_ recommendation: SupercoreSmartRecommendation) -> CustomRuleAction? {
        switch recommendation.action.lowercased() {
        case "direct": .direct
        case "proxy": .proxy
        default: nil
        }
    }

    private func smartRecommendationReason(_ recommendation: SupercoreSmartRecommendation) -> String {
        switch smartRecommendationAction(recommendation) {
        case .direct:
            if let latency = recommendation.latencyMs {
                return "Supercore 直连探测可达（\(latency)ms），建议改为直连"
            }
            return "Supercore 直连探测可达，建议改为直连"
        case .proxy:
            return "Supercore 直连探测失败，建议走代理"
        case nil, .reject, .outbound:
            return recommendation.reason
        }
    }

    private func smartObservedRoute(for observation: SupercoreSmartObservation) -> SmartRuleObservedRoute {
        if observation.proxyRoutedHits > observation.directRoutedHits {
            return .proxy
        }
        if observation.directRoutedHits > 0 {
            return .direct
        }
        return observation.lastOutbound?.caseInsensitiveCompare("direct") == .orderedSame ? .direct : .proxy
    }

    private func smartDirectState(
        for observation: SupercoreSmartObservation,
        recommendationAction: CustomRuleAction?
    ) -> SmartRuleProbeState {
        if recommendationAction == .direct {
            return .reachable
        }
        if recommendationAction == .proxy {
            return .failed
        }
        guard observation.directProbeAttempts > 0 else { return .unknown }
        return observation.directProbeSuccesses > 0 ? .reachable : .failed
    }

    private func smartProxyState(
        for observation: SupercoreSmartObservation,
        recommendationAction: CustomRuleAction?
    ) -> SmartRuleProbeState {
        if recommendationAction == .proxy || observation.proxyRoutedHits > 0 {
            return .reachable
        }
        return .unknown
    }

    private func parseSupercoreDate(_ value: String) -> Date {
        AppState.supercoreDateFormatterWithFractions.date(from: value) ??
            AppState.supercoreDateFormatter.date(from: value) ??
            Date()
    }

    private func enableSmartRules(_ candidates: [SmartRuleCandidate], action: CustomRuleAction) {
        guard activeSubscription != nil else {
            userMessage = "还没有选择订阅，无法启用智能规则"
            return
        }
        let eligible = candidates.filter { $0.recommendationAction == action }
        guard !eligible.isEmpty else {
            userMessage = "没有可启用的\(action.title)建议"
            return
        }
        Task {
            do {
                if coreState.isRunning {
                    if eligible.count == 1 {
                        guard let target = eligible[0].target.supercoreTarget else {
                            throw AppError.processFailed("Supercore 暂不支持该规则类型")
                        }
                        try await supercoreAPIClient.applySmartRecommendation(
                            target: target,
                            value: eligible[0].value
                        )
                    } else {
                        try await supercoreAPIClient.applySmartRecommendations(action: action)
                    }
                }
                for candidate in eligible {
                    upsertHighPriorityCustomRule(from: candidate, action: action)
                }
                let enabledKeys = Set(eligible.map(\.key))
                smartRuleCandidates = smartRuleCandidates.map { candidate in
                    guard enabledKeys.contains(candidate.key) else { return candidate }
                    var copy = candidate
                    copy.markEnabled(action: action)
                    return copy
                }
                saveSmartRulesForActiveProfile()
                saveCustomRulesAndReloadRuntime(
                    successMessage: eligible.count == 1
                        ? "智能规则已启用：\(eligible[0].value) \(action.title)"
                        : "智能规则已批量启用：\(eligible.count) 条\(action.title)"
                )
                if coreState.isRunning {
                    await refreshSupercoreSmartRulesSnapshot(silent: true)
                }
            } catch {
                userMessage = "启用智能规则失败：\(error.localizedDescription)"
                appendLog(userMessage)
            }
        }
    }

    private func upsertHighPriorityCustomRule(from candidate: SmartRuleCandidate, action: CustomRuleAction) {
        if let index = customRules.firstIndex(where: { rule in
            rule.target == candidate.target &&
                rule.action == action &&
                rule.value.caseInsensitiveCompare(candidate.value) == .orderedSame
        }) {
            var rule = customRules.remove(at: index)
            rule.enabled = true
            customRules.insert(rule, at: 0)
            return
        }
        customRules.insert(
            CustomRule(target: candidate.target, value: candidate.value, action: action),
            at: 0
        )
    }

    private func saveCustomRulesAndReloadRuntime(successMessage: String) {
        guard let profileID = activeSubscription?.id else {
            userMessage = "还没有选择订阅，无法保存规则"
            return
        }
        Task {
            do {
                try configManager.saveCustomRules(customRules, profileID: profileID)
                try configManager.regenerateSupercoreRuntime(
                    profileID: profileID,
                    tunEnabled: tunEnabled,
                    runtimeOptions: runtimeOptions
                )
                if coreState.isRunning {
                    do {
                        try await supercoreAPIClient.reloadConfig(path: paths.supercoreRuntimeProfile(id: profileID))
                        try await refreshRuntimeState()
                        mergeRuntimeNodesIntoProviderCatalog()
                        userMessage = "\(successMessage)，已热重载生效"
                    } catch {
                        userMessage = "\(successMessage)，Supercore 重启代理后生效"
                        appendLog("Supercore 规则热重载失败：\(error.localizedDescription)")
                    }
                } else {
                    userMessage = "\(successMessage)，启动代理后生效"
                }
            } catch {
                userMessage = "保存规则失败：\(error.localizedDescription)"
                appendLog(userMessage)
            }
        }
    }

    private func attachExistingCoreIfNeeded() async {
        guard case .notPrepared = coreState else { return }
        guard let version = await supercoreManager.detectRunningVersion() else { return }
        refreshTunLaunchDaemonStatus()
        usingTunLaunchDaemon = tunLaunchDaemonStatus.loaded
        coreState = .running(version: version)
        runtimePurpose = .attached
        do {
            try await refreshRuntimeState()
            mergeRuntimeNodesIntoProviderCatalog()
            startStreams()
            userMessage = "已接入正在运行的 Supercore"
        } catch {
            appendLog("接入已有 Supercore 状态失败：\(error.localizedDescription)")
        }
    }

    private func stopStreams() {
        trafficPollingTask?.cancel()
        logsTask?.cancel()
        smartRuleLearningTask?.cancel()
        smartRuleProbeTasks.values.forEach { $0.cancel() }
        trafficPollingTask = nil
        logsTask = nil
        smartRuleLearningTask = nil
        smartRuleProbeTasks = [:]
        saveSmartRulesForActiveProfile()
    }

    private func testDelay(group: ProxyGroup) async {
        delayTestingGroups.insert(group.name)
        defer { delayTestingGroups.remove(group.name) }
        let result = await testNodeDelays(
            names: group.all,
            timeout: DelayPolicy.timeoutMilliseconds,
            concurrency: DelayPolicy.manualConcurrency
        )
        userMessage = "\(group.name) 延迟测试完成：可用 \(result.available)/\(result.total)"
    }

    private func startLaunchBackgroundRefresh() {
        launchRefreshTask?.cancel()
        launchRefreshTask = Task { [weak self] in
            await self?.refreshOnLaunchInBackground()
        }
    }

    private func startBackgroundSubscriptionRefresh() {
        backgroundSubscriptionTask?.cancel()
        backgroundSubscriptionTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: UInt64((self?.backgroundSubscriptionRefreshInterval ?? 1_800) * 1_000_000_000))
                await self?.refreshSubscriptionsInBackground(reason: "定时后台")
            }
        }
    }

    private func refreshOnLaunchInBackground() async {
        guard !isStartingSupercoreProxy else {
            appendLog("启动订阅自动更新已跳过：代理启动中")
            return
        }
        guard let profile = activeSubscription else { return }
        if shouldAutoUpdateOnLaunch(profile) {
            await autoUpdateActiveSubscriptionOnLaunch(profileID: profile.id)
        } else {
            appendLog("启动订阅自动更新已跳过：距离上次更新未超过 1 小时")
        }
        await refreshProviderNodesForActiveProfile(timeout: launchNetworkTimeout, silent: true)
    }

    private func refreshSubscriptionsInBackground(reason: String) async {
        if isStartingSupercoreProxy {
            appendLog("\(reason)订阅更新已跳过：代理启动中")
            return
        }
        guard operation == nil else {
            appendLog("\(reason)订阅更新已跳过：当前有前台任务")
            return
        }
        let snapshotProfiles = profiles
        guard !snapshotProfiles.isEmpty else { return }
        appendLog("\(reason)订阅更新开始，共 \(snapshotProfiles.count) 个订阅")
        var updatedCount = 0
        let activeProfileID = activeSubscription?.id

        for profile in snapshotProfiles {
            guard shouldAutoUpdateOnLaunch(profile), !Task.isCancelled else { continue }
            do {
                let updated = try await subscriptionManager.updateSubscription(
                    profileID: profile.id,
                    tunEnabled: tunEnabled,
                    timeout: launchNetworkTimeout
                )
                _ = try? await subscriptionManager.downloadProviderNodes(
                    for: profile.id,
                    timeout: launchNetworkTimeout
                )
                updatedCount += 1
                if profile.id == activeProfileID {
                    activeSubscription = updated
                    profiles = subscriptionManager.loadProfiles()
                    loadSmartRulesForActiveProfile()
                    loadLocalProxyGroupsForActiveProfile()
                    loadCachedProviderNodesForActiveProfile()
                }
            } catch {
                appendLog("\(reason)订阅更新失败：\(profile.name)：\(error.localizedDescription)")
            }
        }

        profiles = subscriptionManager.loadProfiles()
        reloadProfileTrafficTotals()
        if updatedCount > 0 {
            appendLog("\(reason)订阅更新完成：\(updatedCount)/\(snapshotProfiles.count)")
        } else {
            appendLog("\(reason)订阅更新无需执行：均未超过更新间隔")
        }
    }

    private func shouldAutoUpdateOnLaunch(_ profile: SubscriptionProfile) -> Bool {
        Date().timeIntervalSince(profile.updatedAt) >= launchAutoUpdateMinimumInterval
    }

    private func autoUpdateActiveSubscriptionOnLaunch(profileID: String) async {
        do {
            appendLog("启动后台自动更新订阅...")
            activeSubscription = try await subscriptionManager.updateSubscription(
                profileID: profileID,
                tunEnabled: tunEnabled,
                timeout: launchNetworkTimeout
            )
            profiles = subscriptionManager.loadProfiles()
            loadCustomRulesForActiveProfile()
            loadSmartRulesForActiveProfile()
            loadLocalProxyGroupsForActiveProfile()
            userMessage = "订阅已在后台自动更新"
        } catch {
            appendLog("启动后台自动更新订阅失败，继续使用本地缓存：\(error.localizedDescription)")
        }
    }

    @discardableResult
    private func restoreSavedSelections() async -> [String] {
        guard let selectedNodes = activeSubscription?.selectedNodes, !selectedNodes.isEmpty else {
            return []
        }
        let groupNames = Set(proxies.map(\.name))
        let candidates = selectedNodes.values.filter { isConcreteProxyNode($0, groupNames: groupNames) }
        guard let node = candidates.first else { return [] }
        do {
            try await supercoreAPIClient.useOutbound(name: node)
            try await refreshRuntimeState()
            return [node]
        } catch {
            appendLog("恢复 Supercore 节点选择失败：\(node)：\(error.localizedDescription)")
            return []
        }
    }

    @discardableResult
    func resolveStartupNodeCandidateFromLastStarted() -> (node: String?, needsManualProbe: Bool) {
        guard selectedMode != .direct else { return (nil, false) }
        guard let rawNode = activeSubscription?.lastStartedNode?
            .trimmingCharacters(in: .whitespacesAndNewlines),
              !rawNode.isEmpty else {
            return (nil, false)
        }
        let groupNames = Set(proxies.map(\.name))
        guard isConcreteProxyNode(rawNode, groupNames: groupNames),
              proxies.contains(where: { $0.all.contains(rawNode) }) else {
            appendLog("上次启动节点已不在当前订阅中：\(rawNode)")
            if let fallback = sameRegionFallbackCandidates(for: rawNode).first {
                appendLog("已找到同国家备用节点：\(fallback)")
                return (fallback, false)
            }
            return (nil, true)
        }
        return (rawNode, false)
    }

    @discardableResult
    private func restoreStartupNodePreference() async -> StartupNodeRestoreResult {
        guard selectedMode != .direct else {
            return .init(nodes: [], needsManualProbe: false)
        }
        let resolved = resolveStartupNodeCandidateFromLastStarted()
        if let node = resolved.node {
            do {
                try await applyConcreteNodeSelection(node)
                if activeSubscription?.lastStartedNode?.trimmingCharacters(in: .whitespacesAndNewlines) == node {
                    appendLog("已使用上次节点：\(node)")
                } else {
                    appendLog("已切换同国家备用节点：\(node)")
                }
                return .init(nodes: [node], needsManualProbe: false)
            } catch {
                appendLog("恢复上次启动节点失败：\(node)：\(error.localizedDescription)")
                if resolved.needsManualProbe {
                    return .init(nodes: [], needsManualProbe: true)
                }
            }
        }
        if resolved.needsManualProbe {
            return .init(nodes: [], needsManualProbe: true)
        }
        return .init(
            nodes: await restoreSavedSelections(),
            needsManualProbe: false
        )
    }

    private func saveLastStartedNode(_ node: String?) {
        guard let profileID = activeSubscription?.id else { return }
        subscriptionManager.saveLastStartedNode(profileID: profileID, node: node)
        profiles = subscriptionManager.loadProfiles()
        activeSubscription = profiles.first(where: { $0.id == profileID })
    }

    private func ensureProxyModeForConcreteSelection() {
        guard selectedMode == .direct else { return }
        selectedMode = .rule
        UserDefaults.standard.set(ProxyMode.rule.rawValue, forKey: "selectedMode")
    }

    private func scheduleStartupNodeHealthCheck(_ node: String) {
        startupNodeHealthTask?.cancel()
        startupNodeHealthTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: 1_500_000_000)
            guard !Task.isCancelled else { return }
            await self?.checkStartupNodeAndFallbackIfNeeded(node)
        }
    }

    private func checkStartupNodeAndFallbackIfNeeded(_ node: String) async {
        guard runtimePurpose == .proxy, coreState.isRunning, !Task.isCancelled else { return }
        appendLog("后台确认上次节点可用性：\(node)")
        await testNodeDelays(
            names: [node],
            timeout: DelayPolicy.timeoutMilliseconds,
            concurrency: 1,
            announcesProgress: false
        )
        guard !Task.isCancelled else { return }
        if isDelayAvailable(node) {
            let display = delayDisplayTitle(for: node)
            appendLog("上次节点可用：\(node) \(display)")
            return
        }

        let candidates = sameRegionFallbackCandidates(for: node)
        guard !candidates.isEmpty else {
            appendLog("上次节点不可用，未找到同地区备用节点：\(node)")
            let message = "上次节点不可用，未找到同地区备用节点，请先手动测速"
            userMessage = message
            appendLog(message)
            return
        }
        appendLog("上次节点不可用，后台测试同地区备用节点 \(candidates.count) 个")
        await testNodeDelays(
            names: candidates,
            timeout: DelayPolicy.timeoutMilliseconds,
            concurrency: DelayPolicy.backgroundConcurrency,
            announcesProgress: false
        )
        guard !Task.isCancelled else { return }
        guard let best = candidates.compactMap({ name -> (String, Int)? in
            guard isDelayAvailable(name), let delay = delayResults[name] else { return nil }
            return (name, delay)
        }).min(by: { $0.1 < $1.1 })?.0 else {
            appendLog("同地区备用节点测速完成，但没有可用低延迟节点")
            let message = "同地区备用节点均不可用，请先手动测速"
            userMessage = message
            appendLog(message)
            return
        }
        do {
            try await applyConcreteNodeSelection(best)
            let message = "上次节点不可用，已切换同地区节点：\(currentNodeStatus.summary)"
            userMessage = message
            appendLog(message)
        } catch {
            appendLog("切换同地区备用节点失败：\(error.localizedDescription)")
        }
    }

    private func sameRegionFallbackCandidates(for node: String) -> [String] {
        let groupNames = Set(proxies.map(\.name))
        let country = ProxyNodeParser.country(for: node)
        var candidates: [String] = []

        func appendCandidate(_ name: String) {
            guard name != node,
                  isConcreteProxyNode(name, groupNames: groupNames),
                  proxies.contains(where: { $0.all.contains(name) }),
                  !candidates.contains(name) else {
                return
            }
            candidates.append(name)
        }

        if country != "未识别" {
            providerNodes
                .filter { $0.country == country }
                .map(\.name)
                .forEach(appendCandidate)
            allKnownProxyNodeNames(includeHistoricalDelayResults: true)
                .filter { ProxyNodeParser.country(for: $0) == country }
                .forEach(appendCandidate)
        }

        if candidates.isEmpty {
            proxies
                .filter { $0.all.contains(node) }
                .flatMap { concreteNodeNames(inGroup: $0.name) }
                .forEach(appendCandidate)
        }

        return candidates
    }

    private func isConcreteProxyNode(_ node: String, groupNames: Set<String>) -> Bool {
        !isSpecialOutboundName(node) && !groupNames.contains(node)
    }

    private func isSpecialOutboundName(_ name: String) -> Bool {
        name.caseInsensitiveCompare("DIRECT") == .orderedSame ||
            name.caseInsensitiveCompare("REJECT") == .orderedSame ||
            name.caseInsensitiveCompare("direct") == .orderedSame ||
            name.caseInsensitiveCompare("reject") == .orderedSame
    }

    private func bestSelectableDelayNodeName() -> String? {
        delayResults
            .compactMap { name, delay -> (String, Int)? in
                guard isDelayAvailable(name),
                      let delay = delayResults[name],
                      !isSpecialOutboundName(name),
                      proxies.contains(where: { $0.all.contains(name) }) else {
                    return nil
                }
                return (name, delay)
            }
            .min { $0.1 < $1.1 }?
            .0
    }

    private func loadLocalProxyGroupsForActiveProfile() {
        guard let profile = activeSubscription else {
            proxies = []
            return
        }
        do {
            let groups = try configManager.loadProxyGroups(profileID: profile.id, selectedNodes: profile.selectedNodes)
            proxies = materializeSubscriptionNodes(in: groups, selectedNodes: profile.selectedNodes)
        } catch {
            proxies = []
            appendLog("解析代理组失败：\(error.localizedDescription)")
        }
    }

    private func loadCachedProviderNodesForActiveProfile() {
        guard let profileID = activeSubscription?.id else {
            providerNodes = []
            rebuildCountryGroups()
            return
        }
        providerNodes = subscriptionManager.loadCachedProviderNodes(profileID: profileID)
        loadLocalProxyGroupsForActiveProfile()
        rebuildCountryGroups()
    }

    private func filterDelayResultsForActiveProfile() {
        let knownNames = Set(providerNodes.map(\.name) + proxies.flatMap(\.all))
        delayResults = delayResults.filter { name, _ in
            knownNames.contains(name)
        }
        delayFailureKinds = delayFailureKinds.filter { name, _ in
            knownNames.contains(name)
        }
        rebuildCountryGroups()
    }

    private func ensureProviderPayloadsForCore(profileID: String, timeout: TimeInterval) async {
        guard subscriptionManager.needsProviderPayloadCache(profileID: profileID) else { return }
        updateOperation("正在准备 provider 本地缓存...")
        await refreshProviderNodesForActiveProfile(timeout: timeout, silent: true)
    }

    private func refreshProviderNodesForActiveProfile(timeout: TimeInterval = 30, silent: Bool = false) async {
        guard let profileID = activeSubscription?.id else {
            providerNodes = []
            rebuildCountryGroups()
            return
        }
        do {
            let nodes = try await subscriptionManager.downloadProviderNodes(for: profileID, timeout: timeout)
            providerNodes = nodes
            loadLocalProxyGroupsForActiveProfile()
            rebuildCountryGroups()
            if !silent {
                userMessage = nodes.isEmpty ? "未拉取到 provider 节点" : "已拉取 \(nodes.count) 个订阅节点"
            }
        } catch {
            appendLog("拉取 provider 节点失败，继续使用本地缓存：\(error.localizedDescription)")
            if !silent {
                userMessage = "provider 节点拉取失败：\(error.localizedDescription)"
            }
            rebuildCountryGroups()
        }
    }

    private func mergeRuntimeNodesIntoProviderCatalog() {
        let groupNames = Set(proxies.map(\.name))
        let runtimeNodes = proxies
            .flatMap(\.all)
            .filter { !$0.isEmpty && isConcreteProxyNode($0, groupNames: groupNames) }
            .map { ProxyNode(name: $0, source: "runtime", country: ProxyNodeParser.country(for: $0)) }
        var byName = Dictionary(uniqueKeysWithValues: providerNodes.map { ($0.name, $0) })
        for node in runtimeNodes {
            byName[node.name] = byName[node.name] ?? node
        }
        providerNodes = byName.values.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
        proxies = materializeSubscriptionNodes(in: proxies, selectedNodes: activeSubscription?.selectedNodes ?? [:])
        rebuildCountryGroups()
    }

    private func materializeSubscriptionNodes(in groups: [ProxyGroup], selectedNodes: [String: String]) -> [ProxyGroup] {
        guard !providerNodes.isEmpty else {
            return groups.filter { !$0.all.isEmpty }
        }
        return groups.compactMap { group in
            var names = group.all
            if group.includeAll || !group.useProviders.isEmpty {
                names.append(contentsOf: providerNodes
                    .filter { nodeMatchesGroupFilter($0.name, filter: group.filter) }
                    .map(\.name))
            }
            let uniqueNames = names.reduce(into: [String]()) { result, name in
                if !name.isEmpty && !result.contains(name) {
                    result.append(name)
                }
            }
            guard !uniqueNames.isEmpty else { return nil }
            let now = selectedNodes[group.name].flatMap { uniqueNames.contains($0) ? $0 : nil }
                ?? group.now.flatMap { uniqueNames.contains($0) ? $0 : nil }
                ?? uniqueNames.first
            return ProxyGroup(
                name: group.name,
                type: group.type,
                now: now,
                all: uniqueNames,
                includeAll: false,
                filter: nil,
                useProviders: []
            )
        }
    }

    private func nodeMatchesGroupFilter(_ node: String, filter: String?) -> Bool {
        guard let filter, !filter.isEmpty else { return true }
        do {
            let regex = try NSRegularExpression(pattern: filter)
            let range = NSRange(node.startIndex..<node.endIndex, in: node)
            return regex.firstMatch(in: node, range: range) != nil
        } catch {
            return node.localizedCaseInsensitiveContains(filter)
        }
    }

    private func rebuildCountryGroups() {
        let visibleNodes = showOnlyAvailableNodes
            ? providerNodes.filter { isDelayAvailable($0.name) }
            : providerNodes
        let grouped = Dictionary(grouping: visibleNodes, by: \.country)
        countryGroups = grouped
            .map { country, nodes in
                let selectedNode = selectedCountry == country ? bestNodeName(in: nodes) : nil
                let bestDelay = selectedNode.flatMap { delayResults[$0] }
                return CountryNodeGroup(
                    country: country,
                    nodes: nodes.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending },
                    selectedNode: selectedNode,
                    bestDelay: bestDelay
                )
            }
            .sorted { lhs, rhs in
                if lhs.country == "未识别" { return false }
                if rhs.country == "未识别" { return true }
                return lhs.country.localizedStandardCompare(rhs.country) == .orderedAscending
            }
    }

    private func configureAutoDelayTask(runImmediately: Bool = false) {
        autoDelayTask?.cancel()
        guard autoCountrySwitchEnabled, selectedCountry != nil else { return }
        autoDelayTask = Task { [weak self] in
            if runImmediately {
                await self?.testSelectedCountryAndSwitch()
            }
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 300_000_000_000)
                await self?.testSelectedCountryAndSwitch()
            }
        }
    }

    private func testSelectedCountryAndSwitch() async {
        guard let selectedCountry,
              let group = countryGroups.first(where: { $0.country == selectedCountry }),
              !group.nodes.isEmpty else {
            return
        }
        guard coreState.isRunning else {
            return
        }
        isBackgroundDelayTesting = true
        defer { isBackgroundDelayTesting = false }
        appendLog("后台自动测试 \(selectedCountry) 节点...")
        let names = group.nodes.prefix(60).map(\.name)
        await testNodeDelays(
            names: names,
            timeout: DelayPolicy.timeoutMilliseconds,
            concurrency: DelayPolicy.backgroundConcurrency,
            announcesProgress: false
        )
        guard !Task.isCancelled else { return }
        guard let refreshedGroup = countryGroups.first(where: { $0.country == selectedCountry }),
              let best = bestNodeName(in: refreshedGroup.nodes) else {
            appendLog("后台自动择优：\(selectedCountry) 没有可用低延迟节点")
            return
        }
        await selectBestCountryNode(best, announcesResult: false)
    }

    private func bestNodeName(in nodes: [ProxyNode]) -> String? {
        nodes
            .compactMap { node -> (String, Int)? in
                guard isDelayAvailable(node.name), let delay = delayResults[node.name] else { return nil }
                return (node.name, delay)
            }
            .min { $0.1 < $1.1 }?
            .0
    }

    @discardableResult
    private func testCatalogNodeDelays(
        limit: Int?,
        concurrency: Int,
        announcesProgress: Bool = true
    ) async -> (available: Int, total: Int) {
        let names = allKnownProxyNodeNames(includeHistoricalDelayResults: false)
        let selectedNames = limit.map { Array(names.prefix($0)) } ?? names
        return await testNodeDelays(
            names: selectedNames,
            timeout: DelayPolicy.timeoutMilliseconds,
            concurrency: concurrency,
            announcesProgress: announcesProgress
        )
    }

    private func allKnownProxyNodeNames(includeHistoricalDelayResults: Bool) -> [String] {
        var names = providerNodes.map(\.name)
        names.append(contentsOf: proxies.flatMap(\.all))
        if includeHistoricalDelayResults {
            names.append(contentsOf: delayResults.keys)
        }
        let groupNames = Set(proxies.map(\.name))
        return names.reduce(into: [String]()) { result, name in
            guard !isSpecialOutboundName(name),
                  !name.isEmpty,
                  !groupNames.contains(name),
                  !result.contains(name) else {
                return
            }
            result.append(name)
        }
        .sorted { $0.localizedStandardCompare($1) == .orderedAscending }
    }

    private func nodesForCountry(_ country: String) -> [ProxyNode] {
        providerNodes.filter { $0.country == country }
    }

    @discardableResult
    private func testNodeDelays(
        names: [String],
        timeout: Int,
        concurrency: Int,
        announcesProgress: Bool = true
    ) async -> (available: Int, total: Int) {
        let groupNames = Set(proxies.map(\.name))
        let selectedNames = names.reduce(into: [String]()) { result, name in
            guard !isSpecialOutboundName(name),
                  !name.isEmpty,
                  !groupNames.contains(name),
                  !result.contains(name) else {
                return
            }
            result.append(name)
        }
        return await testSupercoreNodeDelays(
            names: selectedNames,
            timeout: timeout,
            concurrency: concurrency,
            announcesProgress: announcesProgress
        )
    }

    private func testSupercoreNodeDelays(
        names: [String],
        timeout: Int,
        concurrency: Int,
        announcesProgress: Bool
    ) async -> (available: Int, total: Int) {
        guard !names.isEmpty else { return (0, 0) }
        do {
            try await ensureCoreRunningForDelayTesting()
        } catch {
            let message = "Supercore 测速服务启动失败：\(error.localizedDescription)"
            appendLog(message)
            if announcesProgress {
                userMessage = message
            }
            return (0, names.count)
        }
        if announcesProgress {
            userMessage = "Supercore 正在批量测速 \(names.count) 个节点..."
        }
        do {
            let response = try await supercoreAPIClient.probeOutboundsResponse(
                timeoutMilliseconds: timeout,
                url: probeURL,
                concurrency: concurrency,
                names: names
            )
            let results = response.results
            let mergeSummary = Self.mergeProbeResults(
                requestedNames: names,
                results: results,
                existingDelayResults: delayResults,
                existingDelayFailureKinds: delayFailureKinds
            )
            delayResults = mergeSummary.delayResults
            delayFailureKinds = mergeSummary.delayFailureKinds
            rebuildCountryGroups()
            let missing = mergeSummary.missingNames.count
            let mergedFailureCounts = mergeSummary.failureCounts
            var failureSummary = response.failureSummary ?? mergedFailureCounts
            if !mergeSummary.missingNames.isEmpty {
                failureSummary["outbound_not_found", default: 0] =
                    (failureSummary["outbound_not_found"] ?? 0) + missing
            }
            if failureSummary.isEmpty {
                failureSummary = mergedFailureCounts
                if !mergeSummary.missingNames.isEmpty {
                    failureSummary["outbound_not_found", default: 0] =
                        (failureSummary["outbound_not_found"] ?? 0) + missing
                }
            }
            let failureExamples = results
                .filter { mergeSummary.returnedNames.contains($0.name) && !$0.success }
                .prefix(5)
                .map { result in
                    "\(result.name)：\(result.failureTitle)"
                }
            let userMessageTotal = mergeSummary.total
            appendLog("Supercore 测速返回 \(mergeSummary.returnedNames.count)/\(userMessageTotal)，可用 \(mergeSummary.available)，未返回 \(missing)")
            if !mergeSummary.missingNames.isEmpty {
                appendLog("Supercore 测速未返回节点，不写入超时：\(mergeSummary.missingNames.prefix(8).joined(separator: "；"))")
            }
            if !failureExamples.isEmpty {
                appendLog("Supercore 测速失败分类：\(failureSummary)")
                appendLog("Supercore 测速失败样例：\(failureExamples.joined(separator: "；"))")
            }
            if announcesProgress {
                let suffix = missing > 0 ? "，未返回 \(missing)" : ""
                let failureSuffix = failureSummary.isEmpty ? "" : "（\(failureSummary)）"
                userMessage = "Supercore 节点测速完成：可用 \(mergeSummary.available)/\(userMessageTotal)\(suffix)\(failureSuffix)"
            }
            return (mergeSummary.available, userMessageTotal)
        } catch {
            appendLog("Supercore 测速失败：\(error.localizedDescription)")
            if announcesProgress {
                userMessage = "Supercore 测速失败：\(error.localizedDescription)"
            }
            return (0, names.count)
        }
    }

    private func selectBestCountryNode(_ node: String, announcesResult: Bool = true) async {
        do {
            try await ensureCoreRunningForDelayTesting()
        } catch {
            let message = "自动切换国家节点失败：\(error.localizedDescription)"
            if announcesResult {
                userMessage = message
            }
            appendLog(message)
            return
        }
        do {
            try await applyConcreteNodeSelection(node)
            let message = "已自动切换到 \(selectedCountry ?? "")：\(currentNodeStatus.summary)"
            if announcesResult {
                userMessage = message
            }
            appendLog(announcesResult ? message : "后台自动择优：\(message)")
        } catch {
            let message = "自动切换国家节点失败：\(error.localizedDescription)"
            if announcesResult {
                userMessage = message
            }
            appendLog(message)
        }
    }

    private func selectBestAvailableNode(_ node: String) async {
        do {
            try await applyConcreteNodeSelection(node)
            userMessage = "已切换到最低延迟节点：\(currentNodeStatus.summary)"
        } catch {
            userMessage = "自动切换最低延迟节点失败：\(error.localizedDescription)"
            appendLog(userMessage)
        }
    }

    private func applyBestNode(_ node: String, forGroup groupName: String) async throws {
        ensureProxyModeForConcreteSelection()
        try await supercoreAPIClient.useOutbound(name: node)
        persistSelectedNodes([(group: groupName, node: node)])
        try await refreshRuntimeState()
        saveLastStartedNode(node)
    }

    private func applyConcreteNodeSelection(_ node: String) async throws {
        guard let group = proxies.first(where: { $0.all.contains(node) })?.name else {
            throw AppError.processFailed("未找到包含节点的代理组：\(node)")
        }
        ensureProxyModeForConcreteSelection()
        try await supercoreAPIClient.useOutbound(name: node)
        persistSelectedNodes([(group: group, node: node)])
        try await refreshRuntimeState()
        saveLastStartedNode(node)
    }

    private func concreteNodeNames(inGroup groupName: String, visited: Set<String> = []) -> [String] {
        guard let group = proxies.first(where: { $0.name == groupName }), !visited.contains(groupName) else {
            return []
        }
        let groupNames = Set(proxies.map(\.name))
        var nextVisited = visited
        nextVisited.insert(groupName)
        return group.all.reduce(into: [String]()) { result, item in
            if groupNames.contains(item) {
                for nested in concreteNodeNames(inGroup: item, visited: nextVisited) where !result.contains(nested) {
                    result.append(nested)
                }
            } else if !isSpecialOutboundName(item), !item.isEmpty, !result.contains(item) {
                result.append(item)
            }
        }
    }

    private func selectionPath(
        fromGroup groupName: String,
        toNode node: String,
        visited: Set<String> = []
    ) -> [(group: String, node: String)]? {
        guard let group = proxies.first(where: { $0.name == groupName }), !visited.contains(groupName) else {
            return nil
        }
        if group.all.contains(node) {
            return [(group.name, node)]
        }
        var nextVisited = visited
        nextVisited.insert(groupName)
        for item in group.all where proxies.contains(where: { $0.name == item }) {
            if let nested = selectionPath(fromGroup: item, toNode: node, visited: nextVisited) {
                return [(group.name, item)] + nested
            }
        }
        return nil
    }

    private func primaryParentSelections(for groupName: String) -> [(group: String, node: String)] {
        proxies
            .filter { parent in
                parent.name != groupName &&
                    parent.all.contains(groupName) &&
                    (
                        parent.name.contains("节点选择") ||
                        parent.name.localizedCaseInsensitiveContains("proxy") ||
                        parent.name.contains("代理") ||
                        parent.name.caseInsensitiveCompare("GLOBAL") == .orderedSame
                    )
            }
            .map { (group: $0.name, node: groupName) }
    }

    private func persistSelectedNodes(_ selections: [(group: String, node: String)]) {
        guard let profileID = activeSubscription?.id else { return }
        for selection in selections {
            subscriptionManager.saveSelectedNode(profileID: profileID, group: selection.group, node: selection.node)
        }
        profiles = subscriptionManager.loadProfiles()
        activeSubscription = profiles.first(where: { $0.id == profileID })
    }

    private func ensureCoreRunningForDelayTesting() async throws {
        if coreState.isRunning {
            if trafficPollingTask == nil || logsTask == nil {
                startStreams()
            }
            return
        }
        try await ensureSupercoreRunningForDelayTesting()
    }

    private func ensureSupercoreRunningForDelayTesting() async throws {
        guard let profile = activeSubscription else {
            throw AppError.missingSubscription
        }
        userMessage = "正在启动 Supercore 测速服务..."
        do {
            let options = try prepareDelayTestingRuntime(profileID: profile.id)
            runtimeOptions = options
            supercoreAPIClient.setControlPort(options.controllerPort)
            if try supercoreManager.activateCachedSubscription(profileID: profile.id) {
                appendLog("测速使用本地 Supercore 订阅缓存：\(profile.name)")
            } else {
                throw AppError.processFailed(
                    "Supercore 未加载到本地订阅缓存，请先在导入/更新订阅后再进行测速"
                )
            }
            resetRuntimeTrafficBaselineForActiveProfile(flushImmediately: true)
            try await supercoreManager.start(configPath: paths.supercoreRuntimeProfile(id: profile.id))
            runtimePurpose = .delayTesting
            startStreams()
            try await refreshRuntimeState()
            await refreshTrafficSnapshot(flushImmediately: true)
            mergeRuntimeNodesIntoProviderCatalog()
            userMessage = "Supercore 测速服务已就绪"
        } catch {
            runtimePurpose = .idle
            traffic = TrafficFrame(up: 0, down: 0)
            stopStreams()
            await supercoreManager.stop()
            throw error
        }
    }

    @discardableResult
    func prepareDelayTestingRuntime(profileID: String) throws -> RuntimeOptions {
        let options = try makeRuntimeOptions(tunEnabled: false, useLaunchDaemon: false)
        try configManager.regenerateSupercoreRuntime(
            profileID: profileID,
            tunEnabled: false,
            runtimeOptions: options,
            probeURL: probeURL
        )
        return options
    }

    private func setLocalSelectedNode(group: String, node: String) {
        proxies = proxies.map { item in
            guard item.name == group else { return item }
            return ProxyGroup(
                name: item.name,
                type: item.type,
                now: node,
                all: item.all,
                includeAll: item.includeAll,
                filter: item.filter,
                useProviders: item.useProviders
            )
        }
    }

    private func setOperation(_ kind: OperationKind, _ message: String) {
        operation = OperationState(kind: kind, message: message)
        userMessage = message
    }

    private func updateOperation(_ message: String) {
        if var operation {
            operation.message = message
            self.operation = operation
        }
        userMessage = message
    }

    private func clearOperation() {
        operation = nil
    }

    private func appendLog(_ line: String) {
        let safeLine = LogRedactor.redact(line)
        let entry = AppLogEntry(category: LogClassifier.category(for: safeLine), text: safeLine)
        pendingLogLines.append(safeLine)
        pendingLogEntries.append(entry)
        guard logFlushTask == nil else { return }
        logFlushTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: 250_000_000)
            await MainActor.run {
                self?.flushPendingLogs()
            }
        }
    }

    private func flushPendingLogs() {
        guard !pendingLogLines.isEmpty else {
            logFlushTask = nil
            return
        }
        logLines.append(contentsOf: pendingLogLines)
        logEntries.append(contentsOf: pendingLogEntries)
        pendingLogLines = []
        pendingLogEntries = []
        if logLines.count > 2_000 {
            logLines.removeFirst(logLines.count - 2_000)
        }
        if logEntries.count > 2_000 {
            logEntries.removeFirst(logEntries.count - 2_000)
        }
        logFlushTask = nil
    }
}
