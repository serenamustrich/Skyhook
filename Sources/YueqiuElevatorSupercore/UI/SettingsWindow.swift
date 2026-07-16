import AppKit
import SwiftUI

enum SettingsWindow {
    @MainActor
    static func make(appState: AppState) -> NSWindow {
        let view = SettingsView(appState: appState)
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 980, height: 680),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "玥球电梯"
        window.contentView = NSHostingView(rootView: view)
        window.center()
        return window
    }
}

struct SettingsView: View {
    @ObservedObject var appState: AppState
    @State private var subscriptionURL = ""
    @State private var nodeSearch = ""
    @State private var selectedGroupID = ""
    @State private var selectedLogCategory: LogCategory = .all
    @State private var customRuleTarget: CustomRuleTarget = .domainSuffix
    @State private var customRuleAction: CustomRuleAction = .proxy
    @State private var customRuleOutboundName = ""
    @State private var customRuleValue = ""

    private var isBusy: Bool { appState.operation != nil }

    var body: some View {
        TabView {
            overviewTab
                .tabItem { Label("总览", systemImage: "gauge.with.dots.needle") }

            profilesTab
                .tabItem { Label("订阅", systemImage: "link") }

            nodesTab
                .tabItem { Label("节点", systemImage: "point.3.connected.trianglepath.dotted") }

            logsTab
                .tabItem { Label("日志", systemImage: "terminal") }

            rulesTab
                .tabItem { Label("规则", systemImage: "list.bullet.rectangle") }

            smartRulesTab
                .tabItem { Label("智能规则", systemImage: "sparkles") }
        }
        .frame(minWidth: 900, minHeight: 620)
    }

    private var overviewTab: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                HStack(alignment: .center, spacing: 12) {
                    VStack(alignment: .leading, spacing: 4) {
                        HStack(spacing: 8) {
                            Text("玥球电梯")
                                .font(.system(size: 24, weight: .semibold))
                            StatusBadge(text: appState.runtimePurpose.title, color: statusColor)
                        }
                        Text(appState.userMessage)
                            .foregroundStyle(.secondary)
                            .lineLimit(2)
                    }
                    Spacer()
                    Button {
                        appState.toggleProxy()
                    } label: {
                        Label(proxyActionTitle, systemImage: proxyActionSystemImage)
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(proxyActionTint)
                    .disabled(proxyActionDisabled)
                }

                OperationBanner(operation: appState.operation)

                if appState.networkRecoveryNeeded {
                    NetworkRecoveryBanner(appState: appState)
                }

                CurrentNodeCard(status: appState.currentNodeStatus)

                LazyVGrid(columns: [GridItem(.adaptive(minimum: 220), spacing: 10)], spacing: 10) {
                    StatTile(title: "Core", value: appState.coreState.title, systemImage: "cpu")
                    StatTile(title: "实时速率", value: appState.traffic.title, systemImage: "speedometer")
                    StatTile(title: "总流量", value: appState.trafficTotals.title, systemImage: "arrow.up.arrow.down")
                    StatTile(title: "订阅节点", value: "\(appState.providerNodes.count)", systemImage: "circle.grid.cross")
                    StatTile(title: "可用延迟", value: availableDelayTitle, systemImage: "waveform.path.ecg")
                }

                GroupBox {
                    VStack(alignment: .leading, spacing: 12) {
                        HStack {
                            Toggle(isOn: Binding(
                                get: { appState.tunEnabled },
                                set: { appState.setTunEnabled($0) }
                            )) {
                                Label("TUN", systemImage: "network")
                            }
                            .toggleStyle(.switch)

                            Picker("TUN DNS 处理方式", selection: Binding(
                                get: { appState.runtimeOptions.dnsStrategy },
                                set: { appState.setTunDNSStrategy($0) }
                            )) {
                                ForEach(TunDNSStrategy.allCases) { strategy in
                                    Text(strategy.title).tag(strategy)
                                }
                            }
                            .frame(width: 200)
                            .help("Fake-IP 会使用 198.18.0.0/15 虚拟地址池，核心异常退出时需要自动清理路由")

                            Picker("模式", selection: Binding(
                                get: { appState.selectedMode },
                                set: { appState.setMode($0) }
                            )) {
                                ForEach(ProxyMode.allCases, id: \.self) { mode in
                                    Text(mode.title).tag(mode)
                                }
                            }
                            .pickerStyle(.segmented)
                            .frame(maxWidth: 260)

                            Spacer()
                            Text(appState.activeSubscription?.name ?? "未选择订阅")
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                                .truncationMode(.middle)
                        }
                        HStack(spacing: 8) {
                            Picker("测速 URL", selection: Binding(
                                get: { appState.probeURL },
                                set: { appState.setProbeURL($0) }
                            )) {
                                Text("gstatic HTTP").tag("http://www.gstatic.com/generate_204")
                                Text("gstatic HTTPS").tag("https://www.gstatic.com/generate_204")
                                Text("Google Analytics").tag("http://www.google-analytics.com/generate_204")
                                Text("Cloudflare").tag("http://cp.cloudflare.com/generate_204")
                            }
                            .frame(width: 180)
                            Spacer()
                        }
                        .font(.caption)
                        if let profile = appState.activeSubscription {
                            HStack(spacing: 12) {
                                Label(profile.maskedURL, systemImage: "link")
                                    .lineLimit(1)
                                    .truncationMode(.middle)
                                Spacer()
                                Text(profile.updatedAt.formatted())
                                    .foregroundStyle(.secondary)
                            }
                            .font(.caption)
                        }
                        HStack(spacing: 10) {
                            Label(appState.tunLaunchDaemonStatus.title, systemImage: "lock.shield")
                                .foregroundStyle(appState.tunLaunchDaemonStatus.loaded ? .green : .secondary)
                                .lineLimit(1)
                                .truncationMode(.middle)
                            Spacer()
                            Button {
                                appState.refreshTunLaunchDaemonStatus()
                            } label: {
                                Label("刷新", systemImage: "arrow.clockwise")
                            }
                            Button {
                                appState.installTunLaunchDaemon()
                            } label: {
                                Label("安装/更新权限服务", systemImage: "square.and.arrow.down")
                            }
                            .help("一次性安装系统 LaunchDaemon，让 TUN 模式可以创建虚拟网卡；这不是启动代理，也不会写入订阅。")
                            .disabled(appState.operation != nil || appState.activeSubscription == nil)
                            Button(role: .destructive) {
                                appState.uninstallTunLaunchDaemon()
                            } label: {
                                Label("卸载", systemImage: "trash")
                            }
                            .help("移除 TUN 权限服务；普通代理模式不受影响。")
                            .disabled(appState.operation != nil || !appState.tunLaunchDaemonStatus.installed)
                        }
                        .font(.caption)
                        Text("TUN 权限服务是一次性系统授权，用于创建虚拟网卡；安装后启用 TUN 时可免反复输入管理员密码。")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
            .padding(16)
        }
    }

    private var profilesTab: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .firstTextBaseline) {
                VStack(alignment: .leading, spacing: 3) {
                    Text("订阅")
                        .font(.headline)
                    Text(appState.activeSubscription?.name ?? "还没有选择订阅")
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
                Spacer()
                Button {
                    appState.updateSubscription()
                } label: {
                    Label(appState.operation?.kind == .updatingSubscription ? "更新中" : "更新全部", systemImage: "arrow.clockwise")
                }
                .disabled(isBusy || appState.profiles.isEmpty)
            }

            HStack(spacing: 8) {
                TextField("订阅 URL", text: $subscriptionURL)
                    .textFieldStyle(.roundedBorder)
                    .disabled(isBusy)
                Button {
                    appState.importSubscription(urlString: subscriptionURL)
                } label: {
                    if appState.operation?.kind == .importingSubscription {
                        HStack(spacing: 6) {
                            ProgressView().controlSize(.small)
                            Text("导入中")
                        }
                    } else {
                        Label("导入", systemImage: "square.and.arrow.down")
                    }
                }
                .disabled(isBusy || subscriptionURL.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }

            OperationBanner(operation: appState.operation)

            if appState.profiles.isEmpty {
                EmptyState(systemImage: "link.badge.plus", title: "暂无订阅", message: "粘贴订阅 URL 后导入。")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    LazyVStack(spacing: 8) {
                        ForEach(appState.profiles, id: \.id) { profile in
                            ProfileRow(
                                profile: profile,
                                trafficTotals: appState.trafficTotals(for: profile),
                                isActive: profile.id == appState.activeSubscription?.id,
                                isBusy: isBusy
                            ) {
                                appState.switchProfile(profile.id)
                            }
                        }
                    }
                    .padding(.vertical, 2)
                }
            }
        }
        .padding(16)
    }

    private var nodesTab: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .center) {
                VStack(alignment: .leading, spacing: 3) {
                    Text("节点")
                        .font(.headline)
                    Text(appState.activeSubscription?.name ?? "未选择订阅")
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
                Spacer()
                Button {
                    appState.refreshNodeList()
                } label: {
                    Label("刷新", systemImage: "arrow.clockwise")
                }
                .disabled(isBusy || appState.activeSubscription == nil)
                Button {
                    appState.testAllNodesDelay()
                } label: {
                    Label("测速所有节点", systemImage: "bolt.fill")
                }
                .disabled(isBusy || appState.activeSubscription == nil)
                Button {
                    appState.autoSelectBestNodeNow()
                } label: {
                    Label("自动择优", systemImage: "wand.and.stars")
                }
                .disabled(isBusy || appState.activeSubscription == nil)
                Button {
                    appState.testAllGroupsDelay()
                } label: {
                    Label("测速代理组", systemImage: "timer")
                }
                .disabled(isBusy || appState.activeSubscription == nil)
            }

            OperationBanner(operation: appState.operation)

            GroupBox {
                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("国家分组")
                                .font(.subheadline.weight(.semibold))
                            Text(countrySelectionTitle)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }

                        Spacer()
                        Toggle("自动择优", isOn: Binding(
                            get: { appState.autoCountrySwitchEnabled },
                            set: { appState.setAutoCountrySwitchEnabled($0) }
                        ))
                        .toggleStyle(.switch)
                        .disabled(appState.selectedCountry == nil || appState.providerNodes.isEmpty)

                        Toggle("只看可用", isOn: Binding(
                            get: { appState.showOnlyAvailableNodes },
                            set: { appState.setShowOnlyAvailableNodes($0) }
                        ))
                        .toggleStyle(.switch)
                    }

                    if appState.countryGroups.isEmpty {
                        Text("暂无国家分组")
                            .foregroundStyle(.secondary)
                    } else {
                        LazyVGrid(columns: [GridItem(.adaptive(minimum: 126), spacing: 8)], spacing: 8) {
                            CountryFilterCard(
                                title: "全部国家",
                                count: appState.providerNodes.count,
                                delay: nil,
                                delayFailureKind: nil,
                                isSelected: appState.selectedCountry == nil
                            ) {
                                appState.setSelectedCountry(nil)
                            }
                            ForEach(appState.countryGroups) { group in
                                CountryFilterCard(
                                    title: group.country,
                                    count: group.nodes.count,
                                    delay: group.bestDelay,
                                    delayFailureKind: group.selectedNode.flatMap(appState.delayFailureKind),
                                    isSelected: group.country == appState.selectedCountry
                                ) {
                                    appState.setSelectedCountry(group.country)
                                }
                            }
                        }
                    }
                }
            }

            if appState.proxies.isEmpty {
                EmptyState(systemImage: "point.3.connected.trianglepath.dotted", title: "暂无代理组", message: "导入订阅后自动显示可选择节点。")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                HStack(alignment: .top, spacing: 12) {
                    proxyGroupSidebar
                        .frame(width: 250)
                    Divider()
                    nodeDetailPane
                }
            }
        }
        .padding(16)
    }

    private var proxyGroupSidebar: some View {
        ScrollView {
            LazyVStack(spacing: 6) {
                ForEach(appState.proxies) { group in
                    Button {
                        selectedGroupID = group.id
                        nodeSearch = ""
                    } label: {
                        HStack(spacing: 10) {
                            Image(systemName: selectedProxyGroup?.id == group.id ? "folder.fill" : "folder")
                                .font(.system(size: 15, weight: .semibold))
                                .foregroundStyle(selectedProxyGroup?.id == group.id ? Color.accentColor : Color.secondary)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(group.name)
                                    .font(.subheadline)
                                    .fontWeight(selectedProxyGroup?.id == group.id ? .semibold : .medium)
                                    .lineLimit(1)
                                Text(groupNodeCountTitle(group, appState: appState))
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                            Spacer()
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.vertical, 10)
                        .padding(.leading, selectedProxyGroup?.id == group.id ? 14 : 10)
                        .padding(.trailing, 10)
                        .background(
                            selectedProxyGroup?.id == group.id
                                ? Color.accentColor.opacity(0.08)
                                : Color.clear
                        )
                        .overlay(alignment: .leading) {
                            if selectedProxyGroup?.id == group.id {
                                RoundedRectangle(cornerRadius: 2)
                                    .fill(Color.accentColor)
                                    .frame(width: 4)
                                    .padding(.vertical, 8)
                            }
                        }
                        .overlay {
                            RoundedRectangle(cornerRadius: 8)
                                .stroke(selectedProxyGroup?.id == group.id ? Color.accentColor.opacity(0.34) : Color.clear, lineWidth: 1)
                        }
                        .clipShape(RoundedRectangle(cornerRadius: 8))
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                }
            }
        }
    }

    private var nodeDetailPane: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(selectedProxyGroup?.name ?? "代理组")
                        .font(.headline)
                    Text(selectedProxyGroup.map { appState.delaySubtitle(for: $0) } ?? "-")
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                Spacer()
                if let group = selectedProxyGroup {
                    Button {
                        appState.autoSelectBestNode(in: group.name)
                    } label: {
                        Label("本组择优", systemImage: "wand.and.stars")
                    }
                    .disabled(isBusy || group.all.isEmpty)
                    Button {
                        appState.testDelay(groupName: group.name)
                    } label: {
                        Label("测速", systemImage: "timer")
                    }
                    .disabled(isBusy || group.all.isEmpty)
                }
            }

            TextField("搜索节点", text: $nodeSearch)
                .textFieldStyle(.roundedBorder)

            if let group = selectedProxyGroup {
                let nodes = filteredNodes(in: group, appState: appState, search: nodeSearch)
                if nodes.isEmpty {
                    EmptyState(systemImage: "magnifyingglass", title: "没有匹配节点", message: "换一个关键词。")
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    ScrollView {
                        LazyVStack(spacing: 8) {
                            ForEach(nodes, id: \.self) { node in
                                let isProxyGroupLink = proxyGroup(named: node) != nil
            NodeRow(
                                    node: node,
                                    delay: appState.delayResults[node],
                                    delayFailureKind: appState.delayFailureKinds[node],
                                    isSelected: !isProxyGroupLink && node == group.now,
                                    isProxyGroupLink: isProxyGroupLink,
                                    isBusy: isBusy
                                ) {
                                    if isProxyGroupLink {
                                        selectedGroupID = node
                                        nodeSearch = ""
                                    } else {
                                        appState.selectProxy(group: group.name, node: node)
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    private var logsTab: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("日志")
                    .font(.headline)
                Spacer()
                Button {
                    appState.clearLogs()
                } label: {
                    Label("清空", systemImage: "trash")
                }
                Button {
                    appState.openAppSupport()
                } label: {
                    Label("数据目录", systemImage: "folder")
                }
                Button {
                    appState.restoreNetworkSnapshot()
                } label: {
                    Label("恢复网络", systemImage: "arrow.uturn.backward")
                }
            }

            if appState.logLines.isEmpty {
                EmptyState(systemImage: "terminal", title: "暂无日志", message: "运行、更新或测速后会显示日志。")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                Picker("日志类型", selection: $selectedLogCategory) {
                    ForEach(LogCategory.allCases) { category in
                        Text(category.title).tag(category)
                    }
                }
                .pickerStyle(.segmented)

                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 4) {
                        ForEach(filteredLogEntries.prefix(600)) { entry in
                            HStack(alignment: .firstTextBaseline, spacing: 8) {
                                Text(entry.category.title)
                                    .font(.system(size: 10, weight: .semibold))
                                    .foregroundStyle(logCategoryColor(entry.category))
                                    .frame(width: 32, alignment: .leading)
                                Text(entry.text)
                                    .textSelection(.enabled)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                            }
                                .font(.system(.caption, design: .monospaced))
                        }
                    }
                }
                .padding(8)
                .background(Color(nsColor: .textBackgroundColor))
                .clipShape(RoundedRectangle(cornerRadius: 8))
            }
        }
        .padding(16)
    }

    private var rulesTab: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                VStack(alignment: .leading, spacing: 3) {
                    Text("自定义规则")
                        .font(.headline)
                    Text(appState.activeSubscription?.name ?? "未选择订阅")
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
                Spacer()
                Text("\(appState.customRules.count) 条")
                    .foregroundStyle(.secondary)
            }

            GroupBox {
                VStack(alignment: .leading, spacing: 10) {
                    HStack(spacing: 8) {
                        Picker("类型", selection: $customRuleTarget) {
                            ForEach(CustomRuleTarget.allCases) { target in
                                Text(target.title).tag(target)
                            }
                        }
                        .frame(width: 140)

                        TextField(rulePlaceholder, text: $customRuleValue)
                            .textFieldStyle(.roundedBorder)

                        Picker("动作", selection: $customRuleAction) {
                            ForEach(CustomRuleAction.allCases) { action in
                                Text(action.title).tag(action)
                            }
                        }
                        .frame(width: 110)

                        if customRuleAction == .outbound {
                            Picker("节点/组", selection: Binding(
                                get: { selectedRuleOutboundName ?? "" },
                                set: { customRuleOutboundName = $0 }
                            )) {
                                ForEach(ruleOutboundChoices, id: \.self) { outbound in
                                    Text(outbound).tag(outbound)
                                }
                            }
                            .frame(width: 180)
                            .disabled(ruleOutboundChoices.isEmpty)
                        }

                        Button {
                            appState.addCustomRule(
                                target: customRuleTarget,
                                value: customRuleValue,
                                action: customRuleAction,
                                outboundName: selectedRuleOutboundName
                            )
                            customRuleValue = ""
                        } label: {
                            Label("添加", systemImage: "plus")
                        }
                        .disabled(
                            appState.activeSubscription == nil ||
                                customRuleValue.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ||
                                (customRuleAction == .outbound && selectedRuleOutboundName == nil)
                        )
                    }
                    Text("规则会插入到订阅规则前面，优先级最高。可按域名、IP、App 名称、App 路径或 Bundle ID 指定直连、拒绝、主代理组或具体节点。")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            if appState.customRules.isEmpty {
                EmptyState(systemImage: "list.bullet.rectangle", title: "暂无自定义规则", message: "添加域名或 IP 后，可指定走代理、直连或拒绝。")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    LazyVStack(spacing: 8) {
                        ForEach(appState.customRules) { rule in
                            CustomRuleRow(
                                rule: rule,
                                setEnabled: { appState.setCustomRuleEnabled(rule.id, enabled: $0) },
                                remove: { appState.removeCustomRule(rule.id) }
                            )
                        }
                    }
                    .padding(.vertical, 2)
                }
            }
        }
        .padding(16)
    }

    private var smartRulesTab: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                HStack(alignment: .firstTextBaseline) {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("智能学习规则")
                            .font(.headline)
                        Text(appState.activeSubscription?.name ?? "未选择订阅")
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    }
                    Spacer()
                    Text("\(appState.smartRuleCandidates.count) 条学习记录")
                        .foregroundStyle(.secondary)
                }

                LazyVGrid(columns: [GridItem(.adaptive(minimum: 190), spacing: 10)], spacing: 10) {
                    StatTile(
                        title: "代理可直连比例",
                        value: appState.smartRuleStats.proxyDirectReachableRatioTitle,
                        subtitle: appState.smartRuleStats.proxyDirectReachableDetailTitle,
                        systemImage: "arrow.triangle.branch"
                    )
                    StatTile(
                        title: "推荐直连",
                        value: "\(appState.smartRuleStats.directRecommendationCount)",
                        systemImage: "checkmark.circle"
                    )
                    StatTile(
                        title: "推荐代理",
                        value: "\(appState.smartRuleStats.proxyRecommendationCount)",
                        systemImage: "point.3.connected.trianglepath.dotted"
                    )
                    StatTile(
                        title: "已启用",
                        value: "\(appState.smartRuleStats.enabledCount)",
                        systemImage: "bolt.badge.checkmark"
                    )
                }

                OperationBanner(operation: appState.operation)

                if appState.smartRuleCandidates.isEmpty {
                    EmptyState(
                        systemImage: "sparkles",
                        title: "暂无学习记录",
                        message: "启动代理后，玥球电梯会从实际连接中学习域名/IP，并在后台对比直连可用性。"
                    )
                    .frame(maxWidth: .infinity, minHeight: 320)
                } else {
                    HStack(alignment: .top, spacing: 12) {
                        SmartRuleRecommendationPanel(
                            title: "推荐直连",
                            subtitle: "当前走代理，但直连也能连接",
                            action: .direct,
                            candidates: appState.smartRules(recommendation: .direct),
                            isBusy: isBusy,
                            isEnabled: { appState.isSmartRuleEnabled($0, action: .direct) },
                            enableAll: { appState.enableAllSmartRules(recommendation: .direct) },
                            enableOne: { candidate in appState.enableSmartRule(candidate.id) }
                        )
                        SmartRuleRecommendationPanel(
                            title: "推荐代理",
                            subtitle: "直连不可达，代理链路可连接",
                            action: .proxy,
                            candidates: appState.smartRules(recommendation: .proxy),
                            isBusy: isBusy,
                            isEnabled: { appState.isSmartRuleEnabled($0, action: .proxy) },
                            enableAll: { appState.enableAllSmartRules(recommendation: .proxy) },
                            enableOne: { candidate in appState.enableSmartRule(candidate.id) }
                        )
                    }
                }

                Text("启用后的智能规则会写入当前订阅的自定义规则，并插入到订阅规则前面。")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .padding(16)
        }
    }

    private var selectedProxyGroup: ProxyGroup? {
        if let group = appState.proxies.first(where: { $0.id == selectedGroupID }) {
            return group
        }
        return appState.proxies.first
    }

    private func proxyGroup(named name: String) -> ProxyGroup? {
        appState.proxies.first { $0.name == name }
    }

    private var availableDelayTitle: String {
        var available = 0
        var unavailable = 0
        var skipped = 0
        for (name, delay) in appState.delayResults {
            if DelayPolicy.isAvailable(delay, failureKind: appState.delayFailureKinds[name]) {
                available += 1
            } else if appState.delayFailureKinds[name] == "outbound_not_found" {
                skipped += 1
            } else {
                unavailable += 1
            }
        }
        guard available + unavailable > 0 else { return "未测速" }
        if skipped > 0 {
            return "\(available) 可用 / \(unavailable) 失败，核心无此节点 \(skipped)"
        }
        return "\(available) 可用 / \(unavailable) 失败"
    }

    private var filteredLogEntries: [AppLogEntry] {
        let entries = appState.logEntries.isEmpty
            ? appState.logLines.map { AppLogEntry(category: LogClassifier.category(for: $0), text: $0) }
            : appState.logEntries
        let filtered = selectedLogCategory == .all
            ? entries
            : entries.filter { $0.category == selectedLogCategory }
        return Array(filtered.reversed())
    }

    private var rulePlaceholder: String {
        switch customRuleTarget {
        case .domain: "example.com"
        case .domainSuffix: "example.com"
        case .domainKeyword: "google"
        case .domainRegex: ".*\\.google\\.com"
        case .ipCIDR: "8.8.8.8/32"
        case .ipCIDR6: "2001:4860:4860::8888/128"
        case .appName: "Safari"
        case .appPath: "/Applications/Safari.app"
        case .appPathRegex: ".*Safari.*"
        case .appBundle: "com.apple.Safari"
        }
    }

    private var ruleOutboundChoices: [String] {
        var names: [String] = []
        func append(_ value: String) {
            guard !value.isEmpty,
                  value.caseInsensitiveCompare("direct") != .orderedSame,
                  value.caseInsensitiveCompare("reject") != .orderedSame,
                  !names.contains(value) else {
                return
            }
            names.append(value)
        }
        appState.proxies.forEach { group in
            append(group.name)
            group.all.forEach(append)
        }
        appState.providerNodes.forEach { append($0.name) }
        return names.sorted { $0.localizedStandardCompare($1) == .orderedAscending }
    }

    private var selectedRuleOutboundName: String? {
        let choices = ruleOutboundChoices
        guard !choices.isEmpty else { return nil }
        if choices.contains(customRuleOutboundName) {
            return customRuleOutboundName
        }
        return choices.first
    }

    private func logCategoryColor(_ category: LogCategory) -> Color {
        switch category {
        case .all: .secondary
        case .proxy: .blue
        case .direct: .green
        case .rule: .orange
        case .dns: .purple
        case .tun: .cyan
        case .error: .red
        case .system: .secondary
        }
    }

    private var statusColor: Color {
        switch appState.coreState {
        case .running: return .green
        case .starting: return .orange
        case .crashed: return .red
        default: return .secondary
        }
    }

    private var proxyActionTitle: String {
        if let operation = appState.operation {
            return operation.title
        }
        if appState.runtimePurpose == .proxy, appState.coreState.isRunning {
            return "停止代理"
        }
        return "启动代理"
    }

    private var proxyActionSystemImage: String {
        if appState.operation != nil { return "hourglass" }
        if appState.runtimePurpose == .proxy, appState.coreState.isRunning { return "stop.fill" }
        return "play.fill"
    }

    private var proxyActionTint: Color {
        if appState.runtimePurpose == .proxy, appState.coreState.isRunning {
            return .red
        }
        return .accentColor
    }

    private var proxyActionDisabled: Bool {
        appState.operation != nil || (appState.activeSubscription == nil && !(appState.runtimePurpose == .proxy && appState.coreState.isRunning))
    }

    private var countrySelectionTitle: String {
        if let country = appState.selectedCountry {
            return appState.autoCountrySwitchEnabled ? "已选择 \(country)，自动择优开启" : "已选择 \(country)"
        }
        return "直接点击国家卡片切换；全部国家表示不限制国家"
    }
}

@MainActor
private func filteredNodes(in group: ProxyGroup, appState: AppState, search: String) -> [String] {
    let base = visibleNodes(in: group, appState: appState)
    let keyword = search.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !keyword.isEmpty else { return base }
    return base.filter { $0.localizedCaseInsensitiveContains(keyword) }
}

@MainActor
private func visibleNodes(in group: ProxyGroup, appState: AppState) -> [String] {
    guard appState.showOnlyAvailableNodes else { return group.all }
    return group.all.filter {
        appState.delayFailureKinds[$0] != "outbound_not_found"
            && DelayPolicy.isAvailable(appState.delayResults[$0], failureKind: appState.delayFailureKinds[$0])
    }
}

@MainActor
private func groupNodeCountTitle(_ group: ProxyGroup, appState: AppState) -> String {
    if appState.showOnlyAvailableNodes {
        return "\(visibleNodes(in: group, appState: appState).count)/\(group.all.count) 可用"
    }
    return "\(group.all.count) 个节点"
}

private struct StatTile: View {
    let title: String
    let value: String
    var subtitle: String? = nil
    let systemImage: String

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: systemImage)
                .font(.title3)
                .frame(width: 28)
                .foregroundStyle(.tint)
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(value)
                    .font(.headline)
                    .lineLimit(2)
                    .truncationMode(.middle)
                    .fixedSize(horizontal: false, vertical: true)
                if let subtitle {
                    Text(subtitle)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(10)
        .background(Color(nsColor: .controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }
}

private struct CurrentNodeCard: View {
    let status: CurrentNodeStatus

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: "point.3.connected.trianglepath.dotted")
                .font(.title3)
                .frame(width: 28)
                .foregroundStyle(.tint)
            VStack(alignment: .leading, spacing: 3) {
                Text("当前节点")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(status.nodeTitle)
                    .font(.headline)
                    .lineLimit(2)
                    .truncationMode(.middle)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 8)
            CurrentNodeDelayBadge(delay: status.delay, failureKind: status.failureKind)
        }
        .padding(12)
        .background(Color(nsColor: .controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }
}

private struct CurrentNodeDelayBadge: View {
    let delay: Int?
    let failureKind: String?

    var body: some View {
        Text(DelayPolicy.displayTitle(for: delay, failureKind: failureKind))
            .font(.caption)
            .fontWeight(.semibold)
            .padding(.horizontal, 9)
            .padding(.vertical, 5)
            .background(color.opacity(0.14))
            .foregroundStyle(color)
            .clipShape(RoundedRectangle(cornerRadius: 8))
    }

    private var color: Color {
        if let failureKind {
            if failureKind == "outbound_not_found" {
                return .orange
            }
            if failureKind == "protocol_unsupported" {
                return .purple
            }
            return .red
        }
        guard let delay else { return .secondary }
        if delay < 0 { return .red }
        if delay < 50 { return .green }
        if delay < 150 { return .blue }
        return .red
    }
}

private struct StatusBadge: View {
    let text: String
    let color: Color

    var body: some View {
        Text(text)
            .font(.caption)
            .fontWeight(.semibold)
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(color.opacity(0.14))
            .foregroundStyle(color)
            .clipShape(RoundedRectangle(cornerRadius: 8))
    }
}

private struct ProfileRow: View {
    let profile: SubscriptionProfile
    let trafficTotals: TrafficTotals
    let isActive: Bool
    let isBusy: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 10) {
                Image(systemName: isActive ? "checkmark.circle.fill" : "circle")
                    .foregroundStyle(isActive ? Color.accentColor : Color.secondary)
                VStack(alignment: .leading, spacing: 3) {
                    HStack {
                        Text(profile.name)
                            .font(.headline)
                        if isActive {
                            Text("当前")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    Text(profile.maskedURL)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Text("更新：\(profile.updatedAt.formatted())")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    if let planInfo = profile.planInfo, planInfo.hasContent {
                        SubscriptionInfoRow(planInfo: planInfo)
                    }
                    Text("累计：\(trafficTotals.title)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(10)
            .background(isActive ? Color.accentColor.opacity(0.10) : Color(nsColor: .controlBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 8))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .disabled(isBusy)
    }
}

private struct SubscriptionInfoRow: View {
    let planInfo: SubscriptionPlanInfo

    var body: some View {
        FlowLayout(spacing: 6) {
            if let remainingTraffic = planInfo.remainingTraffic {
                InfoPill(title: "剩余", value: remainingTraffic, color: .green)
            }
            if let usedTraffic = planInfo.usedTraffic {
                InfoPill(title: "已用", value: usedTraffic, color: .blue)
            }
            if let totalTraffic = planInfo.totalTraffic {
                InfoPill(title: "总量", value: totalTraffic, color: .secondary)
            }
            if let resetInfo = planInfo.resetInfo {
                InfoPill(title: "重置", value: resetInfo, color: .orange)
            }
            if let expiresAtText = planInfo.expiresAtText {
                InfoPill(title: "到期", value: expiresAtText, color: .red)
            }
            if let homepage = planInfo.homepage {
                InfoPill(title: "官网", value: homepage, color: .secondary)
            }
        }
    }
}

private struct InfoPill: View {
    let title: String
    let value: String
    let color: Color

    var body: some View {
        HStack(spacing: 3) {
            Text(title)
                .foregroundStyle(.secondary)
            Text(value)
                .foregroundStyle(color)
                .lineLimit(1)
                .truncationMode(.middle)
        }
        .font(.caption)
        .padding(.horizontal, 7)
        .padding(.vertical, 3)
        .background(color.opacity(0.08))
        .clipShape(RoundedRectangle(cornerRadius: 6))
    }
}

private struct FlowLayout<Content: View>: View {
    let spacing: CGFloat
    @ViewBuilder let content: Content

    var body: some View {
        HStack(spacing: spacing) {
            content
        }
    }
}

private struct CountryFilterCard: View {
    let title: String
    let count: Int
    let delay: Int?
    let delayFailureKind: String?
    let isSelected: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 8) {
                VStack(alignment: .leading, spacing: 4) {
                    Text(title)
                        .font(.subheadline.weight(.semibold))
                        .lineLimit(1)
                    HStack(spacing: 6) {
                        Text("\(count) 个节点")
                            .foregroundStyle(.secondary)
                        if delay != nil {
                            Text(DelayPolicy.displayTitle(for: delay, failureKind: delayFailureKind))
                                .foregroundStyle(countryDelayColor)
                        }
                    }
                    .font(.caption)
                }
                Spacer(minLength: 0)
                if isSelected {
                    Image(systemName: "checkmark.circle.fill")
                        .font(.system(size: 15, weight: .semibold))
                        .foregroundStyle(Color.accentColor)
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 10)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(isSelected ? Color.accentColor.opacity(0.08) : Color(nsColor: .controlBackgroundColor))
            .overlay(alignment: .leading) {
                if isSelected {
                    RoundedRectangle(cornerRadius: 2)
                        .fill(Color.accentColor)
                        .frame(width: 4)
                        .padding(.vertical, 8)
                }
            }
            .overlay {
                RoundedRectangle(cornerRadius: 8)
                    .stroke(isSelected ? Color.accentColor.opacity(0.36) : Color(nsColor: .separatorColor).opacity(0.38), lineWidth: 1)
            }
            .clipShape(RoundedRectangle(cornerRadius: 8))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    private var countryDelayColor: Color {
        if let delayFailureKind {
            if delayFailureKind == "outbound_not_found" {
                return .orange
            }
            if delayFailureKind == "protocol_unsupported" {
                return .purple
            }
            return .red
        }
        guard let delay else { return .secondary }
        if delay < 0 { return .red }
        if delay < 50 { return .green }
        if delay < 150 { return .blue }
        return .red
    }
}

private struct CustomRuleRow: View {
    let rule: CustomRule
    let setEnabled: @MainActor (Bool) -> Void
    let remove: @MainActor () -> Void

    var body: some View {
        HStack(spacing: 10) {
            Toggle("", isOn: Binding(
                get: { rule.enabled },
                set: { enabled in setEnabled(enabled) }
            ))
            .toggleStyle(.switch)
            .labelsHidden()

            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(rule.target.title)
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.secondary)
                    Text(rule.action.title)
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(actionColor)
                    if rule.action == .outbound, let outbound = rule.outboundName, !outbound.isEmpty {
                        Text("→ \(outbound)")
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(.purple)
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }
                }
                Text(rule.value)
                    .font(.body)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }

            Spacer(minLength: 8)

            Button(role: .destructive, action: remove) {
                Image(systemName: "trash")
            }
            .buttonStyle(.borderless)
        }
        .padding(10)
        .background(Color(nsColor: .controlBackgroundColor))
        .overlay {
            RoundedRectangle(cornerRadius: 8)
                .stroke(Color(nsColor: .separatorColor).opacity(0.38), lineWidth: 1)
        }
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .opacity(rule.enabled ? 1 : 0.55)
    }

    private var actionColor: Color {
        switch rule.action {
        case .proxy: .blue
        case .direct: .green
        case .reject: .red
        case .outbound: .purple
        }
    }
}

private struct SmartRuleRecommendationPanel: View {
    let title: String
    let subtitle: String
    let action: CustomRuleAction
    let candidates: [SmartRuleCandidate]
    let isBusy: Bool
    let isEnabled: @MainActor (SmartRuleCandidate) -> Bool
    let enableAll: @MainActor () -> Void
    let enableOne: @MainActor (SmartRuleCandidate) -> Void

    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 10) {
                HStack(alignment: .firstTextBaseline) {
                    VStack(alignment: .leading, spacing: 3) {
                        Text(title)
                            .font(.subheadline.weight(.semibold))
                        Text(subtitle)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(2)
                    }
                    Spacer()
                    Button {
                        enableAll()
                    } label: {
                        Label("全部启用", systemImage: "checkmark.circle")
                    }
                    .disabled(isBusy || candidates.allSatisfy { isEnabled($0) })
                }

                if candidates.isEmpty {
                    EmptyState(systemImage: emptySystemImage, title: "暂无建议", message: "有学习结果后会自动出现。")
                        .frame(maxWidth: .infinity, minHeight: 190)
                } else {
                    LazyVStack(spacing: 8) {
                        ForEach(candidates.prefix(200)) { candidate in
                            SmartRuleRow(
                                candidate: candidate,
                                action: action,
                                isEnabled: isEnabled(candidate),
                                isBusy: isBusy
                            ) {
                                enableOne(candidate)
                            }
                        }
                    }
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
    }

    private var emptySystemImage: String {
        action == .direct ? "checkmark.circle" : "point.3.connected.trianglepath.dotted"
    }
}

private struct SmartRuleRow: View {
    let candidate: SmartRuleCandidate
    let action: CustomRuleAction
    let isEnabled: Bool
    let isBusy: Bool
    let enable: @MainActor () -> Void

    var body: some View {
        HStack(alignment: .center, spacing: 10) {
            Image(systemName: iconName)
                .font(.system(size: 16, weight: .semibold))
                .frame(width: 24)
                .foregroundStyle(actionColor)

            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 6) {
                    Text(candidate.value)
                        .font(.body.weight(.semibold))
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Text(candidate.target.title)
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.secondary)
                }

                FlowLayout(spacing: 6) {
                    SmartRulePill(title: "当前", value: candidate.observedRoute.title, color: candidate.observedRoute == .proxy ? .blue : .green)
                    SmartRulePill(title: "直连", value: candidate.directState.title, color: probeColor(candidate.directState))
                    SmartRulePill(title: "代理", value: candidate.proxyState.title, color: probeColor(candidate.proxyState))
                    SmartRulePill(title: "命中", value: "\(candidate.hitCount)", color: .secondary)
                    SmartRulePill(title: "最近", value: candidate.lastSeenAt.formatted(date: .omitted, time: .shortened), color: .secondary)
                }

                Text(candidate.recommendationReason)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            }

            Spacer(minLength: 8)

            if isEnabled {
                Text("已启用")
                    .font(.caption.weight(.semibold))
                    .padding(.horizontal, 9)
                    .padding(.vertical, 5)
                    .background(actionColor.opacity(0.12))
                    .foregroundStyle(actionColor)
                    .clipShape(RoundedRectangle(cornerRadius: 7))
            } else {
                Button {
                    enable()
                } label: {
                    Label("启用", systemImage: "plus.circle")
                }
                .disabled(isBusy)
            }
        }
        .padding(10)
        .background(Color(nsColor: .textBackgroundColor))
        .overlay {
            RoundedRectangle(cornerRadius: 8)
                .stroke(isEnabled ? actionColor.opacity(0.35) : Color(nsColor: .separatorColor).opacity(0.55), lineWidth: 1)
        }
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }

    private var iconName: String {
        action == .direct ? "arrow.down.left.circle" : "point.3.connected.trianglepath.dotted"
    }

    private var actionColor: Color {
        switch action {
        case .proxy: .blue
        case .direct: .green
        case .reject: .red
        case .outbound: .purple
        }
    }

    private func probeColor(_ state: SmartRuleProbeState) -> Color {
        switch state {
        case .unknown: .secondary
        case .reachable: .green
        case .failed: .red
        }
    }
}

private struct SmartRulePill: View {
    let title: String
    let value: String
    let color: Color

    var body: some View {
        HStack(spacing: 3) {
            Text(title)
                .foregroundStyle(.secondary)
            Text(value)
                .foregroundStyle(color)
                .lineLimit(1)
                .truncationMode(.middle)
        }
        .font(.caption)
        .padding(.horizontal, 7)
        .padding(.vertical, 3)
        .background(color.opacity(0.08))
        .clipShape(RoundedRectangle(cornerRadius: 6))
    }
}

private struct NodeRow: View {
    let node: String
    let delay: Int?
    let delayFailureKind: String?
    let isSelected: Bool
    let isProxyGroupLink: Bool
    let isBusy: Bool
    let action: () -> Void

    var body: some View {
        HStack(spacing: 10) {
            if isProxyGroupLink {
                Image(systemName: "folder")
                    .font(.system(size: 15, weight: .semibold))
                    .foregroundStyle(Color.secondary)
            }
            if isSelected {
                Image(systemName: "checkmark.circle.fill")
                    .font(.system(size: 16, weight: .semibold))
                    .foregroundStyle(Color.accentColor)
            }
            VStack(alignment: .leading, spacing: 2) {
                Text(node)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .font(.body.weight(isSelected ? .semibold : .regular))
                if isProxyGroupLink {
                    Text("代理组，点击查看里面的节点")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else if isSelected {
                    Text("当前流量将走这个节点")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            Spacer()
            if !isProxyGroupLink {
                DelayBadge(delay: delay, failureKind: delayFailureKind)
            }
            if isSelected {
                CurrentBadge()
            } else {
                Button(isProxyGroupLink ? "查看" : "选择", action: action)
                    .buttonStyle(.borderless)
                    .disabled(isBusy)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.vertical, isSelected ? 11 : 8)
        .padding(.leading, isSelected ? 16 : 10)
        .padding(.trailing, 10)
        .background(isSelected ? Color.accentColor.opacity(0.075) : Color(nsColor: .textBackgroundColor))
        .overlay(alignment: .leading) {
            if isSelected {
                RoundedRectangle(cornerRadius: 2)
                    .fill(Color.accentColor)
                    .frame(width: 4)
                    .padding(.vertical, 8)
            }
        }
        .overlay {
            RoundedRectangle(cornerRadius: 8)
                .stroke(isSelected ? Color.accentColor.opacity(0.34) : Color(nsColor: .separatorColor).opacity(0.55), lineWidth: 1)
        }
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .contentShape(Rectangle())
        .onTapGesture {
            if !isBusy, (!isSelected || isProxyGroupLink) {
                action()
            }
        }
    }
}

private struct CurrentBadge: View {
    var body: some View {
        Text("当前使用")
            .font(.caption.weight(.semibold))
            .padding(.horizontal, 9)
            .padding(.vertical, 4)
            .background(Color.accentColor.opacity(0.12))
            .foregroundStyle(Color.accentColor)
            .clipShape(RoundedRectangle(cornerRadius: 7))
    }
}

private struct DelayBadge: View {
    let delay: Int?
    let failureKind: String?

    var body: some View {
        Text(title)
            .font(.caption)
            .fontWeight(.medium)
            .padding(.horizontal, 7)
            .padding(.vertical, 3)
            .background(color.opacity(0.12))
            .foregroundStyle(color)
            .clipShape(RoundedRectangle(cornerRadius: 6))
    }

    private var title: String {
        DelayPolicy.displayTitle(for: delay, failureKind: failureKind)
    }

    private var color: Color {
        if let failureKind {
            if failureKind == "outbound_not_found" {
                return .orange
            }
            if failureKind == "protocol_unsupported" {
                return .purple
            }
            return .red
        }
        guard let delay else { return .secondary }
        if delay < 0 { return .red }
        if delay < 50 { return .green }
        if delay < 150 { return .blue }
        return .red
    }
}

private struct EmptyState: View {
    let systemImage: String
    let title: String
    let message: String

    var body: some View {
        VStack(spacing: 8) {
            Image(systemName: systemImage)
                .font(.system(size: 28))
                .foregroundStyle(.secondary)
            Text(title)
                .font(.headline)
            Text(message)
                .foregroundStyle(.secondary)
        }
        .padding()
    }
}

private struct OperationBanner: View {
    let operation: OperationState?

    var body: some View {
        if let operation {
            HStack(spacing: 8) {
                ProgressView()
                    .controlSize(.small)
                VStack(alignment: .leading, spacing: 2) {
                    Text(operation.title)
                        .font(.caption)
                        .fontWeight(.semibold)
                    Text(operation.message)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }
            .padding(10)
            .background(Color.accentColor.opacity(0.10))
            .clipShape(RoundedRectangle(cornerRadius: 8))
        }
    }
}

private struct NetworkRecoveryBanner: View {
    @ObservedObject var appState: AppState

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.title3)
                .foregroundStyle(.orange)
            VStack(alignment: .leading, spacing: 2) {
                Text("检测到上次网络状态未清理")
                    .font(.caption)
                    .fontWeight(.semibold)
                Text("上次异常退出可能导致系统代理或 TUN 路由残留")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button {
                appState.performNetworkRecovery()
            } label: {
                Label("一键恢复网络", systemImage: "arrow.uturn.backward")
            }
            .buttonStyle(.borderedProminent)
            .tint(.orange)
            .disabled(appState.operation != nil)
        }
        .padding(10)
        .background(Color.orange.opacity(0.10))
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }
}
