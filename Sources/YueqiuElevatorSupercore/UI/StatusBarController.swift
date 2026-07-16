import AppKit
import Combine

@MainActor
final class StatusBarController {
    private let item: NSStatusItem
    private let appState: AppState
    private var cancellables: Set<AnyCancellable> = []
    private var statusMenu = NSMenu()
    private var pendingMenuWorkItem: DispatchWorkItem?

    init(appState: AppState) {
        self.appState = appState
        self.item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        item.button?.title = "玥球电梯"
        item.button?.toolTip = "玥球电梯"
        item.button?.target = self
        item.button?.action = #selector(statusButtonClicked(_:))
        item.button?.sendAction(on: [.leftMouseUp, .rightMouseUp])
        rebuildMenu()
        bind()
    }

    private func bind() {
        appState.objectWillChange
            .receive(on: DispatchQueue.main)
            .debounce(for: .milliseconds(350), scheduler: DispatchQueue.main)
            .sink { [weak self] _ in
                DispatchQueue.main.async { self?.rebuildMenu() }
            }
            .store(in: &cancellables)
    }

    private func rebuildMenu() {
        let menu = NSMenu()
        menu.addItem(disabled("玥球电梯：\(appState.userMessage)"))
        if let operation = appState.operation {
            menu.addItem(disabled("处理中：\(operation.message)"))
        }
        menu.addItem(disabled(appState.coreState.title))
        menu.addItem(disabled("运行：\(appState.runtimePurpose.title)"))
        menu.addItem(disabled("TUN：\(appState.tunEnabled ? "开" : "关")"))
        menu.addItem(disabled("模式：\(appState.selectedMode.title)"))
        menu.addItem(disabled("订阅：\(appState.activeSubscription?.name ?? "未选择")"))
        menu.addItem(disabled("当前节点：\(appState.currentNodeStatus.summary)"))
        menu.addItem(disabled("速率：\(appState.traffic.title)"))
        menu.addItem(disabled("总流量：\(appState.trafficTotals.title)"))
        menu.addItem(.separator())

        let proxyActionTitle = appState.runtimePurpose == .proxy && appState.coreState.isRunning ? "停止代理" : "启动代理"
        let proxyActionEnabled = appState.operation == nil && (appState.activeSubscription != nil || (appState.runtimePurpose == .proxy && appState.coreState.isRunning))
        menu.addItem(action(proxyActionTitle, #selector(toggleProxy), enabled: proxyActionEnabled))
        menu.addItem(toggle("启用 TUN", isOn: appState.tunEnabled, #selector(toggleTun), enabled: appState.operation == nil))
        menu.addItem(.separator())

        let modeMenu = NSMenu()
        for mode in ProxyMode.allCases {
            let item = NSMenuItem(title: mode.title, action: #selector(selectMode(_:)), keyEquivalent: "")
            item.target = self
            item.representedObject = mode.rawValue
            item.state = mode == appState.selectedMode ? .on : .off
            modeMenu.addItem(item)
        }
        let modeItem = NSMenuItem(title: "模式", action: nil, keyEquivalent: "")
        modeItem.submenu = modeMenu
        menu.addItem(modeItem)

        let profileItem = NSMenuItem(title: "订阅配置", action: nil, keyEquivalent: "")
        let profileMenu = NSMenu()
        if appState.profiles.isEmpty {
            profileMenu.addItem(disabled("还没有保存订阅"))
        } else {
            for profile in appState.profiles {
                let item = NSMenuItem(title: profile.name, action: #selector(selectProfile(_:)), keyEquivalent: "")
                item.target = self
                item.representedObject = profile.id
                item.state = profile.id == appState.activeSubscription?.id ? .on : .off
                item.isEnabled = appState.operation == nil
                profileMenu.addItem(item)
            }
        }
        profileItem.submenu = profileMenu
        menu.addItem(profileItem)

        let groupRoot = NSMenuItem(title: "代理组", action: nil, keyEquivalent: "")
        let groupMenu = NSMenu()
        if appState.proxies.isEmpty {
            groupMenu.addItem(disabled("未读取到代理组"))
        } else {
            for group in appState.proxies.prefix(16) {
                let sub = NSMenu()
                let testItem = NSMenuItem(title: "测试本组延迟", action: #selector(testGroupDelay(_:)), keyEquivalent: "")
                testItem.target = self
                testItem.representedObject = group.name
                testItem.isEnabled = appState.operation == nil
                sub.addItem(testItem)
                sub.addItem(.separator())
                let groupNames = Set(appState.proxies.map(\.name))
                for node in group.all.prefix(40) {
                    if groupNames.contains(node) {
                        sub.addItem(disabled("代理组：\(node)（在设置中查看）"))
                        continue
                    }
                    let nodeItem = NSMenuItem(title: appState.delayTitle(for: node), action: #selector(selectNode(_:)), keyEquivalent: "")
                    nodeItem.target = self
                    nodeItem.representedObject = ["group": group.name, "node": node]
                    nodeItem.state = node == group.now ? .on : .off
                    sub.addItem(nodeItem)
                }
                if group.all.count > 40 {
                    sub.addItem(.separator())
                    sub.addItem(disabled("更多节点请在设置窗口中操作"))
                }
                let item = NSMenuItem(title: "\(group.name)：\(appState.delaySubtitle(for: group))", action: nil, keyEquivalent: "")
                item.submenu = sub
                groupMenu.addItem(item)
            }
        }
        groupRoot.submenu = groupMenu
        menu.addItem(groupRoot)
        menu.addItem(.separator())

        menu.addItem(action("更新全部订阅", #selector(updateSubscription), enabled: appState.operation == nil && !appState.profiles.isEmpty))
        menu.addItem(action("测试全部节点延迟", #selector(testAllDelays), enabled: appState.operation == nil))
        menu.addItem(action("设置...", #selector(openSettings)))
        menu.addItem(action("打开数据目录", #selector(openAppSupport)))
        menu.addItem(action("恢复系统代理快照", #selector(restoreNetwork)))
        menu.addItem(.separator())
        menu.addItem(action("退出", #selector(quit)))
        statusMenu = menu
        item.button?.title = appState.coreState.isRunning ? "玥球电梯 ●" : "玥球电梯"
    }

    private func disabled(_ title: String) -> NSMenuItem {
        let item = NSMenuItem(title: title, action: nil, keyEquivalent: "")
        item.isEnabled = false
        return item
    }

    private func action(_ title: String, _ selector: Selector, enabled: Bool = true) -> NSMenuItem {
        let item = NSMenuItem(title: title, action: selector, keyEquivalent: "")
        item.target = self
        item.isEnabled = enabled
        return item
    }

    private func toggle(_ title: String, isOn: Bool, _ selector: Selector, enabled: Bool = true) -> NSMenuItem {
        let item = action(title, selector, enabled: enabled)
        item.state = isOn ? .on : .off
        return item
    }

    @objc private func toggleProxy() { appState.toggleProxy() }
    @objc private func updateSubscription() { appState.updateSubscription() }
    @objc private func testAllDelays() { appState.testAllGroupsDelay() }
    @objc private func openSettings() { appState.showSettings() }
    @objc private func openAppSupport() { appState.openAppSupport() }
    @objc private func restoreNetwork() { appState.restoreNetworkSnapshot() }
    @objc private func quit() { NSApp.terminate(nil) }

    @objc private func statusButtonClicked(_ sender: NSStatusBarButton) {
        let event = NSApp.currentEvent
        if event?.type == .rightMouseUp {
            pendingMenuWorkItem?.cancel()
            pendingMenuWorkItem = nil
            popUpStatusMenu()
            return
        }

        if (event?.clickCount ?? 1) >= 2 {
            pendingMenuWorkItem?.cancel()
            pendingMenuWorkItem = nil
            appState.showSettings()
            return
        }

        pendingMenuWorkItem?.cancel()
        let workItem = DispatchWorkItem { [weak self] in
            Task { @MainActor in
                self?.popUpStatusMenu()
            }
        }
        pendingMenuWorkItem = workItem
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.22, execute: workItem)
    }

    private func popUpStatusMenu() {
        pendingMenuWorkItem = nil
        guard let button = item.button else { return }
        statusMenu.popUp(
            positioning: nil,
            at: NSPoint(x: 0, y: button.bounds.height + 2),
            in: button
        )
    }

    @objc private func toggleTun() {
        appState.setTunEnabled(!appState.tunEnabled)
    }

    @objc private func selectMode(_ sender: NSMenuItem) {
        guard let raw = sender.representedObject as? String, let mode = ProxyMode(rawValue: raw) else { return }
        appState.setMode(mode)
    }

    @objc private func selectProfile(_ sender: NSMenuItem) {
        guard let profileID = sender.representedObject as? String else { return }
        appState.switchProfile(profileID)
    }

    @objc private func selectNode(_ sender: NSMenuItem) {
        guard let payload = sender.representedObject as? [String: String],
              let group = payload["group"],
              let node = payload["node"] else { return }
        appState.selectProxy(group: group, node: node)
    }

    @objc private func testGroupDelay(_ sender: NSMenuItem) {
        guard let groupName = sender.representedObject as? String else { return }
        appState.testDelay(groupName: groupName)
    }
}
