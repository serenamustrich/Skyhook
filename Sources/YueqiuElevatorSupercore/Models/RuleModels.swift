import Foundation

enum CustomRuleTarget: String, CaseIterable, Codable, Identifiable, Sendable {
    case domain = "DOMAIN"
    case domainSuffix = "DOMAIN-SUFFIX"
    case domainKeyword = "DOMAIN-KEYWORD"
    case domainRegex = "DOMAIN-REGEX"
    case ipCIDR = "IP-CIDR"
    case ipCIDR6 = "IP-CIDR6"
    case appName = "APP-NAME"
    case appPath = "APP-PATH"
    case appPathRegex = "APP-PATH-REGEX"
    case appBundle = "APP-BUNDLE"

    var id: String { rawValue }

    var title: String {
        switch self {
        case .domain: "域名"
        case .domainSuffix: "域名后缀"
        case .domainKeyword: "域名关键词"
        case .domainRegex: "域名正则"
        case .ipCIDR: "IPv4/CIDR"
        case .ipCIDR6: "IPv6/CIDR"
        case .appName: "App 名称"
        case .appPath: "App 路径"
        case .appPathRegex: "App 路径正则"
        case .appBundle: "Bundle ID"
        }
    }

    var supercoreTarget: String? {
        switch self {
        case .domain: "domain"
        case .domainSuffix: "domain-suffix"
        case .domainKeyword: "domain-keyword"
        case .domainRegex: "domain-regex"
        case .ipCIDR: "ip-cidr"
        case .ipCIDR6: "ip-cidr6"
        case .appName: "app-name"
        case .appPath: "app-path"
        case .appPathRegex: "app-path-regex"
        case .appBundle: "app-bundle"
        }
    }

    init?(supercoreTarget: String) {
        switch supercoreTarget.lowercased() {
        case "domain": self = .domain
        case "domain-suffix": self = .domainSuffix
        case "domain-keyword": self = .domainKeyword
        case "domain-regex": self = .domainRegex
        case "ip-cidr": self = .ipCIDR
        case "ip-cidr6": self = .ipCIDR6
        case "app-name": self = .appName
        case "app-path": self = .appPath
        case "app-path-regex": self = .appPathRegex
        case "app-bundle": self = .appBundle
        default: return nil
        }
    }
}

enum CustomRuleAction: String, CaseIterable, Codable, Identifiable, Sendable {
    case proxy
    case direct
    case reject
    case outbound

    var id: String { rawValue }

    var title: String {
        switch self {
        case .proxy: "走代理"
        case .direct: "直连"
        case .reject: "拒绝"
        case .outbound: "指定节点/组"
        }
    }

}

struct CustomRule: Codable, Identifiable, Equatable, Sendable {
    let id: UUID
    var target: CustomRuleTarget
    var value: String
    var action: CustomRuleAction
    var outboundName: String?
    var enabled: Bool
    var createdAt: Date

    init(
        id: UUID = UUID(),
        target: CustomRuleTarget,
        value: String,
        action: CustomRuleAction,
        outboundName: String? = nil,
        enabled: Bool = true,
        createdAt: Date = Date()
    ) {
        self.id = id
        self.target = target
        self.value = value
        self.action = action
        self.outboundName = outboundName
        self.enabled = enabled
        self.createdAt = createdAt
    }
}

enum SmartRuleObservedRoute: String, CaseIterable, Codable, Identifiable, Sendable {
    case proxy
    case direct

    var id: String { rawValue }

    var title: String {
        switch self {
        case .proxy: "走代理"
        case .direct: "直连"
        }
    }

}

enum SmartRuleProbeState: String, Codable, Sendable {
    case unknown
    case reachable
    case failed

    var title: String {
        switch self {
        case .unknown: "未对比"
        case .reachable: "可连接"
        case .failed: "不可达"
        }
    }
}

struct SmartRuleObservation: Equatable, Sendable {
    let connectionID: String?
    let target: CustomRuleTarget
    let value: String
    let endpointHost: String
    let port: Int?
    let route: SmartRuleObservedRoute
    let seenAt: Date

    var key: String {
        SmartRuleCandidate.key(target: target, value: value)
    }
}

struct SmartRuleCandidate: Codable, Identifiable, Equatable, Sendable {
    let id: UUID
    var target: CustomRuleTarget
    var value: String
    var endpointHost: String
    var port: Int?
    var observedRoute: SmartRuleObservedRoute
    var directState: SmartRuleProbeState
    var proxyState: SmartRuleProbeState
    var hitCount: Int
    var firstSeenAt: Date
    var lastSeenAt: Date
    var enabledAction: CustomRuleAction?
    var recommendationActionOverride: CustomRuleAction?
    var recommendationReasonText: String?

    init(
        id: UUID = UUID(),
        target: CustomRuleTarget,
        value: String,
        endpointHost: String,
        port: Int?,
        observedRoute: SmartRuleObservedRoute,
        directState: SmartRuleProbeState = .unknown,
        proxyState: SmartRuleProbeState = .unknown,
        hitCount: Int = 1,
        firstSeenAt: Date = Date(),
        lastSeenAt: Date = Date(),
        enabledAction: CustomRuleAction? = nil,
        recommendationActionOverride: CustomRuleAction? = nil,
        recommendationReasonText: String? = nil
    ) {
        self.id = id
        self.target = target
        self.value = value
        self.endpointHost = endpointHost
        self.port = port
        self.observedRoute = observedRoute
        self.directState = directState
        self.proxyState = proxyState
        self.hitCount = hitCount
        self.firstSeenAt = firstSeenAt
        self.lastSeenAt = lastSeenAt
        self.enabledAction = enabledAction
        self.recommendationActionOverride = recommendationActionOverride
        self.recommendationReasonText = recommendationReasonText
    }

    init(observation: SmartRuleObservation) {
        self.init(
            target: observation.target,
            value: observation.value,
            endpointHost: observation.endpointHost,
            port: observation.port,
            observedRoute: observation.route,
            directState: observation.route == .direct ? .reachable : .unknown,
            proxyState: observation.route == .proxy ? .reachable : .unknown,
            firstSeenAt: observation.seenAt,
            lastSeenAt: observation.seenAt
        )
    }

    var key: String {
        Self.key(target: target, value: value)
    }

    var recommendationAction: CustomRuleAction? {
        if let recommendationActionOverride {
            return recommendationActionOverride
        }
        if observedRoute == .proxy, directState == .reachable {
            return .direct
        }
        if directState == .failed, proxyState == .reachable {
            return .proxy
        }
        return nil
    }

    var recommendationReason: String {
        if let recommendationReasonText, !recommendationReasonText.isEmpty {
            return recommendationReasonText
        }
        return switch recommendationAction {
        case .direct:
            "订阅规则当前走代理，但直连探测可连接"
        case .proxy:
            "直连探测不可达，代理链路可连接"
        case nil:
            "还没有形成可启用建议"
        case .reject, .outbound:
            "还没有形成可启用建议"
        }
    }

    mutating func record(_ observation: SmartRuleObservation) {
        observedRoute = observation.route
        endpointHost = observation.endpointHost
        port = observation.port ?? port
        hitCount += 1
        lastSeenAt = observation.seenAt
        switch observation.route {
        case .direct:
            directState = .reachable
        case .proxy:
            proxyState = .reachable
        }
    }

    mutating func setDirectProbeResult(_ state: SmartRuleProbeState) {
        directState = state
        lastSeenAt = Date()
    }

    mutating func markEnabled(action: CustomRuleAction) {
        enabledAction = action
    }

    static func key(target: CustomRuleTarget, value: String) -> String {
        "\(target.rawValue)|\(value.lowercased())"
    }
}

struct SmartRuleStats: Equatable, Sendable {
    let proxyComparedCount: Int
    let proxyDirectReachableCount: Int
    let directRecommendationCount: Int
    let proxyRecommendationCount: Int
    let enabledCount: Int

    init(candidates: [SmartRuleCandidate]) {
        let comparedProxyRules = candidates.filter {
            $0.observedRoute == .proxy && $0.directState != .unknown
        }
        proxyComparedCount = comparedProxyRules.count
        proxyDirectReachableCount = comparedProxyRules.filter { $0.directState == .reachable }.count
        directRecommendationCount = candidates.filter { $0.recommendationAction == .direct }.count
        proxyRecommendationCount = candidates.filter { $0.recommendationAction == .proxy }.count
        enabledCount = candidates.filter { $0.enabledAction != nil }.count
    }

    var proxyDirectReachableRatioTitle: String {
        guard proxyComparedCount > 0 else { return "暂无数据" }
        let ratio = Double(proxyDirectReachableCount) / Double(proxyComparedCount)
        return "\(Int((ratio * 100).rounded()))%"
    }

    var proxyDirectReachableDetailTitle: String {
        guard proxyComparedCount > 0 else { return "等待学习" }
        return "\(proxyDirectReachableCount)/\(proxyComparedCount) 可直连"
    }
}

enum LogCategory: String, CaseIterable, Identifiable, Sendable {
    case all
    case proxy
    case direct
    case rule
    case dns
    case tun
    case error
    case system

    var id: String { rawValue }

    var title: String {
        switch self {
        case .all: "全部"
        case .proxy: "代理"
        case .direct: "直连"
        case .rule: "规则"
        case .dns: "DNS"
        case .tun: "TUN"
        case .error: "错误"
        case .system: "系统"
        }
    }
}

struct AppLogEntry: Identifiable, Equatable, Sendable {
    let id: UUID
    let date: Date
    let category: LogCategory
    let text: String

    init(id: UUID = UUID(), date: Date = Date(), category: LogCategory, text: String) {
        self.id = id
        self.date = date
        self.category = category
        self.text = text
    }
}

enum LogClassifier {
    static func category(for line: String) -> LogCategory {
        let lower = line.lowercased()
        if lower.contains("error") || lower.contains("失败") || lower.contains("failed") || lower.contains("fatal") {
            return .error
        }
        if lower.contains("tun") || lower.contains("虚拟网卡") || lower.contains("tun2proxy") {
            return .tun
        }
        if lower.contains("dns") || lower.contains("fake-ip") || lower.contains("nameserver") {
            return .dns
        }
        if lower.contains("direct") || lower.contains("直连") {
            return .direct
        }
        if lower.contains("rule") || lower.contains("match") || lower.contains("规则") {
            return .rule
        }
        if lower.contains("proxy") || lower.contains("using") || lower.contains("代理") {
            return .proxy
        }
        return .system
    }
}
