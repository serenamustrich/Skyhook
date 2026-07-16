import Foundation

enum ProbeTimeoutCalculator {
    private static let timeoutBufferSeconds: TimeInterval = 0.5

    static func requestTimeout(
        timeoutMilliseconds: Int,
        concurrency: Int?,
        names: [String]?
    ) -> TimeInterval {
        let baseTimeoutSeconds = TimeInterval(max(1, timeoutMilliseconds)) / 1000.0
        let parallelism = max(1, concurrency ?? DelayPolicy.manualConcurrency)
        let count = names?.filter { !$0.isEmpty }.count ?? 0
        guard count > 0 else {
            return baseTimeoutSeconds + timeoutBufferSeconds
        }
        let batches = Int(ceil(Double(count) / Double(parallelism)))
        return baseTimeoutSeconds * TimeInterval(max(1, batches)) + timeoutBufferSeconds
    }
}

final class SupercoreAPIClient: @unchecked Sendable {
    private var baseURL: URL
    private let baseURLLock = DispatchQueue(label: "YueqiuElevatorSupercore.SupercoreAPIClient.baseURL")
    private let decoder = JSONDecoder()

    init(baseURL: URL = URL(string: "http://127.0.0.1:9197")!) {
        self.baseURL = baseURL
        decoder.dateDecodingStrategy = .iso8601
    }

    func setControlPort(_ port: Int) {
        setBaseURL(URL(string: "http://127.0.0.1:\(port)")!)
    }

    func setBaseURL(_ url: URL) {
        baseURLLock.sync {
            baseURL = url
        }
    }

    func getVersion(timeoutInterval: TimeInterval? = nil) async throws -> SupercoreVersion {
        try await request(path: "/supercore/version", timeoutInterval: timeoutInterval)
    }

    func getStatus() async throws -> SupercoreStatus {
        try await request(path: "/supercore/status")
    }

    func getGroups() async throws -> [SupercoreProxyGroup] {
        let response: SupercoreGroupsResponse = try await request(path: "/supercore/groups")
        return response.groups
    }

    func getProxyGroups() async throws -> [ProxyGroup] {
        let groups = try await getGroups()
        return groups.map { group in
            ProxyGroup(
                name: group.name,
                type: group.kind,
                now: group.selectedMember,
                all: group.members.map(\.name)
            )
        }
        .filter { !$0.name.isEmpty && !$0.all.isEmpty }
        .sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
    }

    func getCountries() async throws -> [SupercoreCountryGroup] {
        let response: SupercoreCountriesResponse = try await request(path: "/supercore/countries")
        return response.countries
    }

    func useCountry(code: String) async throws {
        let body = try JSONSerialization.data(withJSONObject: ["code": code])
        let response: SupercoreOKResponse = try await request(
            path: "/supercore/countries/use",
            method: "POST",
            body: body
        )
        try response.throwIfNeeded()
    }

    func useOutbound(name: String) async throws {
        let body = try JSONSerialization.data(withJSONObject: ["name": name])
        let response: SupercoreOKResponse = try await request(
            path: "/supercore/outbounds/use",
            method: "POST",
            body: body
        )
        try response.throwIfNeeded()
    }

    func probeGroup(
        name: String,
        timeoutMilliseconds: Int = DelayPolicy.timeoutMilliseconds,
        url: String = DelayPolicy.probeURL,
        concurrency: Int? = nil
    ) async throws -> [SupercoreProbeResult] {
        let response = try await probeGroupResponse(
            name: name,
            timeoutMilliseconds: timeoutMilliseconds,
            url: url,
            concurrency: concurrency
        )
        return response.results
    }

    func probeGroupResponse(
        name: String,
        timeoutMilliseconds: Int = DelayPolicy.timeoutMilliseconds,
        url: String = DelayPolicy.probeURL,
        concurrency: Int? = nil
    ) async throws -> SupercoreProbeGroupResponse {
        var payload: [String: Any] = [
            "timeout_ms": timeoutMilliseconds,
            "url": url,
        ]
        if let concurrency {
            payload["concurrency"] = concurrency
        }
        payload["group"] = name
        let body = try JSONSerialization.data(withJSONObject: payload)
        let response: SupercoreProbeGroupResponse = try await request(
            path: "/supercore/probe/group",
            method: "POST",
            timeoutInterval: TimeInterval(timeoutMilliseconds) / 1000.0 + 10,
            body: body
        )
        guard response.ok else {
            throw AppError.processFailed(response.error ?? "group probe failed")
        }
        return response
    }

    func probeOutbounds(
        timeoutMilliseconds: Int = DelayPolicy.timeoutMilliseconds,
        url: String = DelayPolicy.probeURL,
        concurrency: Int? = nil,
        names: [String]? = nil
    ) async throws -> [SupercoreProbeResult] {
        let response = try await probeOutboundsResponse(
            timeoutMilliseconds: timeoutMilliseconds,
            url: url,
            concurrency: concurrency,
            names: names
        )
        return response.results
    }

    func probeOutboundsResponse(
        timeoutMilliseconds: Int = DelayPolicy.timeoutMilliseconds,
        url: String = DelayPolicy.probeURL,
        concurrency: Int? = nil,
        names: [String]? = nil
    ) async throws -> SupercoreProbeResponse {
        var payload: [String: Any] = [
            "timeout_ms": timeoutMilliseconds,
            "url": url
        ]
        if let concurrency {
            payload["concurrency"] = concurrency
        }
        if let names {
            payload["names"] = names
        }
        let requestTimeout = probeRequestTimeout(
            timeoutMilliseconds: timeoutMilliseconds,
            concurrency: concurrency,
            names: names
        )
        let body = try JSONSerialization.data(withJSONObject: payload)
        let response: SupercoreProbeResponse = try await request(
            path: "/supercore/probe/outbounds",
            method: "POST",
            timeoutInterval: requestTimeout,
            body: body
        )
        return response
    }

    private func probeRequestTimeout(
        timeoutMilliseconds: Int,
        concurrency: Int?,
        names: [String]?
    ) -> TimeInterval {
        ProbeTimeoutCalculator.requestTimeout(
            timeoutMilliseconds: timeoutMilliseconds,
            concurrency: concurrency,
            names: names
        )
    }

    func importSubscription(name: String?, url: String, switchToImported: Bool) async throws {
        var payload: [String: Any] = ["url": url, "switch": switchToImported]
        if let name, !name.isEmpty {
            payload["name"] = name
        }
        let body = try JSONSerialization.data(withJSONObject: payload)
        let response: SupercoreOKResponse = try await request(
            path: "/supercore/subscriptions/import",
            method: "POST",
            timeoutInterval: 20,
            body: body
        )
        try response.throwIfNeeded()
    }

    func useSubscription(id: String) async throws {
        let body = try JSONSerialization.data(withJSONObject: ["id": id])
        let response: SupercoreOKResponse = try await request(
            path: "/supercore/subscriptions/use",
            method: "POST",
            body: body
        )
        try response.throwIfNeeded()
    }

    func updateAllSubscriptions() async throws {
        let response: SupercoreOKResponse = try await request(
            path: "/supercore/subscriptions/update-all",
            method: "POST",
            timeoutInterval: 60
        )
        try response.throwIfNeeded()
    }

    func reloadActiveSubscription() async throws {
        let response: SupercoreOKResponse = try await request(
            path: "/supercore/subscriptions/reload-active",
            method: "POST"
        )
        try response.throwIfNeeded()
    }

    func reloadConfig(path: URL) async throws {
        let body = try JSONSerialization.data(withJSONObject: ["path": path.path])
        let response: SupercoreOKResponse = try await request(
            path: "/supercore/config/reload",
            method: "POST",
            body: body
        )
        try response.throwIfNeeded()
    }

    func getConnectionsTrafficSnapshot() async throws -> ConnectionTrafficSnapshot {
        let status = try await getStatus()
        return ConnectionTrafficSnapshot(
            upTotal: Int(clamping: status.traffic.uploadTotal),
            downTotal: Int(clamping: status.traffic.downloadTotal)
        )
    }

    func getConnectionObservations() async throws -> [SmartRuleObservation] {
        let response: SupercoreConnectionsResponse = try await request(path: "/supercore/connections")
        return response.connections.compactMap { record in
            guard let endpoint = SmartRuleEndpointClassifier.classify(host: record.destination.host) else {
                return nil
            }
            return SmartRuleObservation(
                connectionID: record.id,
                target: endpoint.target,
                value: endpoint.value,
                endpointHost: endpoint.endpointHost,
                port: record.destination.port,
                route: record.outbound.caseInsensitiveCompare("direct") == .orderedSame ? .direct : .proxy,
                seenAt: Date()
            )
        }
    }

    func getLogs() async throws -> [String] {
        let response: SupercoreLogsResponse = try await request(path: "/supercore/logs")
        return response.logs.map { "[supercore:\($0.level)] \($0.message)" }
    }

    func getSubscriptionTraffic() async throws -> [SupercoreSubscriptionTraffic] {
        let response: SupercoreSubscriptionTrafficResponse = try await request(path: "/supercore/traffic/subscriptions")
        try response.throwIfNeeded()
        return response.subscriptions
    }

    func getSmartRules() async throws -> SupercoreSmartRulesSnapshot {
        try await request(path: "/supercore/smart-rules")
    }

    func applySmartRecommendation(target: String, value: String) async throws {
        let body = try JSONSerialization.data(withJSONObject: ["target": target, "value": value])
        let response: SupercoreOKResponse = try await request(
            path: "/supercore/smart-rules/apply-recommendation",
            method: "POST",
            body: body
        )
        try response.throwIfNeeded()
    }

    func applySmartRecommendations(action: CustomRuleAction?) async throws {
        var payload: [String: Any] = [:]
        if let smartAction = action?.supercoreSmartAction {
            payload["action"] = smartAction
        }
        let body = try JSONSerialization.data(withJSONObject: payload)
        let response: SupercoreOKResponse = try await request(
            path: "/supercore/smart-rules/apply-recommendations",
            method: "POST",
            body: body
        )
        try response.throwIfNeeded()
    }

    private func request<T: Decodable>(
        path: String,
        method: String = "GET",
        timeoutInterval: TimeInterval? = nil,
        body: Data? = nil
    ) async throws -> T {
        let baseURL = baseURLLock.sync { self.baseURL }
        var request = URLRequest(url: baseURL.appendingPathComponent(path))
        request.httpMethod = method
        if let timeoutInterval {
            request.timeoutInterval = timeoutInterval
        }
        if let body {
            request.httpBody = body
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw AppError.unexpectedResponse }
        guard (200..<300).contains(http.statusCode) else {
            throw AppError.apiError(http.statusCode, String(data: data, encoding: .utf8) ?? "")
        }
        return try decoder.decode(T.self, from: data)
    }
}

struct SupercoreVersion: Decodable, Sendable {
    let name: String
    let version: String
    let engine: String
}

struct SupercoreStatus: Decodable, Sendable {
    let mixedListen: String
    let controlListen: String
    let outbounds: Int
    let rules: Int
    let smartRulesEnabled: Bool
    let traffic: SupercoreTrafficTotals

    enum CodingKeys: String, CodingKey {
        case mixedListen = "mixed_listen"
        case controlListen = "control_listen"
        case outbounds
        case rules
        case smartRulesEnabled = "smart_rules_enabled"
        case traffic
    }
}

struct SupercoreTrafficTotals: Decodable, Sendable {
    let uploadTotal: UInt64
    let downloadTotal: UInt64

    enum CodingKeys: String, CodingKey {
        case uploadTotal = "upload_total"
        case downloadTotal = "download_total"
    }
}

struct SupercoreGroupsResponse: Decodable, Sendable {
    let groups: [SupercoreProxyGroup]
}

struct SupercoreProxyGroup: Decodable, Sendable, Identifiable {
    var id: String { name }
    let name: String
    let kind: String
    let autoSelect: Bool
    let selectedMember: String?
    let selectionReason: String
    let members: [SupercoreGroupMember]

    enum CodingKeys: String, CodingKey {
        case name
        case kind
        case autoSelect = "auto_select"
        case selectedMember = "selected_member"
        case selectionReason = "selection_reason"
        case members
    }
}

struct SupercoreGroupMember: Decodable, Sendable, Identifiable {
    var id: String { name }
    let name: String
    let kind: String
    let healthy: Bool
    let attempts: UInt64
    let successes: UInt64
    let failures: UInt64
    let lastLatencyMs: UInt64?
    let lastError: String?
    let score: UInt8?

    enum CodingKeys: String, CodingKey {
        case name
        case kind
        case healthy
        case attempts
        case successes
        case failures
        case lastLatencyMs = "last_latency_ms"
        case lastError = "last_error"
        case score
    }
}

struct SupercoreCountriesResponse: Decodable, Sendable {
    let countries: [SupercoreCountryGroup]
}

struct SupercoreCountryGroup: Decodable, Sendable, Identifiable {
    var id: String { code }
    let code: String
    let name: String
    let nodeCount: Int
    let bestOutbound: String?
    let members: [SupercoreGroupMember]

    enum CodingKeys: String, CodingKey {
        case code
        case name
        case nodeCount = "node_count"
        case bestOutbound = "best_outbound"
        case members
    }
}

struct SupercoreProbeResponse: Decodable, Sendable {
    let results: [SupercoreProbeResult]
    let failureSummary: [String: Int]?

    enum CodingKeys: String, CodingKey {
        case results
        case failureSummary = "failure_summary"
    }
}

struct SupercoreProbeGroupResponse: Decodable, Sendable {
    let ok: Bool
    let error: String?
    let group: String?
    let results: [SupercoreProbeResult]
    let failureSummary: [String: Int]?

    enum CodingKeys: String, CodingKey {
        case ok
        case error
        case group
        case results
        case failureSummary = "failure_summary"
    }
}

struct SupercoreProbeResult: Decodable, Sendable, Identifiable {
    var id: String { name }
    let name: String
    let kind: String
    let success: Bool
    let latencyMs: UInt64?
    let failureKind: String?
    let error: String?

    enum CodingKeys: String, CodingKey {
        case name
        case kind
        case success
        case latencyMs = "latency_ms"
        case failureKind = "failure_kind"
        case error
    }

    var failureTitle: String {
        guard let kind = failureKind?.lowercased() else { return "未知错误" }
        switch kind {
        case "timeout":
            return "超时"
        case "outbound_not_found":
            return "核心无此节点"
        case "protocol_unsupported":
            return "协议暂不支持"
        case "dial_error":
            return "拨号失败"
        case "tls_error":
            return "TLS 失败"
        case "http_status":
            return "HTTP 状态异常"
        case "empty_response":
            return "空响应"
        case "dns_error":
            return "DNS 解析失败"
        case "invalid_probe_url":
            return "无效检测地址"
        case "probe_task_failed":
            return "探测任务失败"
        default:
            return error ?? "未知错误"
        }
    }
}

struct SupercoreSubscriptionTrafficResponse: Decodable, Sendable {
    let ok: Bool
    let error: String?
    let activeID: String?
    let subscriptions: [SupercoreSubscriptionTraffic]

    enum CodingKeys: String, CodingKey {
        case ok
        case error
        case activeID = "active_id"
        case subscriptions
    }

    func throwIfNeeded() throws {
        if !ok { throw AppError.processFailed(error ?? "Supercore request failed") }
    }
}

struct SupercoreLogsResponse: Decodable, Sendable {
    let logs: [SupercoreLogEvent]
}

struct SupercoreConnectionsResponse: Decodable, Sendable {
    let traffic: SupercoreTrafficTotals
    let connections: [SupercoreConnectionRecord]
}

struct SupercoreConnectionRecord: Decodable, Sendable {
    let id: String
    let destination: SupercoreConnectionDestination
    let outbound: String
}

struct SupercoreConnectionDestination: Decodable, Sendable {
    let host: String
    let port: Int
}

struct SupercoreLogEvent: Decodable, Sendable {
    let time: String
    let level: String
    let message: String
}

struct SupercoreSubscriptionTraffic: Decodable, Sendable, Identifiable {
    let id: String
    let name: String
    let uploadTotal: UInt64
    let downloadTotal: UInt64
    let total: UInt64

    enum CodingKeys: String, CodingKey {
        case id
        case name
        case uploadTotal = "upload_total"
        case downloadTotal = "download_total"
        case total
    }
}

struct SupercoreSmartRulesSnapshot: Decodable, Sendable {
    let directOutbound: String
    let proxyOutbound: String?
    let stats: [String: DoubleOrInt]
    let rules: [SupercoreSmartRule]
    let observations: [SupercoreSmartObservation]
    let recommendations: [SupercoreSmartRecommendation]

    enum CodingKeys: String, CodingKey {
        case directOutbound = "direct_outbound"
        case proxyOutbound = "proxy_outbound"
        case stats
        case rules
        case observations
        case recommendations
    }
}

struct SupercoreSmartRule: Decodable, Sendable {
    let target: String
    let value: String
    let outbound: String
    let enabled: Bool
}

struct SupercoreSmartObservation: Decodable, Sendable, Identifiable {
    var id: String { key }
    let key: String
    let target: String
    let value: String
    let visits: UInt64
    let directRoutedHits: UInt64
    let proxyRoutedHits: UInt64
    let directProbeAttempts: UInt64
    let directProbeSuccesses: UInt64
    let directProbeFailures: UInt64
    let lastOutbound: String?
    let lastDirectLatencyMs: UInt64?
    let lastError: String?
    let lastSeenAt: String
    let lastProbeAt: String?

    enum CodingKeys: String, CodingKey {
        case key
        case target
        case value
        case visits
        case directRoutedHits = "direct_routed_hits"
        case proxyRoutedHits = "proxy_routed_hits"
        case directProbeAttempts = "direct_probe_attempts"
        case directProbeSuccesses = "direct_probe_successes"
        case directProbeFailures = "direct_probe_failures"
        case lastOutbound = "last_outbound"
        case lastDirectLatencyMs = "last_direct_latency_ms"
        case lastError = "last_error"
        case lastSeenAt = "last_seen_at"
        case lastProbeAt = "last_probe_at"
    }
}

struct SupercoreSmartRecommendation: Decodable, Sendable, Identifiable {
    var id: String { "\(target):\(value)" }
    let target: String
    let value: String
    let recommendedOutbound: String
    let action: String
    let confidence: Double
    let reason: String
    let latencyMs: UInt64?

    enum CodingKeys: String, CodingKey {
        case target
        case value
        case recommendedOutbound = "recommended_outbound"
        case action
        case confidence
        case reason
        case latencyMs = "latency_ms"
    }
}

enum DoubleOrInt: Decodable, Sendable {
    case double(Double)
    case int(Int)

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let intValue = try? container.decode(Int.self) {
            self = .int(intValue)
        } else {
            self = .double(try container.decode(Double.self))
        }
    }
}

private extension CustomRuleAction {
    var supercoreSmartAction: String? {
        switch self {
        case .direct: "direct"
        case .proxy: "proxy"
        case .reject, .outbound: nil
        }
    }
}

struct SupercoreOKResponse: Decodable, Sendable {
    let ok: Bool?
    let error: String?

    func throwIfNeeded() throws {
        if ok == false {
            throw AppError.processFailed(error ?? "Supercore request failed")
        }
    }
}
