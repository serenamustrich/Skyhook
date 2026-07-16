import Foundation

enum ProbeTimeoutCalculator {
    private static let timeoutBufferSeconds: TimeInterval = 0.5
    private static let unknownNodeMinimumSeconds: TimeInterval = 60
    private static let unknownNodeBatchBudget = 80

    static func requestTimeout(
        timeoutMilliseconds: Int,
        concurrency: Int?,
        names: [String]?
    ) -> TimeInterval {
        let baseTimeoutSeconds = TimeInterval(max(1, timeoutMilliseconds)) / 1000.0
        let parallelism = max(1, concurrency ?? DelayPolicy.manualConcurrency)
        guard let names else {
            return max(
                unknownNodeMinimumSeconds,
                baseTimeoutSeconds * TimeInterval(unknownNodeBatchBudget) + timeoutBufferSeconds
            )
        }
        let count = names.filter { !$0.isEmpty }.count
        guard count > 0 else {
            return baseTimeoutSeconds + timeoutBufferSeconds
        }
        let batches = Int(ceil(Double(count) / Double(parallelism)))
        return baseTimeoutSeconds * TimeInterval(max(1, batches)) + timeoutBufferSeconds
    }
}

final class SupercoreAPIClient: @unchecked Sendable {
    private var baseURL: URL
    private var controlToken: String?
    private let baseURLLock = DispatchQueue(label: "YueqiuElevatorSupercore.SupercoreAPIClient.baseURL")

    init(baseURL: URL = URL(string: "http://127.0.0.1:9197")!) {
        self.baseURL = baseURL
    }

    func setControlPort(_ port: Int) {
        setBaseURL(URL(string: "http://127.0.0.1:\(port)")!)
    }

    func setBaseURL(_ url: URL) {
        baseURLLock.sync {
            baseURL = url
        }
    }

    func setControlToken(_ token: String?) {
        baseURLLock.sync {
            controlToken = token?.trimmingCharacters(in: .whitespacesAndNewlines)
        }
    }

    func getVersion(timeoutInterval: TimeInterval? = nil) async throws -> SupercoreVersion {
        try await request(path: "/v1/version", timeoutInterval: timeoutInterval)
    }

    func getStatus() async throws -> SupercoreStatus {
        try await request(path: "/v1/status")
    }

    func getGroups() async throws -> [SupercoreProxyGroup] {
        let response: SupercoreGroupsResponse = try await request(path: "/v1/groups")
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
        let response: SupercoreCountriesResponse = try await request(path: "/v1/countries")
        return response.countries
    }

    func useCountry(code: String) async throws {
        let body = try JSONSerialization.data(withJSONObject: ["code": code])
        let response: SupercoreOKResponse = try await request(
            path: "/v1/countries/use",
            method: "POST",
            body: body
        )
        try response.throwIfNeeded()
    }

    func useOutbound(name: String) async throws {
        let body = try JSONSerialization.data(withJSONObject: ["name": name])
        let response: SupercoreOKResponse = try await request(
            path: "/v1/outbounds/use",
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
        let response: SupercoreProbeGroupResponse = try await requestTask(
            path: "/v1/probes/group",
            method: "POST",
            taskTimeout: ProbeTimeoutCalculator.requestTimeout(
                timeoutMilliseconds: timeoutMilliseconds,
                concurrency: concurrency,
                names: nil
            ),
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
        let response: SupercoreProbeResponse = try await requestTask(
            path: "/v1/probes",
            method: "POST",
            taskTimeout: requestTimeout,
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
        let response: SupercoreOKResponse = try await requestTask(
            path: "/v1/subscriptions/import",
            method: "POST",
            taskTimeout: 20,
            body: body
        )
        try response.throwIfNeeded()
    }

    func useSubscription(id: String) async throws {
        let body = try JSONSerialization.data(withJSONObject: ["id": id])
        let response: SupercoreOKResponse = try await request(
            path: "/v1/subscriptions/use",
            method: "POST",
            body: body
        )
        try response.throwIfNeeded()
    }

    func updateAllSubscriptions() async throws {
        let response: SupercoreOKResponse = try await requestTask(
            path: "/v1/subscriptions/update-all",
            method: "POST",
            taskTimeout: 300
        )
        try response.throwIfNeeded()
    }

    func updateSubscription(id: String) async throws -> SupercoreSubscriptionUpdateResponse {
        let body = try JSONSerialization.data(withJSONObject: ["id": id])
        return try await requestTask(
            path: "/v1/subscriptions/update",
            method: "POST",
            taskTimeout: 300,
            body: body
        )
    }

    func updateProviders(subscriptionID: String? = nil) async throws -> SupercoreProviderUpdateResponse {
        var payload: [String: Any] = [:]
        if let subscriptionID, !subscriptionID.isEmpty {
            payload["subscription_id"] = subscriptionID
        }
        let body = try JSONSerialization.data(withJSONObject: payload)
        return try await requestTask(
            path: "/v1/providers/update",
            method: "POST",
            taskTimeout: 300,
            body: body
        )
    }

    func updateAllProviders() async throws -> SupercoreProviderUpdateResponse {
        try await requestTask(
            path: "/v1/providers/update-all",
            method: "POST",
            taskTimeout: 300
        )
    }

    func updateGeoAssets() async throws -> SupercoreGeoUpdateResponse {
        try await requestTask(
            path: "/v1/geo/update",
            method: "POST",
            taskTimeout: 300
        )
    }

    func runDoctor() async throws -> SupercoreDoctorResponse {
        try await requestTask(
            path: "/v1/doctor/run",
            method: "POST",
            taskTimeout: 30
        )
    }

    func exportDiagnostics() async throws -> SupercoreDiagnosticExportResponse {
        try await requestTask(
            path: "/v1/diagnostics/export",
            method: "POST",
            taskTimeout: 30
        )
    }

    func reloadActiveSubscription() async throws {
        let response: SupercoreOKResponse = try await request(
            path: "/v1/subscriptions/reload-active",
            method: "POST"
        )
        try response.throwIfNeeded()
    }

    func reloadConfig(path: URL) async throws {
        let body = try JSONSerialization.data(withJSONObject: ["path": path.path])
        let response: SupercoreOKResponse = try await request(
            path: "/v1/config/reload",
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
        let response: SupercoreConnectionsResponse = try await request(path: "/v1/connections")
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
        try await getLogEvents().map { "[supercore:\($0.level)] \($0.message)" }
    }

    func getLogEvents() async throws -> [SupercoreLogEvent] {
        let response: SupercoreLogsResponse = try await request(path: "/v1/logs")
        return response.logs
    }

    func getSubscriptionTraffic() async throws -> [SupercoreSubscriptionTraffic] {
        let response: SupercoreSubscriptionTrafficResponse = try await request(path: "/v1/traffic/subscriptions")
        try response.throwIfNeeded()
        return response.subscriptions
    }

    func getSmartRules() async throws -> SupercoreSmartRulesSnapshot {
        try await request(path: "/v1/smart-rules")
    }

    func eventStream(lastEventID: String? = nil) -> AsyncThrowingStream<SupercoreControlEvent, Error> {
        let (baseURL, controlToken) = baseURLLock.sync {
            (self.baseURL, self.controlToken)
        }
        return AsyncThrowingStream { continuation in
            let streamTask = Task {
                do {
                    var request = URLRequest(url: baseURL.appendingPathComponent("/v1/events"))
                    request.setValue("text/event-stream", forHTTPHeaderField: "Accept")
                    request.setValue("no-cache", forHTTPHeaderField: "Cache-Control")
                    if let controlToken, !controlToken.isEmpty {
                        request.setValue("Bearer \(controlToken)", forHTTPHeaderField: "Authorization")
                    }
                    if let lastEventID, !lastEventID.isEmpty {
                        request.setValue(lastEventID, forHTTPHeaderField: "Last-Event-ID")
                    }
                    let (bytes, response) = try await URLSession.shared.bytes(for: request)
                    guard let http = response as? HTTPURLResponse else {
                        throw AppError.unexpectedResponse
                    }
                    guard (200..<300).contains(http.statusCode) else {
                        throw AppError.apiError(
                            http.statusCode,
                            HTTPURLResponse.localizedString(forStatusCode: http.statusCode)
                        )
                    }
                    continuation.yield(.connected)
                    var parser = SupercoreSSEParser()
                    for try await line in bytes.lines {
                        try Task.checkCancellation()
                        if let event = parser.consume(line: line) {
                            continuation.yield(event)
                        }
                    }
                    if let event = parser.finish() {
                        continuation.yield(event)
                    }
                    if !Task.isCancelled {
                        throw URLError(.networkConnectionLost)
                    }
                    continuation.finish()
                } catch is CancellationError {
                    continuation.finish()
                } catch {
                    continuation.finish(throwing: error)
                }
            }
            continuation.onTermination = { _ in
                streamTask.cancel()
            }
        }
    }

    func applySmartRecommendation(target: String, value: String) async throws {
        let body = try JSONSerialization.data(withJSONObject: ["target": target, "value": value])
        let response: SupercoreOKResponse = try await request(
            path: "/v1/smart-rules/apply-recommendation",
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
            path: "/v1/smart-rules/apply-recommendations",
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
        let (baseURL, controlToken) = baseURLLock.sync {
            (self.baseURL, self.controlToken)
        }
        var request = URLRequest(url: baseURL.appendingPathComponent(path))
        request.httpMethod = method
        if let controlToken, !controlToken.isEmpty {
            request.setValue("Bearer \(controlToken)", forHTTPHeaderField: "Authorization")
        }
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
            let decoder = Self.makeDecoder()
            if let apiError = try? decoder.decode(SupercoreAPIErrorEnvelope.self, from: data) {
                let trace = apiError.traceID.map { "，trace \($0)" } ?? ""
                throw AppError.apiError(
                    http.statusCode,
                    "\(apiError.message)（\(apiError.code)/\(apiError.kind)\(trace)）"
                )
            }
            throw AppError.apiError(
                http.statusCode,
                String(data: data, encoding: .utf8) ?? HTTPURLResponse.localizedString(forStatusCode: http.statusCode)
            )
        }
        return try Self.makeDecoder().decode(T.self, from: data)
    }

    private func requestTask<T: Decodable>(
        path: String,
        method: String,
        taskTimeout: TimeInterval,
        body: Data? = nil
    ) async throws -> T {
        let start: SupercoreTaskStart<T> = try await request(
            path: path,
            method: method,
            timeoutInterval: min(max(taskTimeout, 1), 10),
            body: body
        )
        switch start {
        case .completed(let result):
            return result
        case .accepted(let taskID):
            return try await waitForTask(taskID, timeout: taskTimeout)
        }
    }

    private func waitForTask<T: Decodable>(_ taskID: String, timeout: TimeInterval) async throws -> T {
        let deadline = Date().addingTimeInterval(max(timeout, 1))
        do {
            while Date() < deadline {
                try Task.checkCancellation()
                let snapshot: SupercoreTaskSnapshot<T> = try await request(
                    path: "/v1/tasks/\(taskID)",
                    timeoutInterval: min(max(deadline.timeIntervalSinceNow, 0.5), 3)
                )
                switch snapshot.status {
                case .queued, .running:
                    try await Task.sleep(nanoseconds: 100_000_000)
                case .succeeded:
                    guard let result = snapshot.result else {
                        throw AppError.processFailed("Supercore 任务 \(taskID) 完成但没有结果")
                    }
                    return result
                case .failed:
                    let failure = snapshot.error
                    let trace = failure?.traceID.map { "，trace \($0)" } ?? ""
                    throw AppError.processFailed(
                        "\(failure?.message ?? snapshot.message)（\(failure?.code ?? "task_failed")/\(failure?.kind ?? "internal")\(trace)）"
                    )
                case .cancelled:
                    throw CancellationError()
                }
            }
        } catch is CancellationError {
            await cancelTask(taskID)
            throw CancellationError()
        }
        await cancelTask(taskID)
        throw AppError.processFailed("Supercore 任务 \(taskID) 等待超时")
    }

    private func cancelTask(_ taskID: String) async {
        let client = self
        await Task.detached {
            let response: SupercoreOKResponse? = try? await client.request(
                path: "/v1/tasks/\(taskID)/cancel",
                method: "POST",
                timeoutInterval: 2
            )
            _ = response
        }.value
    }

    private static func makeDecoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }
}

struct SupercoreControlEvent: Sendable, Equatable {
    let id: String?
    let name: String
    let data: Data

    static let connected = SupercoreControlEvent(id: nil, name: "__connected", data: Data())

    func decode<T: Decodable>(_ type: T.Type) throws -> T {
        try JSONDecoder().decode(type, from: data)
    }
}

struct SupercoreTelemetryEnvelope<Payload: Decodable>: Decodable {
    let schemaVersion: Int
    let id: String
    let event: String
    let timestamp: String
    let data: Payload

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case id
        case event
        case timestamp
        case data
    }
}

struct SupercoreTaskEventEnvelope: Decodable {
    let schemaVersion: Int
    let id: String
    let event: String
    let timestamp: String
    let task: SupercoreTaskProgress

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case id
        case event
        case timestamp
        case task
    }
}

struct SupercoreTaskProgress: Decodable {
    let id: String
    let traceID: String?
    let kind: String
    let status: String
    let current: UInt64
    let total: UInt64?
    let message: String

    enum CodingKeys: String, CodingKey {
        case id
        case traceID = "trace_id"
        case kind
        case status
        case current
        case total
        case message
    }
}

struct SupercoreProbeProgressEvent: Decodable {
    let taskID: String
    let completed: UInt64
    let total: UInt64
    let node: String

    enum CodingKeys: String, CodingKey {
        case taskID = "task_id"
        case completed
        case total
        case node
    }
}

struct SupercoreTrafficEvent: Decodable {
    let uploadTotal: UInt64
    let downloadTotal: UInt64
    let uploadRate: UInt64
    let downloadRate: UInt64

    enum CodingKeys: String, CodingKey {
        case uploadTotal = "upload_total"
        case downloadTotal = "download_total"
        case uploadRate = "upload_rate"
        case downloadRate = "download_rate"
    }
}

struct SupercoreOutboundHealthEvent: Decodable {
    let name: String
    let attempts: UInt64
    let successes: UInt64
    let failures: UInt64
    let lastLatencyMs: UInt64?
    let lastError: String?

    enum CodingKeys: String, CodingKey {
        case name
        case attempts
        case successes
        case failures
        case lastLatencyMs = "last_latency_ms"
        case lastError = "last_error"
    }
}

struct SupercoreSSEParser {
    private var id: String?
    private var eventName = "message"
    private var dataLines: [String] = []

    mutating func consume(line: String) -> SupercoreControlEvent? {
        if line.isEmpty {
            return flush()
        }
        if line.hasPrefix(":") {
            return nil
        }
        let field: String
        var value = ""
        if let separator = line.firstIndex(of: ":") {
            field = String(line[..<separator])
            let valueStart = line.index(after: separator)
            value = String(line[valueStart...])
            if value.first == " " {
                value.removeFirst()
            }
        } else {
            field = line
        }
        switch field {
        case "id":
            if !value.contains("\0") {
                id = value
            }
        case "event":
            eventName = value.isEmpty ? "message" : value
        case "data":
            dataLines.append(value)
        default:
            break
        }
        return nil
    }

    mutating func finish() -> SupercoreControlEvent? {
        flush()
    }

    private mutating func flush() -> SupercoreControlEvent? {
        defer {
            eventName = "message"
            dataLines = []
        }
        guard !dataLines.isEmpty else { return nil }
        return SupercoreControlEvent(
            id: id,
            name: eventName,
            data: Data(dataLines.joined(separator: "\n").utf8)
        )
    }
}

private enum SupercoreTaskStart<Result: Decodable>: Decodable {
    case accepted(taskID: String)
    case completed(Result)

    private enum CodingKeys: String, CodingKey {
        case taskID = "task_id"
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        if let taskID = try container.decodeIfPresent(String.self, forKey: .taskID) {
            self = .accepted(taskID: taskID)
        } else {
            self = .completed(try Result(from: decoder))
        }
    }
}

private enum SupercoreTaskStatus: String, Decodable {
    case queued
    case running
    case succeeded
    case failed
    case cancelled
}

private struct SupercoreTaskSnapshot<Result: Decodable>: Decodable {
    let id: String
    let status: SupercoreTaskStatus
    let message: String
    let result: Result?
    let error: SupercoreTaskFailure?
}

private struct SupercoreTaskFailure: Decodable {
    let code: String
    let kind: String
    let message: String
    let retryable: Bool
    let traceID: String?

    enum CodingKeys: String, CodingKey {
        case code
        case kind
        case message
        case retryable
        case traceID = "trace_id"
    }
}

private struct SupercoreAPIErrorEnvelope: Decodable {
    let code: String
    let kind: String
    let message: String
    let retryable: Bool
    let traceID: String?

    enum CodingKeys: String, CodingKey {
        case code
        case kind
        case message
        case retryable
        case traceID = "trace_id"
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

struct SupercoreProviderUpdateResponse: Decodable, Sendable {
    let ok: Bool
    let partialFailure: Bool
    let results: [SupercoreProviderSubscriptionResult]
    let runtime: SupercoreRuntimeReload

    enum CodingKeys: String, CodingKey {
        case ok
        case partialFailure = "partial_failure"
        case results
        case runtime
    }
}

struct SupercoreProviderSubscriptionResult: Decodable, Sendable {
    let id: String
    let name: String
    let result: SupercoreProviderRefreshResult
}

struct SupercoreProviderRefreshResult: Decodable, Sendable {
    let committed: Bool
    let updated: Bool
    let providerCount: Int?
    let refreshedCount: Int?
    let fallbackCount: Int?
    let nodeCount: Int?
    let ruleCount: Int?
    let issues: [SupercoreProviderRefreshIssue]?
    let fatalError: String?

    enum CodingKeys: String, CodingKey {
        case committed
        case updated
        case providerCount = "provider_count"
        case refreshedCount = "refreshed_count"
        case fallbackCount = "fallback_count"
        case nodeCount = "node_count"
        case ruleCount = "rule_count"
        case issues
        case fatalError = "fatal_error"
    }
}

struct SupercoreProviderRefreshIssue: Decodable, Sendable {
    let providerType: String
    let name: String
    let message: String
    let usedFallback: Bool

    enum CodingKeys: String, CodingKey {
        case providerType = "provider_type"
        case name
        case message
        case usedFallback = "used_fallback"
    }
}

struct SupercoreRuntimeReload: Decodable, Sendable {
    let reloaded: Bool
    let summary: String?
}

struct SupercoreSubscriptionUpdateResponse: Decodable, Sendable {
    let ok: Bool
    let result: SupercoreSubscriptionUpdateResult
    let runtime: SupercoreRuntimeReload
}

struct SupercoreSubscriptionUpdateResult: Decodable, Sendable {
    let id: String
    let name: String
    let updated: Bool
    let error: String?
}

struct SupercoreGeoUpdateResponse: Decodable, Sendable {
    let ok: Bool
    let summaries: [SupercoreGeoUpdateSummary]
    let runtime: SupercoreRuntimeReload
}

struct SupercoreGeoUpdateSummary: Decodable, Sendable {
    let kind: String
    let source: String
    let path: String
    let updated: Bool
    let bytes: UInt64
    let error: String?
}

struct SupercoreDoctorResponse: Decodable, Sendable {
    let ok: Bool
    let report: SupercoreDoctorReport
}

struct SupercoreDoctorReport: Decodable, Sendable {
    let schemaVersion: Int
    let redacted: Bool
    let checks: [SupercoreDoctorCheck]

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case redacted
        case checks
    }
}

struct SupercoreDoctorCheck: Decodable, Sendable {
    let id: String
    let status: String
    let message: String
}

struct SupercoreDiagnosticExportResponse: Decodable, Sendable {
    let ok: Bool
    let export: SupercoreDiagnosticExport
}

struct SupercoreDiagnosticExport: Decodable, Sendable {
    let path: String
    let bytes: UInt64
    let sha256: String
    let redacted: Bool
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
