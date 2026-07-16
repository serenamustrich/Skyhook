import Foundation

struct ProxiesResponse: Decodable, Sendable {
    let proxies: [String: ProxyItem]
}

struct ProxyItem: Decodable, Sendable {
    let name: String?
    let type: String
    let now: String?
    let all: [String]?
    let history: [DelayHistory]?
}

struct DelayHistory: Decodable, Sendable {
    let time: String?
    let delay: Int?
}

struct ProxyGroup: Identifiable, Equatable, Sendable {
    let name: String
    let type: String
    let now: String?
    let all: [String]
    var includeAll: Bool = false
    var filter: String?
    var useProviders: [String] = []

    var id: String { name }
}

struct CurrentNodeStatus: Equatable, Sendable {
    let name: String?
    let delay: Int?
    let failureKind: String?

    var nodeTitle: String {
        name ?? "未选择节点"
    }

    var delayTitle: String {
        DelayPolicy.displayTitle(for: delay, failureKind: failureKind)
    }

    var summary: String {
        "\(nodeTitle) · \(delayTitle)"
    }
}

enum ActiveProxyResolver {
    static func concreteNodeName(in groups: [ProxyGroup], mode: ProxyMode) -> String? {
        if mode == .direct {
            return "DIRECT"
        }
        guard !groups.isEmpty else { return nil }
        let groupsByName = Dictionary(uniqueKeysWithValues: groups.map { ($0.name, $0) })
        let roots = rootCandidates(in: groups, mode: mode)
        for root in roots {
            if let now = root.now,
               let resolved = resolve(now, groupsByName: groupsByName, visited: []) {
                return resolved
            }
        }
        for group in groups {
            if let now = group.now,
               let resolved = resolve(now, groupsByName: groupsByName, visited: []) {
                return resolved
            }
        }
        return nil
    }

    private static func rootCandidates(in groups: [ProxyGroup], mode: ProxyMode) -> [ProxyGroup] {
        var candidates: [ProxyGroup] = []
        func appendFirst(where predicate: (ProxyGroup) -> Bool) {
            guard let group = groups.first(where: predicate), !candidates.contains(where: { $0.name == group.name }) else {
                return
            }
            candidates.append(group)
        }

        if mode == .global {
            appendFirst { $0.name.caseInsensitiveCompare("GLOBAL") == .orderedSame }
        }
        appendFirst { $0.name.contains("节点选择") }
        appendFirst { $0.name.localizedCaseInsensitiveContains("proxy") }
        appendFirst { $0.name.contains("代理") }
        if let first = groups.first, !candidates.contains(where: { $0.name == first.name }) {
            candidates.append(first)
        }
        return candidates
    }

    private static func resolve(
        _ name: String,
        groupsByName: [String: ProxyGroup],
        visited: Set<String>
    ) -> String? {
        guard !name.isEmpty else { return nil }
        if name == "DIRECT" || name == "REJECT" {
            return name
        }
        guard let group = groupsByName[name] else {
            return name
        }
        guard !visited.contains(name) else {
            return nil
        }
        guard let now = group.now, !now.isEmpty else {
            return nil
        }
        var nextVisited = visited
        nextVisited.insert(name)
        return resolve(now, groupsByName: groupsByName, visited: nextVisited)
    }
}

struct TrafficFrame: Codable, Equatable, Sendable {
    let up: Int
    let down: Int
    let upTotal: Int?
    let downTotal: Int?

    init(up: Int, down: Int, upTotal: Int? = nil, downTotal: Int? = nil) {
        self.up = up
        self.down = down
        self.upTotal = upTotal
        self.downTotal = downTotal
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        up = try container.decodeIfPresent(Int.self, forKey: .up)
            ?? container.decodeIfPresent(Int.self, forKey: .upload)
            ?? 0
        down = try container.decodeIfPresent(Int.self, forKey: .down)
            ?? container.decodeIfPresent(Int.self, forKey: .download)
            ?? 0
        upTotal = try container.decodeIfPresent(Int.self, forKey: .upTotal)
            ?? container.decodeIfPresent(Int.self, forKey: .uploadTotal)
        downTotal = try container.decodeIfPresent(Int.self, forKey: .downTotal)
            ?? container.decodeIfPresent(Int.self, forKey: .downloadTotal)
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(up, forKey: .up)
        try container.encode(down, forKey: .down)
        try container.encodeIfPresent(upTotal, forKey: .upTotal)
        try container.encodeIfPresent(downTotal, forKey: .downTotal)
    }

    var title: String {
        "↑ \(ByteFormatter.rate(up))  ↓ \(ByteFormatter.rate(down))"
    }

    private enum CodingKeys: String, CodingKey {
        case up
        case down
        case upload
        case download
        case upTotal
        case downTotal
        case uploadTotal
        case downloadTotal
    }
}

struct ConnectionTrafficSnapshot: Equatable, Sendable {
    let upTotal: Int
    let downTotal: Int
}

struct TrafficTotals: Equatable, Sendable {
    let up: Int
    let down: Int

    static let zero = TrafficTotals(up: 0, down: 0)

    var title: String {
        "↑ \(ByteFormatter.bytes(up))  ↓ \(ByteFormatter.bytes(down))"
    }
}

struct ProfileTrafficUsage: Codable, Equatable, Sendable {
    var up: Int
    var down: Int
    var lastRuntimeUp: Int
    var lastRuntimeDown: Int
    var updatedAt: Date?

    static let zero = ProfileTrafficUsage(
        up: 0,
        down: 0,
        lastRuntimeUp: 0,
        lastRuntimeDown: 0,
        updatedAt: nil
    )

    var totals: TrafficTotals {
        TrafficTotals(up: up, down: down)
    }

    @discardableResult
    mutating func record(snapshot: ConnectionTrafficSnapshot, at date: Date = Date()) -> TrafficTotals {
        let upDelta = max(0, snapshot.upTotal - lastRuntimeUp)
        let downDelta = max(0, snapshot.downTotal - lastRuntimeDown)
        if upDelta > 0 || downDelta > 0 {
            up += upDelta
            down += downDelta
        }
        lastRuntimeUp = max(0, snapshot.upTotal)
        lastRuntimeDown = max(0, snapshot.downTotal)
        updatedAt = date
        return totals
    }

    mutating func resetRuntimeBaseline(at date: Date = Date()) {
        lastRuntimeUp = 0
        lastRuntimeDown = 0
        updatedAt = date
    }
}

struct ProxyNode: Identifiable, Equatable, Codable, Sendable {
    let name: String
    let source: String
    let country: String

    var id: String { "\(source)#\(name)" }
}

struct CountryNodeGroup: Identifiable, Equatable, Sendable {
    let country: String
    let nodes: [ProxyNode]
    let selectedNode: String?
    let bestDelay: Int?

    var id: String { country }
}
