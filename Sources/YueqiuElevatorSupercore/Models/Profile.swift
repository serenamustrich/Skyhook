import Foundation

struct SubscriptionProfile: Codable, Equatable, Sendable {
    let id: String
    var name: String
    var maskedURL: String
    var importedAt: Date
    var updatedAt: Date
    var selectedNodes: [String: String]
    var lastStartedNode: String? = nil
    var lastStartedAt: Date? = nil
    var planInfo: SubscriptionPlanInfo?
}

struct SubscriptionPlanInfo: Codable, Equatable, Sendable {
    var remainingTraffic: String?
    var usedTraffic: String?
    var totalTraffic: String?
    var resetInfo: String?
    var expiresAtText: String?
    var homepage: String?

    var hasContent: Bool {
        remainingTraffic != nil ||
            usedTraffic != nil ||
            totalTraffic != nil ||
            resetInfo != nil ||
            expiresAtText != nil ||
            homepage != nil
    }
}

struct ProfileIndex: Codable, Equatable, Sendable {
    var activeProfileID: String?
    var profiles: [SubscriptionProfile]

    func appendingImportedProfile(_ profile: SubscriptionProfile) -> ProfileIndex {
        var copy = self
        let shouldActivateImportedProfile = copy.activeProfileID == nil && copy.profiles.isEmpty
        copy.profiles.append(profile)
        if shouldActivateImportedProfile {
            copy.activeProfileID = profile.id
        }
        return copy
    }
}

struct RuntimeOptions: Codable, Equatable, Sendable {
    var mixedPort = 7890
    var controllerPort = 9090
    var tunEnabled = true
    var dnsStrategy = TunDNSStrategy.direct
    var dnsServer = "223.5.5.5"
}

enum TunDNSStrategy: String, CaseIterable, Codable, Identifiable, Sendable {
    case virtual
    case overTcp = "over-tcp"
    case direct

    var id: String { rawValue }

    var title: String {
        switch self {
        case .virtual: "Fake-IP 虚拟 DNS（高级）"
        case .overTcp: "核心 DNS over TCP"
        case .direct: "系统 DNS（推荐）"
        }
    }
}
