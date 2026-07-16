import Foundation

struct SystemProxySnapshot: Codable, Equatable, Sendable {
    var services: [ServiceProxySnapshot]
    var appHost: String
    var appPort: Int
    var createdAt: Date
}

struct ServiceProxySnapshot: Codable, Equatable, Sendable {
    var service: String
    var web: ProxySetting
    var secureWeb: ProxySetting
    var socks: ProxySetting
    var bypassDomains: [String]
}

struct ProxySetting: Codable, Equatable, Sendable {
    var enabled: Bool
    var server: String
    var port: Int
    var authenticated: Bool
}
