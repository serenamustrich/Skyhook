import Foundation

final class SystemProxyManager: @unchecked Sendable {
    private let paths: AppPaths
    private let networksetup = URL(fileURLWithPath: "/usr/sbin/networksetup")

    init(paths: AppPaths) {
        self.paths = paths
    }

    var hasSavedSnapshot: Bool {
        FileManager.default.fileExists(atPath: paths.proxySnapshot.path)
    }

    func isSystemProxyPointingTo(port: Int) -> Bool {
        do {
            let services = try activeServices()
            guard let service = services.first else { return false }
            let web = try getProxy(kind: .web, service: service)
            let secure = try getProxy(kind: .secureWeb, service: service)
            let socks = try getProxy(kind: .socks, service: service)
            return (web.enabled && web.port == port) ||
                   (secure.enabled && secure.port == port) ||
                   (socks.enabled && socks.port == port)
        } catch {
            return false
        }
    }

    func enableSystemProxy(host: String = "127.0.0.1", port: Int = 7890) throws {
        let services = try activeServices()
        let snapshot = try SystemProxySnapshot(
            services: services.map { service in
                ServiceProxySnapshot(
                    service: service,
                    web: try getProxy(kind: .web, service: service),
                    secureWeb: try getProxy(kind: .secureWeb, service: service),
                    socks: try getProxy(kind: .socks, service: service),
                    bypassDomains: try getBypassDomains(service: service)
                )
            },
            appHost: host,
            appPort: port,
            createdAt: Date()
        )
        try saveSnapshot(snapshot)
        for service in services {
            try run(["-setwebproxy", service, host, "\(port)", "off"])
            try run(["-setsecurewebproxy", service, host, "\(port)", "off"])
            try run(["-setsocksfirewallproxy", service, host, "\(port)", "off"])
            try run(["-setwebproxystate", service, "on"])
            try run(["-setsecurewebproxystate", service, "on"])
            try run(["-setsocksfirewallproxystate", service, "on"])
            try run(["-setproxybypassdomains", service, "localhost", "127.0.0.1", "::1"])
        }
    }

    func restoreIfOwned() throws {
        let snapshot = try loadSnapshot()
        for item in snapshot.services {
            let currentWeb = try getProxy(kind: .web, service: item.service)
            let currentSecure = try getProxy(kind: .secureWeb, service: item.service)
            let currentSocks = try getProxy(kind: .socks, service: item.service)
            guard isOwned(currentWeb, snapshot: snapshot),
                  isOwned(currentSecure, snapshot: snapshot),
                  isOwned(currentSocks, snapshot: snapshot) else {
                continue
            }
            try restore(kind: .web, service: item.service, setting: item.web)
            try restore(kind: .secureWeb, service: item.service, setting: item.secureWeb)
            try restore(kind: .socks, service: item.service, setting: item.socks)
            if item.bypassDomains.isEmpty {
                try run(["-setproxybypassdomains", item.service, "Empty"])
            } else {
                try run(["-setproxybypassdomains", item.service] + item.bypassDomains)
            }
        }
        try? FileManager.default.removeItem(at: paths.proxySnapshot)
    }

    private func activeServices() throws -> [String] {
        let output = try run(["-listallnetworkservices"])
        let services = output.split(separator: "\n").map(String.init)
            .filter { !$0.hasPrefix("An asterisk") && !$0.hasPrefix("*") }
        if services.contains("Wi-Fi") { return ["Wi-Fi"] }
        return Array(services.prefix(1))
    }

    private func getProxy(kind: ProxyKind, service: String) throws -> ProxySetting {
        let output = try run([kind.getCommand, service])
        var enabled = false
        var server = ""
        var port = 0
        var authenticated = false
        for line in output.split(separator: "\n").map(String.init) {
            let parts = line.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            guard parts.count == 2 else { continue }
            switch parts[0] {
            case "Enabled": enabled = parts[1].lowercased() == "yes"
            case "Server": server = parts[1]
            case "Port": port = Int(parts[1]) ?? 0
            case "Authenticated Proxy Enabled": authenticated = parts[1].lowercased() == "yes"
            default: break
            }
        }
        return ProxySetting(enabled: enabled, server: server, port: port, authenticated: authenticated)
    }

    private func getBypassDomains(service: String) throws -> [String] {
        let output = try run(["-getproxybypassdomains", service])
        if output.contains("There aren't any bypass domains") { return [] }
        return output.split(separator: "\n").map(String.init).filter { !$0.isEmpty }
    }

    private func restore(kind: ProxyKind, service: String, setting: ProxySetting) throws {
        try run([kind.setCommand, service, setting.server.isEmpty ? "127.0.0.1" : setting.server, "\(setting.port)", "off"])
        try run([kind.stateCommand, service, setting.enabled ? "on" : "off"])
    }

    private func isOwned(_ setting: ProxySetting, snapshot: SystemProxySnapshot) -> Bool {
        setting.enabled && setting.server == snapshot.appHost && setting.port == snapshot.appPort
    }

    private func saveSnapshot(_ snapshot: SystemProxySnapshot) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        try encoder.encode(snapshot).write(to: paths.proxySnapshot, options: .atomic)
    }

    private func loadSnapshot() throws -> SystemProxySnapshot {
        let data = try Data(contentsOf: paths.proxySnapshot)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode(SystemProxySnapshot.self, from: data)
    }

    @discardableResult
    private func run(_ arguments: [String]) throws -> String {
        let process = Process()
        process.executableURL = networksetup
        process.arguments = arguments
        let output = Pipe()
        let error = Pipe()
        process.standardOutput = output
        process.standardError = error
        try process.run()
        let stdout = String(data: output.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        let stderr = String(data: error.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw AppError.processFailed(stderr.isEmpty ? stdout : stderr)
        }
        return stdout
    }
}

private enum ProxyKind {
    case web
    case secureWeb
    case socks

    var getCommand: String {
        switch self {
        case .web: "-getwebproxy"
        case .secureWeb: "-getsecurewebproxy"
        case .socks: "-getsocksfirewallproxy"
        }
    }

    var setCommand: String {
        switch self {
        case .web: "-setwebproxy"
        case .secureWeb: "-setsecurewebproxy"
        case .socks: "-setsocksfirewallproxy"
        }
    }

    var stateCommand: String {
        switch self {
        case .web: "-setwebproxystate"
        case .secureWeb: "-setsecurewebproxystate"
        case .socks: "-setsocksfirewallproxystate"
        }
    }
}
