import Darwin
import Foundation
import Network

enum SmartRuleEndpointClassifier {
    static func classify(host: String) -> (target: CustomRuleTarget, value: String, endpointHost: String)? {
        guard let endpointHost = canonicalHost(host) else { return nil }
        if isIPv4(endpointHost) {
            guard !isPrivateIPv4(endpointHost) else { return nil }
            return (.ipCIDR, "\(endpointHost)/32", endpointHost)
        }
        if isIPv6(endpointHost) {
            guard !isPrivateIPv6(endpointHost) else { return nil }
            return (.ipCIDR6, "\(endpointHost)/128", endpointHost)
        }
        guard endpointHost.contains("."),
              !endpointHost.hasSuffix(".local"),
              endpointHost != "localhost" else {
            return nil
        }
        return (.domain, endpointHost, endpointHost)
    }

    private static func canonicalHost(_ value: String) -> String? {
        var host = value.trimmingCharacters(in: .whitespacesAndNewlines)
        if host.hasPrefix("["), let closing = host.firstIndex(of: "]") {
            host = String(host[host.index(after: host.startIndex)..<closing])
        }
        if let zoneIndex = host.firstIndex(of: "%") {
            host = String(host[..<zoneIndex])
        }
        host = host.trimmingCharacters(in: CharacterSet(charactersIn: ".")).lowercased()
        guard !host.isEmpty,
              host.count <= 253,
              !host.contains(","),
              !host.contains("\n"),
              !host.contains(" ") else {
            return nil
        }
        return host
    }

    private static func isIPv4(_ value: String) -> Bool {
        var addr = in_addr()
        return value.withCString { inet_pton(AF_INET, $0, &addr) == 1 }
    }

    private static func isIPv6(_ value: String) -> Bool {
        var addr = in6_addr()
        return value.withCString { inet_pton(AF_INET6, $0, &addr) == 1 }
    }

    private static func isPrivateIPv4(_ value: String) -> Bool {
        let parts = value.split(separator: ".").compactMap { Int($0) }
        guard parts.count == 4 else { return true }
        let first = parts[0]
        let second = parts[1]
        if first == 0 || first == 10 || first == 127 { return true }
        if first == 100, (64...127).contains(second) { return true }
        if first == 169, second == 254 { return true }
        if first == 172, (16...31).contains(second) { return true }
        if first == 192, second == 168 { return true }
        if first == 198, second == 18 || second == 19 { return true }
        if first >= 224 { return true }
        return false
    }

    private static func isPrivateIPv6(_ value: String) -> Bool {
        value == "::1" ||
            value.hasPrefix("fe80:") ||
            value.hasPrefix("fc") ||
            value.hasPrefix("fd")
    }
}

enum SmartRuleDirectProbe {
    static func canConnect(host: String, port: Int?, timeout: TimeInterval = 1.2) async -> Bool {
        let boundedPort = UInt16(max(1, min(port ?? 443, 65_535)))
        guard let endpointPort = NWEndpoint.Port(rawValue: boundedPort) else { return false }
        return await withCheckedContinuation { continuation in
            let box = SmartRuleProbeBox(continuation: continuation)
            let connection = NWConnection(host: NWEndpoint.Host(host), port: endpointPort, using: .tcp)
            let queue = DispatchQueue(label: "YueqiuElevatorSupercore.smart-rule-probe.\(UUID().uuidString)")
            box.connection = connection
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    box.finish(true)
                case .failed, .cancelled:
                    box.finish(false)
                default:
                    break
                }
            }
            connection.start(queue: queue)
            queue.asyncAfter(deadline: .now() + timeout) {
                box.finish(false)
            }
        }
    }
}

private final class SmartRuleProbeBox: @unchecked Sendable {
    let continuation: CheckedContinuation<Bool, Never>
    let lock = NSLock()
    var connection: NWConnection?
    var didResume = false

    init(continuation: CheckedContinuation<Bool, Never>) {
        self.continuation = continuation
    }

    func finish(_ result: Bool) {
        lock.lock()
        guard !didResume else {
            lock.unlock()
            return
        }
        didResume = true
        let connection = connection
        self.connection = nil
        lock.unlock()
        connection?.cancel()
        continuation.resume(returning: result)
    }
}
