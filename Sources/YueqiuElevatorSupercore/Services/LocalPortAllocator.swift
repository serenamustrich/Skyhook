import Darwin
import Foundation

enum LocalPortAllocator {
    static func availablePort(preferred: Int, fallbackRange: ClosedRange<Int> = 7890...7999) throws -> Int {
        let candidates = [preferred] + fallbackRange.filter { $0 != preferred }
        for port in candidates where isLocalTCPPortAvailable(port) {
            return port
        }
        throw AppError.processFailed("没有可用的本地代理端口")
    }

    static func waitUntilLocalPortAcceptsConnections(_ port: Int, timeout: TimeInterval = 4) async throws {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if canConnectToLocalTCPPort(port) {
                return
            }
            try? await Task.sleep(nanoseconds: 100_000_000)
        }
        throw AppError.processFailed("Supercore 已启动，但代理端口 \(port) 未监听")
    }

    static func isLocalTCPPortAvailable(_ port: Int) -> Bool {
        guard (1...65_535).contains(port) else { return false }
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return false }
        defer { close(fd) }

        var address = localAddress(port: port)
        let bindResult = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
                Darwin.bind(fd, sockaddrPointer, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindResult == 0 else { return false }
        return Darwin.listen(fd, 1) == 0
    }

    private static func canConnectToLocalTCPPort(_ port: Int) -> Bool {
        guard (1...65_535).contains(port) else { return false }
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return false }
        defer { close(fd) }

        var address = localAddress(port: port)
        let result = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
                Darwin.connect(fd, sockaddrPointer, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        return result == 0
    }

    private static func localAddress(port: Int) -> sockaddr_in {
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = in_port_t(port).bigEndian
        address.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
        return address
    }
}
