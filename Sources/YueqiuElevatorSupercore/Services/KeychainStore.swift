import Foundation

final class KeychainStore: @unchecked Sendable {
    private let service: String
    private let secretsURL: URL
    private let lock = NSLock()

    init(service: String) {
        self.service = service
        let root = FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("YueqiuElevator/state", isDirectory: true)
        self.secretsURL = root.appendingPathComponent("secrets-\(service).json")
    }

    func set(_ value: String, for account: String) throws {
        try locked {
            var secrets = try loadSecrets()
            secrets[account] = value
            try saveSecrets(secrets)
        }
    }

    func get(_ account: String) throws -> String? {
        try locked {
            try loadSecrets()[account]
        }
    }

    func delete(_ account: String) throws {
        try locked {
            var secrets = try loadSecrets()
            secrets.removeValue(forKey: account)
            try saveSecrets(secrets)
        }
    }

    private func loadSecrets() throws -> [String: String] {
        guard FileManager.default.fileExists(atPath: secretsURL.path) else {
            return [:]
        }
        let data = try Data(contentsOf: secretsURL)
        return try JSONDecoder().decode([String: String].self, from: data)
    }

    private func saveSecrets(_ secrets: [String: String]) throws {
        try FileManager.default.createDirectory(
            at: secretsURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        let data = try JSONEncoder().encode(secrets)
        try data.write(to: secretsURL, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: secretsURL.path)
    }

    private func locked<T>(_ work: () throws -> T) throws -> T {
        lock.lock()
        defer { lock.unlock() }
        return try work()
    }
}
