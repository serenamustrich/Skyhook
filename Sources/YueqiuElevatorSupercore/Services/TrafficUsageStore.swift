import Foundation

final class TrafficUsageStore: @unchecked Sendable {
    private let paths: AppPaths

    init(paths: AppPaths) {
        self.paths = paths
    }

    func load(profileID: String) -> ProfileTrafficUsage {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        guard let data = try? Data(contentsOf: paths.trafficUsage(id: profileID)),
              let usage = try? decoder.decode(ProfileTrafficUsage.self, from: data) else {
            return .zero
        }
        return usage
    }

    func save(_ usage: ProfileTrafficUsage, profileID: String) throws {
        try paths.prepareProfileDirectory(id: profileID)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        try encoder.encode(usage).write(to: paths.trafficUsage(id: profileID), options: .atomic)
    }
}
