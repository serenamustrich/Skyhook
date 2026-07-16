import Foundation

final class SmartRuleStore: @unchecked Sendable {
    private let paths: AppPaths

    init(paths: AppPaths) {
        self.paths = paths
    }

    func load(profileID: String) -> [SmartRuleCandidate] {
        guard let data = try? Data(contentsOf: paths.smartRules(id: profileID)) else {
            return []
        }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return (try? decoder.decode([SmartRuleCandidate].self, from: data)) ?? []
    }

    func save(_ candidates: [SmartRuleCandidate], profileID: String) throws {
        try paths.prepareProfileDirectory(id: profileID)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        try encoder.encode(candidates).write(to: paths.smartRules(id: profileID), options: .atomic)
    }
}
