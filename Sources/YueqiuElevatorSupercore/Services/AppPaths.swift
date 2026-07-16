import Foundation

struct AppPaths: Sendable {
    let root: URL
    let cores: URL
    let profiles: URL
    let state: URL
    let logs: URL

    init(fileManager: FileManager = .default, root overrideRoot: URL? = nil) {
        let support = fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        root = overrideRoot ?? support.appendingPathComponent("YueqiuElevator", isDirectory: true)
        cores = root.appendingPathComponent("cores", isDirectory: true)
        profiles = root.appendingPathComponent("profiles", isDirectory: true)
        state = root.appendingPathComponent("state", isDirectory: true)
        let logRoot = fileManager.urls(for: .libraryDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Logs/YueqiuElevator", isDirectory: true)
        logs = logRoot
    }

    var supercoreBinary: URL { cores.appendingPathComponent("supercore") }
    var supercoreSubscriptionStore: URL { state.appendingPathComponent("supercore-subscriptions", isDirectory: true) }
    var supercoreDaemonRuntimeProfile: URL { state.appendingPathComponent("supercore-daemon-runtime.yaml") }
    var profilesIndex: URL { profiles.appendingPathComponent("index.json") }
    var originalProfile: URL { originalProfile(id: "default") }
    var profileMetadata: URL { profileMetadata(id: "default") }
    var proxySnapshot: URL { state.appendingPathComponent("proxy-snapshot.json") }
    var coreLog: URL { logs.appendingPathComponent("core.log") }

    func profileDirectory(id: String) -> URL {
        profiles.appendingPathComponent(safeProfileID(id), isDirectory: true)
    }

    func originalProfile(id: String) -> URL {
        profileDirectory(id: id).appendingPathComponent("original.yaml")
    }

    func supercoreRuntimeProfile(id: String) -> URL {
        profileDirectory(id: id).appendingPathComponent("supercore-runtime.yaml")
    }

    func supercoreSubscriptionSource(id: String) -> URL {
        profileDirectory(id: id).appendingPathComponent("supercore-subscription-source.yaml")
    }

    func profileMetadata(id: String) -> URL {
        profileDirectory(id: id).appendingPathComponent("meta.json")
    }

    func providerNodesCache(id: String) -> URL {
        profileDirectory(id: id).appendingPathComponent("provider-nodes.json")
    }

    func providerPayloadDirectory(id: String) -> URL {
        profileDirectory(id: id).appendingPathComponent("provider-payloads", isDirectory: true)
    }

    func providerPayload(id: String, providerName: String) -> URL {
        providerPayloadDirectory(id: id).appendingPathComponent("\(safePathComponent(providerName)).txt")
    }

    func trafficUsage(id: String) -> URL {
        profileDirectory(id: id).appendingPathComponent("traffic-usage.json")
    }

    func customRules(id: String) -> URL {
        profileDirectory(id: id).appendingPathComponent("custom-rules.json")
    }

    func smartRules(id: String) -> URL {
        profileDirectory(id: id).appendingPathComponent("smart-rules.json")
    }

    func supercoreSmartState(id: String) -> URL {
        profileDirectory(id: id).appendingPathComponent("supercore-smart-state.json")
    }

    func prepareProfileDirectory(id: String) throws {
        try FileManager.default.createDirectory(at: profileDirectory(id: id), withIntermediateDirectories: true)
    }

    func prepareDirectories() throws {
        for url in [root, cores, profiles, state, logs] {
            try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        }
    }

    private func safeProfileID(_ id: String) -> String {
        id.replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: ":", with: "_")
    }

    private func safePathComponent(_ value: String) -> String {
        let safe = value.map { character -> Character in
            if character.isLetter || character.isNumber || character == "-" || character == "_" {
                return character
            }
            return "_"
        }
        let name = String(safe).trimmingCharacters(in: CharacterSet(charactersIn: "_"))
        return name.isEmpty ? "provider" : name
    }
}
