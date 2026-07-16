import CFNetwork
import Foundation

final class SubscriptionManager: @unchecked Sendable {
    private let paths: AppPaths
    private let keychain: KeychainStore
    private let configManager: ConfigManager

    init(paths: AppPaths, keychain: KeychainStore, configManager: ConfigManager) {
        self.paths = paths
        self.keychain = keychain
        self.configManager = configManager
    }

    func importSubscription(urlString: String, tunEnabled: Bool) async throws -> SubscriptionProfile {
        guard let url = URL(string: urlString), let scheme = url.scheme, scheme.hasPrefix("http") else {
            throw AppError.invalidSubscriptionURL
        }
        let payload = try await downloadSubscriptionPayload(from: url)
        let profileID = UUID().uuidString
        try configManager.saveOriginalYAML(payload.yaml, profileID: profileID)
        try configManager.regenerateSupercoreRuntime(profileID: profileID, tunEnabled: tunEnabled)
        try keychain.set(urlString, for: subscriptionURLAccount(profileID))

        let profile = SubscriptionProfile(
            id: profileID,
            name: makeProfileName(from: url, existing: loadProfiles()),
            maskedURL: URLMasker.mask(urlString),
            importedAt: Date(),
            updatedAt: Date(),
            selectedNodes: [:],
            lastStartedNode: nil,
            lastStartedAt: nil,
            planInfo: payload.planInfo
        )
        try saveProfileMetadata(profile)
        try saveIndex(loadIndex().appendingImportedProfile(profile))
        return profile
    }

    func updateSubscription(profileID: String, tunEnabled: Bool, timeout: TimeInterval = 30) async throws -> SubscriptionProfile {
        let existingProfile = try requireProfile(profileID)
        guard let urlString = try keychain.get(subscriptionURLAccount(profileID)) ?? fallbackSubscriptionURL(from: existingProfile) else {
            throw AppError.missingSubscription
        }
        guard let url = URL(string: urlString) else { throw AppError.invalidSubscriptionURL }
        try? keychain.set(urlString, for: subscriptionURLAccount(profileID))
        let payload = try await downloadSubscriptionPayload(from: url, timeout: timeout)
        try configManager.saveOriginalYAML(payload.yaml, profileID: profileID)
        try configManager.regenerateSupercoreRuntime(profileID: profileID, tunEnabled: tunEnabled)

        var profile = existingProfile
        profile.updatedAt = Date()
        profile.maskedURL = URLMasker.mask(urlString)
        profile.planInfo = payload.planInfo
        if profile.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            profile.name = url.host ?? "Subscription"
        }
        try upsertProfile(profile)
        return profile
    }

    func updateCurrentSubscription(tunEnabled: Bool) async throws -> SubscriptionProfile {
        guard let profileID = loadIndex().activeProfileID else {
            throw AppError.missingSubscription
        }
        return try await updateSubscription(profileID: profileID, tunEnabled: tunEnabled)
    }

    func loadProfiles() -> [SubscriptionProfile] {
        loadIndex().profiles
    }

    func loadActiveProfile() -> SubscriptionProfile? {
        let index = loadIndex()
        guard let id = index.activeProfileID else {
            return index.profiles.first
        }
        return index.profiles.first(where: { $0.id == id }) ?? index.profiles.first
    }

    func setActiveProfile(_ profileID: String) throws -> SubscriptionProfile {
        var index = loadIndex()
        guard let profile = index.profiles.first(where: { $0.id == profileID }) else {
            throw AppError.missingSubscription
        }
        index.activeProfileID = profileID
        try saveIndex(index)
        return profile
    }

    func loadProfileMetadata() -> SubscriptionProfile? {
        loadActiveProfile()
    }

    func saveSelectedNode(profileID: String, group: String, node: String) {
        guard var profile = loadProfiles().first(where: { $0.id == profileID }) else { return }
        profile.selectedNodes[group] = node
        try? upsertProfile(profile)
    }

    func saveLastStartedNode(profileID: String, node: String?) {
        guard var profile = loadProfiles().first(where: { $0.id == profileID }) else { return }
        let trimmed = node?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        profile.lastStartedNode = trimmed.isEmpty ? nil : trimmed
        profile.lastStartedAt = Date()
        try? upsertProfile(profile)
    }

    func saveSelectedNode(group: String, node: String) {
        guard let profileID = loadActiveProfile()?.id else { return }
        saveSelectedNode(profileID: profileID, group: group, node: node)
    }

    func loadOriginalYAML(profileID: String) throws -> String {
        try String(contentsOf: paths.originalProfile(id: profileID), encoding: .utf8)
    }

    func needsProviderPayloadCache(profileID: String) -> Bool {
        guard let yaml = try? loadOriginalYAML(profileID: profileID) else { return false }
        let providers = ProxyNodeParser.parseProviderURLs(from: yaml)
        guard !providers.isEmpty else { return false }
        return providers.keys.contains { provider in
            !FileManager.default.fileExists(atPath: paths.providerPayload(id: profileID, providerName: provider).path)
        }
    }

    func coreSubscriptionSourceURL(profileID: String) throws -> URL {
        try writeCoreSubscriptionSource(profileID: profileID)
    }

    func downloadProviderNodes(for profileID: String, timeout: TimeInterval = 30) async throws -> [ProxyNode] {
        let yaml = try loadOriginalYAML(profileID: profileID)
        let providers = ProxyNodeParser.parseProviderURLs(from: yaml)
        var nodes: [ProxyNode] = []
        for (name, url) in providers {
            let text = try await downloadText(from: url, timeout: timeout)
            try saveProviderPayload(text, profileID: profileID, providerName: name)
            nodes.append(contentsOf: ProxyNodeParser.parseNodes(from: text, source: name))
        }
        if nodes.isEmpty {
            nodes = ProxyNodeParser.parseNodes(from: yaml, source: "profile")
        }
        var seen = Set<String>()
        let uniqueNodes = nodes.filter { seen.insert($0.name).inserted }
        try saveCachedProviderNodes(uniqueNodes, profileID: profileID)
        _ = try writeCoreSubscriptionSource(profileID: profileID)
        return uniqueNodes
    }

    func loadCachedProviderNodes(profileID: String) -> [ProxyNode] {
        guard let data = try? Data(contentsOf: paths.providerNodesCache(id: profileID)) else {
            return []
        }
        return (try? JSONDecoder().decode([ProxyNode].self, from: data)) ?? []
    }

    private func loadIndex() -> ProfileIndex {
        migrateLegacyDefaultIfNeeded()
        guard let data = try? Data(contentsOf: paths.profilesIndex) else {
            return ProfileIndex(activeProfileID: nil, profiles: [])
        }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return (try? decoder.decode(ProfileIndex.self, from: data)) ?? ProfileIndex(activeProfileID: nil, profiles: [])
    }

    private func saveIndex(_ index: ProfileIndex) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        try encoder.encode(index).write(to: paths.profilesIndex, options: .atomic)
    }

    private func saveProfileMetadata(_ profile: SubscriptionProfile) throws {
        try paths.prepareProfileDirectory(id: profile.id)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        try encoder.encode(profile).write(to: paths.profileMetadata(id: profile.id), options: .atomic)
    }

    private func upsertProfile(_ profile: SubscriptionProfile) throws {
        try saveProfileMetadata(profile)
        var index = loadIndex()
        if let idx = index.profiles.firstIndex(where: { $0.id == profile.id }) {
            index.profiles[idx] = profile
        } else {
            index.profiles.append(profile)
        }
        if index.activeProfileID == nil {
            index.activeProfileID = profile.id
        }
        try saveIndex(index)
    }

    private func requireProfile(_ profileID: String) throws -> SubscriptionProfile {
        guard let profile = loadProfiles().first(where: { $0.id == profileID }) else {
            throw AppError.missingSubscription
        }
        return profile
    }

    private func fallbackSubscriptionURL(from profile: SubscriptionProfile) -> String? {
        let value = profile.maskedURL.trimmingCharacters(in: .whitespacesAndNewlines)
        guard value.hasPrefix("http"),
              !value.localizedCaseInsensitiveContains("redacted") else {
            return nil
        }
        return value
    }

    private func subscriptionURLAccount(_ profileID: String) -> String {
        "subscription-url-\(profileID)"
    }

    private func makeProfileName(from url: URL, existing: [SubscriptionProfile]) -> String {
        let base = url.host ?? "Subscription"
        if !existing.contains(where: { $0.name == base }) {
            return base
        }
        var number = 2
        while existing.contains(where: { $0.name == "\(base) \(number)" }) {
            number += 1
        }
        return "\(base) \(number)"
    }

    private func migrateLegacyDefaultIfNeeded() {
        guard !FileManager.default.fileExists(atPath: paths.profilesIndex.path),
              FileManager.default.fileExists(atPath: paths.profileMetadata.path) else {
            return
        }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        guard let data = try? Data(contentsOf: paths.profileMetadata),
              var profile = try? decoder.decode(SubscriptionProfile.self, from: data) else {
            return
        }
        profile = SubscriptionProfile(
            id: profile.id.isEmpty ? "default" : profile.id,
            name: profile.name,
            maskedURL: profile.maskedURL,
            importedAt: profile.importedAt,
            updatedAt: profile.updatedAt,
            selectedNodes: profile.selectedNodes,
            lastStartedNode: profile.lastStartedNode,
            lastStartedAt: profile.lastStartedAt,
            planInfo: profile.planInfo
        )
        try? saveIndex(ProfileIndex(activeProfileID: profile.id, profiles: [profile]))
    }

    private func saveCachedProviderNodes(_ nodes: [ProxyNode], profileID: String) throws {
        try paths.prepareProfileDirectory(id: profileID)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(nodes).write(to: paths.providerNodesCache(id: profileID), options: .atomic)
    }

    private func saveProviderPayload(_ text: String, profileID: String, providerName: String) throws {
        try paths.prepareProfileDirectory(id: profileID)
        try FileManager.default.createDirectory(
            at: paths.providerPayloadDirectory(id: profileID),
            withIntermediateDirectories: true
        )
        try text.write(
            to: paths.providerPayload(id: profileID, providerName: providerName),
            atomically: true,
            encoding: .utf8
        )
    }

    private func writeCoreSubscriptionSource(profileID: String) throws -> URL {
        let original = try loadOriginalYAML(profileID: profileID)
        let providers = ProxyNodeParser.parseProviderURLs(from: original)
        guard !providers.isEmpty else {
            return paths.originalProfile(id: profileID)
        }

        let cachedPayloads = providers.keys.reduce(into: [String: URL]()) { result, provider in
            let payload = paths.providerPayload(id: profileID, providerName: provider)
            if FileManager.default.fileExists(atPath: payload.path) {
                result[provider] = payload
            }
        }
        guard !cachedPayloads.isEmpty else {
            return paths.originalProfile(id: profileID)
        }

        let resolved = rewriteProxyProviderURLs(in: original, payloads: cachedPayloads)
        let output = paths.supercoreSubscriptionSource(id: profileID)
        try paths.prepareProfileDirectory(id: profileID)
        try resolved.write(to: output, atomically: true, encoding: .utf8)
        return output
    }

    private func rewriteProxyProviderURLs(in yaml: String, payloads: [String: URL]) -> String {
        let lines = yaml.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        var output: [String] = []
        var inProviders = false
        var currentProvider: String?
        var currentProviderHasPath = false
        var currentProviderPathLine: String?

        func flushProviderPathIfNeeded() {
            guard let pathLine = currentProviderPathLine, !currentProviderHasPath else { return }
            output.append(pathLine)
            currentProviderHasPath = true
        }

        for rawLine in lines {
            let lineWithoutComment = ProxyNodeParser.stripCommentPreservingQuotes(rawLine)
            let trimmed = lineWithoutComment.trimmingCharacters(in: .whitespacesAndNewlines)
            let indent = leadingWhitespaceCount(lineWithoutComment)

            if indent == 0 {
                if inProviders && trimmed != "proxy-providers:" {
                    flushProviderPathIfNeeded()
                    inProviders = false
                    currentProvider = nil
                    currentProviderHasPath = false
                    currentProviderPathLine = nil
                }
                if trimmed == "proxy-providers:" {
                    inProviders = true
                }
            }

            if inProviders, indent == 2, trimmed.hasSuffix(":") {
                flushProviderPathIfNeeded()
                currentProvider = String(trimmed.dropLast()).trimmingCharacters(in: .whitespaces)
                currentProviderHasPath = false
                if let payload = currentProvider.flatMap({ payloads[$0] }) {
                    currentProviderPathLine = "    path: \(quoteYAML(payload.path))"
                } else {
                    currentProviderPathLine = nil
                }
                output.append(rawLine)
                continue
            }

            if inProviders,
               currentProviderPathLine != nil,
               indent >= 4,
               trimmed.hasPrefix("url:") || trimmed.hasPrefix("path:") {
                flushProviderPathIfNeeded()
                continue
            }

            output.append(rawLine)
        }

        if inProviders {
            flushProviderPathIfNeeded()
        }
        return output.joined(separator: "\n")
    }

    private func downloadSubscriptionPayload(from url: URL, timeout: TimeInterval = 30) async throws -> SubscriptionDownloadPayload {
        let response = try await downloadTextResponse(from: url, timeout: timeout)
        return SubscriptionDownloadPayload(
            yaml: URISubscriptionConverter.convertIfNeeded(response.text) ?? response.text,
            planInfo: SubscriptionInfoParser.parse(text: response.text, headers: response.headers)
        )
    }

    private func downloadText(from url: URL, timeout: TimeInterval = 30) async throws -> String {
        try await downloadTextResponse(from: url, timeout: timeout).text
    }

    private func downloadTextResponse(from url: URL, timeout: TimeInterval = 30) async throws -> SubscriptionTextResponse {
        var request = URLRequest(url: url, timeoutInterval: timeout)
        request.setValue("YueqiuElevatorSupercore/0.1", forHTTPHeaderField: "User-Agent")
        let session = directURLSession(timeout: timeout)
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw AppError.unexpectedResponse
        }
        if !(200..<300).contains(http.statusCode) {
            throw AppError.apiError(http.statusCode, HTTPURLResponse.localizedString(forStatusCode: http.statusCode))
        }
        guard let text = String(data: data, encoding: .utf8) else {
            throw AppError.invalidYAML
        }
        return SubscriptionTextResponse(text: text, headers: http.allHeaderFields)
    }

    private func directURLSession(timeout: TimeInterval) -> URLSession {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = timeout
        configuration.timeoutIntervalForResource = timeout
        configuration.waitsForConnectivity = true
        configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        configuration.connectionProxyDictionary = [
            kCFNetworkProxiesHTTPEnable as String: false,
            kCFNetworkProxiesHTTPSEnable as String: false,
            kCFNetworkProxiesSOCKSEnable as String: false
        ]
        return URLSession(configuration: configuration)
    }

    private func leadingWhitespaceCount(_ line: String) -> Int {
        line.prefix { $0 == " " || $0 == "\t" }.count
    }

    private func quoteYAML(_ value: String) -> String {
        let escaped = value
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        return "\"\(escaped)\""
    }
}

private struct SubscriptionDownloadPayload {
    let yaml: String
    let planInfo: SubscriptionPlanInfo?
}

private struct SubscriptionTextResponse {
    let text: String
    let headers: [AnyHashable: Any]
}
