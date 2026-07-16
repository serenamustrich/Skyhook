import Foundation

enum URISubscriptionConverter {
    static func convertIfNeeded(_ text: String) -> String? {
        let decoded = decodeBase64(text) ?? text
        let proxies = decoded
            .split(whereSeparator: \.isNewline)
            .map(String.init)
            .compactMap(parseSSProxy)
            .filter { !isMetadataNode($0.name) }
            .deduplicatedByName()
        guard !proxies.isEmpty else { return nil }
        return makeYAML(from: proxies)
    }

    private static func parseSSProxy(_ line: String) -> SSProxy? {
        let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.hasPrefix("ss://"), let components = URLComponents(string: trimmed) else {
            return nil
        }
        let name = cleanName(components.percentEncodedFragment?.removingPercentEncoding ?? components.fragment ?? "")
        guard let host = components.host, let port = components.port else { return nil }

        let credentials: String
        if let user = components.percentEncodedUser?.removingPercentEncoding ?? components.user {
            credentials = decodeBase64(user) ?? user
        } else {
            let withoutScheme = String(trimmed.dropFirst("ss://".count))
            let encodedPart = withoutScheme.split(separator: "#", maxSplits: 1).first?
                .split(separator: "?", maxSplits: 1).first
                .map(String.init) ?? ""
            credentials = decodeBase64(encodedPart) ?? ""
        }
        guard let separator = credentials.firstIndex(of: ":") else { return nil }
        let cipher = String(credentials[..<separator])
        let password = String(credentials[credentials.index(after: separator)...])
        guard !name.isEmpty, !cipher.isEmpty, !password.isEmpty else { return nil }

        let plugin = components.queryItems?.first(where: { $0.name == "plugin" })?.value
        let pluginOptions = parsePluginOptions(plugin)
        return SSProxy(
            name: name,
            server: host,
            port: port,
            cipher: cipher,
            password: password,
            obfsMode: pluginOptions.mode,
            obfsHost: pluginOptions.host
        )
    }

    private static func makeYAML(from proxies: [SSProxy]) -> String {
        let proxyYAML = proxies.map { proxy in
            var lines = [
                "  - name: \(yamlQuoted(proxy.name))",
                "    type: ss",
                "    server: \(yamlQuoted(proxy.server))",
                "    port: \(proxy.port)",
                "    cipher: \(yamlQuoted(proxy.cipher))",
                "    password: \(yamlQuoted(proxy.password))",
                "    udp: true"
            ]
            if let mode = proxy.obfsMode {
                lines.append("    plugin: obfs")
                lines.append("    plugin-opts:")
                lines.append("      mode: \(yamlQuoted(mode))")
                if let host = proxy.obfsHost {
                    lines.append("      host: \(yamlQuoted(host))")
                }
            }
            return lines.joined(separator: "\n")
        }.joined(separator: "\n")

        let nodeList = proxies.map { "      - \(yamlQuoted($0.name))" }.joined(separator: "\n")
        return """
        proxies:
        \(proxyYAML)

        proxy-groups:
          - name: 节点选择
            type: select
            proxies:
        \(nodeList)
          - name: 自动选择
            type: url-test
            proxies:
        \(nodeList)
            url: https://www.gstatic.com/generate_204
            interval: 300

        rules:
          - MATCH,节点选择
        """
    }

    private static func parsePluginOptions(_ plugin: String?) -> (mode: String?, host: String?) {
        guard let plugin else { return (nil, nil) }
        let parts = plugin.split(separator: ";").map(String.init)
        guard parts.first == "simple-obfs" else { return (nil, nil) }
        var mode: String?
        var host: String?
        for part in parts.dropFirst() {
            let pair = part.split(separator: "=", maxSplits: 1).map(String.init)
            guard pair.count == 2 else { continue }
            if pair[0] == "obfs" {
                mode = pair[1]
            } else if pair[0] == "obfs-host" {
                host = pair[1]
            }
        }
        return (mode, host)
    }

    private static func decodeBase64(_ text: String) -> String? {
        let compact = text.trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: "\n", with: "")
            .replacingOccurrences(of: "\r", with: "")
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        guard !compact.isEmpty else { return nil }
        let padded = compact.padding(toLength: ((compact.count + 3) / 4) * 4, withPad: "=", startingAt: 0)
        guard let data = Data(base64Encoded: padded) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private static func cleanName(_ name: String) -> String {
        name.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private static func isMetadataNode(_ name: String) -> Bool {
        ["剩余流量", "距离下次重置", "套餐到期", "官网", "永久跳转"].contains {
            name.localizedCaseInsensitiveContains($0)
        }
    }

    private static func yamlQuoted(_ value: String) -> String {
        "\"\(value.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\""))\""
    }
}

private struct SSProxy {
    let name: String
    let server: String
    let port: Int
    let cipher: String
    let password: String
    let obfsMode: String?
    let obfsHost: String?
}

private extension Array where Element == SSProxy {
    func deduplicatedByName() -> [SSProxy] {
        var seen = Set<String>()
        return filter { seen.insert($0.name).inserted }
    }
}
