import Foundation

enum ProxyNodeParser {
    static func stripCommentPreservingQuotes(_ line: String) -> String {
        stripComment(line)
    }

    static func parseProviderURLs(from yaml: String) -> [String: URL] {
        let lines = yaml.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        var providers: [String: URL] = [:]
        var inProviders = false
        var currentProvider: String?

        for rawLine in lines {
            let line = stripComment(rawLine)
            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else { continue }
            let indent = leadingWhitespaceCount(line)

            if indent == 0 {
                if trimmed == "proxy-providers:" {
                    inProviders = true
                    continue
                }
                if inProviders {
                    break
                }
            }
            guard inProviders else { continue }

            if indent == 2, trimmed.hasSuffix(":") {
                currentProvider = String(trimmed.dropLast()).trimmingCharacters(in: .whitespaces)
                continue
            }
            guard let currentProvider, let value = value(after: "url:", in: trimmed), let url = URL(string: value) else {
                continue
            }
            providers[currentProvider] = url
        }
        return providers
    }

    static func parseNodes(from text: String, source: String) -> [ProxyNode] {
        if let decoded = decodeBase64(text), decoded.contains("://") {
            return parseURIList(decoded, source: source)
        }
        if text.contains("proxies:") {
            return parseYAMLProxyNames(text, source: source)
        }
        return parseURIList(text, source: source)
    }

    static func country(for nodeName: String) -> String {
        if let fromFlag = countryFromFlag(in: nodeName) {
            return fromFlag
        }
        let table: [(String, [String])] = [
            ("香港", ["香港", "Hong Kong", "HK"]),
            ("台湾", ["台湾", "台灣", "Taiwan", "TW"]),
            ("澳门", ["澳门", "澳門", "Macao", "Macau", "MO"]),
            ("日本", ["日本", "Japan", "JP"]),
            ("韩国", ["韩国", "韓國", "Korea", "KR"]),
            ("新加坡", ["新加坡", "Singapore", "SG"]),
            ("美国", ["美国", "美國", "United States", "USA", "US"]),
            ("英国", ["英国", "英國", "United Kingdom", "UK", "GB"]),
            ("德国", ["德国", "德國", "Germany", "DE"]),
            ("法国", ["法国", "法國", "France", "FR"]),
            ("加拿大", ["加拿大", "Canada", "CA"]),
            ("澳大利亚", ["澳大利亚", "澳洲", "Australia", "AU"]),
            ("俄罗斯", ["俄罗斯", "俄羅斯", "Russia", "RU"]),
            ("印度", ["印度", "India", "IN"]),
            ("马来西亚", ["马来西亚", "馬來西亞", "Malaysia", "MY"]),
            ("泰国", ["泰国", "泰國", "Thailand", "TH"]),
            ("越南", ["越南", "Vietnam", "VN"]),
            ("菲律宾", ["菲律宾", "Philippines", "PH"]),
            ("土耳其", ["土耳其", "Turkey", "TR"]),
            ("巴西", ["巴西", "Brazil", "BR"])
        ]
        let lower = nodeName.lowercased()
        for (country, keywords) in table {
            if keywords.contains(where: { lower.contains($0.lowercased()) }) {
                return country
            }
        }
        return "未识别"
    }

    private static func parseURIList(_ text: String, source: String) -> [ProxyNode] {
        text
            .split(whereSeparator: \.isNewline)
            .map(String.init)
            .compactMap { line -> ProxyNode? in
                let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
                guard trimmed.contains("://") else { return nil }
                let name = nameFromURI(trimmed)
                guard !name.isEmpty else { return nil }
                return ProxyNode(name: name, source: source, country: country(for: name))
            }
            .deduplicated()
    }

    private static func parseYAMLProxyNames(_ text: String, source: String) -> [ProxyNode] {
        text
            .split(separator: "\n", omittingEmptySubsequences: false)
            .map(String.init)
            .compactMap { line -> ProxyNode? in
                let trimmed = stripComment(line).trimmingCharacters(in: .whitespacesAndNewlines)
                guard trimmed.hasPrefix("name:") || trimmed.hasPrefix("- name:") else { return nil }
                let value = trimmed.hasPrefix("- name:")
                    ? String(trimmed.dropFirst("- name:".count))
                    : String(trimmed.dropFirst("name:".count))
                let name = cleanScalar(value)
                guard !name.isEmpty else { return nil }
                return ProxyNode(name: name, source: source, country: country(for: name))
            }
            .deduplicated()
    }

    private static func nameFromURI(_ uri: String) -> String {
        guard let hash = uri.lastIndex(of: "#") else {
            return ""
        }
        let fragment = String(uri[uri.index(after: hash)...])
        return fragment.removingPercentEncoding ?? fragment
    }

    private static func decodeBase64(_ text: String) -> String? {
        let compact = text.trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: "\n", with: "")
            .replacingOccurrences(of: "\r", with: "")
        guard !compact.isEmpty else { return nil }
        let padded = compact.padding(toLength: ((compact.count + 3) / 4) * 4, withPad: "=", startingAt: 0)
        guard let data = Data(base64Encoded: padded) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private static func countryFromFlag(in text: String) -> String? {
        let scalars = Array(text.unicodeScalars)
        for index in scalars.indices.dropLast() {
            let first = scalars[index].value
            let second = scalars[scalars.index(after: index)].value
            guard (0x1F1E6...0x1F1FF).contains(first),
                  (0x1F1E6...0x1F1FF).contains(second) else {
                continue
            }
            let code = String(UnicodeScalar(first - 0x1F1E6 + 65)!) + String(UnicodeScalar(second - 0x1F1E6 + 65)!)
            return [
                "HK": "香港", "TW": "台湾", "MO": "澳门", "JP": "日本", "KR": "韩国",
                "SG": "新加坡", "US": "美国", "GB": "英国", "DE": "德国", "FR": "法国",
                "CA": "加拿大", "AU": "澳大利亚", "RU": "俄罗斯", "IN": "印度",
                "MY": "马来西亚", "TH": "泰国", "VN": "越南", "PH": "菲律宾",
                "TR": "土耳其", "BR": "巴西"
            ][code]
        }
        return nil
    }

    private static func leadingWhitespaceCount(_ line: String) -> Int {
        line.prefix { $0 == " " || $0 == "\t" }.count
    }

    private static func stripComment(_ line: String) -> String {
        var inSingleQuote = false
        var inDoubleQuote = false
        for (index, char) in line.enumerated() {
            if char == "'", !inDoubleQuote { inSingleQuote.toggle() }
            if char == "\"", !inSingleQuote { inDoubleQuote.toggle() }
            if char == "#", !inSingleQuote, !inDoubleQuote {
                let stringIndex = line.index(line.startIndex, offsetBy: index)
                return String(line[..<stringIndex])
            }
        }
        return line
    }

    private static func value(after prefix: String, in line: String) -> String? {
        guard line.hasPrefix(prefix) else { return nil }
        return cleanScalar(String(line.dropFirst(prefix.count)))
    }

    private static func cleanScalar(_ value: String) -> String {
        var result = value.trimmingCharacters(in: .whitespacesAndNewlines)
        if result.hasPrefix("\""), result.hasSuffix("\""), result.count >= 2 {
            result.removeFirst()
            result.removeLast()
        } else if result.hasPrefix("'"), result.hasSuffix("'"), result.count >= 2 {
            result.removeFirst()
            result.removeLast()
        }
        return result
    }
}

private extension Array where Element == ProxyNode {
    func deduplicated() -> [ProxyNode] {
        var seen = Set<String>()
        return filter { node in
            seen.insert(node.name).inserted
        }
    }
}
