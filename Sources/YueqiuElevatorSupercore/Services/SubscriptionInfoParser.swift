import Foundation

enum SubscriptionInfoParser {
    static func parse(text: String, headers: [AnyHashable: Any] = [:]) -> SubscriptionPlanInfo? {
        var info = parseUserInfoHeader(headers)
        let lineInfo = parseMetadataLines(text)

        info.remainingTraffic = lineInfo.remainingTraffic ?? info.remainingTraffic
        info.resetInfo = lineInfo.resetInfo ?? info.resetInfo
        info.expiresAtText = lineInfo.expiresAtText ?? info.expiresAtText
        info.homepage = lineInfo.homepage ?? info.homepage

        return info.hasContent ? info : nil
    }

    private static func parseUserInfoHeader(_ headers: [AnyHashable: Any]) -> SubscriptionPlanInfo {
        guard let value = headers.first(where: { key, _ in
            String(describing: key).caseInsensitiveCompare("subscription-userinfo") == .orderedSame
        })?.value else {
            return SubscriptionPlanInfo()
        }

        let fields = String(describing: value)
            .split(separator: ";")
            .reduce(into: [String: Int]()) { result, item in
                let pair = item.split(separator: "=", maxSplits: 1).map {
                    String($0).trimmingCharacters(in: .whitespacesAndNewlines)
                }
                guard pair.count == 2, let value = Int(pair[1]) else { return }
                result[pair[0].lowercased()] = value
            }

        let upload = fields["upload"] ?? 0
        let download = fields["download"] ?? 0
        let used = upload + download
        let total = fields["total"] ?? 0
        let remaining = max(0, total - used)
        let expiresAt = fields["expire"].flatMap { expiryText(fromUnixTime: $0) }

        return SubscriptionPlanInfo(
            remainingTraffic: total > 0 ? ByteFormatter.bytes(remaining) : nil,
            usedTraffic: used > 0 ? ByteFormatter.bytes(used) : nil,
            totalTraffic: total > 0 ? ByteFormatter.bytes(total) : nil,
            resetInfo: nil,
            expiresAtText: expiresAt,
            homepage: nil
        )
    }

    private static func parseMetadataLines(_ text: String) -> SubscriptionPlanInfo {
        let decoded = decodeBase64(text) ?? text
        var info = SubscriptionPlanInfo()

        for rawLine in decoded.split(whereSeparator: \.isNewline).map(String.init) {
            let value = metadataValue(from: rawLine)
            guard !value.isEmpty else { continue }

            if value.localizedCaseInsensitiveContains("剩余流量") {
                info.remainingTraffic = valueAfterSeparator(in: value)
            } else if value.localizedCaseInsensitiveContains("距离下次重置") {
                info.resetInfo = valueAfterSeparator(in: value)
            } else if value.localizedCaseInsensitiveContains("套餐到期") ||
                        value.localizedCaseInsensitiveContains("到期时间") ||
                        value.localizedCaseInsensitiveContains("expire") {
                info.expiresAtText = valueAfterSeparator(in: value)
            } else if value.localizedCaseInsensitiveContains("官网") ||
                        value.localizedCaseInsensitiveContains("永久跳转") {
                info.homepage = valueAfterSeparator(in: value)
            }
        }

        return info
    }

    private static func metadataValue(from line: String) -> String {
        let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return "" }
        if let hash = trimmed.lastIndex(of: "#") {
            let fragment = String(trimmed[trimmed.index(after: hash)...])
            return (fragment.removingPercentEncoding ?? fragment)
                .trimmingCharacters(in: .whitespacesAndNewlines)
        }
        return trimmed
    }

    private static func valueAfterSeparator(in text: String) -> String {
        for separator in ["：", ":"] {
            if let range = text.range(of: separator) {
                return String(text[range.upperBound...])
                    .trimmingCharacters(in: .whitespacesAndNewlines)
            }
        }
        return text.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private static func expiryText(fromUnixTime seconds: Int) -> String? {
        guard seconds > 0 else { return nil }
        let date = Date(timeIntervalSince1970: TimeInterval(seconds))
        let formatter = DateFormatter()
        formatter.calendar = Calendar(identifier: .gregorian)
        formatter.locale = Locale(identifier: "zh_CN")
        formatter.dateFormat = "yyyy-MM-dd"
        return formatter.string(from: date)
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
}
