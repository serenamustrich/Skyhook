import Foundation

enum AppError: LocalizedError {
    case missingCore(URL)
    case missingSubscription
    case invalidSubscriptionURL
    case invalidYAML
    case missingRuntimeConfig
    case processFailed(String)
    case apiError(Int, String)
    case unexpectedResponse

    var errorDescription: String? {
        switch self {
        case .missingCore(let url): "未找到 Supercore：\(url.path)"
        case .missingSubscription: "还没有保存订阅"
        case .invalidSubscriptionURL: "订阅链接无效"
        case .invalidYAML: "订阅返回内容不是有效的代理订阅 YAML"
        case .missingRuntimeConfig: "未找到 Supercore runtime 配置，请先导入订阅"
        case .processFailed(let message): message
        case .apiError(let code, let body): "Supercore API 错误 \(code)：\(body)"
        case .unexpectedResponse: "返回内容异常"
        }
    }
}

enum ByteFormatter {
    static func bytes(_ bytes: Int) -> String {
        let value = Double(bytes)
        if value >= 1_073_741_824 {
            return String(format: "%.2f GB", value / 1_073_741_824)
        }
        if value >= 1_048_576 {
            return String(format: "%.1f MB", value / 1_048_576)
        }
        if value >= 1_024 {
            return String(format: "%.1f KB", value / 1_024)
        }
        return "\(bytes) B"
    }

    static func rate(_ bytes: Int) -> String {
        let value = Double(bytes)
        if value >= 1_048_576 {
            return String(format: "%.1f MB/s", value / 1_048_576)
        }
        if value >= 1_024 {
            return String(format: "%.1f KB/s", value / 1_024)
        }
        return "\(bytes) B/s"
    }
}

enum LogRedactor {
    static func redact(_ input: String) -> String {
        var output = input
        output = output.replacingOccurrences(
            of: #"(?i)(token|secret|password|passwd|key)=([^&\s]+)"#,
            with: "$1=<redacted>",
            options: .regularExpression
        )
        output = output.replacingOccurrences(
            of: #"Bearer\s+[A-Za-z0-9_\-\.=]+"#,
            with: "Bearer <redacted>",
            options: .regularExpression
        )
        return output
    }
}

enum URLMasker {
    static func mask(_ urlString: String) -> String {
        guard var components = URLComponents(string: urlString) else { return "<invalid-url>" }
        if components.queryItems?.isEmpty == false {
            components.queryItems = components.queryItems?.map { URLQueryItem(name: $0.name, value: "<redacted>") }
        }
        if let password = components.password, !password.isEmpty {
            components.password = "<redacted>"
        }
        return components.string ?? "<redacted-url>"
    }
}
