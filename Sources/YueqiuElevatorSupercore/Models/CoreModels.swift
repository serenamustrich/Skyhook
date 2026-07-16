import Foundation

enum CoreState: Equatable, Sendable {
    case notPrepared
    case stopped
    case starting
    case running(version: String?)
    case crashed(reason: String)

    var title: String {
        switch self {
        case .notPrepared: "Supercore 未准备"
        case .stopped: "Supercore 已停止"
        case .starting: "Supercore 启动中"
        case .running(let version): "Supercore 运行中" + (version.map { " \($0)" } ?? "")
        case .crashed(let reason): "Supercore 错误：\(reason)"
        }
    }

    var isRunning: Bool {
        if case .running = self { return true }
        return false
    }
}

enum RuntimePurpose: String, Equatable, Sendable {
    case idle
    case proxy
    case delayTesting
    case attached

    var title: String {
        switch self {
        case .idle: "未运行"
        case .proxy: "正式代理"
        case .delayTesting: "测速服务"
        case .attached: "已接入 Supercore"
        }
    }
}

enum ProxyMode: String, CaseIterable, Codable, Sendable {
    case rule
    case global
    case direct

    var title: String {
        switch self {
        case .rule: "Rule"
        case .global: "Global"
        case .direct: "Direct"
        }
    }
}

enum OperationKind: String, Sendable {
    case importingSubscription
    case updatingSubscription
    case startingCore
    case switchingProfile
    case testingDelay
    case tunDaemon
    case networkRecovery
}

struct OperationState: Equatable, Sendable {
    let kind: OperationKind
    var message: String

    var title: String {
        switch kind {
        case .importingSubscription: "导入订阅"
        case .updatingSubscription: "更新订阅"
        case .startingCore: "启动代理"
        case .switchingProfile: "切换订阅"
        case .testingDelay: "测试延迟"
        case .tunDaemon: "TUN 权限服务"
        case .networkRecovery: "网络恢复"
        }
    }
}

enum DelayPolicy {
    static let timeoutMilliseconds = 500
    static let probeURL = "http://www.gstatic.com/generate_204"
    static let manualConcurrency = 50
    static let backgroundConcurrency = 32

    static func isAvailable(_ delay: Int?, failureKind: String?) -> Bool {
        guard let delay else { return false }
        guard failureKind == nil else { return false }
        return delay >= 0 && delay < timeoutMilliseconds
    }

    static func displayTitle(for delay: Int?) -> String {
        return displayTitle(for: delay, failureKind: nil)
    }

    static func displayTitle(for delay: Int?, failureKind: String?) -> String {
        guard let delay else { return "未测" }
        if let kind = failureKind {
            return failureTitle(for: kind)
        }
        if !isAvailable(delay, failureKind: nil) { return "超时" }
        return "\(delay)ms"
    }

    static func failureTitle(for failureKind: String?) -> String {
        guard let kind = failureKind?.lowercased() else { return "未知错误" }
        switch kind {
        case "timeout":
            return "超时"
        case "outbound_not_found":
            return "核心无此节点"
        case "protocol_unsupported":
            return "协议暂不支持"
        case "dial_error":
            return "拨号失败"
        case "tls_error":
            return "TLS 失败"
        case "http_status":
            return "HTTP 状态异常"
        case "empty_response":
            return "空响应"
        case "dns_error":
            return "DNS 解析失败"
        case "probe_task_failed":
            return "探测任务失败"
        default:
            return "未知错误"
        }
    }

    static func isAvailable(_ delay: Int?) -> Bool {
        isAvailable(delay, failureKind: nil)
    }
}
