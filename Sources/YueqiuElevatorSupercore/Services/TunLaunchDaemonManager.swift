import Foundation

struct TunLaunchDaemonStatus: Equatable, Sendable {
    var installed = false
    var loaded = false
    var pid: Int?
    var lastCheckedAt: Date?

    var title: String {
        if loaded {
            return pid.map { "LaunchDaemon 运行中 · pid \($0)" } ?? "LaunchDaemon 已加载"
        }
        if installed {
            return "LaunchDaemon 已安装，未运行"
        }
        return "LaunchDaemon 未安装"
    }
}

final class TunLaunchDaemonManager: @unchecked Sendable {
    let label = "cn.yueqiu.elevator.supercore"

    private let plistPath = URL(fileURLWithPath: "/Library/LaunchDaemons/cn.yueqiu.elevator.supercore.plist")
    private let logDirectory = URL(fileURLWithPath: "/Library/Logs/YueqiuElevatorSupercore", isDirectory: true)
    private let stateDirectory = URL(fileURLWithPath: "/Library/Application Support/YueqiuElevatorSupercore", isDirectory: true)
    private let fileManager: FileManager

    init(fileManager: FileManager = .default) {
        self.fileManager = fileManager
    }

    func status() -> TunLaunchDaemonStatus {
        let installed = fileManager.fileExists(atPath: plistPath.path)
        let result = runProcess(URL(fileURLWithPath: "/bin/launchctl"), ["print", "system/\(label)"])
        let loaded = result.exitCode == 0
        return TunLaunchDaemonStatus(
            installed: installed,
            loaded: loaded,
            pid: loaded ? parsePID(from: result.output) : nil,
            lastCheckedAt: Date()
        )
    }

    func installOrUpdate(binaryURL: URL, configURL: URL, controlToken: String) throws {
        guard fileManager.fileExists(atPath: binaryURL.path) else {
            throw AppError.missingCore(binaryURL)
        }
        guard fileManager.fileExists(atPath: configURL.path) else {
            throw AppError.missingRuntimeConfig
        }
        guard controlToken.utf8.count >= 32 else {
            throw AppError.processFailed("TUN 权限服务控制凭据无效")
        }
        try fileManager.setAttributes([.posixPermissions: 0o755], ofItemAtPath: binaryURL.path)
        let tempPlist = fileManager.temporaryDirectory
            .appendingPathComponent("cn.yueqiu.elevator.supercore.\(UUID().uuidString).plist")
        let tempToken = fileManager.temporaryDirectory
            .appendingPathComponent("cn.yueqiu.elevator.supercore.\(UUID().uuidString).token")
        try plist(binaryURL: binaryURL, configURL: configURL).write(to: tempPlist, atomically: true, encoding: .utf8)
        try controlToken.write(to: tempToken, atomically: true, encoding: .utf8)
        try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: tempToken.path)
        defer {
            try? fileManager.removeItem(at: tempPlist)
            try? fileManager.removeItem(at: tempToken)
        }

        let script = ([
            "set -e",
            "/bin/mkdir -p \(shellQuote(logDirectory.path))",
            "/bin/mkdir -p \(shellQuote(stateDirectory.path))",
            "/bin/cp \(shellQuote(tempToken.path)) \(shellQuote(controlTokenPath.path))",
            "/usr/sbin/chown root:wheel \(shellQuote(controlTokenPath.path))",
            "/bin/chmod 600 \(shellQuote(controlTokenPath.path))",
            "/bin/cp \(shellQuote(tempPlist.path)) \(shellQuote(plistPath.path))",
            "/usr/sbin/chown root:wheel \(shellQuote(plistPath.path))",
            "/bin/chmod 644 \(shellQuote(plistPath.path))",
            "/usr/bin/plutil -lint \(shellQuote(plistPath.path)) >/dev/null",
            "/bin/launchctl bootout system \(shellQuote(plistPath.path)) >/dev/null 2>&1 || true",
            "/bin/launchctl bootstrap system \(shellQuote(plistPath.path))",
            "/bin/launchctl enable system/\(label)",
            "/bin/launchctl kickstart -k system/\(label)"
        ]).joined(separator: "\n")
        try runPrivilegedShell(script)
    }

    func uninstall() throws {
        let script = ([
            "set -e",
            "/bin/launchctl bootout system \(shellQuote(plistPath.path)) >/dev/null 2>&1 || true",
            "/bin/rm -f \(shellQuote(plistPath.path))",
            "/bin/rm -f \(shellQuote(controlTokenPath.path))"
        ]).joined(separator: "\n")
        try runPrivilegedShell(script)
    }

    private var controlTokenPath: URL {
        stateDirectory.appendingPathComponent("control-token")
    }

    private func plist(binaryURL: URL, configURL: URL) -> String {
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
          "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
          <key>Label</key>
          <string>\(xmlEscape(label))</string>
          <key>ProgramArguments</key>
          <array>
            <string>\(xmlEscape(binaryURL.path))</string>
            <string>run</string>
            <string>-c</string>
            <string>\(xmlEscape(configURL.path))</string>
          </array>
          <key>WorkingDirectory</key>
          <string>\(xmlEscape(configURL.deletingLastPathComponent().path))</string>
          <key>RunAtLoad</key>
          <true/>
          <key>KeepAlive</key>
          <true/>
          <key>EnvironmentVariables</key>
          <dict>
            <key>RUST_LOG</key>
            <string>supercore=info,info</string>
            <key>SKYHOOK_CONTROL_TOKEN_FILE</key>
            <string>\(xmlEscape(controlTokenPath.path))</string>
          </dict>
          <key>StandardOutPath</key>
          <string>\(xmlEscape(logDirectory.appendingPathComponent("supercore.out.log").path))</string>
          <key>StandardErrorPath</key>
          <string>\(xmlEscape(logDirectory.appendingPathComponent("supercore.err.log").path))</string>
        </dict>
        </plist>
        """
    }

    private func runPrivilegedShell(_ script: String) throws {
        let appleScript = "do shell script \(appleScriptString(script)) with administrator privileges"
        let result = runProcess(URL(fileURLWithPath: "/usr/bin/osascript"), ["-e", appleScript])
        guard result.exitCode == 0 else {
            throw AppError.processFailed(result.output.isEmpty ? "LaunchDaemon 操作失败" : result.output)
        }
    }

    private func runProcess(_ executable: URL, _ arguments: [String]) -> (exitCode: Int32, output: String) {
        let process = Process()
        process.executableURL = executable
        process.arguments = arguments
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return (127, error.localizedDescription)
        }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return (process.terminationStatus, String(data: data, encoding: .utf8) ?? "")
    }

    private func parsePID(from output: String) -> Int? {
        for line in output.split(separator: "\n") where line.lowercased().contains("pid") {
            let digits = line.split { !$0.isNumber }
            if let value = digits.compactMap({ Int($0) }).first {
                return value
            }
        }
        return nil
    }

    private func shellQuote(_ value: String) -> String {
        "'\(value.replacingOccurrences(of: "'", with: "'\\''"))'"
    }

    private func appleScriptString(_ value: String) -> String {
        "\"\(value.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\""))\""
    }

    private func xmlEscape(_ value: String) -> String {
        value
            .replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
            .replacingOccurrences(of: "\"", with: "&quot;")
            .replacingOccurrences(of: "'", with: "&apos;")
    }
}
