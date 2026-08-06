import Darwin
import Foundation

final class SupercoreManager: @unchecked Sendable {
    var onStateChanged: (@Sendable (CoreState) -> Void)?
    var onLogLine: (@Sendable (String) -> Void)?

    private let paths: AppPaths
    private let apiClient: SupercoreAPIClient
    private var process: Process?
    private var intentionallyStoppingPIDs: Set<Int32> = []
    private let queue = DispatchQueue(label: "YueqiuElevatorSupercore.SupercoreManager")

    init(paths: AppPaths, apiClient: SupercoreAPIClient) {
        self.paths = paths
        self.apiClient = apiClient
    }

    func ensureCoreInstalled() throws {
        try ensureCoreExecutable()
    }

    func syncSubscription(profile: SubscriptionProfile, sourcePath: URL) async throws {
        try ensureCoreExecutable()
        guard FileManager.default.fileExists(atPath: sourcePath.path) else {
            throw AppError.missingSubscription
        }
        try FileManager.default.createDirectory(
            at: paths.supercoreSubscriptionStore,
            withIntermediateDirectories: true
        )
        let proc = Process()
        proc.executableURL = paths.supercoreBinary
        proc.arguments = [
            "subscriptions", "import",
            "--file", sourcePath.path,
            "--id", profile.id,
            "--name", profile.name,
            "--store", paths.supercoreSubscriptionStore.path,
            "--switch"
        ]

        let stdout = Pipe()
        let stderr = Pipe()
        proc.standardOutput = stdout
        proc.standardError = stderr
        try proc.run()
        proc.waitUntilExit()
        let errorText = String(
            data: stderr.fileHandleForReading.readDataToEndOfFile(),
            encoding: .utf8
        ) ?? ""
        if proc.terminationStatus != 0 {
            throw AppError.processFailed("Supercore 订阅同步失败：\(errorText)")
        }
    }

    func activateCachedSubscription(profileID: String) throws -> Bool {
        let indexURL = paths.supercoreSubscriptionStore.appendingPathComponent("index.json")
        guard FileManager.default.fileExists(atPath: indexURL.path),
              cachedSubscriptionFilesExist(profileID: profileID) else {
            return false
        }
        let data = try Data(contentsOf: indexURL)
        guard var object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let subscriptions = object["subscriptions"] as? [[String: Any]],
              subscriptions.contains(where: { ($0["id"] as? String) == profileID }) else {
            return false
        }
        if object["active_id"] as? String == profileID {
            return true
        }
        object["active_id"] = profileID
        let encoded = try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted])
        try FileManager.default.createDirectory(
            at: paths.supercoreSubscriptionStore,
            withIntermediateDirectories: true
        )
        try encoded.write(to: indexURL, options: .atomic)
        return true
    }

    func start(configPath: URL) async throws {
        try ensureCoreExecutable()
        guard FileManager.default.fileExists(atPath: configPath.path) else {
            throw AppError.missingRuntimeConfig
        }
        await stop()

        onStateChanged?(.starting)
        let controlToken = try ControlToken.generate()
        apiClient.setControlToken(controlToken)
        let proc = Process()
        proc.executableURL = paths.supercoreBinary
        proc.arguments = ["run", "-c", configPath.path]
        var environment = ProcessInfo.processInfo.environment
        environment["SKYHOOK_CONTROL_TOKEN"] = controlToken
        environment.removeValue(forKey: "SKYHOOK_CONTROL_TOKEN_FILE")
        proc.environment = environment

        let stdout = Pipe()
        let stderr = Pipe()
        proc.standardOutput = stdout
        proc.standardError = stderr
        attachLog(pipe: stdout, prefix: "supercore")
        attachLog(pipe: stderr, prefix: "supercore-error")
        proc.terminationHandler = { [weak self] terminated in
            guard let self else { return }
            let (ownsTermination, intentionalStop) = self.queue.sync {
                let intentionalStop = self.intentionallyStoppingPIDs.remove(terminated.processIdentifier) != nil
                guard self.process === terminated else {
                    return (false, intentionalStop)
                }
                self.process = nil
                return (true, intentionalStop)
            }
            guard ownsTermination || intentionalStop else { return }
            if ownsTermination {
                self.apiClient.setControlToken(nil)
            }
            let reason = "Supercore 已退出，exitCode=\(terminated.terminationStatus)"
            self.onLogLine?(reason)
            if intentionalStop || terminated.terminationStatus == 0 {
                self.onStateChanged?(.stopped)
            } else {
                self.onStateChanged?(.crashed(reason: reason))
            }
        }

        do {
            try proc.run()
        } catch {
            apiClient.setControlToken(nil)
            throw error
        }
        queue.sync { process = proc }
        do {
            let version = try await waitForHealthyVersion(process: proc)
            onStateChanged?(.running(version: version))
        } catch {
            await stop()
            throw error
        }
    }

    func stop() async {
        let proc = queue.sync { process }
        guard let proc, proc.isRunning else {
            terminateOwnedCoreProcesses()
            apiClient.setControlToken(nil)
            onStateChanged?(.stopped)
            return
        }
        _ = queue.sync {
            intentionallyStoppingPIDs.insert(proc.processIdentifier)
        }
        proc.terminate()
        for _ in 0..<20 where proc.isRunning {
            try? await Task.sleep(nanoseconds: 100_000_000)
        }
        if proc.isRunning {
            proc.interrupt()
        }
        queue.sync { process = nil }
        terminateOwnedCoreProcesses()
        apiClient.setControlToken(nil)
        onStateChanged?(.stopped)
    }

    func stopSync() {
        let proc = queue.sync { process }
        if let proc, proc.isRunning {
            _ = queue.sync {
                intentionallyStoppingPIDs.insert(proc.processIdentifier)
            }
            proc.terminate()
            Thread.sleep(forTimeInterval: 0.2)
            if proc.isRunning {
                proc.interrupt()
            }
        }
        terminateOwnedCoreProcesses()
        queue.sync { process = nil }
        apiClient.setControlToken(nil)
    }

    func detectRunningVersion(allowExternalProcess: Bool = false) async -> String? {
        // Do not attach to an unrelated process that happens to expose the same port.
        // A loaded LaunchDaemon is the explicit exception because its binary path is
        // intentionally managed outside the per-user application directory.
        guard allowExternalProcess || !ownedCoreProcessIDs().isEmpty else { return nil }
        return try? await apiClient.getVersion(timeoutInterval: 0.6).version
    }

    private func ensureCoreExecutable() throws {
        try installBundledCoreIfNeeded()
        guard FileManager.default.fileExists(atPath: paths.supercoreBinary.path) else {
            throw AppError.missingCore(paths.supercoreBinary)
        }
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: paths.supercoreBinary.path)
    }

    private func installBundledCoreIfNeeded() throws {
        guard let bundledCore = Bundle.main.resourceURL?.appendingPathComponent("supercore"),
              FileManager.default.fileExists(atPath: bundledCore.path) else {
            return
        }
        let shouldInstall: Bool
        if FileManager.default.fileExists(atPath: paths.supercoreBinary.path) {
            let bundledDate = (try? FileManager.default.attributesOfItem(atPath: bundledCore.path)[.modificationDate] as? Date) ?? .distantPast
            let installedDate = (try? FileManager.default.attributesOfItem(atPath: paths.supercoreBinary.path)[.modificationDate] as? Date) ?? .distantPast
            shouldInstall = bundledDate > installedDate
        } else {
            shouldInstall = true
        }
        guard shouldInstall else { return }
        try FileManager.default.createDirectory(at: paths.cores, withIntermediateDirectories: true)
        if FileManager.default.fileExists(atPath: paths.supercoreBinary.path) {
            try FileManager.default.removeItem(at: paths.supercoreBinary)
        }
        try FileManager.default.copyItem(at: bundledCore, to: paths.supercoreBinary)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: paths.supercoreBinary.path)
    }

    private func cachedSubscriptionFilesExist(profileID: String) -> Bool {
        let directory = paths.supercoreSubscriptionStore
            .appendingPathComponent("subscriptions", isDirectory: true)
            .appendingPathComponent(profileID, isDirectory: true)
        return FileManager.default.fileExists(atPath: directory.appendingPathComponent("document.json").path) &&
            FileManager.default.fileExists(atPath: directory.appendingPathComponent("meta.json").path)
    }

    private func waitForHealthyVersion(process: Process) async throws -> String {
        var lastError: Error?
        for _ in 0..<32 {
            guard process.isRunning else {
                throw AppError.processFailed("Supercore 启动失败，exitCode=\(process.terminationStatus)")
            }
            do {
                return try await apiClient.getVersion(timeoutInterval: 0.6).version
            } catch {
                lastError = error
                try await Task.sleep(nanoseconds: 250_000_000)
            }
        }
        throw lastError ?? AppError.processFailed("Supercore 启动后未响应 /v1/version")
    }

    private func attachLog(pipe: Pipe, prefix: String) {
        pipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty, let text = String(data: data, encoding: .utf8) else { return }
            for line in text.split(separator: "\n", omittingEmptySubsequences: false) {
                guard !line.isEmpty else { continue }
                self?.onLogLine?("[\(prefix)] \(line)")
            }
        }
    }

    private func terminateOwnedCoreProcesses() {
        let currentPID = getpid()
        for pid in ownedCoreProcessIDs() where pid != currentPID {
            kill(pid, SIGTERM)
        }
    }

    private func ownedCoreProcessIDs() -> [pid_t] {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/bin/ps")
        proc.arguments = ["-axo", "pid=,command="]
        let pipe = Pipe()
        proc.standardOutput = pipe
        do {
            try proc.run()
        } catch {
            return []
        }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        proc.waitUntilExit()
        guard let output = String(data: data, encoding: .utf8) else { return [] }
        return output.split(separator: "\n", omittingEmptySubsequences: true).compactMap { line -> pid_t? in
            let trimmed = String(line).trimmingCharacters(in: .whitespacesAndNewlines)
            guard let firstSpace = trimmed.firstIndex(where: { $0 == " " || $0 == "\t" }) else {
                return nil
            }
            let pidText = String(trimmed[..<firstSpace])
            let command = String(trimmed[firstSpace...])
            guard command.contains(paths.supercoreBinary.path),
                  command.contains("run -c") else {
                return nil
            }
            guard let pid = Int32(pidText) else { return nil }
            return pid_t(pid)
        }
    }
}
