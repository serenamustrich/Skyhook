import AppKit

final class AppDelegate: NSObject, NSApplicationDelegate {
    private var statusBarController: StatusBarController?
    private var appState: AppState?

    func applicationDidFinishLaunching(_ notification: Notification) {
        let paths = AppPaths()
        do {
            try paths.prepareDirectories()
        } catch {
            NSAlert(error: error).runModal()
        }

        let state = AppState(
            paths: paths,
            keychain: KeychainStore(service: "YueqiuElevatorSupercore")
        )
        self.appState = state
        self.statusBarController = StatusBarController(appState: state)
        MainMenuBuilder.install(settingsTarget: self, settingsAction: #selector(showSettings))

        Task { await state.bootstrap() }
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard let appState else { return .terminateNow }
        Task { @MainActor in
            await appState.prepareForQuit()
            NSApp.reply(toApplicationShouldTerminate: true)
        }
        return .terminateLater
    }

    @MainActor
    @objc private func showSettings() {
        appState?.showSettings()
    }
}
