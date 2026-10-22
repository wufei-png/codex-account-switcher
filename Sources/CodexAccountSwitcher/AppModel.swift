import SwitcherCore
import Combine
import Foundation
import ServiceManagement

enum LaunchAtLoginState: Equatable {
    case disabled
    case enabled
    case requiresApproval
    case unavailable

    init(status: SMAppService.Status) {
        switch status {
        case .notRegistered:
            self = .disabled
        case .enabled:
            self = .enabled
        case .requiresApproval:
            self = .requiresApproval
        case .notFound:
            self = .unavailable
        @unknown default:
            self = .unavailable
        }
    }

    var isOn: Bool {
        self == .enabled || self == .requiresApproval
    }
}

@MainActor
final class AppModel: AccountController, @MainActor ObservableObject {
    let objectWillChange = ObservableObjectPublisher()
    @Published private(set) var launchAtLoginState: LaunchAtLoginState = .disabled

    override init(store: AccountStore, codex: any AccountClient, switchService: any SwitchServicing,
                  remoteHandoff: RemoteHandoffService? = nil) {
        super.init(store: store, codex: codex, switchService: switchService, remoteHandoff: remoteHandoff)
        onChange = { [weak self] in self?.objectWillChange.send() }
        refreshLaunchAtLoginStatus()
    }

    static func live() -> AppModel {
        let store = AccountStore()
        let codex = CodexClient()
        // Packaging puts the resource bundle in Contents/Resources, while SwiftPM's
        // generated Bundle.module accessor can assume the executable's directory.
        let helperURL = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .appending(path: "Resources/remote-handoff.py")
        let roots = [Bundle.main.resourceURL, Bundle.main.bundleURL].compactMap { $0 }
        let helper = bundledRemoteHelper(in: roots) ?? (try? String(contentsOf: helperURL, encoding: .utf8)) ?? ""
        let desktop = DesktopController()
        let remoteHandoff = RemoteHandoffService(store: store,
            client: SSHRemoteClient(helperSource: helper))
        return AppModel(store: store, codex: codex,
                        switchService: SwitchService(desktop: desktop, store: store, codex: codex,
                                                     commitObserver: remoteHandoff), remoteHandoff: remoteHandoff)
    }

    static func bundledRemoteHelper(in roots: [URL]) -> String? {
        for root in roots {
            let bundleURL = root.appending(path: "CodexAccountSwitcher_CodexAccountSwitcher.bundle")
            if let bundle = Bundle(url: bundleURL),
               let url = bundle.url(forResource: "remote-handoff", withExtension: "py"),
               let source = try? String(contentsOf: url, encoding: .utf8) {
                return source
            }
        }
        return nil
    }

    var launchesAtLogin: Bool { launchAtLoginState.isOn }
    var launchAtLoginRequiresApproval: Bool { launchAtLoginState == .requiresApproval }
    var launchAtLoginUnavailable: Bool { launchAtLoginState == .unavailable }

    func refreshLaunchAtLoginStatus() {
        launchAtLoginState = LaunchAtLoginState(status: SMAppService.mainApp.status)
    }

    func setLaunchAtLogin(_ enabled: Bool) {
        do {
            if enabled { try SMAppService.mainApp.register() }
            else { try SMAppService.mainApp.unregister() }
        } catch {
            visibleError = OperationError(stage: nil, titleKey: "operation_failed", messageKey: nil,
                                          message: error.localizedDescription, underlyingDescription: nil)
        }
        refreshLaunchAtLoginStatus()
    }

    func openLoginItemsSettings() { SMAppService.openSystemSettingsLoginItems() }
}
