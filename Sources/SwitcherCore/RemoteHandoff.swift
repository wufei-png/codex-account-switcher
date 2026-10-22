import Foundation

public struct SSHRemoteHost: Codable, Equatable, Identifiable, Sendable {
    public var id: UUID
    public var alias: String
    /// Empty means the remote login shell's CODEX_HOME, falling back to ~/.codex.
    public var codexHome: String
    public var isEnabled: Bool

    public init(id: UUID = UUID(), alias: String, codexHome: String = "", isEnabled: Bool = false) {
        self.id = id; self.alias = alias; self.codexHome = codexHome; self.isEnabled = isEnabled
    }

    public func validate() throws {
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
        guard !alias.isEmpty, alias.utf8.count <= 128,
              alias.first?.isASCII == true, alias.first?.isLetter == true || alias.first?.isNumber == true,
              alias.unicodeScalars.allSatisfy({ allowed.contains($0) }),
              codexHome.isEmpty || codexHome.hasPrefix("/") || codexHome.hasPrefix("~/"),
              codexHome.utf8.count <= 4096,
              !codexHome.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) })
        else { throw RemoteHandoffError.invalidConfiguration }
    }
}

public enum RemoteHandoffError: String, LocalizedError, Equatable, Sendable {
    case invalidConfiguration = "invalid_configuration"
    case unavailable
    case timeout
    case invalidResponse = "invalid_response"
    case requirements
    case pythonUnavailable = "python_unavailable"
    case unsafePath = "unsafe_path"
    case busy
    case conflict
    case identityMismatch = "identity_mismatch"
    case verification
    case runtimeRestart = "runtime_restart"
    case runtimeVerification = "runtime_verification"
    case restorationFailed = "restoration_failed"
    case writeFailed = "write_failed"
    case credentialChanged = "credential_changed"

    public var localizationKey: String { "remote_error_" + rawValue }
    public var errorDescription: String? { L10n.string(localizationKey, language: .english) }
}

public struct RemoteSyncResult: Equatable, Sendable {
    public let hostID: UUID
    public let alias: String
    public let profileID: UUID?
    public let accountLabel: String?
    public let error: RemoteHandoffError?
    public let checkedAt: Date

    public init(host: SSHRemoteHost, account: AccountProfile? = nil, error: RemoteHandoffError? = nil) {
        hostID = host.id; alias = host.alias; self.error = error; checkedAt = Date()
        profileID = account?.id; accountLabel = account.map { $0.email ?? $0.displayName }
    }
}

public protocol RemoteHandoffClient: Sendable {
    /// Read-only: does not create directories, lock files, or credentials.
    func check(_ host: SSHRemoteHost) async throws -> String
    func sync(_ host: SSHRemoteHost, credential: Data, identity: AccountIdentity) async throws
}

public protocol SwitchCommitObserving: Sendable {
    /// Local credentials and the registry are already committed. Remote failure must not undo them.
    func didCommitAccount(_ account: AccountProfile) async
}

public actor RemoteHandoffService: SwitchCommitObserving {
    private let store: AccountStore
    private let client: any RemoteHandoffClient
    private var latestResults: [RemoteSyncResult] = []
    private var onResult: (@MainActor @Sendable (RemoteSyncResult) -> Void)?

    public init(store: AccountStore, client: any RemoteHandoffClient) {
        self.store = store; self.client = client
    }

    public func results() -> [RemoteSyncResult] { latestResults }
    public func clearResults() { latestResults = [] }
    public func observe(_ callback: @escaping @MainActor @Sendable (RemoteSyncResult) -> Void) {
        onResult = callback
    }

    public func check(_ host: SSHRemoteHost) async throws -> String {
        try host.validate()
        return try await client.check(host)
    }

    public func didCommitAccount(_ account: AccountProfile) async {
        latestResults = []
        do {
            let hosts = try await store.loadSettings().remoteHosts.filter(\.isEnabled)
            await sync(hosts, account: account)
        } catch {
            // Settings could change/become unreadable after local commit. Surface a bounded failure.
            await record(RemoteSyncResult(host: SSHRemoteHost(alias: "SSH"), account: account, error: .invalidConfiguration))
        }
    }

    /// Synchronize the confirmed local account without restarting local Desktop.
    public func retry(hostID: UUID, expectedAccountID: UUID) async throws {
        let settings = try await store.loadSettings()
        guard let host = settings.remoteHosts.first(where: { $0.id == hostID && $0.isEnabled }) else {
            throw RemoteHandoffError.invalidConfiguration
        }
        guard try await store.loadRegistry().activeAccountID == expectedAccountID else {
            throw RemoteHandoffError.credentialChanged
        }
        let account = try await store.profile(id: expectedAccountID)
        await sync([host], account: account)
    }

    private func sync(_ hosts: [SSHRemoteHost], account: AccountProfile) async {
        guard !hosts.isEmpty else { return }
        let credential: Data
        do { credential = try await store.activeCredential(for: account) }
        catch {
            for host in hosts { await record(RemoteSyncResult(host: host, account: account, error: .credentialChanged)) }
            return
        }
        for host in hosts {
            do {
                try Task.checkCancellation()
                try host.validate()
                // Do not distribute a snapshot after another login has replaced the local identity.
                guard try await store.activeCredential(for: account) == credential else {
                    throw RemoteHandoffError.credentialChanged
                }
                try await client.sync(host, credential: credential,
                                      identity: AccountIdentity(accountID: account.accountID, email: account.email))
                await record(RemoteSyncResult(host: host, account: account))
            } catch {
                await record(RemoteSyncResult(host: host, account: account, error: error as? RemoteHandoffError ?? .unavailable))
            }
        }
    }

    private func record(_ result: RemoteSyncResult) async {
        latestResults.removeAll { $0.hostID == result.hostID }
        latestResults.append(result)
        await onResult?(result)
    }
}
