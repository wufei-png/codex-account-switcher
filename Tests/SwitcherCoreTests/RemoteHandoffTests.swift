import Foundation
import Testing
@testable import SwitcherCore

struct RemoteHandoffTests {
    @Test func olderSettingsKeepRemoteSyncDisabled() throws {
        let settings = try JSONDecoder().decode(AppSettings.self, from: Data("{}".utf8))
        #expect(settings.remoteHosts.isEmpty)
        let host = SSHRemoteHost(alias: "dev-box")
        #expect(!host.isEnabled)
        let updated = AppSettings(language: .english, remoteHosts: [host])
        #expect(try JSONDecoder().decode(AppSettings.self, from: JSONEncoder().encode(updated)) == updated)
    }

    @Test func aliasesRejectOptionsCommandsAndPatterns() throws {
        for alias in ["-F", "dev;id", "$(id)", "user@host", "dev box", "dev\nbox", "*", "开发机", ""] {
            #expect(throws: RemoteHandoffError.invalidConfiguration) { try SSHRemoteHost(alias: alias).validate() }
        }
        for alias in ["dev-box", "server_2.example", "123"] { try SSHRemoteHost(alias: alias).validate() }
        #expect(throws: RemoteHandoffError.invalidConfiguration) {
            try SSHRemoteHost(alias: "dev", codexHome: "relative/path").validate()
        }
        try SSHRemoteHost(alias: "dev", codexHome: "/path/$(literal); with 'quotes'").validate()
    }

    @Test func syncRunsAfterLocalCommitBeforeDesktopReopensAndSkipsDisabledHosts() async throws {
        let fixture = try await RemoteFixture.make()
        defer { fixture.remove() }
        try await fixture.switcher.switchAccount(to: fixture.target.id)
        #expect(await fixture.recorder.events() == ["close", "sync:dev-a", "sync:dev-b", "reopen"])
        #expect(await fixture.client.sentCredentials() == [fixture.targetBytes, fixture.targetBytes])
        #expect(await fixture.handoff.results().allSatisfy { $0.error == nil })
        #expect(await fixture.handoff.results().allSatisfy { $0.profileID == fixture.target.id && $0.accountLabel == fixture.target.email })
        #expect(try await fixture.store.loadRegistry().activeAccountID == fixture.target.id)
    }

    @Test func oneRemoteFailureDoesNotRollbackLocalOrSkipOtherHosts() async throws {
        let fixture = try await RemoteFixture.make(failedAliases: ["dev-a"])
        defer { fixture.remove() }
        try await fixture.switcher.switchAccount(to: fixture.target.id)
        #expect(try await fixture.store.loadRegistry().activeAccountID == fixture.target.id)
        let activeHome = await fixture.store.activeCodexHome()
        #expect(try Data(contentsOf: activeHome.appending(path: "auth.json")) == fixture.targetBytes)
        let results = await fixture.handoff.results()
        #expect(results.map(\.error) == [.unavailable, nil])
        #expect(await fixture.recorder.events() == ["close", "sync:dev-a", "sync:dev-b", "reopen"])
    }

    @Test func changedLocalCredentialIsNeverDistributed() async throws {
        let fixture = try await RemoteFixture.make()
        defer { fixture.remove() }
        // The registry still names A; credential B must never be sent under that identity.
        let activeHome = await fixture.store.activeCodexHome()
        try fixture.targetBytes.write(to: activeHome.appending(path: "auth.json"))
        await fixture.handoff.didCommitAccount(fixture.original)
        #expect(await fixture.client.sentCredentials().isEmpty)
        #expect(await fixture.handoff.results().map(\.error) == [.credentialChanged, .credentialChanged])
    }

    @Test func retryKeepsLocalDesktopRunningForAnUnchangedLocalAccount() async throws {
        let fixture = try await RemoteFixture.make()
        defer { fixture.remove() }
        let host = try #require(try await fixture.store.loadSettings().remoteHosts.first)
        try await fixture.handoff.retry(hostID: host.id, expectedAccountID: fixture.original.id)
        #expect(await fixture.recorder.events() == ["sync:dev-a"])
        #expect(try await fixture.store.loadRegistry().activeAccountID == fixture.original.id)
        #expect(await fixture.client.sentCredentials() == [fixture.originalBytes])
    }

    @Test func failedRetryReportsTheHostResultWithoutRestartingLocalDesktop() async throws {
        let fixture = try await RemoteFixture.make(failedAliases: ["dev-a"])
        defer { fixture.remove() }
        let host = try #require(try await fixture.store.loadSettings().remoteHosts.first)
        try await fixture.handoff.retry(hostID: host.id, expectedAccountID: fixture.original.id)
        #expect(await fixture.client.sentCredentials() == [fixture.originalBytes])
        #expect(await fixture.recorder.events() == ["sync:dev-a"])
        #expect(await fixture.handoff.results().map(\.error) == [.unavailable])
        #expect(try await fixture.store.loadRegistry().activeAccountID == fixture.original.id)
        let activeHome = await fixture.store.activeCodexHome()
        #expect(try Data(contentsOf: activeHome.appending(path: "auth.json")) == fixture.originalBytes)
    }

    @Test @MainActor func retryRejectsAnExternalLoginAfterConfirmation() async throws {
        let fixture = try await RemoteFixture.make()
        defer { fixture.remove() }
        let model = AccountController(store: fixture.store, codex: RemoteAccountClient(),
                                      switchService: fixture.switcher, remoteHandoff: fixture.handoff)
        await model.start()
        let confirmedID = try #require(model.activeAccountID)
        let host = try #require(model.settings.remoteHosts.first)
        #expect(confirmedID == fixture.original.id)

        let activeHome = await fixture.store.activeCodexHome()
        try fixture.targetBytes.write(to: activeHome.appending(path: "auth.json"))
        await model.retryRemoteHost(host.id, expectedAccountID: confirmedID)
        await model.waitForWeeklyUsageRefresh()

        #expect(model.activeAccountID == fixture.target.id)
        #expect(model.visibleError?.messageKey == RemoteHandoffError.credentialChanged.localizationKey)
        #expect(await fixture.client.sentCredentials().isEmpty)
        #expect(await fixture.recorder.events().isEmpty)
    }

    @Test func retryRejectsAnAccountChangedInTheRegistry() async throws {
        let fixture = try await RemoteFixture.make()
        defer { fixture.remove() }
        let host = try #require(try await fixture.store.loadSettings().remoteHosts.first)
        try await fixture.store.activateTargetCredential(id: fixture.target.id)
        try await fixture.store.commitActiveAccountID(fixture.target.id)

        await #expect(throws: RemoteHandoffError.credentialChanged) {
            try await fixture.handoff.retry(hostID: host.id, expectedAccountID: fixture.original.id)
        }
        #expect(await fixture.client.sentCredentials().isEmpty)
        #expect(await fixture.recorder.events().isEmpty)
    }

    @Test func readOnlyCheckDoesNotSwitchOrSendCredentials() async throws {
        let fixture = try await RemoteFixture.make()
        defer { fixture.remove() }
        #expect(try await fixture.handoff.check(SSHRemoteHost(alias: "dev-a")) == "/home/test/.codex")
        #expect(await fixture.client.sentCredentials().isEmpty)
        #expect(await fixture.recorder.events().isEmpty)
    }

    @Test func disabledHostCannotBeRetried() async throws {
        let fixture = try await RemoteFixture.make()
        defer { fixture.remove() }
        let disabled = try #require(try await fixture.store.loadSettings().remoteHosts.last)
        await #expect(throws: RemoteHandoffError.invalidConfiguration) {
            try await fixture.handoff.retry(hostID: disabled.id, expectedAccountID: fixture.original.id)
        }
        #expect(await fixture.recorder.events().isEmpty)
    }
}

private actor RemoteRecorder {
    private var values: [String] = []
    func append(_ value: String) { values.append(value) }
    func events() -> [String] { values }
}

private struct RemoteDesktop: DesktopControlling {
    let recorder: RemoteRecorder
    func closeDesktop() async throws {
        await recorder.append("close")
    }
    func reopenDesktop() async throws { await recorder.append("reopen") }
}

private actor RemoteClientFixture: RemoteHandoffClient {
    let recorder: RemoteRecorder
    let store: AccountStore
    let failedAliases: Set<String>
    private var credentials: [Data] = []
    init(recorder: RemoteRecorder, store: AccountStore, failedAliases: Set<String>) {
        self.recorder = recorder; self.store = store; self.failedAliases = failedAliases
    }
    func check(_ host: SSHRemoteHost) async throws -> String { "/home/test/.codex" }
    func sync(_ host: SSHRemoteHost, credential: Data, identity: AccountIdentity) async throws {
        let registry = try await store.loadRegistry()
        let activeID = try #require(registry.activeAccountID)
        let active = try await store.profile(id: activeID)
        #expect(identity.matches(active))
        credentials.append(credential)
        await recorder.append("sync:" + host.alias)
        if failedAliases.contains(host.alias) { throw RemoteHandoffError.unavailable }
    }
    func sentCredentials() -> [Data] { credentials }
}

private struct RemoteAccountClient: AccountClient {
    func readIdentity(profileHome: URL) async throws -> AccountIdentity {
        guard let identity = try CredentialIdentity.read(from: profileHome) else {
            throw CodexClientError.identityUnavailable
        }
        return identity
    }
    func readWeeklyUsage(profileHome: URL) async throws -> WeeklyUsage { throw CodexClientError.weeklyUsageUnavailable }
    func login(profileHome: URL) async throws -> AccountIdentity { throw CodexClientError.identityUnavailable }
}

private struct RemoteFixture {
    let root: URL
    let store: AccountStore
    let original: AccountProfile
    let target: AccountProfile
    let originalBytes: Data
    let targetBytes: Data
    let recorder: RemoteRecorder
    let client: RemoteClientFixture
    let handoff: RemoteHandoffService
    let switcher: SwitchService

    static func make(failedAliases: Set<String> = []) async throws -> RemoteFixture {
        let root = FileManager.default.temporaryDirectory.appending(path: "remote-handoff-\(UUID())")
        let store = AccountStore(baseURL: root.appending(path: "store"), activeHomeURL: root.appending(path: "home"))
        let original = AccountProfile(id: UUID(), displayName: "A", email: "a@example.test", accountID: "account-a", createdAt: Date())
        let target = AccountProfile(id: UUID(), displayName: "B", email: "b@example.test", accountID: "account-b", createdAt: Date())
        func credential(_ profile: AccountProfile) throws -> Data {
            let claims: [String: Any] = ["email": profile.email!, "https://api.openai.com/auth": ["chatgpt_account_id": profile.accountID!]]
            let encoded = try JSONSerialization.data(withJSONObject: claims).base64EncodedString()
                .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
            return try JSONSerialization.data(withJSONObject: ["tokens": ["account_id": profile.accountID!, "id_token": "header.\(encoded).signature"]])
        }
        let originalBytes = try credential(original), targetBytes = try credential(target)
        for (profile, bytes) in [(original, originalBytes), (target, targetBytes)] {
            let home = try await store.createProfileDirectory(id: profile.id)
            try bytes.write(to: home.appending(path: "auth.json"))
            try await store.addProfile(profile)
        }
        try await store.activateTargetCredential(id: original.id)
        try await store.commitActiveAccountID(original.id)
        try await store.saveSettings(AppSettings(language: .english, remoteHosts: [
            SSHRemoteHost(alias: "dev-a", isEnabled: true), SSHRemoteHost(alias: "dev-b", isEnabled: true),
            SSHRemoteHost(alias: "disabled"),
        ]))
        let recorder = RemoteRecorder()
        let desktop = RemoteDesktop(recorder: recorder)
        let client = RemoteClientFixture(recorder: recorder, store: store, failedAliases: failedAliases)
        let handoff = RemoteHandoffService(store: store, client: client)
        return RemoteFixture(root: root, store: store, original: original, target: target,
            originalBytes: originalBytes, targetBytes: targetBytes, recorder: recorder, client: client, handoff: handoff,
            switcher: SwitchService(desktop: desktop, store: store, codex: RemoteAccountClient(), commitObserver: handoff))
    }

    func remove() { try? FileManager.default.removeItem(at: root) }
}
