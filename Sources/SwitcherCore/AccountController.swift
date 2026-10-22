import Foundation

private enum UsageRefreshResult: Sendable {
    case success(UUID, WeeklyUsage)
    case failure(UUID, String)
}

@MainActor
open class AccountController {
    public var onChange: (@MainActor () -> Void)?
    public private(set) var accounts: [AccountProfile] = [] { didSet { onChange?() } }
    public private(set) var activeAccountID: UUID? { didSet { onChange?() } }
    public private(set) var usageStates: [UUID: UsageViewState] = [:] { didSet { onChange?() } }
    public private(set) var subscriptionSnapshots: [UUID: SubscriptionSnapshot] = [:] { didSet { onChange?() } }
    public private(set) var settings: AppSettings = .default { didSet { onChange?() } }
    public private(set) var isMutating = false { didSet { onChange?() } }
    public private(set) var isAddingAccount = false { didSet { onChange?() } }
    public var visibleError: OperationError? { didSet { onChange?() } }
    public private(set) var activeIdentityConfirmed = true { didSet { onChange?() } }
    public private(set) var remoteResults: [RemoteSyncResult] = [] { didSet { onChange?() } }

    private let store: AccountStore
    private let codex: any AccountClient
    private let switchService: any SwitchServicing
    private let remoteHandoff: RemoteHandoffService?
    private var hasStarted = false
    private var usageRefreshTask: Task<Void, Never>?
    private var nextUsageRefreshTask: Task<Void, Never>?
    private var addAccountTask: Task<Void, Never>?
    private var backgroundUsageRefreshInterval: Duration = .seconds(300)
    private var isBackgroundUsageRefreshEnabled = false

    public init(
        store: AccountStore,
        codex: any AccountClient,
        switchService: any SwitchServicing,
        remoteHandoff: RemoteHandoffService? = nil
    ) {
        self.store = store
        self.codex = codex
        self.switchService = switchService
        self.remoteHandoff = remoteHandoff
    }

    public func text(_ key: String) -> String {
        L10n.string(key, language: settings.language)
    }

    public func format(_ key: String, _ argument: String) -> String {
        String(format: text(key), argument)
    }

    public var activeRemainingPercent: Int? {
        guard let activeAccountID else { return nil }
        guard let usage = usageStates[activeAccountID]?.displayedUsage else { return nil }
        return settings.statusBarUsageWindow == .fiveHour
            ? (usage.fiveHourRemainingPercent ?? usage.remainingPercent)
            : usage.remainingPercent
    }

    public func start() async {
        guard !hasStarted else { return }
        hasStarted = true
        isMutating = true
        defer { isMutating = false }
        await remoteHandoff?.observe { [weak self] result in
            guard let self else { return }
            self.remoteResults.removeAll { $0.hostID == result.hostID }
            self.remoteResults.append(result)
        }
        do {
            settings = try await store.loadSettings()
            apply(try await store.loadRegistry())
            try await syncActiveIdentity()
            await refreshSubscriptionSnapshots()
            do {
                apply(try await store.loadUsageCache())
            } catch {
                showError(error)
            }
        } catch {
            showError(error)
        }
    }

    public func refreshWeeklyUsage() {
        if isBackgroundUsageRefreshEnabled {
            scheduleNextWeeklyUsageRefresh()
        }
        guard !isMutating, usageRefreshTask == nil else { return }
        usageRefreshTask = Task { [weak self] in
            guard let self else { return }
            await self.performWeeklyUsageRefresh()
            self.usageRefreshTask = nil
        }
    }

    public func waitForWeeklyUsageRefresh() async {
        await usageRefreshTask?.value
    }

    private func refreshSubscriptionSnapshots() async {
        var snapshots: [UUID: SubscriptionSnapshot] = [:]
        for account in accounts {
            if let snapshot = await store.readSubscriptionSnapshot(
                profile: account, isActive: account.id == activeAccountID
            ) {
                snapshots[account.id] = snapshot
            }
        }
        subscriptionSnapshots = snapshots
    }

    public func startBackgroundUsageRefresh(every interval: Duration = .seconds(300)) async {
        backgroundUsageRefreshInterval = interval
        isBackgroundUsageRefreshEnabled = true
        await start()
        refreshWeeklyUsage()
    }

    public func stopBackgroundUsageRefresh() {
        isBackgroundUsageRefreshEnabled = false
        nextUsageRefreshTask?.cancel()
        nextUsageRefreshTask = nil
    }

    private func scheduleNextWeeklyUsageRefresh() {
        nextUsageRefreshTask?.cancel()
        let interval = backgroundUsageRefreshInterval
        nextUsageRefreshTask = Task { [weak self] in
            do {
                try await Task.sleep(for: interval)
            } catch {
                return
            }
            guard !Task.isCancelled, let self else { return }
            self.nextUsageRefreshTask = nil
            self.refreshWeeklyUsage()
        }
    }

    private func performWeeklyUsageRefresh() async {
        guard !Task.isCancelled else { return }
        do {
            try await syncActiveIdentity()
        } catch {
            showError(error)
            return
        }
        guard !Task.isCancelled else { return }
        await refreshSubscriptionSnapshots()
        await withTaskGroup(of: UsageRefreshResult.self) { group in
            for account in accounts {
                group.addTask { [store, codex] in
                    do {
                        let home = await store.profileHome(id: account.id)
                        try Task.checkCancellation()
                        return .success(account.id, try await codex.readWeeklyUsage(profileHome: home))
                    } catch {
                        return .failure(account.id, error.localizedDescription)
                    }
                }
            }
            for await result in group {
                guard !Task.isCancelled else { continue }
                switch result {
                case let .success(id, usage):
                    guard accounts.contains(where: { $0.id == id }) else { continue }
                    usageStates[id] = .loaded(usage)
                    do {
                        try await store.cacheWeeklyUsage(usage, profileID: id)
                    } catch {
                        showError(error)
                    }
                case let .failure(id, message):
                    guard accounts.contains(where: { $0.id == id }) else { continue }
                    if let cached = usageStates[id]?.displayedUsage {
                        usageStates[id] = .stale(cached, message)
                    } else {
                        usageStates[id] = .unavailable(message)
                    }
                }
            }
        }
    }

    public func switchAccount(to id: UUID) async {
        guard !isMutating else { return }
        isMutating = true
        await cancelUsageRefresh()
        defer { isMutating = false; refreshWeeklyUsage() }
        do {
            try await syncActiveIdentity()
            guard id != activeAccountID else { return }
            remoteResults = []
            await remoteHandoff?.clearResults()
            try await switchService.switchAccount(to: id)
            apply(try await store.loadRegistry())
            await refreshSubscriptionSnapshots()
            activeIdentityConfirmed = true
        } catch let error as OperationError {
            if error.stage == .reopenDesktop {
                do {
                    apply(try await store.loadRegistry())
                    activeIdentityConfirmed = true
                } catch {
                    showError(error)
                    return
                }
                visibleError = OperationError(
                    stage: .reopenDesktop,
                    titleKey: "switched_reopen_title",
                    messageKey: "switched_reopen_message",
                    message: text("switched_reopen_message"),
                    underlyingDescription: error.underlyingDescription
                )
            } else {
                if error.stage == .saveCurrentCredential { activeIdentityConfirmed = false }
                visibleError = error
            }
        } catch {
            showError(error)
        }
        if let remoteHandoff { remoteResults = await remoteHandoff.results() }
    }

    public func addAccount() {
        guard !isMutating, !isAddingAccount else { return }
        visibleError = nil
        isAddingAccount = true
        addAccountTask = Task { [weak self] in
            guard let self else { return }
            await self.performAddAccount()
            self.isAddingAccount = false
            self.addAccountTask = nil
        }
    }

    public func cancelAddingAccount() {
        addAccountTask?.cancel()
    }

    private func performAddAccount() async {
        let id = UUID()
        do {
            let home = try await store.createProfileDirectory(id: id)
            try Task.checkCancellation()
            let identity = try await codex.login(profileHome: home)
            try Task.checkCancellation()
            let profile = AccountProfile(
                id: id,
                displayName: identity.suggestedDisplayName,
                email: identity.email,
                accountID: identity.accountID,
                createdAt: Date(),
                lastUsedAt: nil
            )
            try await store.addProfile(profile)
            apply(try await store.loadRegistry())
            await refreshSubscriptionSnapshots()
        } catch {
            let loginError = error
            do {
                try await store.discardUnregisteredProfile(id: id)
            } catch {
                showError(NSError(domain: "CodexAccountSwitcher.Login", code: 1, userInfo: [
                    NSLocalizedDescriptionKey: "\(loginError.localizedDescription) Removing the incomplete profile also failed: \(error.localizedDescription)",
                ]))
                return
            }
            if !(loginError is CancellationError) { showError(loginError) }
        }
    }

    public func registerCurrentAccount() async {
        guard !isMutating, !isAddingAccount else { return }
        isMutating = true
        await cancelUsageRefresh()
        defer { isMutating = false; refreshWeeklyUsage() }
        do {
            let identity = try await codex.readIdentity(profileHome: await store.activeCodexHome())
            try await store.registerActiveIdentity(identity)
            apply(try await store.loadRegistry())
            await refreshSubscriptionSnapshots()
            activeIdentityConfirmed = true
            visibleError = nil
        } catch { showError(error) }
    }

    public func removeAccount(id: UUID) async {
        guard !isMutating else { return }
        isMutating = true
        await cancelUsageRefresh()
        defer { isMutating = false; refreshWeeklyUsage() }
        do {
            try await syncActiveIdentity()
            try await store.removeAccount(id: id)
            apply(try await store.loadRegistry())
            usageStates[id] = nil
        } catch {
            showError(error)
        }
    }

    public func setLanguage(_ language: AppLanguage) async {
        settings.language = language
        do {
            try await store.saveSettings(settings)
        } catch {
            showError(error)
        }
    }

    public func setRemoteHosts(_ hosts: [SSHRemoteHost]) async {
        guard !isMutating else { return }
        isMutating = true
        defer { isMutating = false }
        do {
            guard hosts.count <= 8,
                  Set(hosts.map { $0.alias.lowercased() }).count == hosts.count,
                  Set(hosts.map(\.id)).count == hosts.count else {
                throw RemoteHandoffError.invalidConfiguration
            }
            for host in hosts { try host.validate() }
            var updated = settings
            updated.remoteHosts = hosts
            try await store.saveSettings(updated)
            settings = updated
            remoteResults.removeAll { result in !hosts.contains(where: { $0.id == result.hostID }) }
        } catch { showError(error) }
    }

    public func checkRemoteHost(_ host: SSHRemoteHost) async throws -> String {
        guard let remoteHandoff else { throw RemoteHandoffError.requirements }
        return try await remoteHandoff.check(host)
    }

    public func retryRemoteHost(_ hostID: UUID, expectedAccountID: UUID) async {
        guard !isMutating, let remoteHandoff else { return }
        isMutating = true
        await cancelUsageRefresh()
        defer { isMutating = false; refreshWeeklyUsage() }
        do {
            try await syncActiveIdentity()
            guard activeAccountID == expectedAccountID else { throw RemoteHandoffError.credentialChanged }
            try await remoteHandoff.retry(hostID: hostID, expectedAccountID: expectedAccountID)
        } catch { showError(error) }
        remoteResults = await remoteHandoff.results()
    }

    public func setShowsMenuBarPercentage(_ enabled: Bool) async {
        settings.showsMenuBarPercentage = enabled
        do {
            try await store.saveSettings(settings)
        } catch {
            showError(error)
        }
    }

    public func setShowsFiveHourUsage(_ enabled: Bool) async {
        settings.showsFiveHourUsage = enabled
        do {
            try await store.saveSettings(settings)
        } catch {
            showError(error)
        }
    }

    public func setStatusBarUsageWindow(_ window: StatusBarUsageWindow) async {
        settings.statusBarUsageWindow = window
        do {
            try await store.saveSettings(settings)
        } catch {
            showError(error)
        }
    }

    public func dismissError() {
        visibleError = nil
    }

    private func cancelUsageRefresh() async {
        usageRefreshTask?.cancel()
        await usageRefreshTask?.value
    }

    private func apply(_ registry: AccountRegistry) {
        accounts = registry.accounts
        activeAccountID = registry.activeAccountID
        usageStates = usageStates.filter { id, _ in registry.accounts.contains(where: { $0.id == id }) }
        subscriptionSnapshots = subscriptionSnapshots.filter { id, _ in registry.accounts.contains(where: { $0.id == id }) }
    }

    private func apply(_ cache: UsageCache) {
        let validAccountIDs = Set(accounts.map(\.id))
        for entry in cache.entries where validAccountIDs.contains(entry.profileID) {
            usageStates[entry.profileID] = .loaded(entry.usage)
        }
    }

    private func syncActiveIdentity() async throws {
        do {
            apply(try await store.syncActiveCredential())
            activeIdentityConfirmed = activeAccountID != nil || accounts.isEmpty
        } catch {
            activeAccountID = nil
            activeIdentityConfirmed = false
            throw error
        }
    }

    private func showError(_ error: any Error) {
        visibleError = OperationError(
            stage: nil,
            titleKey: "operation_failed",
            messageKey: (error as? RemoteHandoffError)?.localizationKey,
            message: error.localizedDescription,
            underlyingDescription: String(describing: error)
        )
    }
}
