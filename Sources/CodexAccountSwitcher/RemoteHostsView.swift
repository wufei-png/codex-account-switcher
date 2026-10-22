import SwitcherCore
import SwiftUI

struct RemoteHostsView: View {
    @ObservedObject var model: AppModel
    let onBack: () -> Void
    let onSync: (SSHRemoteHost) -> Void
    @State private var alias = ""
    @State private var home = ""
    @State private var checking: UUID?
    @State private var checks: [UUID: String] = [:]

    var body: some View {
        VStack(spacing: 0) {
            PopoverHeader(title: model.text("remote_hosts"), backTitle: model.text("back"), onBack: onBack)
            Divider()
            if model.isMutating {
                Text(model.text("remote_working")).font(.caption).foregroundStyle(.secondary).padding(8)
            }
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    Text(model.text("remote_intro")).foregroundStyle(.secondary)
                    Text(model.text("remote_trust")).foregroundStyle(.secondary)
                    ForEach(model.settings.remoteHosts) { host in hostRow(host) }
                    ForEach(model.remoteResults.filter { result in
                        !model.settings.remoteHosts.contains(where: { $0.id == result.hostID })
                    }, id: \.hostID) { result in
                        Text(model.text(result.error?.localizationKey ?? "remote_synced")).foregroundStyle(.orange)
                    }
                    Divider()
                    TextField(model.text("remote_alias"), text: $alias)
                    TextField(model.text("remote_home"), text: $home)
                    Text(model.text("remote_home_hint")).font(.caption).foregroundStyle(.secondary)
                    Button(model.text("remote_add")) {
                        let host = SSHRemoteHost(alias: alias.trimmingCharacters(in: .whitespacesAndNewlines),
                                                 codexHome: home.trimmingCharacters(in: .whitespacesAndNewlines))
                        Task {
                            await model.setRemoteHosts(model.settings.remoteHosts + [host])
                            if model.settings.remoteHosts.contains(where: { $0.id == host.id }) {
                                alias = ""; home = ""
                            }
                        }
                    }
                    .disabled(alias.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                              || model.settings.remoteHosts.count >= 8)
                }
                .padding(14)
                .textFieldStyle(.roundedBorder)
            }
            .frame(height: 440)
        }
        .font(.system(size: 12))
        .controlSize(.small)
        .disabled(model.isMutating)
    }

    private func hostRow(_ host: SSHRemoteHost) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(host.alias).fontWeight(.semibold)
                Spacer()
                Button(model.text("remove")) {
                    Task { await model.setRemoteHosts(model.settings.remoteHosts.filter { $0.id != host.id }) }
                }
                .buttonStyle(.link)
            }
            if !host.codexHome.isEmpty {
                Text(host.codexHome).foregroundStyle(.secondary).textSelection(.enabled)
            }
            Toggle(model.text("remote_enable"), isOn: Binding(
                get: { model.settings.remoteHosts.first(where: { $0.id == host.id })?.isEnabled ?? false },
                set: { enabled in
                    var hosts = model.settings.remoteHosts
                    guard let index = hosts.firstIndex(where: { $0.id == host.id }) else { return }
                    hosts[index].isEnabled = enabled
                    Task { await model.setRemoteHosts(hosts) }
                }
            ))
            .toggleStyle(.switch)
            HStack {
                Button(model.text(checking == host.id ? "remote_testing" : "remote_test")) {
                    checking = host.id
                    Task {
                        defer { checking = nil }
                        do { checks[host.id] = model.format("remote_ready", try await model.checkRemoteHost(host)) }
                        catch { checks[host.id] = model.text((error as? RemoteHandoffError ?? .unavailable).localizationKey) }
                    }
                }
                .disabled(checking != nil)
                Button(model.text("remote_sync")) { onSync(host) }
                    .disabled(!host.isEnabled || model.activeAccountID == nil || checking != nil)
            }
            if let check = checks[host.id] {
                Text(check).font(.caption).foregroundStyle(.secondary)
            }
            if let result = model.remoteResults.first(where: { $0.hostID == host.id }) {
                Text(model.text(result.error?.localizationKey ?? "remote_synced"))
                    .font(.caption)
                    .foregroundStyle(result.error == nil ? Color.secondary : Color.orange)
                if let account = result.accountLabel {
                    Text(model.format("remote_result_account", account)).font(.caption).foregroundStyle(.secondary)
                }
                Text(result.checkedAt, style: .time).font(.caption).foregroundStyle(.secondary)
            }
            Divider()
        }
    }
}
