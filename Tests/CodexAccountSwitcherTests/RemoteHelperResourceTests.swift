import Foundation
import Testing
@testable import CodexAccountSwitcher

@MainActor
struct RemoteHelperResourceTests {
    @Test func packagedAppFindsHelperInsideContentsResources() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: "ssh-resource-\(UUID()).app")
        defer { try? FileManager.default.removeItem(at: root) }
        let resources = root.appending(path: "Contents/Resources")
        let bundle = resources.appending(path: "CodexAccountSwitcher_CodexAccountSwitcher.bundle")
        try FileManager.default.createDirectory(at: bundle, withIntermediateDirectories: true)
        let source = "# synthetic packaged helper\n"
        try Data(source.utf8).write(to: bundle.appending(path: "remote-handoff.py"))
        #expect(AppModel.bundledRemoteHelper(in: [resources, root]) == source)
        #expect(AppModel.bundledRemoteHelper(in: [root]) == nil)
    }
}
