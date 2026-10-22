#if os(macOS)
import Foundation
import Testing
@testable import SwitcherCore

struct SSHRemoteClientTests {
    @Test func quotedHelperAndLiteralPathsSurviveTheLoginShell() async throws {
        let fixture = try SSHFixture(body: """
        export SHELL=/bin/sh
        for command in "$@"; do :; done
        exec /bin/sh -c "$command"
        """, helper: """
        import json, sys
        request = json.load(sys.stdin)
        assert 'literal' in request['home']
        print(json.dumps({'protocolVersion': 1, 'ok': True, 'home': request['home']}))
        """)
        defer { fixture.remove() }
        let path = fixture.root.appending(path: "literal $(touch injected); 'quotes'").path
        #expect(try await fixture.client.check(SSHRemoteHost(alias: "dev", codexHome: path)) == path)
        #expect(!FileManager.default.fileExists(atPath: fixture.root.appending(path: "injected").path))
    }

    @Test func credentialsAndPathsUseStdinAndStrictSSHOptions() async throws {
        let fixture = try SSHFixture(body: """
        printf '%s\\n' "$@" > '\(SSHFixture.argumentFile)'
        """)
        defer { fixture.remove() }
        let secret = Data("test-only-secret".utf8)
        let host = SSHRemoteHost(alias: "dev-box", codexHome: "/literal/$(touch never); 'quotes'")
        try await fixture.client.sync(host, credential: secret, identity: AccountIdentity(accountID: "account-test", email: "test@example.test"))
        let arguments = try String(contentsOf: fixture.arguments, encoding: .utf8)
        #expect(arguments.contains("StrictHostKeyChecking=yes"))
        #expect(arguments.contains("BatchMode=yes"))
        #expect(arguments.contains("PermitLocalCommand=no"))
        #expect(arguments.contains("\n--\ndev-box\n"))
        #expect(!arguments.contains("test-only-secret"))
        #expect(!arguments.contains(secret.base64EncodedString()))
        #expect(!arguments.contains(host.codexHome))
        let payload = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: fixture.input)) as? [String: String])
        #expect(payload["credential"] == secret.base64EncodedString())
        #expect(payload["home"] == host.codexHome)
    }

    @Test func readOnlyCheckSendsNoCredentials() async throws {
        let fixture = try SSHFixture()
        defer { fixture.remove() }
        #expect(try await fixture.client.check(SSHRemoteHost(alias: "dev")) == "/home/test/.codex")
        let payload = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: fixture.input)) as? [String: String])
        #expect(payload["operation"] == "check")
        #expect(payload["credential"] == nil)
    }

    @Test func versionedPythonIsUsedWhenDefaultIsTooOldWithoutConsumingTheRequest() async throws {
        let fixture = try SSHFixture(body: SSHFixture.isolatedPythonShell)
        defer { fixture.remove() }
        let probed = fixture.root.appending(path: "old-python-probed")
        try fixture.addPythonCommand("python3", body: """
        /bin/cat >/dev/null
        printf '%s' 'probed' > '\(probed.path)'
        exit 1
        """)
        try fixture.addPythonCommand("python3.11", body: """
        case "$2" in
            *"fixed helper"*)
                /bin/cat > '\(fixture.input.path)'
                printf '%s' '{"protocolVersion":1,"ok":true}'
                ;;
            *) exit 0 ;;
        esac
        """)

        let secret = Data("test-only-secret".utf8)
        try await fixture.client.sync(SSHRemoteHost(alias: "dev"), credential: secret,
                                      identity: AccountIdentity(accountID: "account-test", email: nil))
        #expect(FileManager.default.fileExists(atPath: probed.path))
        let payload = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: fixture.input)) as? [String: String])
        #expect(payload["operation"] == "sync")
        #expect(payload["credential"] == secret.base64EncodedString())
    }

    @Test func missingCompatiblePythonReportsAnActionableError() async throws {
        let fixture = try SSHFixture(body: SSHFixture.isolatedPythonShell)
        defer { fixture.remove() }
        try fixture.addPythonCommand("python3", body: "printf '%s' 'test-only-secret'; exit 1")
        await #expect(throws: RemoteHandoffError.pythonUnavailable) {
            try await fixture.client.check(SSHRemoteHost(alias: "dev"))
        }
        #expect(!FileManager.default.fileExists(atPath: fixture.input.path))
    }

    @Test func unsafeAliasCannotStartAProcess() async throws {
        let fixture = try SSHFixture()
        defer { fixture.remove() }
        await #expect(throws: RemoteHandoffError.invalidConfiguration) {
            try await fixture.client.check(SSHRemoteHost(alias: "-oProxyCommand=bad"))
        }
        #expect(!FileManager.default.fileExists(atPath: fixture.input.path))
    }

    @Test func rawServerDiagnosticsNeverAppearInErrors() async throws {
        let fixture = try SSHFixture(reply: "test-only-secret")
        defer { fixture.remove() }
        await #expect(throws: RemoteHandoffError.invalidResponse) {
            try await fixture.client.check(SSHRemoteHost(alias: "dev"))
        }
    }

    @Test(arguments: [RemoteHandoffError.restorationFailed, .runtimeRestart, .runtimeVerification])
    func boundedRemoteErrorsKeepTheirFailureCategory(error: RemoteHandoffError) async throws {
        let fixture = try SSHFixture(reply: "{\"protocolVersion\":1,\"ok\":false,\"error\":\"\(error.rawValue)\"}")
        defer { fixture.remove() }
        await #expect(throws: error) {
            try await fixture.client.check(SSHRemoteHost(alias: "dev"))
        }
    }

    @Test func timeoutTerminatesOnlyTheInvocation() async throws {
        let fixture = try SSHFixture(body: "exec /bin/sleep 10", timeout: 0.1)
        defer { fixture.remove() }
        let clock = ContinuousClock(), started = clock.now
        await #expect(throws: RemoteHandoffError.timeout) { try await fixture.client.check(SSHRemoteHost(alias: "dev")) }
        #expect(started.duration(to: clock.now) < .seconds(3))
    }

    @Test func cancellationDoesNotWaitForTheSSHTimeout() async throws {
        let fixture = try SSHFixture(body: "exec /bin/sleep 10")
        defer { fixture.remove() }
        let clock = ContinuousClock(), started = clock.now
        let task = Task { try await fixture.client.check(SSHRemoteHost(alias: "dev")) }
        try await Task.sleep(for: .milliseconds(100))
        task.cancel()
        do { _ = try await task.value; Issue.record("Expected cancellation") }
        catch { #expect(error is CancellationError || error as? RemoteHandoffError == .unavailable) }
        #expect(started.duration(to: clock.now) < .seconds(3))
    }

    @Test func excessiveOutputIsBoundedAndRedacted() async throws {
        let fixture = try SSHFixture(body: "exec /usr/bin/yes test-only-secret")
        defer { fixture.remove() }
        await #expect(throws: RemoteHandoffError.invalidResponse) {
            try await fixture.client.check(SSHRemoteHost(alias: "dev"))
        }
    }

    @Test func earlySSHExitWhileSendingCredentialsDoesNotTerminateTheApp() async throws {
        let fixture = try SSHFixture(body: "exit 0")
        defer { fixture.remove() }
        await #expect(throws: RemoteHandoffError.invalidResponse) {
            try await fixture.client.sync(SSHRemoteHost(alias: "dev"), credential: Data(repeating: 65, count: 1_048_576),
                                          identity: AccountIdentity(accountID: "test-account", email: nil))
        }
    }
}

private struct SSHFixture {
    // Placeholder substituted by the fixture, never shared between concurrently running tests.
    static let argumentFile = "ARGUMENT_FILE_PLACEHOLDER"
    // Emulate a login shell without system profiles adding real interpreters to the test PATH.
    static let isolatedPythonShell = """
    export PATH="${0%/*}/bin"
    if [ "$1" = "-lc" ]; then
        exec /bin/sh -c "$2"
    fi
    export SHELL="$0"
    for command in "$@"; do :; done
    exec /bin/sh -c "$command"
    """
    let root: URL
    let arguments: URL
    let input: URL
    let client: SSHRemoteClient

    init(body: String = "", reply: String = #"{"protocolVersion":1,"ok":true,"home":"/home/test/.codex"}"#,
         timeout: TimeInterval = 5, helper: String = "print('fixed helper')") throws {
        let root = FileManager.default.temporaryDirectory.appending(path: "ssh-client-\(UUID())")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        self.root = root
        arguments = root.appending(path: "arguments")
        input = root.appending(path: "input")
        let executable = root.appending(path: "fake ssh")
        let source = """
        #!/bin/sh
        cd '\(root.path)' || exit 1
        \(body.replacingOccurrences(of: Self.argumentFile, with: arguments.path))
        cat > '\(input.path)'
        printf '%s' '\(reply)'
        """
        try Data(source.utf8).write(to: executable)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)
        client = SSHRemoteClient(helperSource: helper, executable: executable, timeout: timeout)
    }

    func addPythonCommand(_ name: String, body: String) throws {
        let directory = root.appending(path: "bin")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let executable = directory.appending(path: name)
        try Data(("#!/bin/sh\n" + body + "\n").utf8).write(to: executable)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)
    }

    func remove() { try? FileManager.default.removeItem(at: root) }
}
#endif
