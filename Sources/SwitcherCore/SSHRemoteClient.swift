#if os(macOS)
import Darwin
import Foundation

/// One bounded SSH invocation per host. Credentials travel only over the child's stdin.
public struct SSHRemoteClient: RemoteHandoffClient {
    private let helperSource: String
    private let executable: URL
    private let timeout: TimeInterval

    public init(helperSource: String, executable: URL = URL(fileURLWithPath: "/usr/bin/ssh"),
                timeout: TimeInterval = 90) {
        self.helperSource = helperSource; self.executable = executable; self.timeout = timeout
    }

    public func check(_ host: SSHRemoteHost) async throws -> String {
        try await request(host, operation: "check").home ?? ""
    }

    public func sync(_ host: SSHRemoteHost, credential: Data, identity: AccountIdentity) async throws {
        _ = try await request(host, operation: "sync", credential: credential, identity: identity)
    }

    private struct Reply: Decodable {
        let protocolVersion: Int
        let ok: Bool
        let error: String?
        let home: String?
    }

    private func request(_ host: SSHRemoteHost, operation: String, credential: Data? = nil,
                         identity: AccountIdentity? = nil) async throws -> Reply {
        try host.validate()
        guard !helperSource.isEmpty else { throw RemoteHandoffError.requirements }
        var payload: [String: String] = ["operation": operation, "home": host.codexHome]
        payload["credential"] = credential?.base64EncodedString()
        payload["accountID"] = identity?.accountID
        payload["email"] = identity?.email
        // A login shell matches Desktop's PATH and CODEX_HOME resolution. Only fixed helper code
        // appears in the command; aliases are separate argv entries and paths are stdin data.
        let pythonCommand = """
        for python in python3 python3.15 python3.14 python3.13 python3.12 python3.11; do
            if "$python" -c 'import sys, tomllib; sys.exit(sys.version_info < (3, 11))' </dev/null >/dev/null 2>&1; then
                exec "$python" -c \(Self.quote(helperSource))
            fi
        done
        printf '%s\\n' '{"protocolVersion":1,"ok":false,"error":"python_unavailable"}'
        """
        // Keep selection syntax portable even when the login shell is fish. Probes must not
        // consume the request on stdin before the selected interpreter runs the helper.
        let command = "exec \"$SHELL\" -lc " + Self.quote("exec /bin/sh -c " + Self.quote(pythonCommand))
        let arguments = ["-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                         "-o", "ConnectTimeout=8", "-o", "ConnectionAttempts=1",
                         "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=2",
                         "-o", "ClearAllForwardings=yes", "-o", "ForwardAgent=no",
                         "-o", "PermitLocalCommand=no", "-o", "ControlPath=none",
                         "-o", "LogLevel=ERROR", "--", host.alias, command]
        let bytes = try await SSHInvocation(executable: executable, arguments: arguments, timeout: timeout)
            .run(input: JSONSerialization.data(withJSONObject: payload))
        // Login banners and remote diagnostics are untrusted and may include secrets. Never expose
        // raw stdout/stderr or decoder diagnostics. Require one exact protocol response.
        guard let reply = try? JSONDecoder().decode(Reply.self, from: bytes), reply.protocolVersion == 1 else {
            throw RemoteHandoffError.invalidResponse
        }
        guard reply.ok else {
            throw reply.error.flatMap(RemoteHandoffError.init(rawValue:)) ?? .invalidResponse
        }
        return reply
    }

    private static func quote(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\"'\"'") + "'"
    }
}

private final class SSHInvocation: @unchecked Sendable {
    private let process = Process()
    private let inputPipe = Pipe()
    private let outputPipe = Pipe()
    private let timeout: TimeInterval
    private let lock = NSLock()
    private var stopped: RemoteHandoffError?

    init(executable: URL, arguments: [String], timeout: TimeInterval) {
        process.executableURL = executable
        process.arguments = arguments
        process.standardInput = inputPipe
        process.standardOutput = outputPipe
        process.standardError = FileHandle.nullDevice
        self.timeout = timeout
    }

    func run(input: Data) async throws -> Data {
        try Task.checkCancellation()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                DispatchQueue.global().async { [self] in
                    do {
                        // A disconnected/timed-out SSH child can close stdin before this writer runs.
                        // Suppress SIGPIPE on this pipe only; never change the app's signal disposition.
                        guard Darwin.fcntl(inputPipe.fileHandleForWriting.fileDescriptor, F_SETNOSIGPIPE, 1) == 0 else {
                            throw RemoteHandoffError.unavailable
                        }
                        try process.run()
                        try? inputPipe.fileHandleForReading.close()
                        try? outputPipe.fileHandleForWriting.close()
                        if lock.withLock({ stopped != nil }) { stop(.unavailable) }
                        let timer = DispatchWorkItem { [self] in stop(.timeout) }
                        DispatchQueue.global().asyncAfter(deadline: .now() + timeout, execute: timer)
                        defer { timer.cancel() }
                        DispatchQueue.global().async { [self] in
                            try? inputPipe.fileHandleForWriting.write(contentsOf: input)
                            try? inputPipe.fileHandleForWriting.close()
                        }
                        var bytes = Data()
                        while let chunk = try outputPipe.fileHandleForReading.read(upToCount: 4096), !chunk.isEmpty {
                            guard bytes.count + chunk.count <= 65_536 else {
                                stop(.invalidResponse)
                                break
                            }
                            bytes.append(chunk)
                        }
                        process.waitUntilExit()
                        try? outputPipe.fileHandleForReading.close()
                        if let error = lock.withLock({ stopped }) { throw error }
                        guard process.terminationStatus == 0 else { throw RemoteHandoffError.unavailable }
                        continuation.resume(returning: bytes)
                    } catch {
                        stop(.unavailable)
                        try? inputPipe.fileHandleForWriting.close()
                        try? outputPipe.fileHandleForReading.close()
                        continuation.resume(throwing: error as? RemoteHandoffError ?? .unavailable)
                    }
                }
            }
        } onCancel: { self.stop(.unavailable) }
    }

    private func stop(_ reason: RemoteHandoffError) {
        lock.withLock {
            if stopped == nil { stopped = reason }
            guard process.isRunning else { return }
            process.terminate()
            // Only this invocation's SSH child can be killed. Never signal Desktop or remote CLI jobs.
            DispatchQueue.global().asyncAfter(deadline: .now() + 1) { [self] in
                lock.withLock {
                    if process.isRunning { _ = Darwin.kill(process.processIdentifier, SIGKILL) }
                }
            }
        }
    }
}
#endif
