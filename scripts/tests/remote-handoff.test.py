"""Exercise the production helper with isolated homes and a fake Codex RPC process."""
import base64
import ctypes
import errno
import fcntl
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import signal
import socket
import socketserver
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

HELPER = Path(__file__).resolve().parents[2] / "Sources/CodexAccountSwitcher/Resources/remote-handoff.py"
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("remote_handoff", HELPER)
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


def credential(account="account-b", email="b@example.test", secret="test-only-secret"):
    claims = {"email": email, "https://api.openai.com/auth": {"chatgpt_account_id": account}}
    token = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return json.dumps({"tokens": {"account_id": account, "id_token": "header." + token + ".signature",
                                  "access_token": secret, "refresh_token": "test-only-refresh"}}).encode()


class CachedRuntime(socketserver.ThreadingUnixStreamServer):
    """A live socket whose cached account does not follow auth.json writes."""
    daemon_threads = True

    def __init__(self, home, cached):
        parent = home / "app-server-control"
        parent.mkdir(mode=0o700, exist_ok=True)
        self.cached = cached
        super().__init__(str(parent / "app-server-control.sock"), RuntimeRequest)

    def __enter__(self):
        self.worker = threading.Thread(target=self.serve_forever, daemon=True)
        self.worker.start()
        return self

    def __exit__(self, *args):
        self.shutdown()
        self.server_close()
        self.worker.join()


class RuntimeRequest(socketserver.StreamRequestHandler):
    def handle(self):
        self.rfile.readline()
        headers = {}
        while True:
            line = self.rfile.readline().strip()
            if not line:
                break
            name, value = line.split(b":", 1)
            headers[name.lower()] = value.strip()
        accept = base64.b64encode(hashlib.sha1(headers[b"sec-websocket-key"] + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest())
        self.wfile.write(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + b"\r\n\r\n")
        while True:
            start = self.rfile.read(2)
            if len(start) != 2:
                return
            length = start[1] & 127
            if length == 126:
                length = struct.unpack("!H", self.rfile.read(2))[0]
            assert start[1] & 128
            mask = self.rfile.read(4)
            payload = self.rfile.read(length)
            request = json.loads(bytes(value ^ mask[index % 4] for index, value in enumerate(payload)))
            if "id" not in request:
                continue
            tokens = json.loads(self.server.cached)["tokens"]
            claims = json.loads(base64.urlsafe_b64decode(tokens["id_token"].split(".")[1] + "==="))
            result = {}
            if request["method"] == "account/read":
                assert request["params"]["refreshToken"] is False
                result = {"account": {"type": "chatgpt", "email": claims["email"]}}
            elif request["method"] == "getAuthStatus":
                assert request["params"]["refreshToken"] is False
                result = {"authMethod": "chatgpt", "authToken": tokens["id_token"]}
            # Fragmented responses and a ping exercise control-frame handling too.
            data = json.dumps({"id": request["id"], "result": result}).encode()
            cut = len(data) // 2
            for opcode, chunk in [(0x01, data[:cut]), (0x89, b"ping"), (0x80, data[cut:])]:
                frame = bytes([opcode, len(chunk)]) if len(chunk) < 126 else bytes([opcode, 126]) + struct.pack("!H", len(chunk))
                self.wfile.write(frame + chunk)
            # The client answers each ping with a masked pong before its next RPC.
            pong = self.rfile.read(2)
            assert pong[0] == 0x8A
            mask = self.rfile.read(4)
            assert self.rfile.read(pong[1] & 127) == bytes(value ^ mask[index % 4] for index, value in enumerate(b"ping"))


class HelperTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="rh-", dir="/tmp")
        self.root = Path(self.temporary.name).resolve()
        self.home = self.root / "codex home ' with spaces"
        self.home.mkdir(mode=0o700)
        self.original = credential("account-a", "a@example.test")
        self.target = credential()
        self.auth = self.home / "auth.json"
        self.auth.write_bytes(self.original)
        self.auth.chmod(0o600)
        fixture = self.root / "fixture.py"
        fixture.write_text('''import json, os, sys
for line in sys.stdin:
    request = json.loads(line)
    if request.get("id") == 0:
        print(json.dumps({"id": 0, "result": {}}), flush=True)
    elif request.get("method") == "account/read":
        assert request["params"]["refreshToken"] is False
        mode = os.environ.get("HANDOFF_FIXTURE_MODE", "ok")
        if mode == "malformed":
            print("test-only-secret", flush=True)
        else:
            email = "wrong@example.test" if mode == "mismatch" else "b@example.test"
            print(json.dumps({"id": 1, "result": {"account": {"type": "chatgpt", "email": email}}}), flush=True)
''')
        executable = self.root / "codex"
        executable.write_text("#!/bin/sh\nexec " + shlex.quote(sys.executable) + " " + shlex.quote(str(fixture)) + "\n")
        executable.chmod(0o700)
        self.environment = patch.dict(os.environ, {"PATH": str(self.root) + os.pathsep + os.environ["PATH"],
                                                  "HANDOFF_FIXTURE_MODE": "ok"})
        self.environment.start()
        self.directory = os.open(self.home, os.O_RDONLY | os.O_DIRECTORY)

    def tearDown(self):
        os.close(self.directory)
        self.environment.stop()
        self.temporary.cleanup()

    def request(self, **updates):
        value = {"operation": "sync", "home": str(self.home),
                 "credential": base64.b64encode(self.target).decode(),
                 "accountID": "account-b", "email": "b@example.test"}
        value.update(updates)
        return value

    def invoke(self, request):
        result = subprocess.run([sys.executable, str(HELPER)], input=json.dumps(request).encode(),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=self.root, timeout=10, check=True)
        self.assertEqual(result.stderr, b"")
        self.assertNotIn(b"test-only-secret", result.stdout)
        self.assertNotIn(b"test-only-refresh", result.stdout)
        return json.loads(result.stdout)

    def test_read_only_check_does_not_create_or_modify_files(self):
        before = {p.name: (p.read_bytes(), p.stat().st_mode) for p in self.home.iterdir()}
        self.assertTrue(self.invoke({"operation": "check", "home": str(self.home)})["ok"])
        after = {p.name: (p.read_bytes(), p.stat().st_mode) for p in self.home.iterdir()}
        self.assertEqual(before, after)

    def test_sync_installs_exact_bytes_with_private_permissions(self):
        self.assertTrue(self.invoke(self.request())["ok"])
        self.assertEqual(self.auth.read_bytes(), self.target)
        self.assertEqual(stat.S_IMODE(self.auth.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.home.stat().st_mode), 0o700)
        self.assertFalse(list(self.home.glob("*.tmp")))

    def test_failed_verification_restores_original(self):
        os.environ["HANDOFF_FIXTURE_MODE"] = "mismatch"
        self.assertEqual(self.invoke(self.request())["error"], "verification")
        self.assertEqual(self.auth.read_bytes(), self.original)

    def test_cached_desktop_account_is_restarted_and_verified(self):
        with CachedRuntime(self.home, self.original) as server:
            def restart(directory, home, runtime):
                self.assertEqual(self.auth.read_bytes(), self.target)
                self.assertEqual(runtime.pid, os.getpid())
                server.cached = self.target

            with patch.object(helper, "restart_runtime", side_effect=restart) as restarted:
                helper.sync(self.directory, str(self.home), self.request())
            restarted.assert_called_once()
            self.assertEqual(server.cached, self.target)
        self.assertEqual(self.auth.read_bytes(), self.target)

    def test_still_cached_old_account_cannot_report_success(self):
        with CachedRuntime(self.home, self.original):
            with patch.object(helper, "restart_runtime"), self.assertRaisesRegex(helper.HandoffError, "runtime_verification"):
                helper.sync(self.directory, str(self.home), self.request())
        self.assertEqual(self.auth.read_bytes(), self.original)

    def test_same_email_with_wrong_runtime_workspace_is_rejected(self):
        with CachedRuntime(self.home, credential("different-workspace", "b@example.test")):
            with patch.object(helper, "restart_runtime"), self.assertRaisesRegex(helper.HandoffError, "runtime_verification"):
                helper.sync(self.directory, str(self.home), self.request())
        self.assertEqual(self.auth.read_bytes(), self.original)

    def test_runtime_restart_failure_restores_file_and_reports_uncertainty(self):
        with CachedRuntime(self.home, self.original):
            with patch.object(helper, "restart_runtime", side_effect=OSError("test-only-secret")):
                with self.assertRaisesRegex(helper.HandoffError, "runtime_restart"):
                    helper.sync(self.directory, str(self.home), self.request())
        self.assertEqual(self.auth.read_bytes(), self.original)

    def test_private_codex_socket_symlink_is_supported(self):
        other = self.root / "runtime"
        other.mkdir(mode=0o700)
        parent = self.home / "app-server-control"
        parent.mkdir(mode=0o700)
        with CachedRuntime(other, self.original) as server:
            (parent / "app-server-control.sock").symlink_to(other / "app-server-control/app-server-control.sock")
            with patch.object(helper, "restart_runtime", side_effect=lambda *_: setattr(server, "cached", self.target)):
                helper.sync(self.directory, str(self.home), self.request())
        self.assertEqual(self.auth.read_bytes(), self.target)

    def test_socket_in_shared_writable_directory_is_rejected(self):
        other = self.root / "runtime"
        other.mkdir(mode=0o700)
        parent = self.home / "app-server-control"
        parent.mkdir(mode=0o700)
        with CachedRuntime(other, self.original):
            (other / "app-server-control").chmod(0o777)
            (parent / "app-server-control.sock").symlink_to(other / "app-server-control/app-server-control.sock")
            with patch.object(helper, "restart_runtime") as restarted:
                with self.assertRaisesRegex(helper.HandoffError, "runtime_verification"):
                    helper.sync(self.directory, str(self.home), self.request())
            restarted.assert_not_called()
        self.assertEqual(self.auth.read_bytes(), self.original)

    def test_disconnected_desktop_does_not_block_sync(self):
        parent = self.home / "app-server-control"
        parent.mkdir(mode=0o700)
        published = parent / "app-server-control.sock"
        for stale in ("missing-target", "no-listener"):
            with self.subTest(stale=stale):
                published.unlink(missing_ok=True)
                if stale == "missing-target":
                    published.symlink_to(self.root / "removed-runtime/socket")
                else:
                    with socket.socket(socket.AF_UNIX) as listener:
                        listener.bind(str(published))
                self.auth.write_bytes(self.original)
                with patch.object(helper, "restart_runtime") as restarted:
                    helper.sync(self.directory, str(self.home), self.request())
                restarted.assert_not_called()
                self.assertEqual(self.auth.read_bytes(), self.target)
                published.unlink()

    def test_unmanaged_restart_signals_only_the_socket_peer(self):
        (self.home / "app-server-control").mkdir(mode=0o700)
        peer = Mock(pid=12345)
        descriptor = os.open(os.devnull, os.O_RDONLY)
        events = []
        with patch.object(helper.sys, "platform", "linux"), \
                patch.object(helper, "peer_executable", return_value="/fixture/codex"), \
                patch.object(helper, "desktop_runtime", side_effect=lambda *_: (events.append("peer-checked"), peer)[1]), \
                patch.object(helper.subprocess, "run", return_value=Mock(returncode=1)), \
                patch.object(helper.os, "pidfd_open", side_effect=lambda *_: (events.append("process-bound"), descriptor)[1], create=True) as opened, \
                patch.object(helper.signal, "pidfd_send_signal", side_effect=lambda *_: self.assertTrue(peer.close.called), create=True) as signaled, \
                patch.object(helper.select, "select", return_value=([descriptor], [], [])), \
                patch.object(helper.subprocess, "Popen") as launched:
            helper.restart_runtime(self.directory, str(self.home), peer)
        opened.assert_called_once_with(12345)
        self.assertEqual(events, ["process-bound", "peer-checked"])
        signaled.assert_called_once_with(descriptor, signal.SIGTERM)
        self.assertEqual(launched.call_args.args[0], ["/fixture/codex", "-c", "features.code_mode_host=true", "app-server", "--listen", "unix://"])
        self.assertEqual(launched.call_args.kwargs["env"]["CODEX_HOME"], str(self.home))
        self.assertTrue(launched.call_args.kwargs["start_new_session"])

    def test_service_that_does_not_exit_is_never_force_killed(self):
        peer = Mock(pid=12345)
        descriptor = os.open(os.devnull, os.O_RDONLY)
        with patch.object(helper.sys, "platform", "linux"), \
                patch.object(helper, "peer_executable", return_value="/fixture/codex"), \
                patch.object(helper, "desktop_runtime", return_value=peer), \
                patch.object(helper.subprocess, "run", return_value=Mock(returncode=1)), \
                patch.object(helper.os, "pidfd_open", return_value=descriptor, create=True), \
                patch.object(helper.signal, "pidfd_send_signal", create=True) as signaled, \
                patch.object(helper.select, "select", return_value=([], [], [])), \
                patch.object(helper.subprocess, "Popen") as launched:
            with self.assertRaisesRegex(helper.HandoffError, "runtime_restart"):
                helper.restart_runtime(self.directory, str(self.home), peer)
        signaled.assert_called_once_with(descriptor, signal.SIGTERM)
        launched.assert_not_called()

    def test_changed_peer_after_process_binding_is_not_signaled(self):
        descriptor = os.open(os.devnull, os.O_RDONLY)
        with patch.object(helper.sys, "platform", "linux"), \
                patch.object(helper, "peer_executable", return_value="/fixture/codex"), \
                patch.object(helper, "desktop_runtime", return_value=Mock(pid=54321)), \
                patch.object(helper.subprocess, "run", return_value=Mock(returncode=1)), \
                patch.object(helper.os, "pidfd_open", return_value=descriptor, create=True), \
                patch.object(helper.signal, "pidfd_send_signal", create=True) as signaled, \
                patch.object(helper.subprocess, "Popen") as launched:
            with self.assertRaisesRegex(helper.HandoffError, "runtime_restart"):
                helper.restart_runtime(self.directory, str(self.home), Mock(pid=12345))
        signaled.assert_not_called()
        launched.assert_not_called()
        with self.assertRaises(OSError):
            os.fstat(descriptor)

    def test_linux_without_pidfd_is_rejected_before_credential_changes(self):
        for error in (OSError(errno.ENOSYS, "unsupported syscall"),
                      PermissionError(errno.EPERM, "blocked syscall"), AttributeError("missing API")):
            with self.subTest(error=type(error).__name__), \
                    patch.object(helper.sys, "platform", "linux"), \
                    patch.object(helper.os, "pidfd_open", side_effect=error, create=True), \
                    patch.object(helper.sys, "stdin", Mock(buffer=io.BytesIO(json.dumps(self.request()).encode()))), \
                    patch.object(helper.sys, "stdout", new_callable=io.StringIO) as output:
                helper.main()
            self.assertEqual(json.loads(output.getvalue())["error"], "requirements")
            self.assertEqual(self.auth.read_bytes(), self.original)
            self.assertFalse((self.home / ".account-switcher-handoff.lock").exists())

    def test_linux_capability_check_closes_its_process_handle(self):
        descriptor = os.open(os.devnull, os.O_RDONLY)
        with patch.object(helper.sys, "platform", "linux"), \
                patch.object(helper.os, "pidfd_open", return_value=descriptor, create=True) as opened, \
                patch.object(helper.signal, "pidfd_send_signal", create=True) as checked:
            helper.validate_requirements(self.directory)
        opened.assert_called_once_with(os.getpid())
        checked.assert_called_once_with(descriptor, 0)
        with self.assertRaises(OSError):
            os.fstat(descriptor)

    def test_missing_python_pidfd_apis_use_the_same_kernel_operations(self):
        descriptor = os.open(os.devnull, os.O_RDONLY)
        with patch.object(helper.sys, "platform", "linux"), \
                patch.object(helper.os, "pidfd_open", None, create=True), \
                patch.object(helper.signal, "pidfd_send_signal", None, create=True), \
                patch.object(helper, "linux_pidfd", side_effect=[descriptor, 0]) as syscall:
            helper.validate_requirements(self.directory)
        self.assertEqual([call.args for call in syscall.call_args_list],
                         [("pidfd_open", os.getpid(), 0), ("pidfd_send_signal", descriptor, 0, 0, 0)])
        with self.assertRaises(OSError):
            os.fstat(descriptor)

    def test_native_pidfd_syscall_preserves_kernel_errors(self):
        library = Mock(pidfd_open=None, pidfd_send_signal=None)
        library.syscall.return_value = -1
        with patch.object(helper.sys, "platform", "linux"), \
                patch.object(helper.os, "uname", return_value=Mock(machine="x86_64")), \
                patch.object(ctypes, "CDLL", return_value=library), \
                patch.object(ctypes, "get_errno", return_value=errno.EPERM):
            with self.assertRaises(OSError) as raised:
                helper.linux_pidfd("pidfd_open", 12345, 0)
        self.assertEqual(raised.exception.errno, errno.EPERM)
        self.assertEqual([value.value for value in library.syscall.call_args.args], [434, 12345, 0])

    def test_libc_pidfd_interfaces_do_not_need_raw_syscall_abi_mapping(self):
        library = Mock()
        library.pidfd_open.return_value = 41
        library.pidfd_send_signal.return_value = 0
        with patch.object(helper.sys, "platform", "linux"), \
                patch.object(helper.os, "uname") as architecture, \
                patch.object(ctypes, "CDLL", return_value=library):
            self.assertEqual(helper.linux_pidfd("pidfd_open", 12345, 0), 41)
            self.assertEqual(helper.linux_pidfd("pidfd_send_signal", 41, 0, 0, 0), 0)
        architecture.assert_not_called()
        library.syscall.assert_not_called()
        library.pidfd_open.assert_called_once_with(12345, 0)
        self.assertEqual(library.pidfd_open.argtypes, [ctypes.c_int, ctypes.c_uint])
        library.pidfd_send_signal.assert_called_once_with(41, 0, 0, 0)
        self.assertEqual(library.pidfd_send_signal.argtypes,
                         [ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint])

    def test_raw_pidfd_syscall_numbers_match_supported_64_bit_abis(self):
        for machine in ("x86_64", "aarch64"):
            library = Mock(pidfd_open=None, pidfd_send_signal=None)
            library.syscall.return_value = 41
            with self.subTest(machine=machine), \
                    patch.object(helper.sys, "platform", "linux"), \
                    patch.object(helper.os, "uname", return_value=Mock(machine=machine)), \
                    patch.object(ctypes, "CDLL", return_value=library):
                self.assertEqual(helper.linux_pidfd("pidfd_open", 12345, 0), 41)
                helper.linux_pidfd("pidfd_send_signal", 41, signal.SIGTERM, 0, 0)
            self.assertEqual([[value.value for value in call.args] for call in library.syscall.call_args_list],
                             [[434, 12345, 0], [424, 41, signal.SIGTERM, 0, 0]])

    def test_native_pidfd_rejection_stops_before_credential_changes(self):
        for code in (errno.ENOSYS, errno.EPERM):
            with self.subTest(errno=code), \
                    patch.object(helper.sys, "platform", "linux"), \
                    patch.object(helper.os, "pidfd_open", None, create=True), \
                    patch.object(helper.signal, "pidfd_send_signal", None, create=True), \
                    patch.object(helper, "linux_pidfd", side_effect=OSError(code, "unavailable")), \
                    patch.object(helper.sys, "stdin", Mock(buffer=io.BytesIO(json.dumps(self.request()).encode()))), \
                    patch.object(helper.sys, "stdout", new_callable=io.StringIO) as output:
                helper.main()
            self.assertEqual(json.loads(output.getvalue())["error"], "requirements")
            self.assertEqual(self.auth.read_bytes(), self.original)
            self.assertFalse((self.home / ".account-switcher-handoff.lock").exists())

    def test_native_pidfd_syscall_rejects_unknown_abis(self):
        for machine, width in (("mips64", 8), ("x86_64", 4)):
            library = Mock(pidfd_open=None, pidfd_send_signal=None)
            with self.subTest(machine=machine, width=width), \
                    patch.object(helper.sys, "platform", "linux"), \
                    patch.object(helper.os, "uname", return_value=Mock(machine=machine)), \
                    patch.object(ctypes, "sizeof", return_value=width), \
                    patch.object(ctypes, "CDLL", return_value=library):
                with self.assertRaises(OSError) as raised:
                    helper.linux_pidfd("pidfd_open", 12345, 0)
            self.assertEqual(raised.exception.errno, errno.ENOSYS)
            library.syscall.assert_not_called()

    @unittest.skipUnless(sys.platform == "linux", "requires Linux pidfd syscalls")
    def test_native_pidfd_probe_without_python_wrappers_on_linux(self):
        for backend in ("system-libc", "raw-syscall"):
            library = ctypes.CDLL(None, use_errno=True)
            if backend == "raw-syscall":
                library.pidfd_open = library.pidfd_send_signal = None
            with self.subTest(backend=backend), \
                    patch.object(helper.os, "pidfd_open", None, create=True), \
                    patch.object(helper.signal, "pidfd_send_signal", None, create=True), \
                    patch.object(ctypes, "CDLL", return_value=library):
                helper.validate_requirements(self.directory)
                # Exercise termination and exit readiness on an isolated child only.
                with subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"]) as child:
                    descriptor = helper.pidfd_open(child.pid)
                    try:
                        helper.pidfd_send_signal(descriptor, signal.SIGTERM)
                        self.assertEqual(child.wait(timeout=2), -signal.SIGTERM)
                        self.assertEqual(helper.select.select([descriptor], [], [], 0)[0], [descriptor])
                    finally:
                        os.close(descriptor)
                        if child.poll() is None:
                            child.terminate()

    def test_first_login_is_removed_after_failed_verification(self):
        self.auth.unlink()
        os.environ["HANDOFF_FIXTURE_MODE"] = "mismatch"
        self.assertEqual(self.invoke(self.request())["error"], "verification")
        self.assertFalse(self.auth.exists())

    def test_first_login_can_be_installed(self):
        self.auth.unlink()
        self.assertTrue(self.invoke(self.request())["ok"])
        self.assertEqual(self.auth.read_bytes(), self.target)

    def test_invalid_identity_never_replaces_original(self):
        for changes in [{"accountID": "account-other"}, {"email": "wrong@example.test"},
                        {"credential": "not-base64"}, {"credential": base64.b64encode(b"test-only-secret").decode()}]:
            with self.subTest(changes=changes):
                self.assertEqual(self.invoke(self.request(**changes))["error"], "identity_mismatch")
                self.assertEqual(self.auth.read_bytes(), self.original)

    def test_case_insensitive_email(self):
        self.assertTrue(self.invoke(self.request(email="B@EXAMPLE.TEST"))["ok"])

    def test_symlink_home_and_parent_are_rejected(self):
        link = self.root / "link"
        link.symlink_to(self.home, target_is_directory=True)
        self.assertEqual(self.invoke(self.request(home=str(link)))["error"], "unsafe_path")
        link.unlink()
        link.symlink_to(self.root, target_is_directory=True)
        self.assertEqual(self.invoke(self.request(home=str(link / self.home.name)))["error"], "unsafe_path")
        self.assertEqual(self.auth.read_bytes(), self.original)

    def test_symlink_auth_cannot_touch_destination(self):
        other = self.root / "other.json"
        other.write_bytes(self.original)
        self.auth.unlink()
        self.auth.symlink_to(other)
        self.assertEqual(self.invoke(self.request())["error"], "unsafe_path")
        self.assertEqual(other.read_bytes(), self.original)

    def test_hardlinked_auth_is_rejected(self):
        os.link(self.auth, self.root / "other.json")
        self.assertEqual(self.invoke(self.request())["error"], "unsafe_path")

    def test_fifo_auth_does_not_block(self):
        self.auth.unlink()
        os.mkfifo(self.auth)
        self.assertEqual(self.invoke(self.request())["error"], "unsafe_path")

    def test_group_writable_home_is_rejected(self):
        self.home.chmod(0o770)
        self.assertEqual(self.invoke(self.request())["error"], "unsafe_path")

    def test_keyring_configuration_is_rejected_without_mutation(self):
        for content in ['cli_auth_credentials_store = "keyring"',
                        '[profiles.work]\ncli_auth_credentials_store = "auto"']:
            (self.home / "config.toml").write_text(content)
            self.assertEqual(self.invoke(self.request())["error"], "requirements")
            self.assertEqual(self.auth.read_bytes(), self.original)

    def test_file_configuration_and_comment_are_accepted(self):
        (self.home / "config.toml").write_text('# cli_auth_credentials_store = "keyring"\ncli_auth_credentials_store = "file"')
        self.assertTrue(self.invoke(self.request())["ok"])

    def test_concurrent_handoff_is_rejected(self):
        with (self.home / ".account-switcher-handoff.lock").open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertEqual(self.invoke(self.request())["error"], "busy")
        self.assertEqual(self.auth.read_bytes(), self.original)

    def test_replacement_failure_preserves_original_and_cleans_temp_file(self):
        with patch.object(helper.os, "replace", side_effect=OSError("test-only-secret")):
            with self.assertRaisesRegex(helper.HandoffError, "write_failed"):
                helper.sync(self.directory, str(self.home), self.request())
        self.assertEqual(self.auth.read_bytes(), self.original)
        self.assertFalse(list(self.home.glob("*.tmp")))

    def test_concurrent_change_before_install_is_preserved(self):
        with self.assertRaisesRegex(helper.HandoffError, "conflict"):
            helper.atomic_replace(self.directory, self.target, b"outdated snapshot")
        self.assertEqual(self.auth.read_bytes(), self.original)
        self.assertFalse(list(self.home.glob("*.tmp")))

    def test_concurrent_login_is_preserved_when_verification_fails(self):
        other = credential("account-c", "c@example.test")

        def verify(*args):
            self.auth.write_bytes(other)
            helper.fail("verification")

        with patch.object(helper, "verify_codex", side_effect=verify):
            with self.assertRaisesRegex(helper.HandoffError, "restoration_failed"):
                helper.sync(self.directory, str(self.home), self.request())
        self.assertEqual(self.auth.read_bytes(), other)

    def test_failed_restoration_is_reported(self):
        real_replace = helper.atomic_replace
        calls = 0

        def replace(*args):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("test-only-secret")
            real_replace(*args)

        with patch.object(helper, "verify_codex", side_effect=helper.HandoffError("verification")), \
                patch.object(helper, "atomic_replace", side_effect=replace):
            with self.assertRaisesRegex(helper.HandoffError, "restoration_failed"):
                helper.sync(self.directory, str(self.home), self.request())
        self.assertEqual(self.auth.read_bytes(), self.target)

    def test_malformed_rpc_output_is_redacted_and_restored(self):
        os.environ["HANDOFF_FIXTURE_MODE"] = "malformed"
        self.assertEqual(self.invoke(self.request())["error"], "verification")
        self.assertEqual(self.auth.read_bytes(), self.original)

    def test_remote_login_shell_home_is_used(self):
        os.environ["CODEX_HOME"] = str(self.home)
        self.assertEqual(self.invoke({"operation": "check"})["home"], str(self.home))

    def test_shell_metacharacters_in_path_are_data(self):
        home = self.root / "$(touch should-not-exist); quoted"
        home.mkdir(mode=0o700)
        self.assertTrue(self.invoke(self.request(home=str(home)))["ok"])
        self.assertFalse((self.root / "should-not-exist").exists())


if __name__ == "__main__":
    unittest.main()
