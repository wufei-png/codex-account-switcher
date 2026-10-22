"""Apply one SSH account-sync request and return a redacted JSON response."""

import base64
import errno
import fcntl
import hashlib
import json
import os
import select
import selectors
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
import uuid

MAX_CREDENTIAL = 1024 * 1024


class HandoffError(Exception):
    pass


def fail(code):
    raise HandoffError(code)


def read_file(directory, name, limit=MAX_CREDENTIAL):
    try:
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    except FileNotFoundError:
        return None
    except OSError:
        fail("unsafe_path")
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
            fail("unsafe_path")
        data = stream.read(limit + 1)
        if len(data) > limit:
            fail("unsafe_path")
        return data


def open_home(requested):
    home = requested or os.environ.get("CODEX_HOME") or os.path.join(os.path.expanduser("~"), ".codex")
    if home.startswith("~/"):
        home = os.path.join(os.path.expanduser("~"), home[2:])
    if not os.path.isabs(home) or "\x00" in home:
        fail("unsafe_path")
    home = os.path.normpath(home)
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in home.split("/"):
            if not part:
                continue
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        info = os.fstat(descriptor)
        if info.st_uid != os.getuid() or info.st_mode & 0o022:
            fail("unsafe_path")
        return home, descriptor
    except OSError:
        os.close(descriptor)
        fail("unsafe_path")
    except BaseException:
        os.close(descriptor)
        raise


def identity(data):
    try:
        tokens = json.loads(data)["tokens"]
        token = tokens.get("id_token")
        claims = {}
        if token:
            parts = token.split(".")
            if len(parts) != 3:
                fail("identity_mismatch")
            claims = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
        account_id = tokens.get("account_id") or claims.get("https://api.openai.com/auth", {}).get("chatgpt_account_id")
        email = claims.get("email")
        if not isinstance(account_id, str) or not account_id.strip():
            fail("identity_mismatch")
        if email is not None and not isinstance(email, str):
            fail("identity_mismatch")
        return account_id, email.casefold() if email else None
    except (KeyError, TypeError, ValueError):
        fail("identity_mismatch")


def require_identity(data, expected):
    actual = identity(data)
    if actual[0] != expected[0] or (expected[1] is not None and actual[1] != expected[1]):
        fail("identity_mismatch")


def linux_pidfd(name, *arguments):
    import ctypes
    if sys.platform != "linux":
        raise OSError(errno.ENOSYS, "pidfd requires Linux")
    number, signature = {
        "pidfd_open": (434, [ctypes.c_int, ctypes.c_uint]),
        "pidfd_send_signal": (424, [ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint]),
    }[name]
    library = ctypes.CDLL(None, use_errno=True)
    operation = getattr(library, name, None)
    if operation is not None:
        operation.argtypes = signature
        operation.restype = ctypes.c_int
        result = operation(*arguments)
    else:
        # Only the raw syscall fallback needs architecture-specific numbers.
        if os.uname().machine not in ("x86_64", "aarch64") or ctypes.sizeof(ctypes.c_void_p) != 8:
            raise OSError(errno.ENOSYS, "unsupported pidfd ABI")
        library.syscall.restype = ctypes.c_long
        result = library.syscall(ctypes.c_long(number), *(ctypes.c_long(value) for value in arguments))
    if result == -1:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    return result


def pidfd_open(pid):
    operation = getattr(os, "pidfd_open", None)
    return operation(pid) if operation is not None else linux_pidfd("pidfd_open", pid, 0)


def pidfd_send_signal(descriptor, value):
    operation = getattr(signal, "pidfd_send_signal", None)
    if operation is not None:
        operation(descriptor, value)
    else:
        linux_pidfd("pidfd_send_signal", descriptor, value, 0, 0)


def validate_requirements(directory):
    # Parse the actual TOML rather than guessing whether a keyring setting is in a comment/table.
    try:
        import tomllib
    except ImportError:
        fail("python_unavailable")
    if sys.platform not in ("linux", "darwin") or shutil.which("codex") is None:
        fail("requirements")
    if sys.platform == "linux":
        # Check the running kernel/policy, even when Python lacks pidfd wrappers.
        # This happens before credential writes; never fall back to kill(pid).
        descriptor = None
        try:
            descriptor = pidfd_open(os.getpid())
            pidfd_send_signal(descriptor, 0)
        except (AttributeError, OSError):
            fail("requirements")
        finally:
            if descriptor is not None:
                os.close(descriptor)
    config = read_file(directory, "config.toml")
    if config:
        try:
            value = tomllib.loads(config.decode("utf-8"))
        except (ValueError, UnicodeError):
            fail("requirements")
        candidates = [value] + list(value.get("profiles", {}).values())
        if any(not isinstance(item, dict) or item.get("cli_auth_credentials_store", "file") != "file"
               for item in candidates):
            fail("requirements")
    # Catch unsafe auth paths during the read-only check as well.
    read_file(directory, "auth.json")


def atomic_replace(directory, data, expected):
    temporary = ".auth.switcher-" + uuid.uuid4().hex + ".tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=directory)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if read_file(directory, "auth.json") != expected:
            fail("conflict")
        os.replace(temporary, "auth.json", src_dir_fd=directory, dst_dir_fd=directory)
    finally:
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass


def verify_codex(home, expected):
    environment = dict(os.environ, CODEX_HOME=home)
    process = subprocess.Popen(["codex", "app-server", "--stdio"], env=environment,
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    buffer = b""
    deadline = time.monotonic() + 15

    def send(value):
        process.stdin.write(json.dumps(value).encode() + b"\n")
        process.stdin.flush()

    try:
        send({"id": 0, "method": "initialize", "params": {
            "clientInfo": {"name": "codex_account_switcher", "version": "0.1.20"}}})
        while time.monotonic() < deadline:
            if not selector.select(max(0, deadline - time.monotonic())):
                fail("verification")
            chunk = os.read(process.stdout.fileno(), 4096)
            if not chunk or len(buffer) + len(chunk) > 65536:
                fail("verification")
            buffer += chunk
            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                response = json.loads(line)
                if "error" in response:
                    fail("verification")
                if response.get("id") == 0:
                    send({"method": "initialized", "params": {}})
                    send({"id": 1, "method": "account/read", "params": {"refreshToken": False}})
                elif response.get("id") == 1:
                    account = response.get("result", {}).get("account") or {}
                    if account.get("type") != "chatgpt":
                        fail("verification")
                    email = account.get("email")
                    if expected[1] and (not isinstance(email, str) or email.casefold() != expected[1]):
                        fail("verification")
                    return
        fail("verification")
    except (OSError, ValueError, TypeError, AttributeError):
        fail("verification")
    finally:
        selector.close()
        process.stdin.close()
        process.stdout.close()
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


class DesktopRuntime:
    """Bounded JSON-RPC over Desktop's existing private Unix WebSocket."""

    def __init__(self, path):
        self.socket = socket.socket(socket.AF_UNIX)
        self.deadline = time.monotonic() + 10
        self.sequence = 0
        try:
            self.socket.settimeout(10)
            self.socket.connect(path)
            if sys.platform == "linux":
                self.pid, uid, _ = struct.unpack("3i", self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            else:
                import ctypes
                uid_value, gid_value = ctypes.c_uint(), ctypes.c_uint()
                if ctypes.CDLL(None).getpeereid(self.socket.fileno(), ctypes.byref(uid_value), ctypes.byref(gid_value)) != 0:
                    fail("runtime_verification")
                uid = uid_value.value
                self.pid = struct.unpack("i", self.socket.getsockopt(0, 2, 4))[0]  # Darwin LOCAL_PEERPID
            if uid != os.getuid() or self.pid <= 1:
                fail("runtime_verification")
            key = base64.b64encode(os.urandom(16))
            self.socket.sendall(b"GET /rpc HTTP/1.1\r\nHost: codex-app-server\r\nUpgrade: websocket\r\n"
                                b"Connection: Upgrade\r\nSec-WebSocket-Key: " + key +
                                b"\r\nSec-WebSocket-Version: 13\r\n\r\n")
            header = b""
            while not header.endswith(b"\r\n\r\n"):
                header += self.read(1)
                if len(header) > 8192:
                    fail("runtime_verification")
            lines = header.decode("ascii").split("\r\n")
            fields = dict(line.split(":", 1) for line in lines[1:] if ":" in line)
            fields = {name.lower(): value.strip() for name, value in fields.items()}
            accept = base64.b64encode(hashlib.sha1(key + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest()).decode()
            if lines[0] != "HTTP/1.1 101 Switching Protocols" or fields.get("sec-websocket-accept") != accept:
                fail("runtime_verification")
            self.rpc("initialize", {"clientInfo": {"name": "codex_account_switcher", "version": "0.1.20"}})
            self.send({"method": "initialized", "params": {}})
        except BaseException:
            self.close()
            raise

    def close(self):
        self.socket.close()

    def read(self, count):
        data = b""
        while len(data) < count:
            self.socket.settimeout(max(0.001, self.deadline - time.monotonic()))
            if time.monotonic() >= self.deadline:
                fail("runtime_verification")
            chunk = self.socket.recv(count - len(data))
            if not chunk:
                fail("runtime_verification")
            data += chunk
        return data

    def frame(self, opcode, payload):
        size = len(payload)
        header = bytes([0x80 | opcode, 0x80 | size]) if size < 126 else bytes([0x80 | opcode, 0xFE]) + struct.pack("!H", size)
        mask = os.urandom(4)
        self.socket.settimeout(max(0.001, self.deadline - time.monotonic()))
        self.socket.sendall(header + mask + bytes(value ^ mask[index % 4] for index, value in enumerate(payload)))

    def send(self, value):
        self.frame(1, json.dumps(value).encode())

    def receive(self):
        data = b""
        fragmented = False
        for _ in range(128):
            first, second = self.read(2)
            opcode, size = first & 15, second & 127
            if first & 0x70 or second & 0x80:
                fail("runtime_verification")
            if size == 126:
                size = struct.unpack("!H", self.read(2))[0]
            elif size == 127:
                size = struct.unpack("!Q", self.read(8))[0]
            if len(data) + size > MAX_CREDENTIAL:
                fail("runtime_verification")
            payload = self.read(size)
            if opcode in (9, 10) and first & 0x80 and size <= 125:
                if opcode == 9:
                    self.frame(10, payload)
                continue
            if opcode != (0 if fragmented else 1):
                fail("runtime_verification")
            data += payload
            if first & 0x80:
                return json.loads(data)
            fragmented = True
        fail("runtime_verification")

    def rpc(self, method, params):
        self.sequence += 1
        self.send({"id": self.sequence, "method": method, "params": params})
        for _ in range(128):
            reply = self.receive()
            if reply.get("id") == self.sequence:
                if "error" in reply or not isinstance(reply.get("result"), dict):
                    fail("runtime_verification")
                return reply["result"]
        fail("runtime_verification")

    def verify(self, expected):
        account = self.rpc("account/read", {"refreshToken": False}).get("account") or {}
        email = account.get("email")
        if account.get("type") != "chatgpt" or (expected[1] and (not isinstance(email, str) or email.casefold() != expected[1])):
            fail("runtime_verification")
        # Email alone cannot distinguish workspaces belonging to the same user.
        auth = self.rpc("getAuthStatus", {"includeToken": True, "refreshToken": False})
        token = auth.get("authToken")
        if auth.get("authMethod") != "chatgpt" or not isinstance(token, str):
            fail("runtime_verification")
        if identity(json.dumps({"tokens": {"id_token": token}}))[0] != expected[0]:
            fail("runtime_verification")


def desktop_runtime(directory, home):
    try:
        parent = os.open("app-server-control", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
    except FileNotFoundError:
        return None
    try:
        info = os.fstat(parent)
        if info.st_uid != os.getuid() or info.st_mode & 0o022:
            fail("runtime_verification")
        try:
            info = os.stat("app-server-control.sock", dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return None
        if info.st_uid != os.getuid() or not (stat.S_ISSOCK(info.st_mode) or stat.S_ISLNK(info.st_mode)):
            fail("runtime_verification")
        path = os.path.realpath(os.path.join(home, "app-server-control", "app-server-control.sock"))
        # Codex can publish a symlink to its shorter socket path in a private temp directory.
        try:
            target = os.stat(path)
        except FileNotFoundError:
            return None  # A reboot can leave the published link pointing at a removed temp socket.
        container = os.stat(os.path.dirname(path))
        if not stat.S_ISSOCK(target.st_mode) or target.st_uid != os.getuid() or container.st_uid != os.getuid() or container.st_mode & 0o022:
            fail("runtime_verification")
        try:
            return DesktopRuntime(path)
        except (FileNotFoundError, ConnectionRefusedError):
            return None  # An owned socket inode can outlive its listener after a crash.
    finally:
        os.close(parent)


def peer_executable(pid, require_listener=False):
    if sys.platform == "linux":
        path = os.readlink("/proc/" + str(pid) + "/exe")
        with open("/proc/" + str(pid) + "/cmdline", "rb") as stream:
            arguments = stream.read(65536).split(b"\0")
        if b"app-server" not in arguments or b"proxy" in arguments or (require_listener and b"--listen" not in arguments):
            fail("runtime_restart")
    else:
        import ctypes
        library = ctypes.CDLL("/usr/lib/libproc.dylib")
        buffer = ctypes.create_string_buffer(4096)
        if library.proc_pidpath(pid, buffer, len(buffer)) <= 0:
            fail("runtime_restart")
        path = os.fsdecode(buffer.value)
    if not os.path.isabs(path) or os.path.basename(path) != "codex":
        fail("runtime_restart")
    return path


def restart_runtime(directory, home, runtime):
    pid = runtime.pid
    executable = peer_executable(pid)
    runtime.close()
    environment = dict(os.environ, CODEX_HOME=home)
    command = subprocess.run([executable, "app-server", "daemon", "restart"], env=environment,
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
    if command.returncode == 0:
        return
    # Older Desktop versions launch an unmanaged listener. Address only the process
    # identified by the private socket, never a name-based process list.
    descriptor = None
    if sys.platform == "linux":
        descriptor = pidfd_open(pid)
    try:
        # Bind the handle before checking a fresh connection: a reused PID must
        # never redirect our later signal to a process other than this peer.
        current = desktop_runtime(directory, home)
        if current is None:
            fail("runtime_restart")
        try:
            if current.pid != pid or peer_executable(pid, require_listener=True) != executable:
                fail("runtime_restart")
        finally:
            current.close()
        # Do not keep our verification connection open while waiting for shutdown.
        if descriptor is not None:
            pidfd_send_signal(descriptor, signal.SIGTERM)
            if not select.select([descriptor], [], [], 10)[0]:
                fail("runtime_restart")
        else:
            os.kill(pid, signal.SIGTERM)
            deadline = time.monotonic() + 10
            while True:
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    break
                if time.monotonic() >= deadline:
                    fail("runtime_restart")
                time.sleep(0.1)
    finally:
        if descriptor is not None:
            os.close(descriptor)
    parent = os.open("app-server-control", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
    try:
        log = os.open("app-server.log", os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=parent)
        try:
            info = os.fstat(log)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
                fail("runtime_restart")
            agent = os.path.join(home, "app-server-control", "forwarded-ssh-agent.sock")
            if os.path.exists(agent) and stat.S_ISSOCK(os.stat(agent).st_mode) and os.stat(agent).st_uid == os.getuid():
                environment["SSH_AUTH_SOCK"] = agent
            subprocess.Popen([executable, "-c", "features.code_mode_host=true", "app-server", "--listen", "unix://"],
                             env=environment, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                             start_new_session=True, close_fds=True)
        finally:
            os.close(log)
    finally:
        os.close(parent)


def update_desktop_runtime(directory, home, expected):
    try:
        runtime = desktop_runtime(directory, home)
    except BaseException:
        fail("runtime_verification")
    if runtime is None:
        return
    try:
        restart_runtime(directory, home, runtime)
    except BaseException:
        fail("runtime_restart")
    finally:
        runtime.close()
    deadline = time.monotonic() + 10
    while True:
        try:
            runtime = desktop_runtime(directory, home)
        except (OSError, ValueError, HandoffError):
            runtime = None
        if runtime is not None:
            try:
                runtime.verify(expected)
                return
            except BaseException:
                fail("runtime_verification")
            finally:
                runtime.close()
        if time.monotonic() >= deadline:
            fail("runtime_verification")
        time.sleep(0.1)


def sync(directory, home, request):
    try:
        data = base64.b64decode(request["credential"], validate=True)
        expected = (request["accountID"], request.get("email"))
        if expected[1]:
            expected = (expected[0], expected[1].casefold())
        if len(data) > MAX_CREDENTIAL:
            fail("identity_mismatch")
        require_identity(data, expected)
    except (KeyError, TypeError, ValueError):
        fail("identity_mismatch")
    lock = os.open(".account-switcher-handoff.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                   0o600, dir_fd=directory)
    try:
        info = os.fstat(lock)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
            fail("unsafe_path")
        os.fchmod(lock, 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            fail("busy")
        original = read_file(directory, "auth.json")
        os.fchmod(directory, 0o700)
        try:
            atomic_replace(directory, data, original)
        except HandoffError:
            raise
        except OSError:
            fail("write_failed")
        try:
            verify_codex(home, expected)
            require_identity(read_file(directory, "auth.json"), expected)
            update_desktop_runtime(directory, home, expected)
            require_identity(read_file(directory, "auth.json"), expected)
        except BaseException as error:
            # Restore only our own write. Preserve an intervening login/refresh and report uncertainty.
            try:
                if read_file(directory, "auth.json") != data:
                    fail("restoration_failed")
                if original is None:
                    os.unlink("auth.json", dir_fd=directory)
                else:
                    atomic_replace(directory, original, data)
            except BaseException:
                fail("restoration_failed")
            if isinstance(error, HandoffError) and str(error) in ("runtime_restart", "runtime_verification"):
                raise error
            fail("verification")
    finally:
        os.close(lock)


def main():
    descriptor = None
    try:
        data = sys.stdin.buffer.read(2 * MAX_CREDENTIAL + 1)
        if len(data) > 2 * MAX_CREDENTIAL:
            fail("invalid_response")
        request = json.loads(data)
        if request.get("operation") not in ("check", "sync"):
            fail("invalid_response")
        home, descriptor = open_home(request.get("home", ""))
        validate_requirements(descriptor)
        if request["operation"] == "sync":
            sync(descriptor, home, request)
        result = {"protocolVersion": 1, "ok": True, "home": home}
    except HandoffError as error:
        result = {"protocolVersion": 1, "ok": False, "error": str(error)}
    except BaseException:
        # System/parser diagnostics may contain credentials, paths or server output.
        result = {"protocolVersion": 1, "ok": False, "error": "requirements"}
    finally:
        if descriptor is not None:
            os.close(descriptor)
    print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
