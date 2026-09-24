"""End-to-end tests against a real sshd on a loopback port.

They skip on machines without sshd; the password tests also need root.
"""

from __future__ import annotations

import os
import socket
import socketserver
import threading
import time

import pytest

from conftest import call, plugin, sub


def _wait(predicate, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.1)
    return False


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _Echo(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request.recv(1024)
        self.request.sendall(b"echo:" + data)


@pytest.fixture
def echo_server():
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _Echo)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


def _roundtrip(port: int, payload: bytes = b"ping") -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.sendall(payload)
        return s.recv(1024)


# Host keys


def test_unknown_host_is_refused_then_accepted(profile):
    refused = call("ssh_exec", {"command": "true"})
    assert "error" in refused
    assert "acceptNewHostKey" in refused["error"] or "not known" in refused["error"].lower()

    accepted = call("ssh_exec", {"command": "echo hi", "acceptNewHostKey": True})
    assert accepted["exitCode"] == 0 and "hi" in accepted["result"]

    again = call("ssh_exec", {"command": "echo again"})
    assert again["exitCode"] == 0


def test_changed_host_key_is_refused(known, isolated):
    known_hosts = os.path.join(os.environ["HOME"], ".ssh", "known_hosts")
    with open(known_hosts) as handle:
        line = next(l for l in handle if l.strip())
    other = sub("keys").generate_key_pair("impostor").public_key.split()
    fields = line.split()
    fields[1], fields[2] = other[0], other[1]
    with open(known_hosts, "w") as handle:
        handle.write(" ".join(fields[:3]) + "\n")
    outcome = call("ssh_exec", {"command": "true", "acceptNewHostKey": True})
    assert "error" in outcome
    assert "changed" in outcome["error"].lower()


# Commands


def test_exec_reports_exit_code_and_stderr(known):
    outcome = call("ssh_exec", {"command": "echo out; echo err >&2; exit 3"})
    assert outcome["exitCode"] == 3
    assert "out" in outcome["result"] and "err" in outcome["result"]


def test_exec_cwd_with_spaces(known, tmp_path):
    directory = tmp_path / "dir with 'quotes' and spaces"
    directory.mkdir()
    outcome = call("ssh_exec", {"command": "pwd", "cwd": str(directory)})
    assert outcome["exitCode"] == 0
    assert str(directory) in outcome["result"]


def test_exec_timeout_keeps_partial_output(known):
    started = time.monotonic()
    outcome = call("ssh_exec", {"command": "echo before; sleep 30", "timeoutSeconds": 1})
    assert time.monotonic() - started < 15
    assert "error" in outcome
    assert "before" in outcome["error"]


# SFTP


def test_list_upload_download(known, tmp_path):
    remote_dir = tmp_path / "remote"
    remote_dir.mkdir()
    local = tmp_path / "local.bin"
    payload = bytes(range(256)) * 40
    local.write_bytes(payload)

    up = call("ssh_upload", {"localPath": str(local), "remotePath": str(remote_dir / "copy.bin")})
    assert up["size"] == len(payload)

    listing = call("ssh_list", {"path": str(remote_dir)})
    assert listing["count"] == 1 and "copy.bin" in listing["result"]

    target = tmp_path / "new" / "sub" / "back.bin"
    down = call("ssh_download", {"remotePath": str(remote_dir / "copy.bin"), "localPath": str(target)})
    assert down["size"] == len(payload)
    assert target.read_bytes() == payload


def test_download_of_missing_file_leaves_nothing_behind(known, tmp_path):
    target = tmp_path / "never.txt"
    outcome = call("ssh_download", {"remotePath": str(tmp_path / "missing.txt"), "localPath": str(target)})
    assert "error" in outcome
    assert not target.exists()


def test_list_missing_directory_is_an_error(known, tmp_path):
    outcome = call("ssh_list", {"path": str(tmp_path / "nope")})
    assert "error" in outcome


# Keys


def test_authorize_installs_and_verifies(known, server, tmp_path):
    key_path = str(tmp_path / "home" / ".ssh" / "id_ed25519_e2e")
    first = call("ssh_authorize", {"keyPath": key_path, "authorizedKeysPath": server.authorized_keys_path})
    assert first.get("verified") is True, first
    assert first["installed"] is True
    assert sub("config").get_profile("test")["privateKeyPath"] == key_path

    second = call("ssh_authorize", {"keyPath": key_path, "authorizedKeysPath": server.authorized_keys_path})
    assert second["installed"] is False  # already there, not duplicated
    with open(server.authorized_keys_path) as handle:
        fingerprint_lines = [l for l in handle if first["fingerprint"] and l.strip()]
    public = open(key_path + ".pub").read().split()[1]
    assert sum(1 for l in fingerprint_lines if public in l) == 1


def test_password_profile_is_upgraded_on_first_use(password_profile):
    outcome = call("ssh_exec", {"command": "whoami", "profile": "pw"})
    assert outcome["exitCode"] == 0, outcome
    assert "installed a key" in outcome["result"]
    stored = sub("config").get_profile("pw")
    assert "password" not in stored
    assert "id_ed25519_hermes_" in stored["privateKeyPath"]

    again = call("ssh_exec", {"command": "whoami", "profile": "pw"})
    assert "installed a key" not in again["result"]


def test_auto_key_false_keeps_password(password_profile):
    sub("config").update_profile("pw", {"autoKey": False})
    outcome = call("ssh_exec", {"command": "true", "profile": "pw"})
    assert outcome["exitCode"] == 0
    assert sub("config").get_profile("pw").get("password")


# Tunnels


def test_local_tunnel_passes_traffic(known, echo_server):
    port = _free_port()
    started = call("ssh_tunnel", {"action": "start", "name": "echo", "listenPort": port,
                                  "destHost": "127.0.0.1", "destPort": echo_server})
    assert "error" not in started, started
    assert _roundtrip(port) == b"echo:ping"

    listed = call("ssh_tunnel", {"action": "list"})
    assert listed["running"] == 1

    stopped = call("ssh_tunnel", {"action": "stop", "name": "echo"})
    assert stopped["stopped"] is True
    with pytest.raises(OSError):
        _roundtrip(port)


def test_remote_tunnel_passes_traffic(known, echo_server):
    port = _free_port()
    started = call("ssh_tunnel", {"action": "start", "name": "back", "kind": "remote", "listenPort": port,
                                  "destHost": "127.0.0.1", "destPort": echo_server})
    assert "error" not in started, started
    # The server listens on its loopback, which is ours too.
    assert _wait(lambda: _try_roundtrip(port) == b"echo:ping")


def _try_roundtrip(port: int):
    try:
        return _roundtrip(port)
    except OSError:
        return None


def test_defined_tunnel_starts_by_name_and_survives_setup(known, echo_server):
    port = _free_port()
    defined = call("ssh_tunnel", {"action": "define", "name": "db", "listenPort": port,
                                  "destHost": "127.0.0.1", "destPort": echo_server})
    assert "error" not in defined, defined
    # Re-running setup must not lose stored tunnels.
    setup = call("ssh_setup", {"host": known["host"], "port": known["port"], "user": known["user"],
                               "privateKeyPath": known["privateKeyPath"], "name": "test"})
    assert "error" not in setup, setup
    assert "db" in sub("config").get_profile("test")["tunnels"]

    started = call("ssh_tunnel", {"action": "start", "name": "db"})
    assert "error" not in started, started
    assert _roundtrip(port) == b"echo:ping"

    forgotten = call("ssh_tunnel", {"action": "forget", "name": "db"})
    assert forgotten["removed"] is True


def test_tunnel_ends_when_connection_dies(known, server, echo_server):
    port = _free_port()
    call("ssh_tunnel", {"action": "start", "name": "fragile", "listenPort": port,
                        "destHost": "127.0.0.1", "destPort": echo_server})
    assert _roundtrip(port) == b"echo:ping"
    server.kill_connections()
    tunnels = sub("tunnels")
    assert _wait(lambda: tunnels._running_count() == 0, timeout=90)
    assert _try_roundtrip(port) is None


def test_tunnel_duration_limit(known, echo_server):
    port = _free_port()
    call("ssh_tunnel", {"action": "start", "name": "short", "listenPort": port, "destHost": "127.0.0.1",
                        "destPort": echo_server, "durationSeconds": 1})
    tunnels = sub("tunnels")
    assert _wait(lambda: tunnels._running_count() == 0, timeout=10)


def test_session_finalize_stops_only_that_sessions_tunnels(known, echo_server):
    a, b = _free_port(), _free_port()
    call("ssh_tunnel", {"action": "start", "name": "a", "listenPort": a, "destHost": "127.0.0.1",
                        "destPort": echo_server}, session_id="session-a")
    call("ssh_tunnel", {"action": "start", "name": "b", "listenPort": b, "destHost": "127.0.0.1",
                        "destPort": echo_server}, session_id="session-b")

    context_a = plugin._open_tunnels_context(session_id="session-a")
    assert context_a and "a" in context_a["context"]
    assert f":{b}" not in context_a["context"]
    assert plugin._open_tunnels_context(session_id="session-c") is None

    plugin._on_session_finalize(session_id="session-a")
    remaining = [t.name for t in sub("tunnels").list_tunnels()]
    assert remaining == ["b"]
    assert _roundtrip(b) == b"echo:ping"


# Status


def test_status_connects_and_shows_identity(known):
    outcome = call("ssh_status", {"connect": True})
    assert "error" not in outcome, outcome
    assert "SHA256:" in outcome["result"]
