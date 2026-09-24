"""SSH connection, command execution and SFTP.

All network I/O lives here. The connection lifecycle is owned by
``with_connection``, the single place that opens, hands over and always
closes a connection -- an SSH session left open is a file descriptor and a
server-side process that nobody will clean up.

The SSH protocol comes from paramiko, a pure-Python implementation, so no
``ssh`` binary is needed on any platform.

Unlike paramiko's ``SSHClient``, the transport is driven by hand: that is
what lets the host key be checked with the same rules as pi-ssh (including
hashed entries and ``@revoked``), the authentication order be fixed (key,
then password), and the method that actually succeeded be reported.
"""

from __future__ import annotations

import os
import select
import socket
import stat
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Optional

import paramiko

from . import known_hosts as kh
from .config import expand_path, port_of
from .models import (
    ExecResult,
    HostKeyChangedError,
    RemoteCommandError,
    RemoteEntry,
    ServerIdentity,
    SshAuthError,
    TransferResult,
    UnknownHostKeyError,
)

DEFAULT_CONNECT_TIMEOUT_S = 20.0
#: SSH-level keepalive interval. Idle tunnels behind NAT die silently without it.
KEEPALIVE_INTERVAL_S = 15
DEFAULT_EXEC_TIMEOUT_S = 120.0
#: Enough to be useful, small enough not to swamp a context window.
MAX_OUTPUT_CHARS = 200_000


@dataclass
class Connection:
    transport: paramiko.Transport
    identity: ServerIdentity
    profile: Dict[str, Any]

    def close(self) -> None:
        try:
            self.transport.close()
        except Exception:
            pass


def _load_private_key(profile: Dict[str, Any]) -> Optional[paramiko.PKey]:
    path = profile.get("privateKeyPath")
    if not path:
        return None
    resolved = expand_path(path)
    if not os.path.isfile(resolved):
        raise SshAuthError(
            f"Private key not readable: {resolved}. Check the path, or use ssh_authorize to create one."
        )
    try:
        return paramiko.PKey.from_path(resolved, password=(profile.get("passphrase") or None))
    except paramiko.PasswordRequiredException:
        raise SshAuthError(
            f"The key at {resolved} is protected by a passphrase. Store it in the profile with ssh_setup "
            "(passphrase), or use another key."
        ) from None
    except (paramiko.SSHException, ValueError, OSError) as err:
        raise SshAuthError(f"Private key not readable: {resolved} ({err}).") from None


def auth_methods(profile: Dict[str, Any], only: Optional[str] = None) -> List[tuple]:
    """``[(label, kind, secret)]`` in the order they are tried: key, then password."""
    methods: List[tuple] = []
    if only != "password":
        key = _load_private_key(profile)
        if key is not None:
            methods.append(("key", "publickey", key))
    if only != "key" and profile.get("password"):
        methods.append(("password", "password", profile["password"]))
    if not methods:
        raise SshAuthError(
            "This profile has no private key configured."
            if only == "key"
            else "This profile has neither a password nor a private key. Add one with ssh_setup."
        )
    return methods


def connect(
    profile: Dict[str, Any],
    accept_new_host_key: bool = False,
    only: Optional[str] = None,
) -> Connection:
    """Open a connection, verifying the host key before any credential is sent."""
    host = str(profile.get("host", ""))
    port = port_of(profile)
    user = str(profile.get("user", ""))
    known_hosts_file = expand_path(profile["knownHostsFile"]) if profile.get("knownHostsFile") \
        else kh.default_known_hosts_path()
    strict = profile.get("strictHostKey") is not False
    methods = auth_methods(profile, only)
    timeout = float(profile.get("connectTimeoutMs") or DEFAULT_CONNECT_TIMEOUT_S * 1000) / 1000

    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except ConnectionRefusedError:
        raise ConnectionError(f"{host}:{port} refused the connection. Is sshd running and the port right?") from None
    except socket.gaierror:
        raise ConnectionError(f"Host not found: {host}.") from None
    except (socket.timeout, TimeoutError):
        raise ConnectionError(f"{host}:{port} did not answer within {round(timeout)}s.") from None
    except OSError as err:
        raise ConnectionError(f"Could not reach {host}:{port}: {err}") from None

    transport = paramiko.Transport(sock)
    try:
        transport.set_keepalive(KEEPALIVE_INTERVAL_S)
        try:
            transport.start_client(timeout=timeout)
        except paramiko.SSHException as err:
            raise ConnectionError(f"SSH handshake with {host}:{port} failed: {err}") from None

        blob = transport.get_remote_server_key().asbytes()
        check = kh.check_host_key(host, port, blob, known_hosts_file)
        if check.verdict == "changed":
            raise HostKeyChangedError(kh.describe_changed_key(check, host), check.fingerprint)
        if check.verdict == "revoked":
            raise HostKeyChangedError(
                f"The host key for {host} is marked as revoked in {check.file}. Refusing to connect.",
                check.fingerprint,
            )
        if check.verdict == "unknown":
            if strict and not accept_new_host_key:
                raise UnknownHostKeyError(
                    "\n".join([
                        f"The host key of {host}:{port} is not in {check.file}.",
                        "",
                        f"Offered: {check.key_type} {check.fingerprint}",
                        "",
                        "Check that fingerprint against the server, then re-run with acceptNewHostKey to record it.",
                    ]),
                    check.fingerprint,
                )
            try:
                kh.add_known_host(host, port, blob, known_hosts_file)
            except OSError:
                pass  # an unwritable known_hosts must not block the connection

        used = None
        for label, kind, secret in methods:
            try:
                if kind == "publickey":
                    transport.auth_publickey(user, secret)
                else:
                    transport.auth_password(user, secret)
            except (paramiko.AuthenticationException, paramiko.BadAuthenticationType):
                continue
            if transport.is_authenticated():
                used = label
                break
        if used is None:
            tried = " and ".join(label for label, _, _ in methods)
            raise SshAuthError(
                f"{user}@{host} rejected the credentials (tried {tried}). Check the user name, password or key."
            )

        identity = ServerIdentity(
            host=host, port=port, user=user, fingerprint=check.fingerprint, key_type=check.key_type,
            host_key_verdict=check.verdict if check.verdict != "unknown" else "recorded now", auth_method=used,
        )
        return Connection(transport=transport, identity=identity, profile=profile)
    except BaseException:
        transport.close()
        raise


@contextmanager
def with_connection(profile: Dict[str, Any], accept_new_host_key: bool = False,
                    only: Optional[str] = None) -> Iterator[Connection]:
    connection = connect(profile, accept_new_host_key=accept_new_host_key, only=only)
    try:
        yield connection
    finally:
        connection.close()


# Commands


def shell_quote(value: str) -> str:
    """Quote for a POSIX shell, so a space or quote cannot break out."""
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _clamp(text: str) -> tuple:
    if len(text) <= MAX_OUTPUT_CHARS:
        return text, False
    return f"{text[:MAX_OUTPUT_CHARS]}\n[output truncated at {MAX_OUTPUT_CHARS} characters]", True


def exec_command(connection: Connection, command: str, cwd: Optional[str] = None,
                 timeout: float = DEFAULT_EXEC_TIMEOUT_S) -> ExecResult:
    full = f"cd {shell_quote(cwd)} && {command}" if cwd else command
    started = time.monotonic()
    channel = connection.transport.open_session(timeout=30)
    limit = MAX_OUTPUT_CHARS * 2 * 4  # bytes; utf-8 is at most 4 per char
    stdout = bytearray()
    stderr = bytearray()
    try:
        channel.exec_command(full)
        deadline = started + timeout
        while True:
            if time.monotonic() > deadline:
                out, _ = _clamp(stdout.decode("utf-8", "replace"))
                err, _ = _clamp(stderr.decode("utf-8", "replace"))
                raise RemoteCommandError(
                    f"Command timed out after {round(timeout)}s: {command}",
                    ExecResult(command=command, stdout=out, stderr=err, code=None,
                               duration_ms=int((time.monotonic() - started) * 1000)),
                )
            select.select([channel], [], [], 0.1)
            while channel.recv_ready():
                chunk = channel.recv(65536)
                if len(stdout) < limit:
                    stdout.extend(chunk)
            while channel.recv_stderr_ready():
                chunk = channel.recv_stderr(65536)
                if len(stderr) < limit:
                    stderr.extend(chunk)
            if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                break
            if channel.closed and not channel.recv_ready() and not channel.recv_stderr_ready():
                break
        code = channel.recv_exit_status() if channel.exit_status_ready() else -1
    finally:
        channel.close()

    out, out_cut = _clamp(stdout.decode("utf-8", "replace"))
    err, err_cut = _clamp(stderr.decode("utf-8", "replace"))
    return ExecResult(
        command=command, stdout=out, stderr=err, code=None if code == -1 else code,
        duration_ms=int((time.monotonic() - started) * 1000), truncated=out_cut or err_cut,
    )


# SFTP


def format_mode(mode: int) -> str:
    """The rwx string people expect from ls."""
    bits = "rwxrwxrwx"
    return "".join(bits[i] if mode & (1 << (8 - i)) else "-" for i in range(9))


def _entry_type(mode: int) -> str:
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISREG(mode):
        return "file"
    return "other"


def list_directory(connection: Connection, remote_path: str) -> List[RemoteEntry]:
    sftp = paramiko.SFTPClient.from_transport(connection.transport)
    try:
        try:
            attrs = sftp.listdir_attr(remote_path)
        except (IOError, OSError) as err:
            raise OSError(f"Cannot list {remote_path}: {_sftp_reason(err)}") from None
    finally:
        sftp.close()
    entries = []
    for attr in attrs:
        mode = attr.st_mode or 0
        modified = (
            datetime.fromtimestamp(attr.st_mtime, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
            if attr.st_mtime else None
        )
        entries.append(RemoteEntry(name=attr.filename, type=_entry_type(mode), size=attr.st_size or 0,
                                   mode=format_mode(mode), modified=modified))
    entries.sort(key=lambda e: e.name)
    return entries


def _sftp_reason(err: BaseException) -> str:
    if isinstance(err, FileNotFoundError) or getattr(err, "errno", None) == 2:
        return "No such file"
    if isinstance(err, PermissionError) or getattr(err, "errno", None) == 13:
        return "Permission denied"
    text = str(err).strip()
    return text or type(err).__name__


def upload_file(connection: Connection, local_path: str, remote_path: str) -> TransferResult:
    local = expand_path(local_path)
    if not os.path.isfile(local):
        raise OSError(f"Not a file: {local}")
    size = os.path.getsize(local)
    sftp = paramiko.SFTPClient.from_transport(connection.transport)
    try:
        sftp.put(local, remote_path)
    except (IOError, OSError) as err:
        raise OSError(f"Upload to {remote_path} failed: {_sftp_reason(err)}") from None
    finally:
        sftp.close()
    return TransferResult(local_path=local, remote_path=remote_path, size=size)


def download_file(connection: Connection, remote_path: str, local_path: str) -> TransferResult:
    local = expand_path(local_path)
    os.makedirs(os.path.dirname(local) or ".", exist_ok=True)
    existed = os.path.exists(local)
    sftp = paramiko.SFTPClient.from_transport(connection.transport)
    try:
        sftp.get(remote_path, local)
    except (IOError, OSError) as err:
        # paramiko leaves an empty file behind on a failed get
        try:
            if not existed and os.path.exists(local) and os.path.getsize(local) == 0:
                os.unlink(local)
        except OSError:
            pass
        raise OSError(f"Download of {remote_path} failed: {_sftp_reason(err)}") from None
    finally:
        sftp.close()
    return TransferResult(local_path=local, remote_path=remote_path, size=os.path.getsize(local))
