"""Data types for the Hermes SSH plugin.

Profiles stay plain dicts (the JSON as it is on disk), so fields this
version does not know -- added by hand, or by pi-ssh -- survive a write.
Everything the plugin produces is a frozen dataclass. Errors are classes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class ExecResult:
    command: str
    stdout: str
    stderr: str
    #: None when the command was killed or the channel closed without a status.
    code: Optional[int]
    duration_ms: int
    #: True when output was cut off at the configured limit.
    truncated: bool = False
    signal: Optional[str] = None


@dataclass(frozen=True)
class RemoteEntry:
    name: str
    type: str  # file | directory | symlink | other
    size: int
    mode: str
    modified: Optional[str] = None


@dataclass(frozen=True)
class TransferResult:
    local_path: str
    remote_path: str
    size: int


@dataclass(frozen=True)
class ServerIdentity:
    host: str
    port: int
    user: str
    fingerprint: str
    key_type: str
    #: How the host key compared to known_hosts.
    host_key_verdict: str
    #: Which authentication method actually succeeded.
    auth_method: str


@dataclass(frozen=True)
class AuthorizeResult:
    profile: str
    key_path: str
    public_key_path: str
    fingerprint: str
    #: False when the key was already present in authorized_keys.
    installed: bool
    #: True when a key-only login was confirmed afterwards.
    verified: bool
    authorized_keys_path: str


@dataclass(frozen=True)
class TunnelDefinition:
    """A port forward.

    local  (ssh -L): this machine listens on bind:listen_port, and the server
                     opens the connection to dest_host:dest_port.
    remote (ssh -R): the server listens on bind:listen_port, and this machine
                     opens the connection to dest_host:dest_port.
    """

    kind: str
    listen_port: int
    dest_host: str
    dest_port: int
    bind: Optional[str] = None
    description: Optional[str] = None

    def to_json(self) -> dict:
        data: dict = {"kind": self.kind, "listenPort": self.listen_port,
                      "destHost": self.dest_host, "destPort": self.dest_port}
        if self.bind:
            data["bind"] = self.bind
        if self.description:
            data["description"] = self.description
        return data

    @staticmethod
    def from_json(raw: dict) -> "TunnelDefinition":
        return TunnelDefinition(
            kind=str(raw.get("kind", "local")),
            listen_port=int(raw.get("listenPort", 0)),
            dest_host=str(raw.get("destHost", "")),
            dest_port=int(raw.get("destPort", 0)),
            bind=raw.get("bind") or None,
            description=raw.get("description") or None,
        )


@dataclass(frozen=True)
class RunningTunnel:
    id: str
    profile: str
    name: str
    definition: TunnelDefinition
    #: Where it actually listens, which matters when listen_port was 0.
    listen_address: str
    started_at: str
    connections: int
    expires_at: Optional[str] = None
    #: The Hermes session that opened it, if known.
    session_id: Optional[str] = None
    extra: dict = field(default_factory=dict)


# Errors


class SshNotConfiguredError(Exception):
    def __init__(self) -> None:
        super().__init__(
            "No SSH host configured. Use the ssh_setup tool first (host, user, and a password or key)."
        )


class HostKeyChangedError(Exception):
    def __init__(self, message: str, fingerprint: str) -> None:
        super().__init__(message)
        self.fingerprint = fingerprint


class UnknownHostKeyError(Exception):
    def __init__(self, message: str, fingerprint: str) -> None:
        super().__init__(message)
        self.fingerprint = fingerprint


class SshAuthError(Exception):
    pass


class TunnelError(Exception):
    pass


class RemoteCommandError(Exception):
    def __init__(self, message: str, result: ExecResult) -> None:
        super().__init__(message)
        self.result = result


class ToolInputError(ValueError):
    """Invalid arguments from the model. Reported back as a tool error."""
