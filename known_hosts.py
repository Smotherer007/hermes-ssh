"""Host key verification against known_hosts.

Trust on first use: an unknown host is recorded with its fingerprint, and
from then on a changed key is a hard failure rather than a prompt. That is the
only part of SSH that protects against someone sitting between you and the
server, so it is not something to skip for convenience.

OpenSSH's own file is used by default, so hosts already visited with ``ssh``
are recognised, and hosts recorded here are recognised by ``ssh``.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
from dataclasses import dataclass, field
from typing import List, Optional

from .keys import key_blob_type, key_fingerprint


@dataclass(frozen=True)
class KnownHostEntry:
    hosts: str
    key_type: str
    blob: bytes
    marker: Optional[str] = None


@dataclass(frozen=True)
class HostKeyCheck:
    verdict: str  # match | unknown | changed | revoked
    fingerprint: str
    key_type: str
    file: str
    #: Fingerprints already on record for this host, when the key changed.
    known_fingerprints: List[str] = field(default_factory=list)


def default_known_hosts_path() -> str:
    return os.path.join(os.path.expanduser("~"), ".ssh", "known_hosts")


def host_pattern(host: str, port: int) -> str:
    """How OpenSSH writes a host: bare, or [host]:port for a non-default port."""
    return host if port == 22 else f"[{host}]:{port}"


def parse_known_hosts(content: str) -> List[KnownHostEntry]:
    entries = []
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        marker = None
        if parts and parts[0].startswith("@"):
            marker, parts = parts[0][1:], parts[1:]
        if len(parts) < 3:
            continue
        hosts, key_type, encoded = parts[0], parts[1], parts[2]
        try:
            blob = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            continue
        if not blob:
            continue
        entries.append(KnownHostEntry(hosts=hosts, key_type=key_type, blob=blob, marker=marker))
    return entries


def entry_matches_host(entry_hosts: str, pattern: str) -> bool:
    """Plain comma-separated patterns, or hashed |1|salt|hash entries."""
    if entry_hosts.startswith("|1|"):
        parts = [p for p in entry_hosts.split("|") if p]
        if len(parts) < 3:
            return False
        try:
            salt = base64.b64decode(parts[1])
            digest = hmac.new(salt, pattern.encode("utf-8"), hashlib.sha1).digest()
            return base64.b64encode(digest).decode("ascii") == parts[2]
        except Exception:
            return False
    return any(candidate.strip() == pattern for candidate in entry_hosts.split(","))


def read_known_hosts(path: str) -> List[KnownHostEntry]:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return parse_known_hosts(handle.read())
    except OSError:
        return []  # a missing file means nothing is known yet


def check_host_key(host: str, port: int, blob: bytes, path: Optional[str] = None) -> HostKeyCheck:
    path = path or default_known_hosts_path()
    pattern = host_pattern(host, port)
    fingerprint = key_fingerprint(blob)
    key_type = key_blob_type(blob)
    entries = [e for e in read_known_hosts(path) if entry_matches_host(e.hosts, pattern)]

    if any(e.marker == "revoked" and e.blob == blob for e in entries):
        return HostKeyCheck("revoked", fingerprint, key_type, path)
    if any(e.marker != "revoked" and e.blob == blob for e in entries):
        return HostKeyCheck("match", fingerprint, key_type, path)
    # Only keys of the same type count as a conflict: a host legitimately
    # offers an ed25519 key even when only its RSA key was recorded.
    same_type = [e for e in entries if e.key_type == key_type and e.marker != "revoked"]
    if same_type:
        return HostKeyCheck("changed", fingerprint, key_type, path,
                            [key_fingerprint(e.blob) for e in same_type])
    return HostKeyCheck("unknown", fingerprint, key_type, path)


def add_known_host(host: str, port: int, blob: bytes, path: Optional[str] = None) -> None:
    path = path or default_known_hosts_path()
    line = f"{host_pattern(host, port)} {key_blob_type(blob)} {base64.b64encode(blob).decode('ascii')}\n"
    directory = os.path.dirname(path)
    if directory and not os.path.exists(directory):
        os.makedirs(directory, mode=0o700, exist_ok=True)
    needs_newline = False
    if os.path.exists(path) and os.path.getsize(path) > 0:
        with open(path, "rb") as handle:
            handle.seek(-1, os.SEEK_END)
            needs_newline = handle.read(1) != b"\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as handle:
        handle.write(("\n" if needs_newline else "") + line)


def describe_changed_key(check: HostKeyCheck, host: str) -> str:
    return "\n".join([
        f"HOST KEY CHANGED for {host}.",
        "",
        f"Offered:  {check.key_type} {check.fingerprint}",
        f"Recorded: {', '.join(check.known_fingerprints)}",
        f"In:       {check.file}",
        "",
        "This is what a machine-in-the-middle looks like. It is also what a",
        "legitimately reinstalled server looks like. Do not connect until you know",
        "which one it is: confirm the fingerprint out of band, then remove the old",
        f"line with: ssh-keygen -R {host}",
    ])
