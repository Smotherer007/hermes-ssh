"""SSH keys, in process.

``ssh-keygen`` is not something to depend on. The ``cryptography`` package
(which Hermes already ships) generates ed25519 keys and writes OpenSSH's own
key formats, so the result works with the plain ``ssh`` command too.
"""

from __future__ import annotations

import base64
import getpass
import hashlib
import re
import socket
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

KEY_TYPE = "ssh-ed25519"


@dataclass(frozen=True)
class GeneratedKeyPair:
    #: OpenSSH private key, ready to write to a file.
    private_key: str
    #: One authorized_keys line.
    public_key: str
    fingerprint: str
    comment: str


def key_fingerprint(blob: bytes) -> str:
    """What OpenSSH shows: SHA256 over the key blob, base64 without padding."""
    digest = base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii")
    return "SHA256:" + digest.rstrip("=")


def key_blob_type(blob: bytes) -> str:
    """The algorithm name at the start of a wire-format key blob."""
    try:
        (length,) = struct.unpack(">I", blob[:4])
        return blob[4:4 + length].decode("utf-8") or "unknown"
    except Exception:
        return "unknown"


def format_public_key_line_from_blob(blob: bytes, comment: str) -> str:
    suffix = f" {comment.strip()}" if comment and comment.strip() else ""
    return f"{key_blob_type(blob)} {base64.b64encode(blob).decode('ascii')}{suffix}"


def generate_key_pair(comment: str) -> GeneratedKeyPair:
    """An ed25519 pair: short, fast, accepted by every OpenSSH of the last decade."""
    private = ed25519.Ed25519PrivateKey.generate()
    public_openssh = private.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    ).decode("ascii")
    blob = base64.b64decode(public_openssh.split()[1])
    private_pem = private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()
    ).decode("ascii")
    return GeneratedKeyPair(
        private_key=private_pem,
        public_key=format_public_key_line_from_blob(blob, comment),
        fingerprint=key_fingerprint(blob),
        comment=comment,
    )


def default_key_comment(user: str, host: str) -> str:
    return f"hermes-remote-ssh {user}@{host}"


def local_identity() -> tuple:
    """(user, hostname) of this machine, for key comments."""
    try:
        user = getpass.getuser()
    except Exception:
        user = "user"
    return user, socket.gethostname()


_KEY_START = re.compile(r"^(ssh|ecdsa|sk)-")


def same_key_material(a: str, b: str) -> bool:
    """Compare two authorized_keys lines by key material, ignoring comment and options."""

    def material(line: str) -> str:
        parts = line.strip().split()
        for index, part in enumerate(parts):
            if _KEY_START.match(part):
                return " ".join(parts[index:index + 2])
        return ""

    left = material(a)
    return bool(left) and left == material(b)
