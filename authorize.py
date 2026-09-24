"""Turning a password login into a key login.

This is what ``ssh-copy-id`` does, in process. The steps are conservative:
the existing authorized_keys is read before anything is written, the key is
appended only when it is not there yet, and the password stays in the
profile unless the caller asks for it to go -- losing both at once would lock
the user out of their own host.

``ensure_key_authentication`` is the automatic variant: the first time a
password-only profile is used, it installs a key and drops the password.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any, Dict, Optional

import paramiko

from . import config as cfg
from .keys import (
    default_key_comment,
    format_public_key_line_from_blob,
    generate_key_pair,
    key_fingerprint,
    same_key_material,
)
from .models import AuthorizeResult
from .ssh_client import Connection, exec_command, shell_quote, with_connection


def key_file_name_for(profile_name: str) -> str:
    slug = re.sub(r"[^a-z0-9_-]+", "-", profile_name.lower()).strip("-")
    return f"id_ed25519_hermes_{slug or 'host'}"


def default_key_path(profile_name: str) -> str:
    return os.path.join(os.path.expanduser("~"), ".ssh", key_file_name_for(profile_name))


@dataclass(frozen=True)
class LocalKey:
    private_key_path: str
    public_key_path: str
    public_key_line: str
    fingerprint: str
    created: bool


def ensure_local_key(key_path: str, comment: str) -> LocalKey:
    """Use the key at ``key_path``, generating one if it is not there.

    An existing key is reused, never replaced: overwriting it would silently
    invalidate every other host that already trusts it.
    """
    private_path = cfg.expand_path(key_path)
    public_path = f"{private_path}.pub"

    if os.path.exists(private_path):
        try:
            key = paramiko.PKey.from_path(private_path)
        except paramiko.PasswordRequiredException:
            raise ValueError(
                f"The key at {private_path} has a passphrase, so this bootstrap cannot use it. "
                "Point keyPath somewhere else."
            ) from None
        except Exception as err:
            raise ValueError(f"The key at {private_path} could not be read: {err}.") from None
        blob = key.asbytes()
        if os.path.exists(public_path):
            with open(public_path, "r", encoding="utf-8") as handle:
                line = handle.read().strip()
        else:
            line = format_public_key_line_from_blob(blob, comment)
        return LocalKey(private_path, public_path, line, key_fingerprint(blob), created=False)

    pair = generate_key_pair(comment)
    os.makedirs(os.path.dirname(private_path), mode=0o700, exist_ok=True)
    fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(pair.private_key)
    os.chmod(private_path, 0o600)
    with open(public_path, "w", encoding="utf-8") as handle:
        handle.write(pair.public_key + "\n")
    os.chmod(public_path, 0o644)
    return LocalKey(private_path, public_path, pair.public_key, pair.fingerprint, created=True)


def _posix_dirname(remote_path: str) -> str:
    trimmed = remote_path.rstrip("/")
    index = trimmed.rfind("/")
    return "/" if index <= 0 else trimmed[:index]


def install_public_key(connection: Connection, public_key_line: str,
                       authorized_keys_path: Optional[str] = None) -> tuple:
    """Put a public key into the remote authorized_keys, exactly once.

    Over exec rather than SFTP, so that ~ is expanded by the remote shell and
    the permissions are set in the same breath -- sshd silently ignores an
    authorized_keys that is group-writable.
    """
    if authorized_keys_path:
        target = shell_quote(authorized_keys_path)
        directory = shell_quote(_posix_dirname(authorized_keys_path))
    else:
        target = '"$HOME/.ssh/authorized_keys"'
        directory = '"$HOME/.ssh"'

    prepare = exec_command(
        connection,
        f"umask 077 && mkdir -p {directory} && touch {target} && chmod 700 {directory} "
        f"&& chmod 600 {target} && printf '%s' {target}",
        timeout=30,
    )
    if prepare.code != 0:
        reason = prepare.stderr.strip() or f"exit {prepare.code}"
        raise OSError(f"Could not prepare the remote .ssh directory: {reason}")
    resolved = prepare.stdout.strip() or "~/.ssh/authorized_keys"

    existing = exec_command(connection, f"cat {target}", timeout=30)
    if any(same_key_material(line, public_key_line) for line in existing.stdout.splitlines()):
        return resolved, False

    append = exec_command(connection, f"printf '%s\\n' {shell_quote(public_key_line)} >> {target}", timeout=30)
    if append.code != 0:
        reason = append.stderr.strip() or f"exit {append.code}"
        raise OSError(f"Could not write to the remote authorized_keys: {reason}")
    return resolved, True


def authorize_key(
    profile_name: str,
    profile: Dict[str, Any],
    key_path: Optional[str] = None,
    comment: Optional[str] = None,
    accept_new_host_key: bool = False,
    remove_password: bool = False,
    authorized_keys_path: Optional[str] = None,
) -> AuthorizeResult:
    """Generate a key if needed, install it, switch the profile over, prove a key-only login."""
    comment = comment or default_key_comment(str(profile.get("user", "")), str(profile.get("host", "")))
    local = ensure_local_key(key_path or default_key_path(profile_name), comment)

    # The first connection deliberately does not use the new key: it is not on
    # the host yet, and falling back to it would hide a broken password.
    only = "password" if profile.get("password") else None
    with with_connection(profile, accept_new_host_key=accept_new_host_key, only=only) as connection:
        remote_path, installed = install_public_key(connection, local.public_key_line, authorized_keys_path)

    # Record the key before verifying, so a failed verification still leaves a
    # usable profile to retry with.
    cfg.update_profile(profile_name, {"privateKeyPath": local.private_key_path})

    verified = False
    try:
        with with_connection({**profile, "privateKeyPath": local.private_key_path}, only="key"):
            verified = True
    except Exception:
        verified = False

    if verified and remove_password:
        cfg.update_profile(profile_name, {"password": None})

    return AuthorizeResult(
        profile=profile_name, key_path=local.private_key_path, public_key_path=local.public_key_path,
        fingerprint=local.fingerprint, installed=installed, verified=verified,
        authorized_keys_path=remote_path,
    )


# First contact upgrades a password login to a key login


def needs_key_upgrade(profile: Dict[str, Any]) -> bool:
    if profile.get("autoKey") is False:
        return False
    return bool(profile.get("password")) and not profile.get("privateKeyPath")


@dataclass(frozen=True)
class UpgradeOutcome:
    profile: Dict[str, Any]
    upgraded: bool
    note: Optional[str] = None


def ensure_key_authentication(profile_name: str, profile: Dict[str, Any],
                              accept_new_host_key: bool = False) -> UpgradeOutcome:
    """Install a key and drop the password, then return the profile to connect with.

    Attempted, not enforced: a host that refuses public keys would otherwise
    become unusable, so a failed upgrade keeps the password and says why.
    """
    if not needs_key_upgrade(profile):
        return UpgradeOutcome(profile=profile, upgraded=False)
    host = profile.get("host")
    try:
        result = authorize_key(profile_name, profile, accept_new_host_key=accept_new_host_key,
                               remove_password=True)
    except Exception as err:
        return UpgradeOutcome(
            profile=profile, upgraded=False,
            note=f"Could not switch {host} to key authentication ({err}). Continuing with the password.",
        )
    if not result.verified:
        return UpgradeOutcome(
            profile=profile, upgraded=False,
            note=f"A key was installed on {host}, but a key-only login could not be verified, so the "
            f"password is still being used. Fingerprint: {result.fingerprint}",
        )
    updated = cfg.get_profile(profile_name) or profile
    return UpgradeOutcome(
        profile=updated, upgraded=True,
        note=f"First connection to {host}: installed a key ({result.fingerprint}) at {result.key_path} and "
        "removed the stored password. Logins from now on use the key.",
    )
