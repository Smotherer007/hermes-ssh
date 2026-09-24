"""Key tools: ssh_keygen, ssh_authorize."""

from __future__ import annotations

import os

from .. import config as cfg
from ..authorize import authorize_key
from ..formatters import format_authorize_result
from ..keys import default_key_comment, generate_key_pair, local_identity
from ..models import ToolInputError
from ._base import ACCEPT_HOST_KEY_PROPERTY, opt_bool, opt_str, result, schema, tool_handler

# ssh_keygen

KEYGEN_SCHEMA = schema(
    "ssh_keygen",
    "Create an ed25519 SSH key pair on this machine. Works on Windows, macOS and Linux alike because the key is "
    "generated in process -- ssh-keygen does not need to be installed. The result is a normal OpenSSH key that "
    "the ssh command can use too. To also install it on a host, use ssh_authorize instead.",
    {
        "path": {
            "type": "string",
            "description": "Where to write the private key. Default ~/.ssh/id_ed25519_hermes. The public key goes "
            "next to it with a .pub suffix.",
        },
        "comment": {"type": "string", "description": "Comment stored in the key, e.g. an email or host name."},
        "profile": {"type": "string", "description": "Record the new key in this SSH profile so it is used for logins."},
        "overwrite": {
            "type": "boolean",
            "description": "Replace an existing key at that path. Default false: overwriting invalidates every host "
            "that already trusts the old key.",
            "default": False,
        },
    },
)


@tool_handler
def keygen(args: dict) -> str:
    private_path = cfg.expand_path(opt_str(args, "path") or os.path.join("~", ".ssh", "id_ed25519_hermes"))
    public_path = f"{private_path}.pub"
    if os.path.exists(private_path) and not opt_bool(args, "overwrite"):
        raise ToolInputError(
            f"A key already exists at {private_path}. Pass overwrite: true to replace it, but note that every host "
            "trusting the old key will stop accepting it."
        )
    profile = opt_str(args, "profile")
    if profile and cfg.get_profile(profile) is None:
        raise ToolInputError(f'Profile "{profile}" does not exist.')

    user, host = local_identity()
    pair = generate_key_pair(opt_str(args, "comment") or default_key_comment(user, host))
    os.makedirs(os.path.dirname(private_path), mode=0o700, exist_ok=True)
    fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(pair.private_key)
    os.chmod(private_path, 0o600)
    with open(public_path, "w", encoding="utf-8") as handle:
        handle.write(pair.public_key + "\n")
    os.chmod(public_path, 0o644)
    if profile:
        cfg.update_profile(profile, {"privateKeyPath": private_path})

    lines = [
        "Created an ed25519 key pair.",
        f"Private: {private_path} (owner only)",
        f"Public:  {public_path}",
        f"Fingerprint: {pair.fingerprint}",
    ]
    if profile:
        lines.append(f'Recorded in profile "{profile}".')
    lines += ["", "Public key to install on a host:", pair.public_key]
    return result("\n".join(lines), privateKeyPath=private_path, publicKeyPath=public_path,
                  fingerprint=pair.fingerprint, publicKey=pair.public_key, profile=profile)


# ssh_authorize

AUTHORIZE_SCHEMA = schema(
    "ssh_authorize",
    "Set up passwordless login: generate an SSH key if the profile has none, install its public key in the "
    "remote authorized_keys, point the profile at it, and verify that a key-only login works. This is what "
    "ssh-copy-id does, but in process, so no ssh-keygen or ssh-copy-id has to be installed.",
    {
        "profile": {"type": "string", "description": "SSH profile to set up. Defaults to the active one."},
        "keyPath": {
            "type": "string",
            "description": "Key to use or create. Default ~/.ssh/id_ed25519_hermes_<profile>. An existing key at "
            "this path is reused, never overwritten.",
        },
        "comment": {"type": "string", "description": "Comment for a newly generated key."},
        "authorizedKeysPath": {
            "type": "string",
            "description": "Absolute path of authorized_keys on the remote host. Only needed when its sshd uses a "
            "non-standard AuthorizedKeysFile; by default the remote account's ~/.ssh/authorized_keys is used.",
        },
        "removePassword": {
            "type": "boolean",
            "description": "Delete the stored password once the key login is proven to work. Default false, which "
            "keeps it as a fallback.",
            "default": False,
        },
        "acceptNewHostKey": ACCEPT_HOST_KEY_PROPERTY,
    },
)


@tool_handler
def authorize(args: dict) -> str:
    name, profile = cfg.resolve_profile(opt_str(args, "profile"))
    remove_password = bool(opt_bool(args, "removePassword"))
    outcome = authorize_key(
        name, profile,
        key_path=opt_str(args, "keyPath"),
        comment=opt_str(args, "comment"),
        accept_new_host_key=bool(opt_bool(args, "acceptNewHostKey")),
        remove_password=remove_password,
        authorized_keys_path=opt_str(args, "authorizedKeysPath"),
    )
    note = ""
    if outcome.verified and remove_password:
        note = "\n\nThe stored password has been removed from the profile."
    elif outcome.verified and profile.get("password"):
        note = "\n\nThe password is still stored as a fallback. Re-run with removePassword: true to drop it."
    return result(
        format_authorize_result(outcome) + note,
        profile=outcome.profile, keyPath=outcome.key_path, publicKeyPath=outcome.public_key_path,
        fingerprint=outcome.fingerprint, installed=outcome.installed, verified=outcome.verified,
        authorizedKeysPath=outcome.authorized_keys_path,
        passwordRemoved=bool(outcome.verified and remove_password),
    )
