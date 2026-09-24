"""Host tools: ssh_setup, ssh_status, ssh_profile, ssh_doctor."""

from __future__ import annotations

import sys

from .. import config as cfg
from ..doctor import format_checks, run_checks
from ..formatters import format_identity, format_profile_status, format_tunnel_list
from ..models import ToolInputError
from ..ssh_client import with_connection
from ..tunnels import list_tunnels
from ._base import opt_bool, opt_int, opt_str, req_str, result, schema, tool_handler
from .common import resolve_for_connection, with_note

# ssh_setup

SETUP_SCHEMA = schema(
    "ssh_setup",
    "Store an SSH host: address, user, and either a password or the path to a private key. Call this before "
    "any other ssh tool. Credentials are saved to $HERMES_HOME/ssh-config.json (owner-readable only). If you "
    "only have a password, the first connection replaces it with a key (see autoKey).",
    {
        "name": {"type": "string", "description": "Profile name, e.g. 'staging', 'nas'. Short and memorable."},
        "host": {"type": "string", "description": "Hostname or IP address."},
        "user": {"type": "string", "description": "Login user on the remote host."},
        "port": {"type": "number", "description": "SSH port. Default 22.", "default": 22},
        "password": {
            "type": "string",
            "description": "Password for this host. Stored in plaintext in the config file until the first "
            "connection replaces it with a key.",
        },
        "privateKeyPath": {
            "type": "string",
            "description": "Path to a private key on this machine, e.g. ~/.ssh/id_ed25519.",
        },
        "passphrase": {"type": "string", "description": "Passphrase for that private key, if it has one."},
        "autoKey": {
            "type": "boolean",
            "description": "On the first connection, install an SSH key on the host and replace the stored "
            "password with it. Default true. Set false to keep using the password.",
            "default": True,
        },
        "strictHostKey": {
            "type": "boolean",
            "description": "Refuse hosts whose key is not in known_hosts. Default true. Turning it off removes "
            "the only protection against a machine-in-the-middle.",
            "default": True,
        },
    },
    ["name", "host", "user"],
)


@tool_handler
def setup(args: dict) -> str:
    name = req_str(args, "name").strip()
    host = req_str(args, "host").strip()
    user = req_str(args, "user").strip()
    port = opt_int(args, "port") or 22
    if port < 1 or port > 65535:
        raise ToolInputError("port must be an integer between 1 and 65535.")
    password = opt_str(args, "password")
    key_path = opt_str(args, "privateKeyPath")
    if not password and not key_path:
        raise ToolInputError("Give either a password or a privateKeyPath -- otherwise there is no way to log in.")
    auto_key = opt_bool(args, "autoKey")
    strict = opt_bool(args, "strictHostKey")

    profile = {"host": host, "port": port, "user": user}
    if password:
        profile["password"] = password
    if key_path:
        profile["privateKeyPath"] = cfg.expand_path(key_path)
    if opt_str(args, "passphrase"):
        profile["passphrase"] = opt_str(args, "passphrase")
    if auto_key is False:
        profile["autoKey"] = False
    if strict is False:
        profile["strictHostKey"] = False

    # Keep what ssh_setup does not manage (named tunnels, hand-added fields).
    existing = cfg.get_profile(name) or {}
    for key in ("tunnels", "knownHostsFile", "connectTimeoutMs"):
        if key in existing:
            profile[key] = existing[key]
    cfg.save_profile(name, profile)

    advice = ""
    if password and not key_path:
        advice = (
            "\n\nThis profile logs in with a password and will keep doing so. Run ssh_authorize to switch to a key."
            if auto_key is False
            else "\n\nThis profile logs in with a password. On the first connection a key will be installed on the "
            "host and the password removed from the config; pass autoKey: false to prevent that."
        )
    return result(
        f'SSH profile "{name}" saved: {user}@{host}:{port}.{advice}',
        profile=name, host=host, port=port, user=user,
        hasPassword=bool(password), hasKey=bool(key_path),
    )


# ssh_status

STATUS_SCHEMA = schema(
    "ssh_status",
    "List the configured SSH hosts and how each authenticates, plus any open tunnels. With connect: true it "
    "also opens a connection to verify that the credentials and host key still work.",
    {
        "profile": {"type": "string", "description": "Profile to check. Defaults to the active one."},
        "connect": {"type": "boolean", "description": "Actually connect to verify the host works. Default false.",
                    "default": False},
    },
)


@tool_handler
def status(args: dict) -> str:
    profiles = cfg.get_profiles()
    running = list_tunnels()
    overview = format_profile_status(profiles, cfg.get_active_profile())
    if running:
        overview += "\n\n" + format_tunnel_list(running, [])
    details = {"count": len(profiles), "profiles": list(profiles), "activeProfile": cfg.get_active_profile()}
    if not profiles or not opt_bool(args, "connect"):
        return result(overview, **details)

    context = resolve_for_connection(opt_str(args, "profile"))
    reachable = False
    try:
        with with_connection(context.profile) as connection:
            text = format_identity(connection.identity)
        reachable = True
    except Exception as err:
        text = f'Connection to "{context.name}" failed:\n{err}'
    return result(with_note(f"{overview}\n\n{text}", context.note), **details, checked=context.name,
                  reachable=reachable)


# ssh_profile

PROFILE_SCHEMA = schema(
    "ssh_profile",
    "List configured SSH hosts, switch the active one, or delete one. Without arguments it lists them.",
    {
        "action": {"type": "string", "description": "One of: list, use, delete. Defaults to list."},
        "name": {"type": "string", "description": "Profile name for 'use' and 'delete'."},
    },
)


@tool_handler
def profile(args: dict) -> str:
    action = (opt_str(args, "action") or "list").lower()
    name = opt_str(args, "name")
    if action == "list":
        return result(format_profile_status(cfg.get_profiles(), cfg.get_active_profile()),
                      profiles=list(cfg.get_profiles()), activeProfile=cfg.get_active_profile())
    if action not in ("use", "delete"):
        raise ToolInputError(f'Unknown action "{args.get("action")}". Use one of: list, use, delete.')
    if not name:
        raise ToolInputError(f'The "{action}" action requires a profile name.')
    if action == "use":
        cfg.set_active_profile(name)
        return result(f'Active SSH profile is now "{name}".', activeProfile=name)
    removed = cfg.delete_profile(name)
    active = cfg.get_active_profile()
    if removed:
        now = f'"{active}"' if active else "unset"
        text = f'Profile "{name}" deleted. Active profile is now {now}.'
    else:
        text = f'No profile named "{name}".'
    return result(text, deleted=removed, activeProfile=active)


# ssh_doctor

DOCTOR_SCHEMA = schema(
    "ssh_doctor",
    "Check whether this machine can use the SSH tools and report anything that needs fixing or installing. "
    "Run it when a connection fails for reasons that are not about the remote host, or when the user asks "
    "what they need to install. Nothing external is normally required.",
    {},
)


@tool_handler
def doctor(args: dict) -> str:
    checks = run_checks()
    return result(
        format_checks(checks),
        platform=sys.platform,
        problems=[c.name for c in checks if c.status == "problem"],
        checks=[{"name": c.name, "status": c.status} for c in checks],
    )
