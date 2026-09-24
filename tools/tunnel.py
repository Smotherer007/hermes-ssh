"""ssh_tunnel: port forwards, and the named ones a profile keeps."""

from __future__ import annotations

from .. import config as cfg
from ..formatters import format_tunnel_list, format_tunnel_started
from ..models import TunnelDefinition, TunnelError
from ..tunnels import list_tunnels, start_tunnel, stop_all_tunnels, stop_tunnel, validate_definition
from ._base import (
    ACCEPT_HOST_KEY_PROPERTY,
    PROFILE_PROPERTY,
    opt_bool,
    opt_int,
    opt_str,
    result,
    schema,
    session_id_of,
    tool_handler,
)
from .common import resolve_for_connection, with_note

ACTIONS = ("start", "stop", "stop-all", "list", "define", "forget")

TUNNEL_SCHEMA = schema(
    "ssh_tunnel",
    "Open, close and list SSH port forwards, and store named ones in a profile. A local tunnel makes a service "
    "behind the server reachable on this machine (like ssh -L); a remote tunnel makes something on this machine "
    "reachable from the server (like ssh -R). Unlike the other tools, a tunnel keeps running after the call "
    "returns, until it is stopped, its time limit expires, or the Hermes session that opened it ends.",
    {
        "action": {
            "type": "string",
            "enum": list(ACTIONS),
            "description": "One of: start, stop, stop-all, list, define, forget. Defaults to list. 'define' stores a "
            "named tunnel in the profile; 'start' runs one, by name or from the ports given here.",
            "default": "list",
        },
        "name": {
            "type": "string",
            "description": "Name of the tunnel. Required for define, forget and stop; for start it selects a stored "
            "definition.",
        },
        "kind": {
            "type": "string",
            "enum": ["local", "remote"],
            "description": "local (this machine listens, the server reaches the destination) or remote (the server "
            "listens, this machine reaches the destination). Default local.",
            "default": "local",
        },
        "listenPort": {
            "type": "number",
            "description": "Port the tunnel accepts connections on: local to this machine for a local tunnel, on "
            "the server for a remote one. 0 picks a free port.",
        },
        "bind": {
            "type": "string",
            "description": "Interface that port binds to. Default 127.0.0.1. Using 0.0.0.0 exposes the forwarded "
            "service to the whole network, and for a remote tunnel the server also needs GatewayPorts enabled.",
        },
        "destHost": {
            "type": "string",
            "description": "Host the traffic is delivered to, resolved from the server for a local tunnel and from "
            "this machine for a remote one.",
        },
        "destPort": {"type": "number", "description": "Port on destHost."},
        "description": {"type": "string", "description": "What this tunnel is for, shown in listings."},
        "durationSeconds": {"type": "number", "description": "Close the tunnel automatically after this long. Default: no limit."},
        "profile": PROFILE_PROPERTY,
        "acceptNewHostKey": ACCEPT_HOST_KEY_PROPERTY,
    },
)


def _definition(args: dict) -> TunnelDefinition:
    definition = TunnelDefinition(
        kind=(opt_str(args, "kind") or "local").lower(),
        listen_port=opt_int(args, "listenPort") or 0,
        dest_host=(opt_str(args, "destHost") or "").strip(),
        dest_port=opt_int(args, "destPort") or 0,
        bind=opt_str(args, "bind") or None,
        description=opt_str(args, "description") or None,
    )
    validate_definition(definition)
    return definition


def _stored(profile: dict) -> dict:
    raw = profile.get("tunnels") if isinstance(profile.get("tunnels"), dict) else {}
    return {name: TunnelDefinition.from_json(value) for name, value in raw.items() if isinstance(value, dict)}


@tool_handler
def tunnel(args: dict, context: dict) -> str:
    action = (opt_str(args, "action") or "list").lower()
    if action not in ACTIONS:
        raise TunnelError(f'Unknown action "{args.get("action")}". Use start, stop, stop-all, list, define or forget.')

    if action == "list":
        running = list_tunnels()
        defined = [
            {"profile": profile_name, "name": name, "definition": definition}
            for profile_name, profile in cfg.get_profiles().items()
            for name, definition in _stored(profile).items()
        ]
        return result(format_tunnel_list(running, defined), running=len(running), defined=len(defined),
                      tunnels=[{"id": t.id, "listenAddress": t.listen_address, "connections": t.connections}
                               for t in running])

    if action == "stop-all":
        stopped = stop_all_tunnels()
        return result("No tunnels were running." if stopped == 0 else f"Stopped {stopped} tunnel(s).", stopped=stopped)

    name = opt_str(args, "name")
    if not name:
        raise TunnelError(f'The "{action}" action requires a tunnel name.')

    if action == "define":
        profile_name, profile = cfg.resolve_profile(opt_str(args, "profile"))
        definition = _definition(args)
        tunnels = dict(profile.get("tunnels") or {})
        tunnels[name] = definition.to_json()
        cfg.update_profile(profile_name, {"tunnels": tunnels})
        return result(
            f'Tunnel "{name}" defined for profile "{profile_name}". Start it with ssh_tunnel action start, name {name}.',
            profile=profile_name, name=name, definition=definition.to_json(),
        )

    if action == "forget":
        profile_name, profile = cfg.resolve_profile(opt_str(args, "profile"))
        tunnels = dict(profile.get("tunnels") or {})
        existed = tunnels.pop(name, None) is not None
        cfg.update_profile(profile_name, {"tunnels": tunnels})
        text = (f'Tunnel "{name}" removed from profile "{profile_name}".' if existed
                else f'Profile "{profile_name}" has no tunnel called "{name}".')
        return result(text, profile=profile_name, name=name, removed=existed)

    if action == "stop":
        profile_name, _ = cfg.resolve_profile(opt_str(args, "profile"))
        stopped = stop_tunnel(profile_name, name)
        text = (f'Tunnel "{name}" stopped.' if stopped
                else f'No running tunnel called "{name}" for profile "{profile_name}".')
        return result(text, profile=profile_name, name=name, stopped=stopped)

    # start
    accept = bool(opt_bool(args, "acceptNewHostKey"))
    connection_context = resolve_for_connection(opt_str(args, "profile"), accept)
    stored = _stored(connection_context.profile)
    if opt_str(args, "destHost") or opt_int(args, "destPort"):
        definition = _definition(args)
    elif name in stored:
        definition = stored[name]
    else:
        available = f" (available: {', '.join(stored)})" if stored else ""
        raise TunnelError(
            f'No tunnel called "{name}" is defined for profile "{connection_context.name}"{available}, and no '
            "destHost/destPort were given to build one."
        )
    validate_definition(definition)

    duration = opt_int(args, "durationSeconds")
    running = start_tunnel(
        connection_context.name, connection_context.profile, name, definition,
        accept_new_host_key=accept, duration_seconds=duration, session_id=session_id_of(context),
    )
    return result(
        with_note(format_tunnel_started(running, connection_context.profile), connection_context.note),
        profile=connection_context.name, id=running.id, name=running.name, listenAddress=running.listen_address,
        expiresAt=running.expires_at, definition=running.definition.to_json(),
    )
