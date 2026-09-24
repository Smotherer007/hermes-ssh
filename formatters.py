"""Output formatters: pure functions from domain data to display strings.

Wording follows pi-ssh, so the bundled skills read the same on both agents.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

from .config import port_of
from .models import (
    AuthorizeResult,
    ExecResult,
    RemoteEntry,
    RunningTunnel,
    ServerIdentity,
    TransferResult,
    TunnelDefinition,
)


def format_bytes(size: Any) -> str:
    try:
        value = float(size)
    except (TypeError, ValueError):
        return "unknown size"
    if value < 0:
        return "unknown size"
    if value < 1024:
        return f"{int(value)} B"
    units = ["KB", "MB", "GB", "TB"]
    value /= 1024
    unit = 0
    while value >= 1024 and unit < len(units) - 1:
        value /= 1024
        unit += 1
    return f"{value:.0f} {units[unit]}" if value >= 10 else f"{value:.1f} {units[unit]}"


def describe_auth(profile: Mapping[str, Any]) -> str:
    """How a profile authenticates, without revealing any secret."""
    methods = []
    if profile.get("privateKeyPath"):
        methods.append(f"key {profile['privateKeyPath']}")
    if profile.get("password"):
        methods.append("password (stored)")
    return ", ".join(methods) if methods else "none configured"


def format_profile_status(profiles: Mapping[str, Mapping[str, Any]], active: Optional[str]) -> str:
    if not profiles:
        return "No SSH hosts configured. Use ssh_setup with a host, user, and a password or key path."
    lines = []
    for name, profile in profiles.items():
        marker = "*" if name == active else " "
        port = port_of(dict(profile))
        suffix = "" if port == 22 else f":{port}"
        lines.append(f"{marker} {name}: {profile.get('user')}@{profile.get('host')}{suffix}")
        lines.append(f"    auth: {describe_auth(profile)}")
        if profile.get("strictHostKey") is False:
            lines.append("    host key checking is OFF for this profile")
    return "\n".join([f"SSH hosts ({len(profiles)}), * marks the active one:", *lines])


def format_identity(identity: ServerIdentity) -> str:
    return "\n".join([
        f"Connected: {identity.user}@{identity.host}:{identity.port}",
        f"Authenticated with: {identity.auth_method}",
        f"Host key: {identity.key_type} {identity.fingerprint} ({identity.host_key_verdict})",
    ])


def format_exec_result(result: ExecResult) -> str:
    if result.code == 0:
        status = "exit 0"
    elif result.code is None:
        status = f"killed by {result.signal}" if result.signal else "no exit status (killed or disconnected)"
    else:
        status = f"exit {result.code}"
    sections = [f"$ {result.command}", f"[{status}, {result.duration_ms} ms]"]
    if result.stdout.strip():
        sections += ["", result.stdout.rstrip()]
    if result.stderr.strip():
        sections += ["", "stderr:", result.stderr.rstrip()]
    if not result.stdout.strip() and not result.stderr.strip():
        sections += ["", "(no output)"]
    return "\n".join(sections)


def format_directory(entries: Sequence[RemoteEntry], remote_path: str) -> str:
    if not entries:
        return f"{remote_path} is empty."
    lines = []
    for entry in entries:
        suffix = "/" if entry.type == "directory" else "@" if entry.type == "symlink" else ""
        size = "" if entry.type == "directory" else f" {format_bytes(entry.size)}"
        date = f" {entry.modified[:10]}" if entry.modified else ""
        lines.append(f"{entry.mode}{date}{size}  {entry.name}{suffix}")
    return "\n".join([f"{remote_path} ({len(entries)} entries):", *lines])


def format_transfer(result: TransferResult, direction: str) -> str:
    if direction == "up":
        return f"Uploaded {result.local_path} to {result.remote_path} ({format_bytes(result.size)})."
    return f"Downloaded {result.remote_path} to {result.local_path} ({format_bytes(result.size)})."


def format_authorize_result(result: AuthorizeResult) -> str:
    return "\n".join([
        f'Key installed on the remote host and recorded in profile "{result.profile}".'
        if result.installed
        else f'The key was already in {result.authorized_keys_path}; profile "{result.profile}" now uses it.',
        "",
        f"Private key: {result.key_path}",
        f"Public key:  {result.public_key_path}",
        f"Fingerprint: {result.fingerprint}",
        "",
        "Verified: a fresh connection authenticated with the key alone, so no password is needed from now on."
        if result.verified
        else "Warning: the key was installed but a key-only login could not be verified. The password is "
        "still in the profile as a fallback.",
    ])


def describe_tunnel(definition: TunnelDefinition) -> str:
    bind = definition.bind or "127.0.0.1"
    listen = f"{bind}:{'(free port)' if definition.listen_port == 0 else definition.listen_port}"
    dest = f"{definition.dest_host}:{definition.dest_port}"
    if definition.kind == "local":
        return f"local {listen} -> {dest} (reached from the server)"
    return f"remote {listen} on the server -> {dest} (reached from this machine)"


def format_tunnel_started(tunnel: RunningTunnel, profile: Mapping[str, Any]) -> str:
    bind = tunnel.definition.bind or "127.0.0.1"
    ending = (f", or automatically at {tunnel.expires_at[11:19]} UTC." if tunnel.expires_at
              else ", or the Hermes session that opened it ends.")
    lines = [
        f'Tunnel "{tunnel.name}" is up: {describe_tunnel(tunnel.definition)}',
        f"Connect to {tunnel.listen_address} on this machine." if tunnel.definition.kind == "local"
        else f"On {profile.get('host')}, connect to {tunnel.listen_address}.",
        "",
        "It keeps running in the background until you stop it with ssh_tunnel action stop" + ending,
    ]
    if bind not in ("127.0.0.1", "localhost", "::1"):
        lines += ["", f"Note: this binds {bind}, not loopback, so anything that can reach that interface can use "
                      "the tunnel."]
    return "\n".join(lines)


def format_tunnel_list(running: Sequence[RunningTunnel], defined: Iterable[Dict[str, Any]]) -> str:
    defined = list(defined)
    sections: List[str] = []
    if not running:
        sections.append("No tunnels are running.")
    else:
        sections.append(f"Running tunnels ({len(running)}):")
        for tunnel in running:
            closes = f", closes at {tunnel.expires_at[11:19]} UTC" if tunnel.expires_at else ""
            sections += [
                f"- {tunnel.profile}/{tunnel.name}: {describe_tunnel(tunnel.definition)}",
                f"  listening on {tunnel.listen_address}, {tunnel.connections} connection(s) since "
                f"{tunnel.started_at[11:19]} UTC{closes}",
            ]
    if defined:
        running_ids = {f"{t.profile}:{t.name}" for t in running}
        sections += ["", f"Defined in profiles ({len(defined)}):"]
        for entry in defined:
            state = " [running]" if f"{entry['profile']}:{entry['name']}" in running_ids else ""
            purpose = f" -- {entry['definition'].description}" if entry["definition"].description else ""
            sections.append(f"- {entry['profile']}/{entry['name']}{state}: {describe_tunnel(entry['definition'])}{purpose}")
    elif not running:
        sections += ["", "Define one with ssh_tunnel action define, so it can be started by name later."]
    return "\n".join(sections)


def render_tunnel_lines(tunnels: Sequence[RunningTunnel]) -> List[str]:
    """One compact line per open tunnel (the reminder injected into each turn)."""
    lines = []
    for tunnel in tunnels:
        arrow = "->" if tunnel.definition.kind == "local" else "<-"
        expiry = f" until {tunnel.expires_at[11:16]}Z" if tunnel.expires_at else ""
        lines.append(f"SSH tunnel {tunnel.profile}/{tunnel.name}: {tunnel.listen_address} {arrow} "
                     f"{tunnel.definition.dest_host}:{tunnel.definition.dest_port}{expiry}")
    return lines
