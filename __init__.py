"""Hermes SSH plugin.

Runs commands and moves files on remote hosts over SSH, forwards ports, and
turns a password login into a key login -- no ``ssh``, ``ssh-keygen`` or
``ssh-copy-id`` binary needed. Port of the pi extension pi-ssh: the same 11
tools with the same parameters, the same config file format, the same skills.

Layout:
  models.py       result dataclasses and error types
  config.py       profile store: merge-on-write, 0600, unknown keys survive
  keys.py         ed25519 keys in process (cryptography)
  known_hosts.py  host key verification against OpenSSH's known_hosts
  ssh_client.py   connection, exec and SFTP (paramiko)
  authorize.py    ssh-copy-id in process, and the automatic password->key switch
  tunnels.py      local/remote port forwards that outlive their tool call
  doctor.py       environment report
  formatters.py   pure display functions
  tools/          the 11 tools
  safety.py       dangerous commands, safety level, read-only profiles
  commands.py     /ssh and /ssh-key
"""

from __future__ import annotations

import atexit
import logging
from pathlib import Path
from typing import Any, Mapping, Optional

from . import config as cfg
from .commands import make_ssh_command, make_ssh_key_command
from .formatters import describe_auth, render_tunnel_lines
from .safety import make_pre_tool_call_hook
from .tools import TOOLS, TOOLSET
from .tunnels import list_tunnels, stop_all_tunnels

logger = logging.getLogger(__name__)

_PLUGIN_DIR = Path(__file__).resolve().parent
_atexit_registered = False

SKILLS = {
    "ssh-remote-work": "Work on a remote machine over SSH: commands, logs, configuration, files, and what "
    "connection errors mean.",
    "ssh-key-setup": "Switch a host from password to key login, and manage the keys involved.",
}


def _frontmatter_description(path: Path) -> str:
    try:
        content = path.read_text(encoding="utf-8")
    except OSError:
        return ""
    if not content.startswith("---\n"):
        return ""
    end = content.find("\n---", 4)
    for line in content[4:end].splitlines():
        if line.startswith("description:"):
            return line[len("description:"):].strip().strip("\"'")
    return ""


def _prompt_section(_session: Mapping[str, Any]) -> str:
    """Frozen per session: where the skills are and which hosts exist. No secrets."""
    lines = ["SSH tools (ssh_*) are available. Load the matching skill with skill_view before remote work:"]
    lines += [f"- ssh:{name} -- {text}" for name, text in SKILLS.items()]
    try:
        profiles = cfg.get_profiles()
        active = cfg.get_active_profile()
    except Exception:
        profiles, active = {}, None
    if profiles:
        lines.append("Configured SSH hosts (profile parameter):")
        for name, profile in profiles.items():
            marker = " (active)" if name == active else ""
            port = profile.get("port") or 22
            suffix = "" if int(port) == 22 else f":{port}"
            lines.append(f"- {name}{marker}: {profile.get('user')}@{profile.get('host')}{suffix}, "
                         f"auth {describe_auth(profile)}")
    else:
        lines.append("No SSH host is configured yet; ssh_setup adds one.")
    return "\n".join(lines)


def _open_tunnels_context(session_id: Optional[str] = None, **_kwargs: Any) -> Optional[dict]:
    """While a tunnel is open, remind the model every turn.

    pi shows open tunnels in a widget above the editor, because a forgotten
    tunnel is a port reaching into someone else's network. Hermes has no such
    surface for plugins, so the reminder goes to the model instead, which can
    mention it and stop what is no longer needed.
    """
    # Only this session's tunnels: in the gateway, one chat must not learn
    # what another chat has open.
    tunnels = [t for t in list_tunnels() if t.session_id in (None, session_id)]
    if not tunnels:
        return None
    return {"context": "Open SSH tunnels (running in the background until stopped):\n"
                       + "\n".join(render_tunnel_lines(tunnels))}


def _on_session_finalize(session_id: Optional[str] = None, **_kwargs: Any) -> None:
    """A tunnel must not outlive the session that opened it."""
    if session_id:
        stop_all_tunnels(session_id=session_id)


def register(ctx) -> None:
    """Called once by the Hermes plugin loader."""
    global _atexit_registered
    cfg.load_config()

    for tool_schema, handler in TOOLS:
        ctx.register_tool(name=tool_schema["name"], toolset=TOOLSET, schema=tool_schema, handler=handler,
                          description=tool_schema["description"])

    for name, short in SKILLS.items():
        skill_md = _PLUGIN_DIR / "skills" / name / "SKILL.md"
        if skill_md.exists():
            ctx.register_skill(name, skill_md, description=_frontmatter_description(skill_md) or short)

    def setting(key: str, default: Any) -> Any:
        try:
            return ctx.get_config(key, default=default)
        except Exception:
            return default

    ctx.register_hook("pre_tool_call", make_pre_tool_call_hook(setting, cfg.get_active_profile))
    ctx.register_hook("pre_llm_call", _open_tunnels_context)
    ctx.register_hook("on_session_finalize", _on_session_finalize)

    ctx.register_command("ssh", handler=make_ssh_command(ctx), description="Run a command on the active SSH host",
                         args_hint="<command>")
    ctx.register_command("ssh-key", handler=make_ssh_key_command(ctx),
                         description="Set up passwordless login for the active SSH host")

    register_section = getattr(ctx, "register_system_prompt_section", None)
    if callable(register_section):
        try:
            register_section("ssh.overview", _prompt_section)
        except Exception:
            logger.debug("ssh: could not register the system prompt section", exc_info=True)

    if not _atexit_registered:
        atexit.register(stop_all_tunnels)
        _atexit_registered = True
