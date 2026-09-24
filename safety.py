"""Guard rails, enforced through Hermes' ``pre_tool_call`` hook.

Settings under ``plugins.entries.ssh.settings`` in ``config.yaml`` (or the
Desktop settings form):

``dangerous_commands`` (default ``confirm``) -- an ``ssh_exec`` command that
Hermes' own detector flags as dangerous (``rm -rf``, ``mkfs``, ``dd`` to a
disk, a fork bomb, ``curl | sh`` ...) goes through the approval gate, exactly
as it would in Hermes' local terminal. ``block`` refuses it, ``open`` lets it
run. The same command should not become safer by running on another machine.

``safety_level`` (default ``open``) -- for everything that changes a remote
host: ``ssh_exec``, ``ssh_upload``, ``ssh_authorize``, and starting,
defining or forgetting a tunnel. ``confirm`` asks a human for every such
call, ``readonly`` blocks them (listing and downloading still work).

``readonly_profiles`` -- profile names (e.g. ``prod``) where every such call
is blocked, whatever the other settings say. A call without a ``profile``
argument counts as the active profile.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Iterable, Optional, Tuple

PLUGIN = "ssh"
LEVELS = ("open", "confirm", "readonly")
DANGEROUS_MODES = ("confirm", "open", "block")

#: Minimal fallback for when Hermes' detector cannot be imported.
_FALLBACK_PATTERNS = (
    (r"\brm\s+(-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r)[a-z]*\b", "recursive forced delete"),
    (r"\bmkfs(\.\w+)?\b", "format a filesystem"),
    (r"\bdd\b[^|;&]*\bof=/dev/", "write to a block device"),
    (r":\(\)\s*\{\s*:\|:&\s*\};:", "fork bomb"),
    (r"\b(curl|wget)\b[^|;&]*\|\s*(sudo\s+)?(ba|z|k)?sh\b", "pipe a download into a shell"),
    (r"\bchmod\s+(-R\s+)?[0-7]*777\s+/", "world-writable system path"),
    (r">\s*/dev/sd[a-z]", "write to a disk device"),
)


#: Checked on top of Hermes' detector: harmless on a laptop, not on a server
#: that other people depend on.
_REMOTE_EXTRA_PATTERNS = (
    (r"(^|[;&|(]\s*|\bsudo\s+)(shutdown|reboot|halt|poweroff)\b", "shut down or reboot the host"),
    (r"\bsystemctl\s+(reboot|poweroff|halt|kexec)\b", "shut down or reboot the host"),
    (r"(^|[;&|(]\s*|\bsudo\s+)init\s+[06]\b", "shut down or reboot the host"),
)


def detect_dangerous(command: str) -> Tuple[bool, Optional[str]]:
    """Hermes' own dangerous-command detector, plus remote-only patterns and a fallback."""
    lowered = command.lower()
    for pattern, description in _REMOTE_EXTRA_PATTERNS:
        if re.search(pattern, lowered):
            return True, description
    try:
        from tools.approval_detection import detect_dangerous_command  # type: ignore
    except Exception:
        try:
            from tools.approval import detect_dangerous_command  # type: ignore  # older layout
        except Exception:
            detect_dangerous_command = None
    if detect_dangerous_command is not None:
        try:
            dangerous, _key, description = detect_dangerous_command(command)
            return bool(dangerous), description
        except Exception:
            pass
    for pattern, description in _FALLBACK_PATTERNS:
        if re.search(pattern, lowered):
            return True, description
    return False, None


def _action(args: dict) -> str:
    return str(args.get("action") or "list").lower()


def is_change(tool_name: str, args: dict) -> bool:
    if tool_name in ("ssh_exec", "ssh_upload", "ssh_authorize"):
        return True
    if tool_name == "ssh_tunnel":
        return _action(args) in ("start", "define", "forget")
    return False


def describe(tool_name: str, args: dict, profile: Optional[str]) -> str:
    where = f" on {profile}" if profile else ""
    if tool_name == "ssh_exec":
        cwd = f" (in {args['cwd']})" if args.get("cwd") else ""
        return f"Run{where}: {args.get('command', '?')}{cwd}"
    if tool_name == "ssh_upload":
        return f"Upload {args.get('localPath', '?')} to {args.get('remotePath', '?')}{where}"
    if tool_name == "ssh_authorize":
        return f"Install an SSH key in authorized_keys{where}"
    if tool_name == "ssh_tunnel":
        return f"{_action(args).capitalize()} SSH tunnel {args.get('name', '?')}{where}"
    return f"Run {tool_name}{where}"


def make_pre_tool_call_hook(
    get_setting: Callable[[str, Any], Any],
    active_profile: Callable[[], Optional[str]],
) -> Callable[..., Optional[dict]]:
    def pre_tool_call(tool_name: str = "", args: Optional[dict] = None, **_kwargs: Any) -> Optional[dict]:
        args = args or {}
        if not is_change(tool_name, args):
            return None
        profile = args.get("profile") or active_profile()

        readonly: Iterable[str] = get_setting("readonly_profiles", []) or []
        if isinstance(readonly, str):
            readonly = [p.strip() for p in readonly.split(",")]
        if profile and profile in set(readonly):
            return {"action": "block",
                    "message": f'{tool_name} is blocked: SSH profile "{profile}" is read-only '
                    f"(plugins.entries.{PLUGIN}.settings.readonly_profiles)."}

        level = str(get_setting("safety_level", "open") or "open").lower()
        level = level if level in LEVELS else "confirm"
        if level == "readonly":
            return {"action": "block",
                    "message": f"{tool_name} is blocked: the SSH plugin is read-only "
                    f"(plugins.entries.{PLUGIN}.settings.safety_level). Listing and downloading still work."}

        if tool_name == "ssh_exec":
            mode = str(get_setting("dangerous_commands", "confirm") or "confirm").lower()
            mode = mode if mode in DANGEROUS_MODES else "confirm"
            dangerous, reason = detect_dangerous(str(args.get("command", "")))
            if dangerous and mode == "block":
                return {"action": "block",
                        "message": f"Blocked: the command was flagged as dangerous ({reason}) "
                        f"(plugins.entries.{PLUGIN}.settings.dangerous_commands)."}
            if dangerous and mode == "confirm":
                return {"action": "approve",
                        "message": f"Dangerous command ({reason}). {describe(tool_name, args, profile)}",
                        "rule_key": f"{PLUGIN}:dangerous:{profile or ''}:{reason}"}

        if level == "confirm":
            return {"action": "approve", "message": describe(tool_name, args, profile),
                    "rule_key": f"{PLUGIN}:{tool_name}:{profile or ''}"}
        return None

    return pre_tool_call
