"""Slash commands ``/ssh`` and ``/ssh-key``.

pi's commands queue a prompt for the agent; the Hermes equivalent is
``ctx.inject_message``. It always works in the CLI. In the gateway Hermes
only allows it with ``plugins.entries.ssh.allow_gateway_injection: true``;
without that, the command answers with the prompt to send as a message.
"""

from __future__ import annotations

import os
from typing import Any, Callable

from . import config as cfg

NOT_CONFIGURED = "No SSH host configured. Use the ssh_setup tool first."


def _session_key() -> str:
    try:
        from gateway.session_context import get_session_env  # type: ignore

        return get_session_env("HERMES_SESSION_KEY", "")
    except Exception:
        return os.environ.get("HERMES_SESSION_KEY", "")


def _deliver(ctx: Any, prompt: str, started: str) -> str:
    try:
        if ctx.inject_message(prompt, session_key=_session_key() or None):
            return started
    except Exception:
        pass
    return ("I could not start this automatically here (the gateway needs "
            "plugins.entries.ssh.allow_gateway_injection: true). Send this as a message instead:\n\n" + prompt)


def make_ssh_command(ctx: Any) -> Callable[[str], str]:
    def ssh(raw_args: str = "") -> str:
        if cfg.get_config() is None:
            return NOT_CONFIGURED
        command = (raw_args or "").strip()
        if not command:
            return "Usage: /ssh <command to run on the remote host>"
        return _deliver(ctx, f"Run this on the active SSH host with ssh_exec and show me the output: {command}",
                        "Running on the remote host...")

    return ssh


def make_ssh_key_command(ctx: Any) -> Callable[[str], str]:
    def ssh_key(raw_args: str = "") -> str:
        if cfg.get_config() is None:
            return NOT_CONFIGURED
        return _deliver(
            ctx,
            "Use ssh_authorize on the active SSH profile to generate a key, install it on the host and verify "
            "that a key-only login works. Tell me the fingerprint and whether the verification succeeded.",
            "Setting up key-based login...",
        )

    return ssh_key
