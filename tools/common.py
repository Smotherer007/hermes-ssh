"""What every tool that opens a connection does first.

Resolving the profile and upgrading it to key authentication belong together:
the upgrade has to happen before the connection the tool actually wants, and
its outcome has to reach the user.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from .. import config as cfg
from ..authorize import ensure_key_authentication


@dataclass(frozen=True)
class ConnectionContext:
    name: str
    profile: Dict[str, Any]
    #: Worth showing the user, e.g. that the password was just replaced.
    note: Optional[str] = None


def resolve_for_connection(profile_name: Optional[str], accept_new_host_key: bool = False) -> ConnectionContext:
    name, profile = cfg.resolve_profile(profile_name)
    outcome = ensure_key_authentication(name, profile, accept_new_host_key=accept_new_host_key)
    return ConnectionContext(name=name, profile=outcome.profile, note=outcome.note)


def with_note(text: str, note: Optional[str]) -> str:
    return f"{text}\n\n{note}" if note else text
