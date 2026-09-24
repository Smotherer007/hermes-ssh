"""Configuration persistence and state.

Stores named host profiles in ``$HERMES_HOME/ssh-config.json`` (override with
``HERMES_SSH_CONFIG``). Because ``HERMES_HOME`` is per Hermes profile, every
Hermes profile gets its own set of hosts.

File format -- identical to pi-ssh, so the same file works for both::

    { "profiles": { "name": {host, port, user, password?, privateKeyPath?, ...} },
      "activeProfile": "name" }

The file is safe to edit while Hermes runs, and safe to share with another
process (CLI and gateway, or pi):

* **Writes merge.** Every write re-reads the file and applies only its own
  change, so a host added by hand or by another process is not erased.
* **Outside edits are picked up** on the next call.
* **Unknown keys survive**, at the top level and inside a profile.
* **Nothing is rewritten needlessly**: an unchanged file keeps its mtime.

Writes are atomic (private temp file, then rename) and owner-only (0600),
because the file can hold passwords and key passphrases.
"""

from __future__ import annotations

import copy
import json
import os
import threading
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

from .models import SshNotConfiguredError

_lock = threading.RLock()

# Mutable state
_store: Dict[str, Any] = {"profiles": {}, "activeProfile": None, "extra": {}}
_last_seen: Optional[Tuple[int, int]] = None
_last_path: Optional[Path] = None


# Paths


def _hermes_home() -> Path:
    try:
        from hermes_constants import get_hermes_home  # type: ignore

        return Path(get_hermes_home())
    except Exception:
        home = os.environ.get("HERMES_HOME", "").strip()
        return Path(home).expanduser() if home else Path.home() / ".hermes"


def config_path() -> Path:
    override = os.environ.get("HERMES_SSH_CONFIG", "").strip()
    if override:
        return Path(override).expanduser()
    return _hermes_home() / "ssh-config.json"


def expand_path(value: str) -> str:
    """Expand a leading ~ and make the path absolute."""
    raw = str(value if value is not None else "").strip()
    if not raw:
        return raw
    return os.path.abspath(os.path.expanduser(raw))


# Reading and writing


def _empty() -> Dict[str, Any]:
    return {"profiles": {}, "activeProfile": None, "extra": {}}


def _stamp(path: Path) -> Optional[Tuple[int, int]]:
    try:
        stat = path.stat()
        return stat.st_mtime_ns, stat.st_size
    except OSError:
        return None


def _read(path: Path) -> Dict[str, Any]:
    """The file as a store. Missing or unreadable is empty."""
    try:
        if not path.exists():
            return _empty()
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return _empty()
    if not isinstance(raw, dict):
        return _empty()
    extra = {k: v for k, v in raw.items() if k not in ("profiles", "activeProfile")}
    profiles = raw.get("profiles") if isinstance(raw.get("profiles"), dict) else {}
    profiles = {str(k): v for k, v in profiles.items() if isinstance(v, dict)}
    active = raw.get("activeProfile")
    if not (isinstance(active, str) and active in profiles):
        active = next(iter(profiles), None)
    return {"profiles": profiles, "activeProfile": active, "extra": extra}


def _serialize(store: Dict[str, Any]) -> str:
    data = {"profiles": store["profiles"], "activeProfile": store["activeProfile"], **store["extra"]}
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


def _commit(store: Dict[str, Any]) -> None:
    global _last_seen, _last_path
    path = config_path()
    text = _serialize(store)
    try:
        current = path.read_text(encoding="utf-8")
    except OSError:
        current = None
    if current == text:
        _last_seen, _last_path = _stamp(path), path
        return

    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except Exception:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise
    _last_seen, _last_path = _stamp(path), path


def _mutate(change: Callable[[Dict[str, Any]], Dict[str, Any]]) -> Dict[str, Any]:
    """Apply a change to what is on disk *now*, not to a cached copy."""
    global _store
    with _lock:
        updated = change(_read(config_path()))
        _commit(updated)
        _store = updated
        return updated


def _ensure_fresh() -> None:
    global _store, _last_seen, _last_path
    path = config_path()
    stamp = _stamp(path)
    if path != _last_path or stamp != _last_seen:
        _store = _read(path)
        _last_seen, _last_path = stamp, path


def load_config() -> None:
    global _store, _last_seen, _last_path
    with _lock:
        path = config_path()
        _store = _read(path)
        try:
            if path.exists() and os.name != "nt" and (path.stat().st_mode & 0o777) != 0o600:
                os.chmod(path, 0o600)
        except OSError:
            pass  # reported by ssh_doctor, not fatal here
        _last_seen, _last_path = _stamp(path), path


# Access (copies, so callers cannot mutate the cache)


def get_profiles() -> Dict[str, Dict[str, Any]]:
    with _lock:
        _ensure_fresh()
        return copy.deepcopy(_store["profiles"])


def get_active_profile() -> Optional[str]:
    with _lock:
        _ensure_fresh()
        return _store["activeProfile"]


def get_profile(name: str) -> Optional[Dict[str, Any]]:
    with _lock:
        _ensure_fresh()
        profile = _store["profiles"].get(name)
        return copy.deepcopy(profile) if profile is not None else None


def get_config() -> Optional[Dict[str, Any]]:
    with _lock:
        _ensure_fresh()
        active = _store["activeProfile"]
        return get_profile(active) if active else None


def resolve_profile(name: Optional[str] = None) -> Tuple[str, Dict[str, Any]]:
    """The named profile (or raise), or the active one."""
    with _lock:
        _ensure_fresh()
        if name:
            profile = _store["profiles"].get(name)
            if profile is None:
                available = ", ".join(_store["profiles"]) or "none"
                raise ValueError(f'Profile "{name}" not found. Available: {available}')
            return name, copy.deepcopy(profile)
        active = _store["activeProfile"]
        if not active or active not in _store["profiles"]:
            raise SshNotConfiguredError()
        return active, copy.deepcopy(_store["profiles"][active])


# Mutations


def save_profile(name: str, profile: Dict[str, Any]) -> None:
    def change(store: Dict[str, Any]) -> Dict[str, Any]:
        store["profiles"][name] = dict(profile)
        if not store["activeProfile"] or len(store["profiles"]) == 1:
            store["activeProfile"] = name
        return store

    _mutate(change)


def update_profile(name: str, patch: Dict[str, Any]) -> Dict[str, Any]:
    """Merge ``patch`` into a profile. A value of None removes that key."""
    result: Dict[str, Any] = {}

    def change(store: Dict[str, Any]) -> Dict[str, Any]:
        existing = store["profiles"].get(name)
        if existing is None:
            raise ValueError(f'Profile "{name}" does not exist.')
        updated = dict(existing)
        for key, value in patch.items():
            if value is None:
                updated.pop(key, None)
            else:
                updated[key] = value
        store["profiles"][name] = updated
        result.update(updated)
        return store

    _mutate(change)
    return copy.deepcopy(result)


def set_active_profile(name: str) -> None:
    def change(store: Dict[str, Any]) -> Dict[str, Any]:
        if name not in store["profiles"]:
            available = ", ".join(store["profiles"]) or "none"
            raise ValueError(f'Profile "{name}" does not exist. Available: {available}')
        store["activeProfile"] = name
        return store

    _mutate(change)


def delete_profile(name: str) -> bool:
    removed = []

    def change(store: Dict[str, Any]) -> Dict[str, Any]:
        if name in store["profiles"]:
            removed.append(True)
            del store["profiles"][name]
            if store["activeProfile"] == name:
                store["activeProfile"] = next(iter(store["profiles"]), None)
        return store

    _mutate(change)
    return bool(removed)


def _reset_for_testing() -> None:
    global _store, _last_seen, _last_path
    with _lock:
        _store, _last_seen, _last_path = _empty(), None, None


# Profile field helpers (defaults as in pi-ssh)


def port_of(profile: Dict[str, Any]) -> int:
    try:
        return int(profile.get("port") or 22)
    except (TypeError, ValueError):
        return 22
