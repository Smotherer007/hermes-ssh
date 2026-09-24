"""Test fixtures.

The plugin is imported the way Hermes imports a directory plugin: as a
package whose ``__init__.py`` is the repository root.

Every test runs with its own HOME (so ~/.ssh, known_hosts and generated keys
land in a temp directory) and its own config file. The end-to-end tests share
one real sshd on a loopback port, and skip where there is none.
"""

from __future__ import annotations

import importlib
import importlib.util
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Optional

import pytest

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = "hermes_plugins_test.ssh"
sys.path.insert(0, str(Path(__file__).resolve().parent))


def _load_plugin():
    if PACKAGE in sys.modules:
        return sys.modules[PACKAGE]
    parent = "hermes_plugins_test"
    if parent not in sys.modules:
        namespace = importlib.util.module_from_spec(importlib.machinery.ModuleSpec(parent, None, is_package=True))
        namespace.__path__ = []  # type: ignore[attr-defined]
        sys.modules[parent] = namespace
    spec = importlib.util.spec_from_file_location(PACKAGE, ROOT / "__init__.py", submodule_search_locations=[str(ROOT)])
    module = importlib.util.module_from_spec(spec)
    sys.modules[PACKAGE] = module
    spec.loader.exec_module(module)
    return module


plugin = _load_plugin()


def sub(name: str):
    return importlib.import_module(f"{PACKAGE}.{name}")


import sshd as sshd_helper  # noqa: E402  (tests/ is on sys.path)


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_SSH_CONFIG", str(tmp_path / "ssh-config.json"))
    config = sub("config")
    config._reset_for_testing()
    yield tmp_path
    sub("tunnels").stop_all_tunnels()
    config._reset_for_testing()


@pytest.fixture(scope="session")
def server():
    keys = sub("keys")
    srv = sshd_helper.start_test_server(keys.generate_key_pair)
    if srv is None:
        pytest.skip("no sshd on this machine")
    yield srv
    srv.stop()


@pytest.fixture
def profile(server):
    """A key-authenticated profile 'test' for the sshd, host key not yet known."""
    config = sub("config")
    data = {"host": "127.0.0.1", "port": server.port, "user": server.user, "privateKeyPath": server.client_key_path}
    config.save_profile("test", data)
    return data


@pytest.fixture
def known(profile):
    """The same profile with its host key already recorded."""
    client = sub("ssh_client")
    with client.with_connection(profile, accept_new_host_key=True):
        pass
    return profile


@pytest.fixture
def password_profile(server):
    """A password-only profile for a throwaway local account (root-only environments)."""
    if not server.password_user:
        pytest.skip("password logins need sshd running as root")
    home = os.path.expanduser(f"~{server.password_user}")
    # expanduser with a user name ignores the patched HOME: it reads /etc/passwd
    shutil.rmtree(os.path.join(home, ".ssh"), ignore_errors=True)
    config = sub("config")
    data = {"host": "127.0.0.1", "port": server.port, "user": server.password_user,
            "password": sshd_helper.PASSWORD}
    config.save_profile("pw", data)
    client = sub("ssh_client")
    with client.with_connection(data, accept_new_host_key=True):
        pass
    return data


def call(tool: str, args: Optional[dict] = None, **context) -> dict:
    """Invoke a tool handler the way Hermes does and decode its JSON result."""
    tools = sub("tools")
    handler = next(h for s, h in tools.TOOLS if s["name"] == tool)
    raw = handler(args or {}, task_id=context.get("task_id", "t1"), session_id=context.get("session_id", "s1"))
    assert isinstance(raw, str), "handlers must return a JSON string"
    return json.loads(raw)
