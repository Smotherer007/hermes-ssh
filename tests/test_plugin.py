"""The plugin as Hermes sees it: registration matches the manifest."""

from __future__ import annotations

import inspect
from pathlib import Path

import yaml

from conftest import ROOT, call, plugin, sub


class FakeContext:
    def __init__(self, settings=None, inject=True):
        self.tools, self.hooks, self.commands, self.skills, self.sections = {}, {}, {}, {}, {}
        self.settings = settings or {}
        self.injected = []
        self.inject = inject

    def register_tool(self, name, toolset, schema, handler, description=""):
        self.tools[name] = (toolset, schema, handler)

    def register_hook(self, name, fn):
        self.hooks.setdefault(name, []).append(fn)

    def register_command(self, name, handler, description="", args_hint=""):
        self.commands[name] = handler

    def register_skill(self, name, path, description=""):
        self.skills[name] = (Path(path), description)

    def register_system_prompt_section(self, section_id, fn):
        self.sections[section_id] = fn

    def get_config(self, key, default=None):
        return self.settings.get(key, default)

    def inject_message(self, prompt, session_key=None):
        self.injected.append(prompt)
        return self.inject


def manifest():
    return yaml.safe_load((ROOT / "plugin.yaml").read_text())


def test_registration_matches_manifest():
    ctx = FakeContext()
    plugin.register(ctx)
    data = manifest()
    assert data["name"] == "hermes-remote-ssh"
    assert sorted(ctx.tools) == sorted(data["provides_tools"])
    assert sorted(ctx.hooks) == sorted(data["provides_hooks"])
    assert {t[0] for t in ctx.tools.values()} == {"ssh"}
    assert set(ctx.commands) == {"ssh", "ssh-key"}
    assert set(ctx.skills) == {"ssh-remote-work", "ssh-key-setup"}


def test_skill_frontmatter_is_valid_yaml():
    for name in ("ssh-remote-work", "ssh-key-setup"):
        text = (ROOT / "skills" / name / "SKILL.md").read_text()
        assert text.startswith("---\n")
        front = yaml.safe_load(text[4:text.index("\n---", 4)])
        assert front["name"] == name
        assert front["description"]
        assert front["metadata"]["hermes"]["requires_toolsets"] == ["ssh"]


def test_handler_signature_exposes_kwargs_for_session_id():
    ctx = FakeContext()
    plugin.register(ctx)
    handler = ctx.tools["ssh_tunnel"][2]
    kinds = [p.kind for p in inspect.signature(handler).parameters.values()]
    assert inspect.Parameter.VAR_KEYWORD in kinds


def test_prompt_section_lists_hosts_without_secrets():
    config = sub("config")
    config.save_profile("prod", {"host": "db.example", "user": "ops", "password": "hunter2-secret", "port": 2222})
    ctx = FakeContext()
    plugin.register(ctx)
    text = ctx.sections["ssh.overview"]({})
    assert "prod" in text and "ops@db.example:2222" in text
    assert "hunter2-secret" not in text


def test_commands_without_config_and_with_injection():
    ctx = FakeContext()
    plugin.register(ctx)
    assert "ssh_setup" in ctx.commands["ssh"]("uptime")
    sub("config").save_profile("box", {"host": "h", "user": "u", "password": "p"})
    assert ctx.commands["ssh"]("").startswith("Usage")
    assert ctx.commands["ssh"]("uptime") == "Running on the remote host..."
    assert "uptime" in ctx.injected[-1]
    assert ctx.commands["ssh-key"]("")
    assert "ssh_authorize" in ctx.injected[-1]


def test_command_falls_back_when_injection_is_refused():
    ctx = FakeContext(inject=False)
    plugin.register(ctx)
    sub("config").save_profile("box", {"host": "h", "user": "u", "password": "p"})
    reply = ctx.commands["ssh"]("df -h")
    assert "allow_gateway_injection" in reply and "df -h" in reply


def test_hook_blocks_in_readonly_mode():
    ctx = FakeContext(settings={"safety_level": "readonly"})
    plugin.register(ctx)
    hook = ctx.hooks["pre_tool_call"][0]
    verdict = hook(tool_name="ssh_exec", args={"command": "ls"}, session_id="s", task_id="t")
    assert verdict and verdict["action"] == "block"
    assert hook(tool_name="ssh_list", args={"path": "/"}, session_id="s", task_id="t") is None


def test_unknown_tool_error_is_json():
    outcome = call("ssh_exec", {})
    assert "error" in outcome
