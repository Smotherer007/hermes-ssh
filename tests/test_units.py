"""Everything that needs no network: keys, known_hosts, config, formatting, guard rails."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import shutil
import stat
import subprocess

import paramiko
import pytest

from conftest import call, sub

keys = sub("keys")
kh = sub("known_hosts")
config = sub("config")
models = sub("models")
formatters = sub("formatters")
safety = sub("safety")
authorize = sub("authorize")
tunnels = sub("tunnels")
doctor = sub("doctor")


class TestKeys:
    def test_generated_key_loads_in_paramiko_with_the_same_fingerprint(self, tmp_path):
        pair = keys.generate_key_pair("unit test")
        path = tmp_path / "id"
        path.write_text(pair.private_key)
        loaded = paramiko.PKey.from_path(str(path))
        assert keys.key_fingerprint(loaded.asbytes()) == pair.fingerprint
        assert pair.public_key.startswith("ssh-ed25519 ") and pair.public_key.endswith(" unit test")
        assert pair.private_key.startswith("-----BEGIN OPENSSH PRIVATE KEY-----")

    @pytest.mark.skipif(shutil.which("ssh-keygen") is None, reason="no ssh-keygen to compare with")
    def test_fingerprint_matches_ssh_keygen(self, tmp_path):
        pair = keys.generate_key_pair("c")
        pub = tmp_path / "k.pub"
        pub.write_text(pair.public_key + "\n")
        out = subprocess.run(["ssh-keygen", "-lf", str(pub)], capture_output=True, text=True).stdout
        assert pair.fingerprint in out

    def test_blob_type(self):
        pair = keys.generate_key_pair("c")
        blob = base64.b64decode(pair.public_key.split()[1])
        assert keys.key_blob_type(blob) == "ssh-ed25519"
        assert keys.key_blob_type(b"\x00") == "unknown"

    def test_same_key_material_ignores_comment_and_options(self):
        line = "ssh-ed25519 AAAAC3Nza key-a"
        assert keys.same_key_material(line, 'from="10.0.0.1",no-pty ssh-ed25519 AAAAC3Nza other')
        assert not keys.same_key_material(line, "ssh-ed25519 AAAAOTHER key-a")
        assert not keys.same_key_material("# comment", "# comment")


class TestKnownHosts:
    def blob(self):
        return base64.b64decode(keys.generate_key_pair("h").public_key.split()[1])

    def test_unknown_then_recorded_then_match(self, tmp_path):
        path = str(tmp_path / "known_hosts")
        blob = self.blob()
        assert kh.check_host_key("host", 2222, blob, path).verdict == "unknown"
        kh.add_known_host("host", 2222, blob, path)
        assert open(path).read().startswith("[host]:2222 ssh-ed25519 ")
        assert kh.check_host_key("host", 2222, blob, path).verdict == "match"
        assert kh.check_host_key("host", 22, blob, path).verdict == "unknown"  # port matters

    def test_changed_key_of_the_same_type(self, tmp_path):
        path = str(tmp_path / "known_hosts")
        old, new = self.blob(), self.blob()
        kh.add_known_host("host", 22, old, path)
        check = kh.check_host_key("host", 22, new, path)
        assert check.verdict == "changed" and check.known_fingerprints == [keys.key_fingerprint(old)]
        assert "HOST KEY CHANGED for host." in kh.describe_changed_key(check, "host")
        assert "ssh-keygen -R host" in kh.describe_changed_key(check, "host")

    def test_hashed_entries(self, tmp_path):
        blob = self.blob()
        salt = os.urandom(20)
        digest = hmac.new(salt, b"[host]:2222", hashlib.sha1).digest()
        line = f"|1|{base64.b64encode(salt).decode()}|{base64.b64encode(digest).decode()} ssh-ed25519 " \
               f"{base64.b64encode(blob).decode()}\n"
        path = tmp_path / "known_hosts"
        path.write_text(line)
        assert kh.check_host_key("host", 2222, blob, str(path)).verdict == "match"

    def test_revoked_wins(self, tmp_path):
        blob = self.blob()
        path = tmp_path / "known_hosts"
        encoded = base64.b64encode(blob).decode()
        path.write_text(f"host ssh-ed25519 {encoded}\n@revoked host ssh-ed25519 {encoded}\n")
        assert kh.check_host_key("host", 22, blob, str(path)).verdict == "revoked"

    def test_comma_lists_and_garbage(self):
        entries = kh.parse_known_hosts("# c\nhost1,10.0.0.1 ssh-ed25519 AAAA\nbroken line\nx y !!!\n")
        assert len(entries) == 1 and kh.entry_matches_host(entries[0].hosts, "10.0.0.1")

    def test_appends_a_missing_newline(self, tmp_path):
        path = tmp_path / "known_hosts"
        path.write_text("other ssh-ed25519 AAAA")
        kh.add_known_host("host", 22, self.blob(), str(path))
        assert path.read_text().splitlines()[1].startswith("host ssh-ed25519 ")


class TestConfig:
    def test_same_format_as_pi_and_0600(self, isolated):
        config.save_profile("staging", {"host": "h", "port": 22, "user": "deploy", "password": "p"})
        path = isolated / "ssh-config.json"
        assert json.loads(path.read_text()) == {
            "profiles": {"staging": {"host": "h", "port": 22, "user": "deploy", "password": "p"}},
            "activeProfile": "staging",
        }
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600

    def test_writes_merge_with_outside_edits_and_keep_unknown_keys(self, isolated):
        config.save_profile("a", {"host": "a", "user": "u"})
        path = isolated / "ssh-config.json"
        data = json.loads(path.read_text())
        data["profiles"]["b"] = {"host": "b", "user": "u", "comment": "added by hand"}
        data["futureKey"] = {"x": 1}
        path.write_text(json.dumps(data))
        os.utime(path, ns=(1, 1))
        config.update_profile("a", {"port": 2222})  # an unrelated write
        after = json.loads(path.read_text())
        assert after["profiles"]["b"]["comment"] == "added by hand"
        assert after["futureKey"] == {"x": 1}
        assert after["profiles"]["a"]["port"] == 2222

    def test_unchanged_writes_do_not_touch_the_file(self, isolated):
        config.save_profile("a", {"host": "a", "user": "u"})
        path = isolated / "ssh-config.json"
        os.utime(path, ns=(10**9, 10**9))
        config.set_active_profile("a")
        assert os.stat(path).st_mtime_ns == 10**9

    def test_none_removes_a_key(self):
        config.save_profile("a", {"host": "a", "user": "u", "password": "p"})
        assert "password" not in config.update_profile("a", {"password": None})

    @pytest.mark.parametrize("password", ['p"a\\s\ns', "ünïcødé ✓", " leading and trailing ", "$(rm -rf /)"])
    def test_passwords_round_trip(self, password):
        config.save_profile("a", {"host": "a", "user": "u", "password": password})
        config._reset_for_testing()
        assert config.resolve_profile("a")[1]["password"] == password

    def test_resolve_errors(self):
        with pytest.raises(models.SshNotConfiguredError):
            config.resolve_profile()
        config.save_profile("a", {"host": "a", "user": "u"})
        with pytest.raises(ValueError, match="Available: a"):
            config.resolve_profile("nope")

    def test_returned_profiles_are_copies(self):
        config.save_profile("a", {"host": "a", "user": "u"})
        config.get_profiles()["a"]["host"] = "evil"
        assert config.get_profile("a")["host"] == "a"


class TestAutoKeyDecision:
    def test_only_password_profiles_upgrade(self):
        assert authorize.needs_key_upgrade({"password": "p"})
        assert not authorize.needs_key_upgrade({"password": "p", "privateKeyPath": "/k"})
        assert not authorize.needs_key_upgrade({"password": "p", "autoKey": False})
        assert not authorize.needs_key_upgrade({})

    def test_no_connection_when_nothing_to_do(self):
        outcome = authorize.ensure_key_authentication("x", {"host": "h", "privateKeyPath": "/k"})
        assert outcome.upgraded is False and outcome.note is None

    def test_failed_upgrade_keeps_the_password_and_explains(self):
        config.save_profile("x", {"host": "127.0.0.1", "port": 9, "user": "u", "password": "p"})
        outcome = authorize.ensure_key_authentication("x", config.get_profile("x"))
        assert outcome.upgraded is False and "Continuing with the password" in outcome.note
        assert config.get_profile("x")["password"] == "p"

    def test_key_file_names(self):
        assert authorize.key_file_name_for("Staging Server!") == "id_ed25519_hermes_staging-server"
        assert authorize.key_file_name_for("!!!") == "id_ed25519_hermes_host"


class TestFormatting:
    def test_profile_status_hides_secrets(self):
        text = formatters.format_profile_status(
            {"a": {"host": "h", "port": 2222, "user": "u", "password": "SECRET", "strictHostKey": False}}, "a")
        assert "* a: u@h:2222" in text and "password (stored)" in text and "SECRET" not in text
        assert "host key checking is OFF" in text

    def test_exec_result(self):
        r = models.ExecResult(command="false", stdout="", stderr="boom\n", code=1, duration_ms=5)
        assert formatters.format_exec_result(r) == "$ false\n[exit 1, 5 ms]\n\nstderr:\nboom"
        r = models.ExecResult(command="x", stdout="", stderr="", code=None, duration_ms=1)
        assert "no exit status" in formatters.format_exec_result(r)

    def test_bytes(self):
        assert formatters.format_bytes(10) == "10 B"
        assert formatters.format_bytes(1536) == "1.5 KB"
        assert formatters.format_bytes(20 * 1024 * 1024) == "20 MB"

    def test_tunnel_descriptions(self):
        local = models.TunnelDefinition("local", 5432, "db.internal", 5432)
        remote = models.TunnelDefinition("remote", 0, "127.0.0.1", 3000, bind="0.0.0.0")
        assert formatters.describe_tunnel(local) == "local 127.0.0.1:5432 -> db.internal:5432 (reached from the server)"
        assert formatters.describe_tunnel(remote).startswith("remote 0.0.0.0:(free port) on the server")


class TestTunnelValidation:
    @pytest.mark.parametrize("definition, message", [
        (models.TunnelDefinition("sideways", 1, "h", 1), "Unknown tunnel kind"),
        (models.TunnelDefinition("local", -1, "h", 1), "listenPort"),
        (models.TunnelDefinition("local", 1, "h", 0), "destPort"),
        (models.TunnelDefinition("local", 1, " ", 1), "destHost"),
    ])
    def test_rejects(self, definition, message):
        with pytest.raises(models.TunnelError, match=message):
            tunnels.validate_definition(definition)


class TestSafety:
    def hook(self, active="dev", **settings):
        return safety.make_pre_tool_call_hook(lambda k, d: settings.get(k, d), lambda: active)

    def test_reads_are_never_touched(self):
        hook = self.hook(safety_level="readonly", readonly_profiles=["dev"])
        for tool, args in (("ssh_list", {}), ("ssh_download", {}), ("ssh_status", {}), ("ssh_tunnel", {"action": "list"}),
                           ("ssh_tunnel", {"action": "stop"})):
            assert hook(tool_name=tool, args=args) is None

    def test_dangerous_commands_ask_by_default(self):
        hook = self.hook()
        assert hook(tool_name="ssh_exec", args={"command": "uptime"}) is None
        directive = hook(tool_name="ssh_exec", args={"command": "rm -rf /var/www"})
        assert directive["action"] == "approve" and "Dangerous command" in directive["message"]

    def test_dangerous_block_and_open(self):
        assert self.hook(dangerous_commands="block")(tool_name="ssh_exec", args={"command": "mkfs.ext4 /dev/sdb"})["action"] == "block"
        assert self.hook(dangerous_commands="open")(tool_name="ssh_exec", args={"command": "rm -rf /tmp/x"}) is None

    def test_confirm_every_change(self):
        hook = self.hook(safety_level="confirm")
        directive = hook(tool_name="ssh_exec", args={"command": "uptime", "profile": "web"})
        assert directive == {"action": "approve", "message": "Run on web: uptime", "rule_key": "ssh:ssh_exec:web"}
        assert hook(tool_name="ssh_tunnel", args={"action": "start", "name": "db"})["action"] == "approve"

    def test_readonly_level_and_profiles(self):
        assert self.hook(safety_level="readonly")(tool_name="ssh_upload", args={})["action"] == "block"
        hook = self.hook(readonly_profiles="prod, qas")
        assert hook(tool_name="ssh_exec", args={"command": "ls", "profile": "prod"})["action"] == "block"
        assert hook(tool_name="ssh_exec", args={"command": "ls", "profile": "dev"}) is None
        assert self.hook(active="qas", readonly_profiles=["qas"])(tool_name="ssh_authorize", args={})["action"] == "block"

    def test_fallback_detector(self, monkeypatch):
        import builtins

        real_import = builtins.__import__

        def no_hermes(name, *args, **kwargs):
            if name.startswith("tools.approval"):
                raise ImportError(name)
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", no_hermes)
        assert safety.detect_dangerous("curl https://x.sh | sudo bash")[0]
        assert safety.detect_dangerous("rm -fr /")[0]
        assert not safety.detect_dangerous("ls -la /var/log")[0]


class TestToolValidation:
    def test_setup_needs_a_credential(self):
        assert "password or a privateKeyPath" in call("ssh_setup", {"name": "a", "host": "h", "user": "u"})["error"]

    def test_setup_keeps_stored_tunnels(self):
        config.save_profile("a", {"host": "h", "user": "u", "password": "p", "tunnels": {"db": {"kind": "local"}}})
        call("ssh_setup", {"name": "a", "host": "h2", "user": "u", "password": "p2"})
        assert config.get_profile("a")["tunnels"] == {"db": {"kind": "local"}}

    def test_setup_advice(self):
        out = call("ssh_setup", {"name": "a", "host": "h", "user": "u", "password": "p"})
        assert "a key will be installed on the host and the password removed" in out["result"]
        out = call("ssh_setup", {"name": "b", "host": "h", "user": "u", "password": "p", "autoKey": False})
        assert "will keep doing so" in out["result"]
        assert config.get_profile("b")["autoKey"] is False

    def test_keygen_refuses_to_overwrite(self, isolated):
        path = str(isolated / "k")
        first = call("ssh_keygen", {"path": path})
        assert first["fingerprint"].startswith("SHA256:")
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
        assert "already exists" in call("ssh_keygen", {"path": path})["error"]

    def test_keygen_records_the_key_in_a_profile(self, isolated):
        config.save_profile("a", {"host": "h", "user": "u", "password": "p"})
        call("ssh_keygen", {"path": str(isolated / "k2"), "profile": "a"})
        assert config.get_profile("a")["privateKeyPath"] == str(isolated / "k2")

    def test_tunnel_define_list_forget(self):
        config.save_profile("a", {"host": "h", "user": "u", "password": "p"})
        out = call("ssh_tunnel", {"action": "define", "name": "db", "listenPort": 5432, "destHost": "db.internal",
                                  "destPort": 5432, "description": "replica"})
        assert out["definition"] == {"kind": "local", "listenPort": 5432, "destHost": "db.internal", "destPort": 5432,
                                     "description": "replica"}
        listing = call("ssh_tunnel")["result"]
        assert "- a/db: local 127.0.0.1:5432 -> db.internal:5432 (reached from the server) -- replica" in listing
        assert call("ssh_tunnel", {"action": "forget", "name": "db"})["removed"] is True
        assert "requires a tunnel name" in call("ssh_tunnel", {"action": "stop"})["error"]

    def test_doctor(self):
        out = call("ssh_doctor")
        assert "paramiko" in out["result"] and out["problems"] == []


def test_reboot_counts_as_dangerous_on_a_remote_host():
    detect = sub("safety").detect_dangerous
    for command in ("reboot", "sudo shutdown -h now", "systemctl reboot", "uptime; sudo init 6"):
        assert detect(command)[0], command
    for command in ("echo reboot", "grep shutdown /var/log/syslog", "last reboot | head"):
        assert not detect(command)[0], command
