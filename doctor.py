"""Environment report: "what do I have to install to use this?", answered with evidence.

The short answer is nothing beyond the plugin itself: paramiko speaks SSH in
Python and keys are generated with ``cryptography``, so no ``ssh``,
``ssh-keygen`` or ``ssh-copy-id`` binary is needed. What the checks find are
the optional conveniences and the things that genuinely break a connection.
"""

from __future__ import annotations

import os
import platform
import shutil
import sys
from dataclasses import dataclass
from typing import List, Optional, Sequence

from . import config as cfg
from .known_hosts import default_known_hosts_path


@dataclass(frozen=True)
class Check:
    name: str
    status: str  # ok | note | problem
    detail: str
    remedy: Optional[str] = None


def describe_permission_support(system: str) -> Check:
    if system != "win32":
        return Check("File permissions", "ok", "secrets are written owner-only (0600) and that is enforced")
    return Check(
        "File permissions", "note",
        "Windows ignores the owner-only modes this plugin sets; access is governed by ACLs instead",
        f"{cfg.config_path()} can hold a password and ~/.ssh holds private keys. Make sure your user profile "
        "directory is not shared, or let ssh_authorize replace the password with a key.",
    )


def _check_python() -> Check:
    version = ".".join(str(p) for p in sys.version_info[:3])
    if sys.version_info >= (3, 11):
        return Check("Python", "ok", version)
    return Check("Python", "problem", f"{version} is older than Hermes supports", "Run Hermes on Python 3.11+.")


def _check_paramiko() -> Check:
    try:
        import paramiko

        return Check("SSH implementation", "ok", f"paramiko {paramiko.__version__}, pure Python -- no ssh binary needed")
    except Exception as err:
        return Check("SSH implementation", "problem", f"paramiko is not importable ({err})",
                     "Reinstall the plugin: hermes plugins update ssh (it installs paramiko).")


def _check_keygen() -> Check:
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519

        ed25519.Ed25519PrivateKey.generate()
        return Check("Key generation", "ok", "ed25519 keys are generated in process; ssh-keygen is not required")
    except Exception as err:
        return Check("Key generation", "problem", f"cryptography cannot generate ed25519 keys ({err})")


def _check_openssh_client() -> Check:
    found = shutil.which("ssh")
    if found:
        return Check("OpenSSH client (optional)", "ok", f"{found} -- keys made here work with it too")
    remedy = ("Not needed by this plugin. To use keys from a terminal too: Settings -> Apps -> Optional features "
              "-> OpenSSH Client." if sys.platform == "win32"
              else "Not needed by this plugin. Install openssh-client if you also want to ssh by hand.")
    return Check("OpenSSH client (optional)", "note", "no ssh command on PATH", remedy)


def _check_ssh_directory() -> Check:
    directory = os.path.join(os.path.expanduser("~"), ".ssh")
    if not os.path.isdir(directory):
        return Check("~/.ssh", "note", f"{directory} does not exist yet; it will be created when first needed")
    if sys.platform != "win32":
        mode = os.stat(directory).st_mode & 0o777
        if mode & 0o077:
            return Check("~/.ssh", "note", f"{directory} is group- or world-accessible (mode {mode:o})",
                         f"chmod 700 {directory} -- OpenSSH refuses some keys otherwise.")
    return Check("~/.ssh", "ok", directory)


def _check_known_hosts() -> Check:
    path = default_known_hosts_path()
    if not os.path.exists(path):
        return Check("known_hosts", "note",
                     f"{path} does not exist; the first connection to each host will have to be confirmed")
    if not os.access(path, os.R_OK | os.W_OK):
        return Check("known_hosts", "problem", f"{path} is not readable and writable",
                     "Host keys cannot be verified or recorded until that is fixed.")
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        count = sum(1 for line in handle if line.strip() and not line.startswith("#"))
    return Check("known_hosts", "ok", f"{path} ({count} host{'' if count == 1 else 's'} on record)")


def _check_config_file() -> Check:
    path = cfg.config_path()
    if not path.exists():
        return Check("Stored hosts", "note", "no hosts configured yet")
    if sys.platform != "win32":
        mode = path.stat().st_mode & 0o777
        if mode != 0o600:
            return Check("Stored hosts", "problem", f"{path} has mode {mode:o} and may contain passwords",
                         f"chmod 600 {path}")
    return Check("Stored hosts", "ok", f"{path} (owner only)")


def run_checks() -> List[Check]:
    return [
        _check_python(),
        _check_paramiko(),
        _check_keygen(),
        _check_openssh_client(),
        describe_permission_support(sys.platform),
        _check_ssh_directory(),
        _check_known_hosts(),
        _check_config_file(),
    ]


def format_checks(checks: Sequence[Check]) -> str:
    symbol = {"ok": "ok  ", "note": "note", "problem": "FAIL"}
    lines = []
    for check in checks:
        head = f"[{symbol[check.status]}] {check.name}: {check.detail}"
        lines.append(f"{head}\n         {check.remedy}" if check.remedy else head)
    problems = sum(1 for c in checks if c.status == "problem")
    summary = (f"{problems} problem(s) need attention before this will work reliably." if problems
               else "Nothing needs to be installed: this plugin speaks SSH itself and generates its own keys.")
    return "\n".join([f"Environment ({sys.platform}, {platform.machine()}):", *lines, "", summary])
