# hermes-ssh

SSH plugin for [Hermes Agent](https://github.com/NousResearch/hermes-agent).

With it, Hermes can run commands on remote hosts, move files over SFTP and forward ports. It can also switch a host from password to key login. SSH is spoken in Python ([paramiko](https://www.paramiko.org/)) and keys are generated in process, so no `ssh`, `ssh-keygen` or `ssh-copy-id` has to be installed. That includes Windows.

This is the Hermes port of [pi-ssh](https://github.com/Smotherer007/pi-ssh). The 11 tools, their parameters, the config file format and the two skills are the same.

## Installation

```bash
hermes plugins install Smotherer007/hermes-ssh
hermes plugins enable ssh
```

The plugin's name is `ssh`. The Hermes catalog already has an unrelated plugin called `hermes-ssh`. Installing also installs paramiko.

**The install-time security scan blocks this plugin.** Hermes' scanner treats every occurrence of `authorized_keys` as a critical "SSH backdoor" finding, and `--force` does not override that. But installing a public key in `authorized_keys` is exactly what `ssh_authorize` does, on purpose, when you ask it to. This plugin does not hide the string to get past the scanner. Instead, read the code, then install with the scan turned off for this one step:

```bash
hermes config set plugins.scan_on_install false
hermes plugins install Smotherer007/hermes-ssh --enable
hermes config set plugins.scan_on_install true
```

To install from a local checkout for development, use the same steps with `file://$PWD/hermes-ssh`.

## Quick start

```yaml
ssh_setup:
  name: staging
  host: staging.example.com
  user: deploy
  password: ...
```

On the first connection, the plugin runs through these steps:

1. It shows the host key fingerprint and refuses to continue until it is confirmed. The model asks you, then retries with `acceptNewHostKey: true`.
2. It generates a key `~/.ssh/id_ed25519_hermes_staging`, installs it on the host and verifies a key-only login.
3. It removes the password from the config file.

From then on, the host uses key login. To keep password login, set `autoKey: false`. If a host refuses keys, the password stays and the tool says why.

## Tools

All tools belong to the `ssh` toolset.

| Group | Tools |
|---|---|
| Hosts | `ssh_setup`, `ssh_status`, `ssh_profile`, `ssh_doctor` |
| Remote work | `ssh_exec`, `ssh_list`, `ssh_upload`, `ssh_download` |
| Keys | `ssh_keygen`, `ssh_authorize` |
| Port forwarding | `ssh_tunnel` (start, stop, stop-all, list, define, forget) |

Each tool returns JSON. `result` holds the text for the model, and the other keys hold structured details, for example `exitCode`. On failure the tool returns `{"error": "..."}`. Each call opens its own connection and closes it at the end. The only exception is a running tunnel.

Two slash commands queue a prompt for the agent. `/ssh <command>` runs a command on the active host, and `/ssh-key` sets up key login. In the gateway, this needs `plugins.entries.ssh.allow_gateway_injection: true`. Without it, the command replies with the text to send as a message.

## Host keys

Host keys are checked against OpenSSH's `~/.ssh/known_hosts`. It is the same file the `ssh` command uses, including hashed entries, `[host]:port` and `@revoked`. Each case is handled differently:

- **Unknown host:** refused until confirmed.
- **Changed key:** always refused, even with `acceptNewHostKey`. Changed keys can come from a reinstall or an attack. The error tells the user how to remove the old entry.
- **`strictHostKey: false`:** records unknown keys without asking. Only use it for throwaway machines.

## Tunnels

`ssh_tunnel` supports two directions:

- **`local`:** like `ssh -L`. A port on this machine reaches a service behind the server.
- **`remote`:** like `ssh -R`. A port on the server reaches something on this machine.

Named tunnels can be stored in the profile with `define` and started by name later. `ssh_setup` keeps stored tunnels when a host is reconfigured.

Unlike the other tools, a tunnel keeps running after the call returns. It stops when one of these happens:

- `stop` or `stop-all` is called.
- `durationSeconds` runs out.
- The connection dies. A keepalive probe every 15 s notices a dead path within about a minute.
- The Hermes session that opened it ends.
- The Hermes process exits.

pi-ssh shows open tunnels in a widget. Hermes has no such surface for plugins, so while a tunnel is open, the plugin reminds the model at every turn (`pre_llm_call`). The reminder only lists that session's tunnels, so in the gateway one chat does not learn what another has open.

## Guard rails

Three settings under `plugins.entries.ssh.settings` control what may change a remote host. They also appear as a form in the Desktop app under **Capabilities → Plugins**.

| Setting | Values | Applies to |
|---|---|---|
| `dangerous_commands` | `confirm` (default), `open`, `block` | `ssh_exec` commands that look destructive |
| `safety_level` | `open` (default), `confirm`, `readonly` | `ssh_exec`, `ssh_upload`, `ssh_authorize`, tunnel `start`/`define`/`forget` |
| `readonly_profiles` | list of profile names | everything in the row above, for these hosts |

- **`dangerous_commands`:** Hermes' own detector decides what "looks destructive", the same one that guards its local terminal. Examples are `rm -rf`, `rm` below `/`, `sed -i` or `>` on `/etc`, `curl | sh`, `mkfs`, `systemctl restart` and `docker restart`. On top of that, the plugin checks `reboot`, `shutdown`, `poweroff`, `halt`, `init 0/6` and `systemctl reboot`, because on a shared server those matter more than on a laptop. A command should not become safer by running on another machine.
- **`confirm`:** sends the call through Hermes' approval gate. **Always allow** only covers that profile, and for dangerous commands only that kind of danger.
- **`readonly_profiles`:** wins over everything else. Use it for production (`[prod]`). Listing and downloading still work. A call without a `profile` argument counts as the active profile.

```bash
hermes config set plugins.entries.ssh.settings.readonly_profiles '["prod"]'
hermes config set plugins.entries.ssh.settings.safety_level confirm
```

## Configuration

`ssh_setup` writes `$HERMES_HOME/ssh-config.json` with mode `0600`. Every Hermes profile has its own `HERMES_HOME` and therefore its own hosts. `HERMES_SSH_CONFIG` points the plugin at a different file. The format is the same as pi-ssh's, so `cp ~/.pi/ssh-config.json ~/.hermes/` is enough:

```json
{
  "activeProfile": "staging",
  "profiles": {
    "staging": {
      "host": "staging.example.com", "port": 22, "user": "deploy",
      "privateKeyPath": "~/.ssh/id_ed25519_hermes_staging",
      "tunnels": { "db": { "kind": "local", "listenPort": 5432, "destHost": "db.internal", "destPort": 5432 } }
    }
  }
}
```

The file is merged on write, so keys the plugin does not know survive. It is reread when it changes, so a running gateway sees hosts added from the CLI.

The system prompt names the configured hosts and how they authenticate. Passwords and passphrases are never included.

## What is different from pi-ssh

- **Plugin name:** `ssh` instead of `hermes-ssh`, see Installation.
- **SSH library:** paramiko instead of ssh2. Keys are generated with `cryptography`, which paramiko already needs.
- **Default key path:** `~/.ssh/id_ed25519_hermes_<profile>` instead of `…_pi_<profile>`. Keys pi already made keep working, because the profile stores the path.
- **Tunnels:** they end with the Hermes session that opened them, and the widget is replaced by a turn reminder.
- **Dangerous commands:** they ask for confirmation by default. pi-ssh has no such check.
- **`ssh_setup`:** keeps a profile's stored tunnels.

## Development

```bash
python -m pip install paramiko pytest pyyaml
python -m pytest tests

hermes plugins doctor . --ci
```

The end-to-end tests start a real OpenSSH `sshd` on a loopback port with a host key made by this plugin. They cover host key handling, exec (exit codes, `cwd` with quotes, timeouts), SFTP, key installation, local and remote tunnels, and tunnels ending when the connection is killed. The password tests only run where sshd can run as root, because they create a throwaway local account. Without sshd, these tests are skipped.

`hermes plugins validate .` reports the `authorized_keys` findings described under Installation.

| Path | Content |
|---|---|
| `ssh_client.py` | connection, host key check, exec, SFTP |
| `known_hosts.py` | OpenSSH known_hosts: hashed entries, ports, revoked keys |
| `keys.py` | ed25519 keys in process |
| `authorize.py` | ssh-copy-id in process, and the automatic switch from password to key |
| `tunnels.py` | port forwards, keepalive monitor, per-session teardown |
| `config.py` | profile store |
| `doctor.py` | environment report |
| `formatters.py` | pure display functions |
| `tools/` | the 11 tools |
| `safety.py` | guard rails (`pre_tool_call` hook) |
| `commands.py` | `/ssh`, `/ssh-key` |

## License

MIT
