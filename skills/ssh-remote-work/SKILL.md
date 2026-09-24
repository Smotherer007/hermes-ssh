---
name: ssh-remote-work
description: Work on a remote machine over SSH - run commands, inspect logs and configuration, and move files with SFTP. Use whenever the task belongs on another host, for example deploying or restarting a service, reading logs on a server, checking disk or process state, copying a build artefact to or from a machine, or anything the user describes as "on the server", "on the NAS", "on staging", or by a hostname. Also covers what to do when a connection fails and how to read a host key warning.
allowed-tools: ssh_status, ssh_profile, ssh_exec, ssh_list, ssh_upload, ssh_download, ssh_doctor
version: 1.0.0
metadata:
  hermes:
    tags: [ssh, remote, devops]
    requires_toolsets: [ssh]
---

# Working on a remote host

Commands run through `ssh_exec` land on someone's actual machine. That is the
whole value and also the whole risk: there is no undo, and the blast radius is
whatever the account can reach.

## Before the first command

`ssh_status` shows which hosts are configured and which one is active. **When
more than one exists, pass `profile` explicitly** rather than relying on
whichever was active from an earlier session - "restart nginx" on the wrong
host is not recoverable by apologising.

If the user names a host you have no profile for, say so and ask for the
details rather than guessing at a hostname.

## Running commands

`ssh_exec` opens a connection, runs one command, and closes it. There is no
persistent shell, which has two consequences worth remembering:

- **State does not carry over.** `cd /var/log` in one call does not affect the
  next. Use the `cwd` parameter, or chain with `&&` in a single command.
- **There is no TTY.** Anything interactive hangs until the timeout: `sudo`
  that prompts for a password, `top`, `vim`, `apt` without `-y`. Use
  non-interactive forms (`sudo -n`, `apt-get -y`, `systemctl --no-pager`), and
  if a password prompt is genuinely needed, tell the user rather than trying to
  feed it in.

Read the exit code, not just the output. A command that printed nothing and
exited 1 failed; reporting "done" because stdout was empty is wrong.

## Reading before writing

Prefer commands that observe over commands that change, and look before you
act: `systemctl status` before `systemctl restart`, `ls` before `rm`, a diff
before an overwrite.

For anything destructive or disruptive - deleting files, restarting services,
changing configuration, `chmod`/`chown` on system paths, package installs,
anything with `sudo` - **say what you are about to run and why, and let the
user confirm**, unless they already asked for exactly that. Piping a remote
script into a shell (`curl ... | sh`) is not something to do on someone's
server on your own initiative.

## Files

`ssh_list` gives a structured listing with sizes, modes and dates - use it
rather than parsing `ls` output. `ssh_download` and `ssh_upload` move files
over SFTP; prefer them over `cat`-ing a file through `ssh_exec`, which mangles
binaries and pushes the whole content through the model for nothing.

## When it does not connect

The error usually says which layer failed. Work from it rather than retrying:

- **"not in known_hosts"** - the host has never been seen. Show the user the
  fingerprint and ask them to confirm it against the server before re-running
  with `acceptNewHostKey: true`. Do not pass that flag reflexively; it is the
  moment the trust decision is made.
- **"HOST KEY CHANGED"** - stop. This is either a reinstalled server or
  someone between you and it. Never work around it by disabling host key
  checking. Relay the message; the user has to resolve it deliberately.
- **"rejected the credentials"** - user name, password or key is wrong, or the
  key is not in the remote authorized_keys. `ssh_authorize` fixes the last one.
- **"refused the connection"** - nothing is listening: wrong port, or sshd is
  down.
- Something about the local environment - run `ssh_doctor`, which reports what
  is missing and what to do about it.

## Tunnels

`ssh_tunnel` is the one tool here whose effect outlives the call: a forward
keeps running until stopped, its time limit expires, or the session ends.

- Start one only when something actually needs it, and tell the user it is
  running and how to reach it.
- While a tunnel is open, every turn starts with a short reminder listing it.
  Mention open tunnels to the user when they are no longer needed.
  `ssh_tunnel action list` and `ssh_status` give the same information on
  demand; check one of them before starting another tunnel for the same
  purpose.
- Stop tunnels when the work that needed them is done rather than leaving them
  open for the rest of the session.
- `bind` defaults to loopback. Do not set it to `0.0.0.0` unless the user asked
  for the service to be reachable from other machines, and say plainly what
  that exposes when you do.

## What to report back

Give the user the command's actual output and its exit code. When a command
failed, quote stderr rather than summarising it - the exact message is what
they need. Say which host you ran it on.
