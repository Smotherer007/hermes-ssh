"""Remote work: ssh_exec, ssh_list, ssh_upload, ssh_download."""

from __future__ import annotations

from ..formatters import format_directory, format_exec_result, format_transfer
from ..models import RemoteCommandError
from ..ssh_client import download_file, exec_command, list_directory, upload_file, with_connection
from ._base import (
    ACCEPT_HOST_KEY_PROPERTY,
    PROFILE_PROPERTY,
    opt_bool,
    opt_int,
    opt_str,
    req_str,
    result,
    schema,
    tool_handler,
)
from .common import resolve_for_connection, with_note

# ssh_exec

EXEC_SCHEMA = schema(
    "ssh_exec",
    "Run a shell command on the configured remote host and return its output and exit code. The connection is "
    "opened for this command and closed again. Commands run non-interactively, so anything that expects input "
    "or a TTY (sudo with a password prompt, an editor, top) will hang until the timeout.",
    {
        "command": {"type": "string", "description": "The command line to run on the remote host."},
        "cwd": {"type": "string", "description": "Directory to run it in. Default: the login directory."},
        "timeoutSeconds": {"type": "number", "description": "Give up after this long. Default 120.", "default": 120},
        "profile": PROFILE_PROPERTY,
        "acceptNewHostKey": ACCEPT_HOST_KEY_PROPERTY,
    },
    ["command"],
)


@tool_handler
def exec_(args: dict) -> str:
    command = req_str(args, "command")
    accept = bool(opt_bool(args, "acceptNewHostKey"))
    context = resolve_for_connection(opt_str(args, "profile"), accept)
    timeout = min(max(opt_int(args, "timeoutSeconds") or 120, 1), 3600)
    try:
        with with_connection(context.profile, accept_new_host_key=accept) as connection:
            outcome = exec_command(connection, command, cwd=opt_str(args, "cwd"), timeout=timeout)
    except RemoteCommandError as err:
        # A timeout still has output worth showing.
        partial = format_exec_result(err.result)
        raise RemoteCommandError(f"{err}\n\nOutput so far:\n{partial}", err.result) from None
    return result(
        with_note(format_exec_result(outcome), context.note),
        profile=context.name, host=context.profile.get("host"), exitCode=outcome.code,
        durationMs=outcome.duration_ms, truncated=outcome.truncated,
        stdoutBytes=len(outcome.stdout), stderrBytes=len(outcome.stderr),
    )


# ssh_list

LIST_SCHEMA = schema(
    "ssh_list",
    "List a directory on the remote host with sizes, permissions and dates, over SFTP. Use this instead of "
    "running ls, because the result is structured.",
    {
        "path": {"type": "string", "description": "Remote directory, e.g. /var/log or ."},
        "profile": PROFILE_PROPERTY,
        "acceptNewHostKey": ACCEPT_HOST_KEY_PROPERTY,
    },
    ["path"],
)


@tool_handler
def list_(args: dict) -> str:
    accept = bool(opt_bool(args, "acceptNewHostKey"))
    context = resolve_for_connection(opt_str(args, "profile"), accept)
    remote_path = (opt_str(args, "path") or "").strip() or "."
    with with_connection(context.profile, accept_new_host_key=accept) as connection:
        entries = list_directory(connection, remote_path)
    return result(
        with_note(format_directory(entries, remote_path), context.note),
        profile=context.name, path=remote_path, count=len(entries),
        directories=sum(1 for e in entries if e.type == "directory"),
    )


# ssh_upload

UPLOAD_SCHEMA = schema(
    "ssh_upload",
    "Copy a file from this machine to the remote host over SFTP. The remote path must include the file name; "
    "an existing file at that path is overwritten.",
    {
        "localPath": {"type": "string", "description": "File on this machine. Absolute paths are safest."},
        "remotePath": {"type": "string", "description": "Destination path on the remote host, including the file name."},
        "profile": PROFILE_PROPERTY,
        "acceptNewHostKey": ACCEPT_HOST_KEY_PROPERTY,
    },
    ["localPath", "remotePath"],
)


@tool_handler
def upload(args: dict) -> str:
    local_path = req_str(args, "localPath")
    remote_path = req_str(args, "remotePath")
    accept = bool(opt_bool(args, "acceptNewHostKey"))
    context = resolve_for_connection(opt_str(args, "profile"), accept)
    with with_connection(context.profile, accept_new_host_key=accept) as connection:
        transfer = upload_file(connection, local_path, remote_path)
    return result(with_note(format_transfer(transfer, "up"), context.note), profile=context.name,
                  localPath=transfer.local_path, remotePath=transfer.remote_path, size=transfer.size)


# ssh_download

DOWNLOAD_SCHEMA = schema(
    "ssh_download",
    "Copy a file from the remote host to this machine over SFTP. Missing local directories are created. Prefer "
    "this over cat-ing a file through ssh_exec: it handles binary content and does not pass the file through "
    "the model.",
    {
        "remotePath": {"type": "string", "description": "File on the remote host."},
        "localPath": {"type": "string", "description": "Destination on this machine, including the file name."},
        "profile": PROFILE_PROPERTY,
        "acceptNewHostKey": ACCEPT_HOST_KEY_PROPERTY,
    },
    ["remotePath", "localPath"],
)


@tool_handler
def download(args: dict) -> str:
    remote_path = req_str(args, "remotePath")
    local_path = req_str(args, "localPath")
    accept = bool(opt_bool(args, "acceptNewHostKey"))
    context = resolve_for_connection(opt_str(args, "profile"), accept)
    with with_connection(context.profile, accept_new_host_key=accept) as connection:
        transfer = download_file(connection, remote_path, local_path)
    return result(with_note(format_transfer(transfer, "down"), context.note), profile=context.name,
                  localPath=transfer.local_path, remotePath=transfer.remote_path, size=transfer.size)
