"""Tool registry: (schema, handler), in pi-ssh's registration order."""

from __future__ import annotations

from . import hosts, keys, remote, tunnel

TOOLSET = "ssh"

TOOLS = (
    (hosts.SETUP_SCHEMA, hosts.setup),
    (hosts.STATUS_SCHEMA, hosts.status),
    (hosts.PROFILE_SCHEMA, hosts.profile),
    (remote.EXEC_SCHEMA, remote.exec_),
    (remote.LIST_SCHEMA, remote.list_),
    (remote.UPLOAD_SCHEMA, remote.upload),
    (remote.DOWNLOAD_SCHEMA, remote.download),
    (keys.KEYGEN_SCHEMA, keys.keygen),
    (keys.AUTHORIZE_SCHEMA, keys.authorize),
    (hosts.DOCTOR_SCHEMA, hosts.doctor),
    (tunnel.TUNNEL_SCHEMA, tunnel.tunnel),
)
