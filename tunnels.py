"""Port forwarding.

The one place where something deliberately outlives the tool call that
created it: a tunnel is only useful while it is open, so it runs in the
background until it is stopped. Everything else here keeps that from becoming
a leak:

* every tunnel is in a registry that ``ssh_tunnel list`` and ``ssh_status`` show,
* each one can carry a time limit,
* a dead SSH connection takes its listener down with it,
* the tunnels a Hermes session opened close when that session ends, and all
  of them close when the process exits.

Each tunnel owns its own SSH connection. Sharing one would be tidier on the
wire, but a single dropped connection would then take every tunnel with it.

Keepalives: paramiko's own keepalive only sends, it never notices silence.
A monitor thread therefore sends an OpenSSH keepalive request every 15s and
closes the tunnel after four that go unanswered -- a dead path behind NAT is
noticed within about a minute instead of never.
"""

from __future__ import annotations

import socket
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional

from .models import RunningTunnel, TunnelDefinition, TunnelError
from .ssh_client import Connection, connect

DEFAULT_BIND = "127.0.0.1"
PROBE_INTERVAL_S = 15.0
PROBE_MISSES_MAX = 4


def validate_definition(definition: TunnelDefinition) -> None:
    if definition.kind not in ("local", "remote"):
        raise TunnelError(f'Unknown tunnel kind "{definition.kind}". Use local or remote.')
    for label, port, minimum in (("listenPort", definition.listen_port, 0), ("destPort", definition.dest_port, 1)):
        if not isinstance(port, int) or isinstance(port, bool) or port < minimum or port > 65535:
            raise TunnelError(f"{label} must be an integer between {minimum} and 65535.")
    if not (definition.dest_host or "").strip():
        raise TunnelError("destHost must not be empty.")


def _pump(a: socket.socket, b: Any, on_close: Callable[[], None]) -> None:
    """Copy bytes both ways between a socket and a channel until either side ends."""
    import select

    try:
        while True:
            readable, _, _ = select.select([a, b], [], [], 1.0)
            if a in readable:
                data = a.recv(65536)
                if not data:
                    break
                b.sendall(data)
            if b in readable:
                data = b.recv(65536)
                if not data:
                    break
                a.sendall(data)
    except Exception:
        pass
    finally:
        for end in (a, b):
            try:
                end.close()
            except Exception:
                pass
        on_close()


def _spawn(target: Callable, *args: Any, name: str) -> threading.Thread:
    thread = threading.Thread(target=target, args=args, name=name, daemon=True)
    thread.start()
    return thread


@dataclass
class _Handle:
    id: str
    profile: str
    name: str
    definition: TunnelDefinition
    connection: Connection
    started_at: datetime
    session_id: Optional[str] = None
    listen_address: str = ""
    connections: int = 0
    expires_at: Optional[datetime] = None
    stopped: bool = False
    server: Optional[socket.socket] = None
    sockets: set = field(default_factory=set)
    bound: Optional[tuple] = None
    lock: threading.Lock = field(default_factory=threading.Lock)

    def describe(self) -> RunningTunnel:
        iso = lambda d: d.strftime("%Y-%m-%dT%H:%M:%S.000Z") if d else None  # noqa: E731
        return RunningTunnel(
            id=self.id, profile=self.profile, name=self.name, definition=self.definition,
            listen_address=self.listen_address, started_at=iso(self.started_at),
            connections=self.connections, expires_at=iso(self.expires_at), session_id=self.session_id,
        )


_running: Dict[str, _Handle] = {}
_registry_lock = threading.RLock()
_listeners: List[Callable[[List[RunningTunnel]], None]] = []


def on_tunnels_changed(listener: Callable[[List[RunningTunnel]], None]) -> Callable[[], None]:
    _listeners.append(listener)
    return lambda: _listeners.remove(listener) if listener in _listeners else None


def _notify() -> None:
    snapshot = list_tunnels()
    for listener in list(_listeners):
        try:
            listener(snapshot)
        except Exception:
            pass  # a broken observer must never take a tunnel down


def tunnel_id(profile: str, name: str) -> str:
    return f"{profile}:{name}"


# Local: ssh -L


def _start_local(handle: _Handle) -> str:
    definition = handle.definition
    bind = definition.bind or DEFAULT_BIND
    server = socket.socket(socket.AF_INET6 if ":" in bind else socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind((bind, definition.listen_port))
    except PermissionError:
        server.close()
        raise TunnelError(
            f"Not allowed to listen on port {definition.listen_port}. Ports below 1024 need elevated rights."
        ) from None
    except OSError as err:
        server.close()
        if getattr(err, "errno", None) in (98, 48, 10048):  # EADDRINUSE on Linux, macOS, Windows
            raise TunnelError(
                f"Local port {definition.listen_port} is already in use. Pick another listenPort, "
                "or 0 to let the system choose."
            ) from None
        raise TunnelError(f"Cannot listen on {bind}:{definition.listen_port}: {err}") from None
    server.listen(64)
    server.settimeout(1.0)
    handle.server = server
    port = server.getsockname()[1]

    def accept_loop() -> None:
        while not handle.stopped:
            try:
                client, origin = server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                channel = handle.connection.transport.open_channel(
                    "direct-tcpip", (definition.dest_host, definition.dest_port), origin[:2], timeout=15,
                )
            except Exception:
                # The destination refused or does not resolve from the server.
                # The tunnel stays up; only this connection fails.
                client.close()
                continue
            with handle.lock:
                handle.connections += 1
                handle.sockets.add(client)
            _spawn(_pump, client, channel, lambda c=client: handle.sockets.discard(c), name=f"tunnel-{handle.id}")

    _spawn(accept_loop, name=f"tunnel-accept-{handle.id}")
    return f"{bind}:{port}"


# Remote: ssh -R


def _start_remote(handle: _Handle) -> str:
    definition = handle.definition
    bind = definition.bind or DEFAULT_BIND
    transport = handle.connection.transport

    def on_channel(channel: Any, origin: tuple, server: tuple) -> None:
        # Called on paramiko's transport thread: never block it.
        _spawn(connect_back, channel, name=f"tunnel-back-{handle.id}")

    def connect_back(channel: Any) -> None:
        with handle.lock:
            handle.connections += 1
        try:
            local = socket.create_connection((definition.dest_host, definition.dest_port), timeout=10)
        except OSError:
            channel.close()  # nothing is listening on our side
            return
        local.settimeout(None)
        with handle.lock:
            handle.sockets.add(local)
        _spawn(_pump, local, channel, lambda s=local: handle.sockets.discard(s), name=f"tunnel-{handle.id}")

    try:
        port = transport.request_port_forward(bind, definition.listen_port, handler=on_channel)
    except Exception as err:
        raise TunnelError(
            f"The server refused to listen on {bind}:{definition.listen_port}: {err}. Usually the port is "
            "taken, or sshd only allows loopback binds -- binding to anything other than 127.0.0.1 needs "
            "GatewayPorts in its sshd_config."
        ) from None
    handle.bound = (bind, port)
    return f"{bind}:{port}"


# Lifecycle


def _monitor(handle: _Handle) -> None:
    """Close the tunnel when its connection is gone or stops answering."""
    transport = handle.connection.transport
    misses = 0
    while not handle.stopped:
        waited = 0.0
        while waited < PROBE_INTERVAL_S and not handle.stopped:
            if not transport.is_active():
                _teardown(handle)
                return
            time.sleep(0.5)
            waited += 0.5
        if handle.stopped:
            return
        answered = threading.Event()

        def probe() -> None:
            try:
                transport.global_request("keepalive@openssh.com", wait=True)
                answered.set()
            except Exception:
                pass

        _spawn(probe, name=f"tunnel-probe-{handle.id}")
        if answered.wait(PROBE_INTERVAL_S):
            misses = 0
        else:
            misses += 1
            if misses >= PROBE_MISSES_MAX:
                _teardown(handle)
                return


def start_tunnel(
    profile_name: str,
    profile: Dict[str, Any],
    name: str,
    definition: TunnelDefinition,
    accept_new_host_key: bool = False,
    duration_seconds: Optional[float] = None,
    session_id: Optional[str] = None,
) -> RunningTunnel:
    validate_definition(definition)
    identifier = tunnel_id(profile_name, name)
    with _registry_lock:
        if identifier in _running:
            raise TunnelError(
                f'A tunnel called "{name}" is already running for profile "{profile_name}". '
                "Stop it first, or give this one another name."
            )

    connection = connect(profile, accept_new_host_key=accept_new_host_key)
    handle = _Handle(id=identifier, profile=profile_name, name=name, definition=definition,
                     connection=connection, started_at=datetime.now(timezone.utc), session_id=session_id)
    try:
        handle.listen_address = _start_local(handle) if definition.kind == "local" else _start_remote(handle)
    except BaseException:
        handle.stopped = True
        connection.close()
        raise

    if duration_seconds and duration_seconds > 0:
        handle.expires_at = handle.started_at + timedelta(seconds=duration_seconds)
        timer = threading.Timer(duration_seconds, _teardown, args=(handle,))
        timer.daemon = True
        timer.start()

    with _registry_lock:
        _running[identifier] = handle
    _spawn(_monitor, handle, name=f"tunnel-monitor-{identifier}")
    _notify()
    return handle.describe()


def _teardown(handle: _Handle) -> None:
    """Stop a tunnel exactly once, whether asked to or because its connection died."""
    with handle.lock:
        if handle.stopped:
            return
        handle.stopped = True
    try:
        if handle.server is not None:
            # shutdown() first: a plain close() does not release a listening
            # socket that another thread is blocked in accept() on.
            try:
                handle.server.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                handle.server.close()
            except Exception:
                pass
        if handle.bound is not None:
            try:
                handle.connection.transport.cancel_port_forward(*handle.bound)
            except Exception:
                pass
        for sock in list(handle.sockets):
            try:
                sock.close()
            except Exception:
                pass
        handle.connection.close()
    finally:
        with _registry_lock:
            if _running.get(handle.id) is handle:
                del _running[handle.id]
        _notify()


def list_tunnels() -> List[RunningTunnel]:
    with _registry_lock:
        handles = list(_running.values())
    return sorted((h.describe() for h in handles), key=lambda t: t.id)


def stop_tunnel(profile_name: str, name: str) -> bool:
    with _registry_lock:
        handle = _running.get(tunnel_id(profile_name, name))
    if handle is None:
        return False
    _teardown(handle)
    return True


def stop_all_tunnels(session_id: Optional[str] = None) -> int:
    """Stop every tunnel, or only those a given Hermes session opened."""
    with _registry_lock:
        handles = [h for h in _running.values() if session_id is None or h.session_id == session_id]
    for handle in handles:
        _teardown(handle)
    return len(handles)


def _running_count() -> int:
    with _registry_lock:
        return len(_running)

