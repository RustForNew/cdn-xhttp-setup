"""Socket-only route selection; never change adapters, routes or another VPN."""

from __future__ import annotations

import contextlib
import ipaddress
import json
import os
import select
import socket
import struct
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Route:
    name: str = "default"
    interface: str | None = None
    index: int | None = None
    source: str | None = None


def _command_json(command: list[str]) -> object:
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    result = subprocess.run(
        command,
        capture_output=True,
        encoding="utf-8-sig",
        errors="replace",
        check=True,
        timeout=12,
        creationflags=flags,
    )
    return json.loads(result.stdout or "[]")


def ethernet_routes() -> list[Route]:
    """Only interfaces positively identified as physical wired Ethernet.

    A failed/unsupported inventory returns no route, never guesses from an
    adapter's user-editable name. Every returned route still needs a probe.
    """
    try:
        if os.name == "nt":
            script = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$rows = @(Get-NetAdapter -Physical | Where-Object {
    $_.Status -eq 'Up' -and $_.HardwareInterface -and
    [int]$_.NdisPhysicalMedium -eq 14
} | ForEach-Object {
    $adapter = $_
    Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 |
        Where-Object { $_.AddressState -eq 'Preferred' -and -not $_.SkipAsSource } |
        ForEach-Object {
            [PSCustomObject]@{name=$adapter.Name; index=$adapter.ifIndex; source=$_.IPAddress}
        }
})
ConvertTo-Json -InputObject $rows -Compress
"""
            rows = _command_json(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script]
            )
            if isinstance(rows, dict):
                rows = [rows]
            if not isinstance(rows, list):
                return []
            routes = []
            for row in rows:
                address = ipaddress.IPv4Address(row["source"])
                if (
                    address.is_unspecified
                    or address.is_loopback
                    or address.is_link_local
                ):
                    continue
                if type(row["index"]) is int and row["index"] > 0:
                    routes.append(
                        Route("ethernet", str(row["name"]), row["index"], str(address))
                    )
            return routes[:4]
        if not os.sys.platform.startswith("linux"):
            return []
        rows = _command_json(["ip", "-j", "-4", "address", "show", "up"])
        routes = []
        for row in rows:
            name = row["ifname"]
            if not isinstance(name, str) or "/" in name or "\0" in name:
                continue
            root = Path("/sys/class/net") / name
            if not (root / "device").exists() or (root / "wireless").exists():
                continue
            if (root / "type").read_text(encoding="utf-8").strip() != "1":
                continue
            for info in row.get("addr_info", []):
                if info.get("scope") != "global" or info.get("family") != "inet":
                    continue
                address = ipaddress.IPv4Address(info["local"])
                routes.append(
                    Route("ethernet", name, int(row["ifindex"]), str(address))
                )
        return routes[:4]
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        return []


def connect_route(
    address: str, port: int, route: Route, timeout: float
) -> socket.socket:
    """Connect a literal address. Binding failure must never silently fall back."""
    ip = ipaddress.ip_address(address)
    family = socket.AF_INET if ip.version == 4 else socket.AF_INET6
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        if route.name == "ethernet":
            if (
                ip.version != 4
                or not route.source
                or not route.interface
                or not route.index
            ):
                raise OSError("Ethernet route requires an IPv4 source and interface")
            if os.name == "nt":
                # Windows IP_UNICAST_IF expects the interface index in network order.
                sock.setsockopt(socket.IPPROTO_IP, 31, struct.pack("!I", route.index))
            elif os.sys.platform.startswith("linux"):
                sock.setsockopt(
                    socket.SOL_SOCKET,
                    socket.SO_BINDTODEVICE,
                    route.interface.encode() + b"\0",
                )
            else:
                raise OSError("Physical-interface binding is unavailable")
            sock.bind((route.source, 0))
        sock.connect((str(ip), port))
        return sock
    except BaseException:
        sock.close()
        raise


class TCPRelay:
    """Loopback listener pinning every XHTTP TCP connection to one edge+route."""

    def __init__(self, address: str, route: Route, *, timeout: float = 8):
        self.address, self.route, self.timeout = address, route, timeout
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.sockets: set[socket.socket] = set()
        self.workers: list[threading.Thread] = []
        self.slots = threading.BoundedSemaphore(32)
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if os.name == "nt":
            self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(32)
        self.listener.settimeout(0.2)
        self.port = self.listener.getsockname()[1]
        self.thread = threading.Thread(
            target=self._accept, daemon=True, name="cdn-edge-relay"
        )

    def __enter__(self):
        self.thread.start()
        return self

    def _accept(self):
        while not self.stop.is_set():
            try:
                client, _ = self.listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            if not self.slots.acquire(blocking=False):
                client.close()
                continue
            worker = threading.Thread(target=self._relay, args=(client,), daemon=True)
            with self.lock:
                self.sockets.add(client)
                self.workers.append(worker)
            worker.start()

    def _relay(self, client: socket.socket):
        upstream = None
        try:
            upstream = connect_route(self.address, 443, self.route, self.timeout)
            with self.lock:
                self.sockets.add(upstream)
            client.settimeout(self.timeout)
            while not self.stop.is_set():
                ready, _, _ = select.select([client, upstream], [], [], 0.2)
                for source in ready:
                    data = source.recv(65536)
                    if not data:
                        return
                    (upstream if source is client else client).sendall(data)
        except (OSError, ValueError):
            pass
        finally:
            for sock in (client, upstream):
                if sock is not None:
                    with self.lock:
                        self.sockets.discard(sock)
                    sock.close()
            self.slots.release()

    def __exit__(self, *exc):
        self.stop.set()
        self.listener.close()
        self.thread.join(timeout=1)
        with self.lock:
            active, workers = list(self.sockets), list(self.workers)
        for sock in active:
            with contextlib.suppress(OSError):
                sock.shutdown(socket.SHUT_RDWR)
            sock.close()
        # A connecting socket has its own bounded connect timeout. Joining all
        # workers ensures no relay survives a cancelled/failed selection.
        for worker in workers:
            worker.join(timeout=self.timeout + 1)
