"""Private, checksum-verified Xray runtime and authenticated loopback probes."""

from __future__ import annotations

import contextlib
import hashlib
import http.client
import io
import ipaddress
import json
import os
import platform
import re
import secrets
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import time
import urllib.request
import zipfile
from pathlib import Path
from urllib.parse import urlsplit

from .config import XRAY_VERSION, write_private
from .render import client_xray


class ProbeError(RuntimeError):
    """A bounded probe failed; messages never contain credentials/configuration."""


def request_https(
    url: str,
    *,
    connector=None,
    method="GET",
    body: bytes | None = None,
    max_bytes: int = 65536,
    timeout: float = 12,
) -> tuple[int, dict, bytes]:
    """No redirects, proxy environment or unverified TLS, including via SOCKS."""
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.port not in (None, 443)
    ):
        raise ProbeError("HTTPS probe destination is invalid")
    connect = connector or (
        lambda host, port, wait: socket.create_connection((host, port), timeout=wait)
    )
    raw = connect(parsed.hostname, 443, timeout)
    try:
        secure = ssl.create_default_context().wrap_socket(
            raw, server_hostname=parsed.hostname
        )
    except BaseException:
        raw.close()
        raise
    connection = http.client.HTTPConnection(parsed.hostname, 443, timeout=timeout)
    connection.sock = secure
    try:
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        connection.request(
            method,
            path,
            body=body,
            headers={
                "Host": parsed.hostname,
                "Accept-Encoding": "identity",
                "Cache-Control": "no-store",
                "Connection": "close",
                "User-Agent": "CDN-XHTTP-Setup/check",
                **(
                    {
                        "Content-Type": "application/octet-stream",
                        "Content-Length": str(len(body)),
                    }
                    if body is not None
                    else {}
                ),
            },
        )
        response = connection.getresponse()
        data = response.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise ProbeError("HTTPS probe response exceeds its limit")
        return (
            response.status,
            {key.lower(): value for key, value in response.getheaders()},
            data,
        )
    finally:
        connection.close()


def options_probe(
    domain: str, connector, *, size: int = 1_000_000, timeout: float = 12
) -> dict:
    payload = secrets.token_bytes(size)
    digest = hashlib.sha256(payload).hexdigest()
    status, headers, raw = request_https(
        f"https://{domain}/cdn-check?nonce={secrets.token_hex(12)}",
        connector=connector,
        method="OPTIONS",
        body=payload,
        timeout=timeout,
    )
    if status != 200:
        raise ProbeError(f"OPTIONS returned HTTP {status}")
    if headers.get("x-cdn-origin", "").strip().lower() != "ok":
        raise ProbeError("Origin diagnostic header is missing")
    if "no-store" not in {
        part.strip().lower() for part in headers.get("cache-control", "").split(",")
    }:
        raise ProbeError("Origin diagnostic response can be cached")
    if (
        headers.get("content-type", "").split(";", 1)[0].lower().strip()
        != "application/json"
    ):
        raise ProbeError("Origin diagnostic response is not JSON")
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise ProbeError("Origin diagnostic response is invalid") from exc
    if (
        not isinstance(data, dict)
        or data.get("method") != "OPTIONS"
        or type(data.get("length")) is not int
        or data["length"] != size
        or data.get("sha256") != digest
    ):
        raise ProbeError("OPTIONS body length/SHA256 verification failed")
    return {"name": "options_integrity", "ok": True, "bytes": size, "sha256": digest}


class _HTTPSRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urlsplit(newurl).scheme != "https":
            raise ProbeError("Binary download attempted a non-HTTPS redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _download(url: str, limit: int) -> bytes:
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), _HTTPSRedirect()
    )
    started = time.monotonic()
    with opener.open(url, timeout=25) as response:
        if response.status != 200 or urlsplit(response.url).scheme != "https":
            raise ProbeError("Official Xray download did not return HTTPS 200")
        parts, total = [], 0
        while True:
            if time.monotonic() - started > 150:
                raise ProbeError("Official Xray download exceeded its time limit")
            part = response.read(min(65536, limit + 1 - total))
            if not part:
                return b"".join(parts)
            parts.append(part)
            total += len(part)
            if total > limit:
                raise ProbeError("Official Xray download exceeds its size limit")


def asset_name(system: str | None = None, machine: str | None = None) -> str:
    system = (system or platform.system()).lower()
    machine = (machine or platform.machine()).lower()
    if system not in {"windows", "linux"}:
        raise ProbeError("Automatic tunnel verification supports Windows and Linux")
    suffix = {
        "amd64": "64",
        "x86_64": "64",
        "arm64": "arm64-v8a",
        "aarch64": "arm64-v8a",
    }.get(machine)
    if suffix is None:
        raise ProbeError("Automatic tunnel verification requires amd64 or arm64")
    # Official Windows ARM assets use arm64-v8a, like Linux assets.
    return f"Xray-{system}-{suffix}.zip"


def checksum_sha256(data: bytes) -> str:
    text = data.decode("ascii")
    matches = re.findall(
        r"(?im)^\s*(?:SHA2?-?256)(?:\([^\r\n]*\))?\s*=\s*([0-9a-f]{64})\s*$", text
    )
    if len(matches) != 1:
        raise ProbeError("Official checksum file has no unambiguous SHA256")
    return matches[0].lower()


class XrayRuntime:
    """Download once per check; cache only in a random private temp folder.

    No executable is taken from PATH or another installation. The archive is
    verified before extracting only its executable. The complete directory is
    removed when the check ends.
    """

    def __enter__(self):
        # Antivirus software on Windows can hold xray.exe briefly after the
        # process exits; a failed cleanup must never mask the check result.
        self.temporary = tempfile.TemporaryDirectory(
            prefix="cdn-xhttp-check-", ignore_cleanup_errors=True
        )
        self.directory = Path(self.temporary.name)
        if os.name != "nt":
            self.directory.chmod(0o700)
        self.binary: Path | None = None
        return self

    def prepare(self):
        if self.binary is not None:
            return self.binary
        asset = asset_name()
        base = f"https://github.com/XTLS/Xray-core/releases/download/v{XRAY_VERSION}/{asset}"
        checksum = _download(base + ".dgst", 16384)
        expected = checksum_sha256(checksum)
        archive = _download(base, 80 * 1024 * 1024)
        if not secrets.compare_digest(hashlib.sha256(archive).hexdigest(), expected):
            raise ProbeError("Official Xray archive SHA256 verification failed")
        executable = "xray.exe" if os.name == "nt" else "xray"
        with zipfile.ZipFile(io.BytesIO(archive)) as package:
            members = [
                item for item in package.infolist() if item.filename == executable
            ]
            if len(members) != 1 or not 0 < members[0].file_size <= 100 * 1024 * 1024:
                raise ProbeError("Official Xray archive has an invalid executable")
            binary = self.directory / executable
            # Only one filename, no archive paths are extracted or trusted.
            fd = os.open(binary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700)
            with os.fdopen(fd, "wb") as destination:
                destination.write(package.read(members[0]))
        self.binary = binary
        self.download_reference = (base + ".dgst", checksum)
        return binary

    @contextlib.contextmanager
    def tunnel(self, config: dict):
        """Run the published client profile unchanged except for its inbound.

        The outbound connects to the CDN domain on port 443 through the
        ordinary system resolver and route, exactly like a client app.
        """
        binary = self.prepare()
        user, password = secrets.token_hex(12), secrets.token_hex(24)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        profile = client_xray(config)
        profile["log"] = {"loglevel": "none"}
        profile["inbounds"] = [
            {
                "listen": "127.0.0.1",
                "port": port,
                "protocol": "socks",
                "settings": {
                    "auth": "password",
                    "accounts": [{"user": user, "pass": password}],
                    "udp": False,
                },
            }
        ]
        path = self.directory / "probe.json"
        write_private(path, json.dumps(profile))
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
        process = None
        try:
            checked = subprocess.run(
                [str(binary), "run", "-test", "-config", str(path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=15,
                creationflags=flags,
                check=False,
            )
            if checked.returncode:
                raise ProbeError("Pinned Xray rejected the temporary client profile")
            process = subprocess.Popen(
                [str(binary), "run", "-config", str(path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=flags,
            )
            deadline = time.monotonic() + 10
            while True:
                if process.poll() is not None:
                    raise ProbeError(
                        "Pinned Xray exited before its SOCKS listener was ready"
                    )
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise ProbeError("Pinned Xray SOCKS listener did not start")
                    time.sleep(0.05)
            yield lambda host, destination_port, timeout: socks_connect(
                port, user, password, host, destination_port, timeout
            )
        finally:
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=4)
            with contextlib.suppress(OSError):
                path.unlink()

    def __exit__(self, *exc):
        for attempt in range(5):
            if attempt:
                time.sleep(0.2 * attempt)
            shutil.rmtree(self.directory, ignore_errors=True)
            if not self.directory.exists():
                break
        # Detach the finalizer; a still locked file is left behind silently.
        self.temporary.cleanup()


def _read_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise ProbeError("SOCKS negotiation ended unexpectedly")
        data.extend(part)
    return bytes(data)


def socks_connect(
    port: int,
    user: str,
    password: str,
    host: str,
    destination_port: int,
    timeout: float,
) -> socket.socket:
    sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        sock.sendall(b"\x05\x01\x02")
        if _read_exact(sock, 2) != b"\x05\x02":
            raise ProbeError("SOCKS listener refused required authentication")
        username, secret = user.encode("ascii"), password.encode("ascii")
        sock.sendall(
            b"\x01" + bytes([len(username)]) + username + bytes([len(secret)]) + secret
        )
        if _read_exact(sock, 2) != b"\x01\x00":
            raise ProbeError("SOCKS listener authentication failed")
        try:
            address = ipaddress.ip_address(host)
            target = bytes([1 if address.version == 4 else 4]) + address.packed
        except ValueError:
            domain = host.encode("idna")
            if not 0 < len(domain) <= 253:
                raise ProbeError("SOCKS destination name is invalid")
            target = b"\x03" + bytes([len(domain)]) + domain
        sock.sendall(b"\x05\x01\x00" + target + struct.pack("!H", destination_port))
        response = _read_exact(sock, 4)
        if response[:3] != b"\x05\x00\x00":
            raise ProbeError("SOCKS tunnel could not connect to the destination")
        length = {1: 4, 4: 16}.get(response[3])
        if response[3] == 3:
            length = _read_exact(sock, 1)[0]
        if length is None:
            raise ProbeError("SOCKS listener returned an invalid address")
        _read_exact(sock, length + 2)
        return sock
    except BaseException:
        sock.close()
        raise
