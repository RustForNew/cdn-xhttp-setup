"""Check that TLS, OPTIONS and its X-Data-N headers survive the CDN path."""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import re
import secrets
import ssl
import time
from typing import Any

# The XHTTP client splits each packet into X-Data-N headers of this size.
HEADER_CHUNK = 4096
MAX_HEADER_BYTES = 32 * 1024


# This self-contained program is installed on the origin. Its port is loopback
# only; nginx exposes just /cdn-check and buffers that diagnostic request body.
HEALTH_SERVER_SOURCE = r'''#!/usr/bin/env python3
"""Loopback-only diagnostic endpoint for CDN OPTIONS requests.

Reports the method plus length and SHA-256 of the request body and of the
concatenated X-Data-0, X-Data-1, ... headers that carry XHTTP uplink.
"""
import hashlib
import json
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

MAX_BODY_BYTES = 1024 * 1024


class HealthHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "CDNHealth/1"
    sys_version = ""

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def log_message(self, format, *args):
        pass

    def respond(self, status, payload):
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-CDN-Origin", "ok")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        self.wfile.write(body)

    def do_OPTIONS(self):
        if urlsplit(self.path).path != "/cdn-check":
            self.respond(404, {"error": "not found"})
            return
        if self.headers.get_all("Transfer-Encoding"):
            self.respond(400, {"error": "chunked requests are not supported"})
            return
        # A CDN may forward a bodyless OPTIONS without Content-Length.
        lengths = self.headers.get_all("Content-Length", []) or ["0"]
        if len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdigit():
            self.respond(411, {"error": "one valid Content-Length is required"})
            return
        # Bound the decimal string before int(), including on Python 3.10.
        if len(lengths[0]) > 10:
            self.respond(413, {"error": "request body too large"})
            return
        length = int(lengths[0])
        if length > MAX_BODY_BYTES:
            self.respond(413, {"error": "request body too large"})
            return
        try:
            body = self.rfile.read(length)
        except (socket.timeout, OSError):
            self.respond(408, {"error": "request body timed out"})
            return
        if len(body) != length:
            self.respond(400, {"error": "incomplete request body"})
            return
        chunks = []
        while True:
            value = self.headers.get("X-Data-%d" % len(chunks))
            if value is None:
                break
            chunks.append(value)
        # http.server decodes header lines as Latin-1; restore their bytes.
        data = "".join(chunks).encode("latin-1", "replace")
        self.respond(200, {
            "method": self.command,
            "length": len(body),
            "sha256": hashlib.sha256(body).hexdigest(),
            "header_bytes": len(data),
            "header_sha256": hashlib.sha256(data).hexdigest(),
        })

    def reject_method(self):
        self.respond(405, {"error": "OPTIONS required"})

    do_GET = do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = reject_method


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", 8004), HealthHandler)
    server.daemon_threads = True
    server.serve_forever()
'''


def _domain(value: str) -> str:
    if not isinstance(value, str) or value != value.strip():
        raise ValueError("Domain must be a hostname without surrounding whitespace")
    try:
        host = value.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("Invalid domain name") from exc
    if (
        len(host) > 253
        or "." not in host
        or not all(
            re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in host.split(".")
        )
    ):
        raise ValueError("Use a domain name without a scheme, port or path")
    return host


def header_payload(size: int) -> tuple[dict[str, str], int, str]:
    """Random base64url data split into X-Data-N headers like XHTTP uplink."""
    text = base64.urlsafe_b64encode(secrets.token_bytes(size)).decode("ascii")
    text = text.rstrip("=")
    headers = {
        f"X-Data-{index}": text[offset : offset + HEADER_CHUNK]
        for index, offset in enumerate(range(0, len(text), HEADER_CHUNK))
    }
    return headers, len(text), hashlib.sha256(text.encode("ascii")).hexdigest()


def _probe(domain: str, size: int, timeout: float) -> dict[str, Any]:
    data_headers, header_bytes, digest = header_payload(size)
    path = "/cdn-check?nonce=" + secrets.token_hex(16)
    result: dict[str, Any] = {
        "bytes": size,
        "header_bytes": header_bytes,
        "ok": False,
        "status": None,
        "errors": [],
    }
    errors = result["errors"]
    started = time.monotonic()
    # HTTPSConnection does not follow redirects. Use the normal trust store and
    # hostname verification; a CDN pointing somewhere else must fail this check.
    connection = http.client.HTTPSConnection(
        domain, 443, timeout=timeout, context=ssl.create_default_context()
    )
    try:
        # Bodyless like the XHTTP uplink: Yandex CDN rejects any OPTIONS body
        # with HTTP 413, so the data travels in request headers only.
        connection.request(
            "OPTIONS",
            path,
            headers={
                "Cache-Control": "no-store",
                "Connection": "close",
                **data_headers,
            },
        )
        response = connection.getresponse()
        result["status"] = response.status
        if response.status != 200:
            if 300 <= response.status < 400:
                errors.append(
                    "Redirect rejected; /cdn-check must reach the configured origin directly"
                )
            elif response.status == 413:
                errors.append(
                    "HTTP 413: the CDN or origin rejected the request size or an OPTIONS body"
                )
            else:
                errors.append(f"Expected HTTP 200, received {response.status}")
            return result
        if (response.getheader("X-CDN-Origin") or "").strip().lower() != "ok":
            errors.append("Missing or unexpected X-CDN-Origin header")
        cache_control = response.getheader("Cache-Control") or ""
        if "no-store" not in {
            part.strip().lower() for part in cache_control.split(",")
        }:
            errors.append("Response does not contain Cache-Control: no-store")
        content_type = (
            (response.getheader("Content-Type") or "").split(";", 1)[0].strip().lower()
        )
        if content_type != "application/json":
            errors.append("Expected a JSON response from the origin health service")
        raw = response.read(65537)
        if len(raw) > 65536:
            errors.append("Health response exceeds 64 KiB")
            return result
        try:
            body = json.loads(raw)
        except (UnicodeError, ValueError):
            errors.append("Origin returned invalid JSON")
            return result
        if not isinstance(body, dict):
            errors.append("Origin returned a non-object JSON response")
            return result
        if body.get("method") != "OPTIONS":
            errors.append("OPTIONS was changed before reaching the health service")
        if body.get("length") != 0:
            errors.append("The bodyless OPTIONS request reached the origin with a body")
        if (
            type(body.get("header_bytes")) is not int
            or body["header_bytes"] != header_bytes
            or body.get("header_sha256") != digest
        ):
            errors.append(
                "X-Data headers SHA-256 mismatch: headers were changed, dropped or cached"
            )
        result["ok"] = not errors
        return result
    except (OSError, http.client.HTTPException, ValueError) as exc:
        errors.append(f"{type(exc).__name__}: {exc}")
        return result
    finally:
        connection.close()
        result["elapsed_ms"] = round((time.monotonic() - started) * 1000)


def check_endpoint(
    domain: str, *, timeout: float = 15, max_bytes: int = 16384
) -> dict[str, Any]:
    """Send bodyless OPTIONS /cdn-check with 16 bytes, then max_bytes in headers.

    The data is base64url text in X-Data-N headers of 4096 characters, the
    shape of one XHTTP uplink packet. max_bytes (4 to 24576) is the binary
    size; the default 16384 matches the client packet. No remote
    configuration changes are made. Errors are returned as JSON-safe values.
    """
    result: dict[str, Any] = {
        "domain": domain,
        "ok": False,
        "status": None,
        "errors": [],
        "probes": [],
    }
    try:
        host = _domain(domain)
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not 0 < timeout <= 300
        ):
            raise ValueError(
                "timeout must be greater than zero and at most 300 seconds"
            )
        if (
            type(max_bytes) is not int
            or not 4 <= max_bytes <= MAX_HEADER_BYTES * 3 // 4
        ):
            raise ValueError("max_bytes must be an integer from 4 to 24576")
    except ValueError as exc:
        result["errors"].append(str(exc))
        return result
    result["domain"] = host
    for size in dict.fromkeys((min(16, max_bytes), max_bytes)):
        probe = _probe(host, size, timeout)
        result["probes"].append(probe)
        result["status"] = probe["status"]
        result["errors"].extend(f"{size} bytes: {error}" for error in probe["errors"])
        if not probe["ok"]:
            break
    result["ok"] = not result["errors"]
    return result
