"""Check that TLS, OPTIONS and its actual body survive the CDN path."""

from __future__ import annotations

import hashlib
import http.client
import json
import re
import secrets
import ssl
import time
from typing import Any


# This self-contained program is installed on the origin. Its port is loopback
# only; nginx exposes just /cdn-check and buffers that diagnostic request body.
HEALTH_SERVER_SOURCE = r'''#!/usr/bin/env python3
"""Loopback-only diagnostic endpoint for CDN OPTIONS request bodies."""
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
        lengths = self.headers.get_all("Content-Length", [])
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
        self.respond(200, {
            "method": self.command,
            "length": len(body),
            "sha256": hashlib.sha256(body).hexdigest(),
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


def _probe(domain: str, size: int, timeout: float) -> dict[str, Any]:
    payload = secrets.token_bytes(size)
    digest = hashlib.sha256(payload).hexdigest()
    path = "/cdn-check?nonce=" + secrets.token_hex(16)
    result: dict[str, Any] = {"bytes": size, "ok": False, "status": None, "errors": []}
    errors = result["errors"]
    started = time.monotonic()
    # HTTPSConnection does not follow redirects. Use the normal trust store and
    # hostname verification; a CDN pointing somewhere else must fail this check.
    connection = http.client.HTTPSConnection(
        domain, 443, timeout=timeout, context=ssl.create_default_context()
    )
    try:
        connection.request(
            "OPTIONS",
            path,
            body=payload,
            headers={
                "Content-Type": "application/octet-stream",
                "Content-Length": str(size),
                "Cache-Control": "no-store",
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        result["status"] = response.status
        if response.status != 200:
            if 300 <= response.status < 400:
                errors.append(
                    "Redirect rejected; /cdn-check must reach the configured origin directly"
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
        if type(body.get("length")) is not int or body["length"] != size:
            errors.append("Origin did not receive the complete OPTIONS request body")
        if body.get("sha256") != digest:
            errors.append(
                "OPTIONS body SHA-256 mismatch: body was changed, dropped or cached"
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
    domain: str, *, timeout: float = 15, max_bytes: int = 65536
) -> dict[str, Any]:
    """Test 4-byte and max_bytes OPTIONS bodies over verified HTTPS.

    max_bytes controls the larger request size (4 bytes to 1 MiB). No remote
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
        if type(max_bytes) is not int or not 4 <= max_bytes <= 1024 * 1024:
            raise ValueError("max_bytes must be an integer from 4 to 1048576")
    except ValueError as exc:
        result["errors"].append(str(exc))
        return result
    result["domain"] = host
    for size in dict.fromkeys((4, max_bytes)):
        probe = _probe(host, size, timeout)
        result["probes"].append(probe)
        result["status"] = probe["status"]
        result["errors"].extend(f"{size} bytes: {error}" for error in probe["errors"])
        if not probe["ok"]:
            break
    result["ok"] = not result["errors"]
    return result
