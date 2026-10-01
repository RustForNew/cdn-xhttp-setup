"""Informational check of the published connection from this computer.

The client always connects to the CDN domain, so there is nothing to select:
this module only reports whether the path works from here right now. It never
changes the configuration, a VPS or the local network, and it never raises for
network failures. Links are issued whatever the result.
"""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import subprocess
import zipfile
from urllib.parse import urljoin, urlsplit

from .config import validate
from .health import check_endpoint
from .xray_runtime import ProbeError, XrayRuntime, options_probe, request_https

MAX_DOWNLOAD_BYTES = 1024 * 1024
NETWORK_ERRORS = (
    OSError,
    http.client.HTTPException,
    ProbeError,
    ValueError,
    subprocess.SubprocessError,
    zipfile.BadZipFile,
)


def _download_document(url, connector=None):
    # GitHub's official release URLs redirect to HTTPS release-asset storage.
    # Only this public document download follows a bounded redirect chain;
    # origin/CDN health requests never follow redirects.
    for _ in range(4):
        status, headers, raw = request_https(
            url, connector=connector, max_bytes=MAX_DOWNLOAD_BYTES
        )
        if status not in {301, 302, 303, 307, 308}:
            return status, raw
        target = urljoin(url, headers.get("location", ""))
        if target == url or urlsplit(target).scheme != "https":
            raise ProbeError("Public download redirected outside HTTPS")
        url = target
    raise ProbeError("Public download exceeded its redirect limit")


def _download_integrity(connector, runtime: XrayRuntime) -> dict:
    # The official checksum document of the pinned release is immutable and
    # was already fetched directly while preparing the runtime.
    url, reference = runtime.download_reference
    status, received = _download_document(url, connector)
    if status != 200:
        raise ProbeError(f"Tunnel download returned HTTP {status}")
    if received != reference:
        raise ProbeError("Tunnel download SHA256 verification failed")
    return {
        "name": "download_integrity",
        "ok": True,
        "bytes": len(received),
        "sha256": hashlib.sha256(received).hexdigest(),
    }


def _egress_probe(c: dict, connector) -> dict:
    expected = ipaddress.ip_address((c.get("exit") or c["origin"])["host"])
    hosts = (
        ("api.ipify.org", "checkip.amazonaws.com")
        if expected.version == 4
        else ("api6.ipify.org",)
    )
    for host in hosts:
        try:
            status, _, raw = request_https(
                f"https://{host}/", connector=connector, max_bytes=256
            )
            if status != 200:
                continue
            actual = ipaddress.ip_address(raw.decode("ascii").strip())
            if actual != expected:
                raise ProbeError(
                    "Tunnel exit IP differs from the configured server (NAT is unsupported)"
                )
            return {
                "name": "exit_ip",
                "ok": True,
                "expected": str(expected),
                "observed": str(actual),
            }
        except (OSError, ValueError, UnicodeError):
            continue
    raise ProbeError("Could not verify the tunnel exit IP over HTTPS")


def _tunnel_probes(c: dict, runtime: XrayRuntime) -> list[dict]:
    with runtime.tunnel(c) as connector:
        # Send the HTTPS request to the configured public origin IP through
        # VLESS, while preserving its certificate name and HTTP Host. This is
        # internet egress, not a direct local request to the origin.
        origin_connector = lambda host, port, timeout: connector(
            c["origin"]["host"], port, timeout
        )
        return [
            dict(
                options_probe(c["origin_domain"], origin_connector),
                name="tunnel_upload_integrity",
            ),
            _download_integrity(connector, runtime),
            _egress_probe(c, connector),
        ]


def _reason(exc: BaseException) -> str:
    # ProbeError is deliberately sanitized. Other errors are summarized by
    # type, never by text that could echo configuration or credentials.
    return str(exc) if isinstance(exc, ProbeError) else type(exc).__name__


def verify_connection(c: dict, *, log=print) -> dict:
    """Report the CDN endpoint and the complete VLESS tunnel via the CDN domain."""
    config = validate(c)
    checks: list[dict] = []
    endpoint = check_endpoint(config["cdn_domain"])
    checks.append(
        {
            "name": "cdn_endpoint",
            "ok": endpoint["ok"],
            "status": endpoint["status"],
            "errors": endpoint["errors"],
        }
    )
    if endpoint["ok"]:
        log("CDN: HTTPS и OPTIONS /cdn-check с данными в заголовках X-Data прошли.")
    else:
        log("CDN: проверка /cdn-check не прошла: " + "; ".join(endpoint["errors"][:2]))
    log(f"Проверяем полный VLESS-путь временным Xray через {config['cdn_domain']}:443.")
    tunnel_ok = False
    try:
        with XrayRuntime() as runtime:
            runtime.prepare()
            probes = _tunnel_probes(config, runtime)
        checks.append({"name": "vless_tunnel", "ok": True, "probes": probes})
        tunnel_ok = True
        log("VLESS-туннель, передача данных и внешний IP подтверждены.")
    except NETWORK_ERRORS as exc:
        checks.append({"name": "vless_tunnel", "ok": False, "error": _reason(exc)})
        log(f"VLESS-туннель не подтверждён: {_reason(exc)}.")
    return {
        "endpoint_verified": endpoint["ok"],
        "vless_tunnel_verified": tunnel_ok,
        "checks": checks,
    }
