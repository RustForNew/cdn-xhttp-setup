"""Select an edge only after verified OPTIONS and the complete VLESS path.

No server, system route or saved deployment is changed here. Candidate and
time limits intentionally bound discovery; failure does not assert that every
address of the CDN is unavailable.
"""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import socket
import subprocess
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlsplit

from .config import validate
from .edge_network import Route, TCPRelay, connect_route, ethernet_routes
from .edge_runtime import ProbeError, XrayRuntime, options_probe, request_https

PREFIX_URL = "https://tech.cdn.yandex.net/prefixes/yc.json"
# Additional discovery candidates, not trusted or pre-approved endpoints.
# Keep these ahead of sampled prefixes so the candidate cap cannot exclude them.
YANDEX_CANDIDATES = (
    "188.72.103.107",
    "188.72.103.102",
    "188.72.103.112",
    "188.72.103.115",
    "188.72.103.106",
    "188.72.103.111",
    "188.72.103.109",
    "188.72.103.108",
    "188.72.103.118",
    "188.72.103.110",
    "188.72.103.113",
    "188.72.103.105",
    "188.72.103.126",
    "188.72.103.114",
    "188.72.103.119",
    "188.72.103.117",
    "188.72.103.121",
    "188.72.103.125",
    "188.72.103.124",
    "188.72.103.128",
    "188.72.103.127",
    "188.72.103.101",
    "188.72.103.103",
    "188.72.103.116",
    "188.72.103.188",
    "188.72.110.17",
    "188.72.110.18",
    "188.72.110.23",
    "188.72.110.24",
    "188.72.110.34",
    "188.72.110.3",
    "188.72.110.35",
    "188.72.110.36",
    "188.72.110.4",
    "188.72.110.52",
    "188.72.110.5",
    "188.72.110.50",
    "188.72.110.51",
    "188.72.110.6",
    "188.72.111.18",
    "188.72.111.19",
    "188.72.111.20",
    "188.72.111.2",
    "188.72.111.21",
    "188.72.111.36",
    "188.72.111.37",
    "188.72.111.35",
    "188.72.111.3",
    "188.72.111.52",
    "188.72.111.51",
    "188.72.111.50",
    "188.72.111.7",
    "188.72.111.8",
)
MAX_PREFIX_BYTES = 1024 * 1024
MAX_PREFIXES = 2048
MAX_CANDIDATES = 256
MAX_FULL_PROBES = 12
PREFILTER_WORKERS = 12
ROUTE_TIME_LIMIT = 180


class EdgeSelectionError(RuntimeError):
    def __init__(self, message: str, *, checks: list[dict] | None = None):
        super().__init__(message)
        self.checks = checks or []


def _public_address(value: str) -> str | None:
    try:
        address = ipaddress.ip_address(value)
        if address.is_global and not address.is_multicast and not address.is_reserved:
            return str(address)
    except (ValueError, TypeError):
        pass
    return None


def parse_prefixes(raw: bytes) -> list[ipaddress.IPv4Network]:
    if len(raw) > MAX_PREFIX_BYTES:
        raise ProbeError("CDN prefix list exceeds its size limit")
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise ProbeError("CDN prefix list is invalid JSON") from exc
    if (
        not isinstance(data, dict)
        or not isinstance(data.get("prefixes"), list)
        or len(data["prefixes"]) > MAX_PREFIXES
    ):
        raise ProbeError("CDN prefix list has an unsupported shape or size")
    networks = set()
    for value in data["prefixes"]:
        if not isinstance(value, str) or len(value) > 64 or "/" not in value:
            raise ProbeError("CDN prefix list contains an invalid CIDR")
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError as exc:
            raise ProbeError("CDN prefix list contains an invalid CIDR") from exc
        # IPv6 networks are never expanded. Private, reserved and multicast
        # ranges are not endpoints to which this discovery tool may connect.
        if network.version == 6:
            continue
        if not _public_address(str(network.network_address)) or not _public_address(
            str(network.broadcast_address)
        ):
            raise ProbeError("CDN prefix list contains a non-public IPv4 range")
        networks.add(network)
    return sorted(
        networks, key=lambda net: (net.num_addresses, int(net.network_address))
    )


def candidate_addresses(
    previous: str | None, current: list[str], networks: list[ipaddress.IPv4Network]
) -> list[str]:
    """Sample offsets across prefixes, not an exhaustive subnet scan.

    Saved/DNS addresses precede the bundled candidates. Then one address
    from each small prefix is tried before another address of the
    same prefix. Prefer offset 3, then 2/1/4; /31 and /32 have their own valid
    host semantics. No giant network is expanded into a Python list.
    """
    found: list[str] = []
    seen: set[str] = set()

    def add(value):
        address = _public_address(value)
        if address and address not in seen and len(found) < MAX_CANDIDATES:
            seen.add(address)
            found.append(address)

    if previous:
        add(previous)
    for address in current[:32]:
        add(address)
    for address in YANDEX_CANDIDATES:
        add(address)
    networks = sorted(
        set(networks), key=lambda net: (net.num_addresses, int(net.network_address))
    )
    for rank in range(8):
        for network in networks:
            if len(found) >= MAX_CANDIDATES:
                return found
            if network.prefixlen == 32:
                offsets = (0,)
            elif network.prefixlen == 31:
                offsets = (1, 0)
            else:
                offsets = (3, 2, 1, 4, 5, 6, 7, 8)
            if rank >= len(offsets):
                continue
            offset = offsets[rank]
            if network.prefixlen >= 31 or 0 < offset < network.num_addresses - 1:
                add(str(network.network_address + offset))
    return found


def _current_dns(domain: str) -> list[str]:
    try:
        return list(
            dict.fromkeys(
                row[4][0]
                for row in socket.getaddrinfo(domain, 443, type=socket.SOCK_STREAM)
            )
        )
    except OSError:
        return []


def _prefix_reference() -> tuple[list[ipaddress.IPv4Network], bytes]:
    status, _, raw = request_https(PREFIX_URL, max_bytes=MAX_PREFIX_BYTES, timeout=10)
    if status != 200:
        raise ProbeError(f"CDN prefix list returned HTTP {status}")
    return parse_prefixes(raw), raw


def _prefilter(address: str, domain: str, route: Route) -> bool:
    if route.name == "ethernet" and ipaddress.ip_address(address).version != 4:
        return False
    try:
        # This is a verified TLS handshake and a tiny OPTIONS request. It is
        # only a filter: even its success cannot publish a connection profile.
        options_probe(
            domain,
            lambda host, port, timeout: connect_route(address, port, route, timeout),
            size=4,
            timeout=4,
        )
        return True
    except (OSError, http.client.HTTPException, ProbeError, ValueError):
        return False


def _download_integrity(
    connector, reference: bytes | None, runtime: XrayRuntime
) -> dict:
    if reference is None:
        # If the prefix service is unavailable, existing DNS/previous edges
        # can still be checked against the immutable official release digest.
        url, reference = runtime.download_reference
    else:
        url = PREFIX_URL
    for attempt in range(2):
        status, received = _download_document(url, connector)
        if status != 200:
            raise ProbeError(f"Tunnel download returned HTTP {status}")
        if received == reference:
            return {
                "name": "download_integrity",
                "ok": True,
                "bytes": len(received),
                "sha256": hashlib.sha256(received).hexdigest(),
            }
        if attempt == 0:
            # The public prefix document may have changed since discovery.
            # Refresh the direct reference once and repeat the tunneled read.
            status, reference = _download_document(url)
            if status != 200:
                break
    raise ProbeError("Tunnel download SHA256 verification failed")


def _download_document(url, connector=None):
    # GitHub's official release URLs redirect to HTTPS release-asset storage.
    # Only this public document download follows a bounded redirect chain;
    # origin/CDN health requests never follow redirects.
    for _ in range(4):
        status, headers, raw = request_https(
            url, connector=connector, max_bytes=MAX_PREFIX_BYTES
        )
        if status not in {301, 302, 303, 307, 308}:
            return status, raw
        target = urljoin(url, headers.get("location", ""))
        if target == url or urlsplit(target).scheme != "https":
            raise ProbeError("Public download redirected outside HTTPS")
        url = target
    raise ProbeError("Public download exceeded its redirect limit")


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


def _probe_candidate(
    c: dict, address: str, route: Route, runtime: XrayRuntime, reference: bytes | None
) -> list[dict]:
    direct = lambda host, port, timeout: connect_route(address, port, route, timeout)
    checks = [
        dict(options_probe(c["cdn_domain"], direct), name="edge_options_integrity")
    ]
    with TCPRelay(address, route) as relay, runtime.tunnel(c, relay.port) as connector:
        # Send the HTTPS request to the configured public origin IP through
        # VLESS, while preserving its certificate name and HTTP Host. This is
        # internet egress, not a direct local request to the CDN diagnostics.
        origin_connector = lambda host, port, timeout: connector(
            c["origin"]["host"], port, timeout
        )
        checks.append(
            dict(
                options_probe(c["origin_domain"], origin_connector),
                name="tunnel_upload_integrity",
            )
        )
        checks.append(_download_integrity(connector, reference, runtime))
        checks.append(_egress_probe(c, connector))
    return checks


def select_edge(c: dict, *, log=print) -> dict:
    """Return a verified connect address, or fail without changing caller data."""
    config = validate(c)
    checks: list[dict] = []
    reference = None
    try:
        networks, reference = _prefix_reference()
    except (OSError, http.client.HTTPException, ProbeError, ValueError):
        networks = []
        log("Список диапазонов edge временно недоступен; проверяем сохранённый адрес, DNS CDN и встроенные кандидаты.")
    candidates = candidate_addresses(
        config.get("connect_address"), _current_dns(config["cdn_domain"]), networks
    )
    if not candidates:
        raise EdgeSelectionError("Нет публичных адресов CDN для проверки.")
    wired = ethernet_routes()
    routes = wired + [Route()]
    with XrayRuntime() as runtime:
        for route in routes:
            if route.name == "default":
                reason = (
                    "Проверки через Ethernet не нашли рабочий edge"
                    if wired
                    else "Доступный физический Ethernet не обнаружен"
                )
                log(
                    reason
                    + "; проверяем обычный системный маршрут (default route). Действующий VPN не отключается."
                )
            else:
                log(f"Проверяем CDN через физический Ethernet: {route.interface}.")
            started, attempted = time.monotonic(), 0
            route_candidates = [
                ip
                for ip in candidates
                if route.name != "ethernet" or ipaddress.ip_address(ip).version == 4
            ]
            for offset in range(0, len(route_candidates), PREFILTER_WORKERS):
                if (
                    time.monotonic() - started >= ROUTE_TIME_LIMIT
                    or attempted >= MAX_FULL_PROBES
                ):
                    break
                batch = route_candidates[offset : offset + PREFILTER_WORKERS]
                with ThreadPoolExecutor(
                    max_workers=PREFILTER_WORKERS, thread_name_prefix="cdn-edge-check"
                ) as pool:
                    available = list(
                        pool.map(
                            lambda address, selected=route: _prefilter(
                                address, config["cdn_domain"], selected
                            ),
                            batch,
                        )
                    )
                for address, ready in zip(batch, available):
                    if (
                        not ready
                        or attempted >= MAX_FULL_PROBES
                        or time.monotonic() - started >= ROUTE_TIME_LIMIT
                    ):
                        continue
                    attempted += 1
                    log(f"Проверяем полный VPN-путь через {address} ({route.name}).")
                    try:
                        # Download failures are independent of the edge and
                        # must not trigger repeated downloads for every IP.
                        runtime.prepare()
                    except (
                        OSError,
                        http.client.HTTPException,
                        ProbeError,
                        ValueError,
                        subprocess.SubprocessError,
                        zipfile.BadZipFile,
                    ) as exc:
                        raise EdgeSelectionError(
                            "Не удалось подготовить проверенный Xray для проверки полного VPN-пути.",
                            checks=checks,
                        ) from exc
                    try:
                        passed = _probe_candidate(
                            config, address, route, runtime, reference
                        )
                    except (
                        OSError,
                        http.client.HTTPException,
                        ProbeError,
                        ValueError,
                        subprocess.SubprocessError,
                    ) as exc:
                        # ProbeError is deliberately sanitized. Other network
                        # errors are summarized by type, never by config/log.
                        reason = (
                            str(exc)
                            if isinstance(exc, ProbeError)
                            else type(exc).__name__
                        )
                        checks.append(
                            {
                                "address": address,
                                "route": route.name,
                                "ok": False,
                                "error": reason,
                            }
                        )
                        log(
                            f"Edge {address}: полный путь не прошёл проверку ({reason})."
                        )
                        continue
                    checks.append(
                        {
                            "address": address,
                            "route": route.name,
                            "ok": True,
                            "probes": passed,
                        }
                    )
                    log(
                        f"Edge {address}: полный VPN-путь и внешний IP подтверждены ({route.name})."
                    )
                    return {
                        "connect_address": address,
                        "endpoint_verified": True,
                        "vless_tunnel_verified": True,
                        "route": route.name,
                        "checks": checks,
                    }
            checks.append(
                {
                    "route": route.name,
                    "ok": False,
                    "full_probes": attempted,
                    "candidate_limit": MAX_CANDIDATES,
                }
            )
    raise EdgeSelectionError(
        "Рабочий полный VPN-путь не найден в ограниченной выборке edge. Ссылки не обновлены; проверьте CDN/origin и повторите проверку из сети клиента.",
        checks=checks,
    )
