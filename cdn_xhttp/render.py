"""Render the same XHTTP contract for server, client and share URI."""

from __future__ import annotations

import ipaddress
import json
from urllib.parse import quote, urlencode


def _uuids(c: dict) -> list[str]:
    return c["uuids"] if "uuids" in c else [c["uuid"]]


def _client_uuid(c: dict, index: int) -> str:
    values = _uuids(c)
    if type(index) is not int or not 0 <= index < len(values):
        raise ValueError("Индекс ссылки находится вне списка UUID")
    return values[index]


ORIGIN_PORT = 8003
CLIENT_POST_BYTES = 16384
UPLINK_CHUNK_SIZE = 4096
SERVER_POST_BYTES = 1000000
SERVER_MAX_HEADER_BYTES = 65536


def padding(c: dict) -> dict:
    return {
        "xPaddingObfsMode": True,
        "xPaddingKey": c["padding_key"],
        "xPaddingHeader": "X-Cache",
        "xPaddingMethod": "tokenish",
        "xPaddingPlacement": "queryInHeader",
        "xPaddingBytes": "100-1000",
    }


def extra(c: dict) -> dict:
    """Client uplink travels in the headers of a bodyless OPTIONS request.

    Yandex CDN answers HTTP 413 to any body on GET/HEAD/OPTIONS and offers no
    POST. Each packet (up to 16 KiB) is therefore split into X-Data-N request
    headers of 4096 characters; the origin raises its header limit and Nginx
    turns OPTIONS into POST. Zero would be Xray's 30 ms default, never "fast".
    The mode belongs to xhttpSettings, outside this dictionary.
    """
    return {
        **padding(c),
        "scMaxEachPostBytes": CLIENT_POST_BYTES,
        "scMinPostsIntervalMs": 10 if c["profile"] == "fast" else 30,
        "uplinkDataPlacement": "header",
        "uplinkChunkSize": UPLINK_CHUNK_SIZE,
        "uplinkHTTPMethod": "OPTIONS",
    }


def server_extra(c: dict) -> dict:
    """Origin inbound. Placement stays Xray's default "auto": headers, cookie
    and body are all read, so clients of earlier releases keep working."""
    return {
        **padding(c),
        "scMaxEachPostBytes": SERVER_POST_BYTES,
        "scMaxBufferedPosts": 64,
        "serverMaxHeaderBytes": SERVER_MAX_HEADER_BYTES,
    }


def origin_xray(c: dict) -> dict:
    return _origin_xray(
        c,
        {"mode": "packet-up", "path": c["path"], "extra": server_extra(c)},
    )


def previous_origin_xray(c: dict) -> dict:
    """Origin config exactly as releases up to 0.3.1 rendered it.

    Used only to recognize an existing installation of an earlier release
    during recovery and compare-and-swap; it is never installed.
    """
    previous_padding = {
        key: value for key, value in padding(c).items() if key != "xPaddingBytes"
    }
    return _origin_xray(
        c,
        {
            "mode": "packet-up",
            "path": c["path"],
            "scMaxEachPostBytes": SERVER_POST_BYTES,
            "scMaxBufferedPosts": 30,
            **previous_padding,
        },
    )


def _origin_xray(c: dict, xhttp_settings: dict) -> dict:
    outbound = {"tag": "internet", "protocol": "freedom"}
    if c.get("exit"):
        outbound = {
            "tag": "to-exit",
            "protocol": "vless",
            "settings": {
                "vnext": [
                    {
                        "address": c["exit"]["host"],
                        "port": 10443,
                        "users": [
                            {
                                "id": c["uuid"],
                                "encryption": "none",
                                "flow": "xtls-rprx-vision",
                            }
                        ],
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "serverName": c["exit_domain"],
                    "alpn": ["h2", "http/1.1"],
                    "allowInsecure": False,
                },
            },
        }
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "from-cdn",
                "listen": "127.0.0.1",
                "port": ORIGIN_PORT,
                "protocol": "vless",
                "settings": {
                    "users": [{"id": identity} for identity in _uuids(c)],
                    "decryption": "none",
                },
                "streamSettings": {
                    "network": "xhttp",
                    "security": "none",
                    "xhttpSettings": xhttp_settings,
                },
            }
        ],
        "outbounds": [outbound],
    }


def exit_xray(c: dict) -> dict:
    listen = "::" if ipaddress.ip_address(c["exit"]["host"]).version == 6 else "0.0.0.0"
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "from-origin",
                "listen": listen,
                "port": 10443,
                "protocol": "vless",
                "settings": {
                    "users": [
                        {"id": identity, "flow": "xtls-rprx-vision"}
                        for identity in _uuids(c)
                    ],
                    "decryption": "none",
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "tls",
                    "tlsSettings": {
                        "alpn": ["h2", "http/1.1"],
                        "certificates": [
                            {
                                "certificateFile": "/etc/cdn-xhttp/tls/fullchain.pem",
                                "keyFile": "/etc/cdn-xhttp/tls/privkey.pem",
                            }
                        ],
                    },
                },
            }
        ],
        "outbounds": [{"tag": "internet", "protocol": "freedom"}],
    }


def client_xray(c: dict, index: int = 0) -> dict:
    identity = _client_uuid(c, index)
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": 10808,
                "protocol": "socks",
                "settings": {"udp": True},
            }
        ],
        "outbounds": [
            {
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": c.get("connect_address", c["cdn_domain"]),
                            "port": 443,
                            "users": [{"id": identity, "encryption": "none"}],
                        }
                    ]
                },
                "streamSettings": {
                    "network": "xhttp",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": c["cdn_domain"],
                        "allowInsecure": False,
                        "alpn": ["h2", "http/1.1"],
                        "fingerprint": "firefox",
                    },
                    "xhttpSettings": {
                        "host": c["cdn_domain"],
                        "path": c["path"],
                        "mode": "packet-up",
                        "extra": extra(c),
                    },
                },
            }
        ],
    }


def vless_uri(c: dict, index: int = 0) -> str:
    identity = _client_uuid(c, index)
    label = c.get("name", "CDN XHTTP")
    if len(_uuids(c)) > 1:
        label = f"{label} {index + 1}"
    params = {
        "encryption": "none",
        "security": "tls",
        "sni": c["cdn_domain"],
        "fp": "firefox",
        "alpn": "h2,http/1.1",
        "type": "xhttp",
        "host": c["cdn_domain"],
        "path": c["path"],
        "mode": "packet-up",
        "extra": json.dumps(extra(c), separators=(",", ":")),
    }
    address = c.get("connect_address", c["cdn_domain"])
    if ":" in address:
        address = f"[{address}]"
    return f"vless://{identity}@{address}:443?{urlencode(params, quote_via=quote)}#{quote(label, safe='')}"


def nginx_config(c: dict, tls: bool = True) -> str:
    host = c["origin_domain"]
    http_response = (
        "return 301 https://$host$request_uri;"
        if tls
        else 'return 200 "origin provisioning\\n";'
    )
    prefix = f"""# Managed by cdn-xhttp-setup; included in nginx http context.
map $request_method $cdn_xhttp_proxy_method {{
    default $request_method;
    OPTIONS POST;
}}
server {{
    listen 80;
    listen [::]:80;
    server_name {host};
    location ^~ /.well-known/acme-challenge/ {{
        root /var/www/cdn-xhttp-acme;
    }}
    location / {{ {http_response} }}
}}
"""
    if not tls:
        return prefix
    # Header-borne uplink means about 100 small requests per second for each
    # uploading client. Without upstream keepalive every request opens a new
    # loopback connection; their TIME_WAIT entries fill nf_conntrack and the
    # host drops new CDN connections (the edge answers 502). nginx 1.18 also
    # closes a client connection after 100 requests by default.
    return (
        prefix
        + f"""
upstream cdn_xhttp_origin {{
    server 127.0.0.1:{ORIGIN_PORT};
    keepalive 64;
    keepalive_requests 100000;
    keepalive_timeout 120s;
}}
server {{
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name {host};
    ssl_certificate /etc/letsencrypt/live/{host}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{host}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    keepalive_requests 100000;
    keepalive_timeout 300s;
    client_max_body_size 2m;
    # One 16 KiB packet is about 23 KB of X-Data-N and padding headers.
    client_header_buffer_size 64k;
    large_client_header_buffers 8 128k;
    # Ubuntu 22.04 ships nginx 1.18; keep its HTTP/2-specific limits.
    # On newer nginx these are obsolete; large_client_header_buffers applies.
    http2_max_field_size 128k;
    http2_max_header_size 128k;
    gzip off;
    add_header Cache-Control "no-store, no-cache, max-age=0" always;
    location = /cdn-check {{
        client_max_body_size 1m;
        proxy_pass http://127.0.0.1:8004;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_request_buffering on;
        proxy_buffering off;
        proxy_read_timeout 20s;
        proxy_send_timeout 20s;
    }}
    location = {c["path"]} {{ return 404; }}
    location ^~ {c["path"]}/ {{
        proxy_pass http://cdn_xhttp_origin;
        # Xray answers a bare OPTIONS itself; only POST carries a packet.
        proxy_method $cdn_xhttp_proxy_method;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_pass_request_headers on;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_cache off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }}
    location / {{ return 404; }}
}}
"""
    )
