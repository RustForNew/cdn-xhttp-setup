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


def padding(c: dict) -> dict:
    return {
        "xPaddingObfsMode": True,
        "xPaddingKey": c["padding_key"],
        "xPaddingHeader": "X-Cache",
        "xPaddingMethod": "tokenish",
        "xPaddingPlacement": "queryInHeader",
    }


def extra(c: dict) -> dict:
    return {
        "mode": "packet-up",
        "scMaxEachPostBytes": 1000000,
        "scMinPostsIntervalMs": 5 if c["profile"] == "fast" else 30,
        "scMaxBufferedPosts": 30,
        **padding(c),
        "uplinkHTTPMethod": "OPTIONS",
    }


def origin_xray(c: dict) -> dict:
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
                "port": 8003,
                "protocol": "vless",
                "settings": {
                    "users": [{"id": identity} for identity in _uuids(c)],
                    "decryption": "none",
                },
                "streamSettings": {
                    "network": "xhttp",
                    "security": "none",
                    "xhttpSettings": {
                        "mode": "packet-up",
                        "path": c["path"],
                        "scMaxEachPostBytes": 1000000,
                        "scMaxBufferedPosts": 30,
                        **padding(c),
                    },
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
                            "address": c["cdn_domain"],
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
        "alpn": "h2,http/1.1",
        "type": "xhttp",
        "host": c["cdn_domain"],
        "path": c["path"],
        "mode": "packet-up",
        "extra": json.dumps(extra(c), separators=(",", ":")),
    }
    return f"vless://{identity}@{c['cdn_domain']}:443?{urlencode(params, quote_via=quote)}#{quote(label, safe='')}"


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
    return (
        prefix
        + f"""
server {{
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name {host};
    ssl_certificate /etc/letsencrypt/live/{host}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{host}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    client_max_body_size 2m;
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
    location {c["path"]} {{
        proxy_pass http://127.0.0.1:8003;
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
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }}
    location / {{ return 404; }}
}}
"""
    )
