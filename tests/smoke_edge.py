"""Local real-core test of the edge relay, TLS and authenticated SOCKS runtime.

Only the official pinned binary download uses the internet. The CDN/origin and
HTTPS sink are temporary loopback fixtures with an explicitly trusted test cert.
No public CDN or VPS configuration is touched.
"""

from __future__ import annotations

import contextlib
import datetime
import hashlib
import json
from pathlib import Path
import socket
import ssl
import sys
import threading
from http.server import ThreadingHTTPServer
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cdn_xhttp import edge_network, edge_runtime
from cdn_xhttp.render import client_xray, origin_xray
from smoke_xray import core_process, proxy_handler, QuietHandler, unused_ports


class Sink(QuietHandler):
    def do_OPTIONS(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        data = json.dumps(
            {
                "method": "OPTIONS",
                "length": len(body),
                "sha256": hashlib.sha256(body).hexdigest(),
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-CDN-Origin", "ok")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        data = bytes(range(256)) * 4096
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@contextlib.contextmanager
def tls_server(handler, certificate, key):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certificate, key)
    ctx.set_alpn_protocols(["http/1.1"])
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)


def main():
    with edge_runtime.XrayRuntime() as runtime:
        binary = runtime.prepare()
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        now = datetime.datetime.now(datetime.timezone.utc)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False
            )
            .sign(key, hashes.SHA256())
        )
        pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
        certificate_path = runtime.directory / "localhost.pem"
        key_path = runtime.directory / "localhost-key.pem"
        certificate_path.write_text(pem, encoding="utf-8")
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()
        c = {
            "origin": {"host": "127.0.0.1"},
            "origin_domain": "origin.example.com",
            "cdn_domain": "cdn.example.com",
            "uuid": "39296dbd-d3db-47e0-a618-2bd24d105942",
            "path": "/smoke-test",
            "padding_key": "dc",
            "profile": "fast",
            "exit": None,
        }
        origin_port = unused_ports(1)[0]
        requests = []
        origin = origin_xray(c)
        origin["inbounds"][0]["port"] = origin_port
        with contextlib.ExitStack() as stack:
            sink_port = stack.enter_context(
                tls_server(Sink, certificate_path, key_path)
            )
            proxy_port = stack.enter_context(
                tls_server(
                    proxy_handler(origin_port, requests, threading.Lock()),
                    certificate_path,
                    key_path,
                )
            )
            origin["outbounds"][0]["settings"] = {
                "finalRules": [
                    {
                        "action": "allow",
                        "network": "tcp",
                        "ip": ["127.0.0.1/32"],
                        "port": str(sink_port),
                    }
                ]
            }
            stack.enter_context(
                core_process(
                    binary, runtime.directory, "smoke-origin", origin, origin_port
                )
            )

            def profile(config):
                result = client_xray(config)
                tls = result["outbounds"][0]["streamSettings"]["tlsSettings"]
                tls.update(
                    serverName="localhost", pinnedPeerCertSha256=pin, alpn=["http/1.1"]
                )
                return result

            def local_edge(address, port, route, timeout):
                return socket.create_connection(
                    ("127.0.0.1", proxy_port), timeout=timeout
                )

            # Trust only this generated fixture certificate; production code
            # still creates its ordinary system-verifying TLS context.
            original_context = ssl.create_default_context
            stack.enter_context(
                patch.object(edge_runtime, "client_xray", side_effect=profile)
            )
            stack.enter_context(
                patch.object(edge_network, "connect_route", side_effect=local_edge)
            )
            stack.enter_context(
                patch.object(
                    edge_runtime.ssl,
                    "create_default_context",
                    side_effect=lambda: original_context(cadata=pem),
                )
            )
            relay = stack.enter_context(
                edge_network.TCPRelay("8.8.8.8", edge_network.Route())
            )
            connector = stack.enter_context(runtime.tunnel(c, relay.port))
            sink = lambda host, port, timeout: connector(
                "127.0.0.1", sink_port, timeout
            )
            result = edge_runtime.options_probe("localhost", sink)
            status, _, downloaded = edge_runtime.request_https(
                "https://localhost/data", connector=sink, max_bytes=2 * 1024 * 1024
            )
            assert result["ok"] and result["bytes"] == 1_000_000
            assert status == 200 and downloaded == bytes(range(256)) * 4096
            assert any(item["method"] == "OPTIONS" for item in requests)
        assert not relay.thread.is_alive()
        assert all(not worker.is_alive() for worker in relay.workers)
        print(
            "PASS edge runtime: real pinned Xray, verified TLS, authenticated SOCKS, TCP relay, 1 MB upload and 1 MiB download integrity; listeners cleaned up"
        )


if __name__ == "__main__":
    main()
