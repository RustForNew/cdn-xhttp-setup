"""Exercise generated profiles with the real pinned Xray binary on loopback.

Run from the project root: python tests/smoke_xray.py --xray /path/to/xray
No VPS, CDN, DNS, nginx, ACME, or public TLS deployment is covered. The HTTP
shim implements only the streaming proxy and OPTIONS-to-POST behavior needed
by this test. The two-server case does exercise VLESS Vision over pinned TLS.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import http.client
import json
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cdn_xhttp.render import client_xray, exit_xray, origin_xray


class TestFailure(RuntimeError):
    pass


def unused_ports(count: int) -> list[int]:
    with contextlib.ExitStack() as stack:
        sockets = [stack.enter_context(socket.socket()) for _ in range(count)]
        for sock in sockets:
            sock.bind(("127.0.0.1", 0))
        return [sock.getsockname()[1] for sock in sockets]


def read_exact(sock: socket.socket, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        part = sock.recv(size - len(result))
        if not part:
            raise TestFailure("Unexpected EOF during SOCKS negotiation")
        result.extend(part)
    return bytes(result)


class QuietHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args: object) -> None:
        pass

    def handle(self) -> None:
        try:
            super().handle()
        except (ConnectionError, TimeoutError):
            pass


class EchoHandler(QuietHandler):
    def do_POST(self) -> None:
        remaining = int(self.headers.get("Content-Length", "0"))
        expected = remaining
        digest = hashlib.sha256()
        while remaining:
            chunk = self.rfile.read(min(65536, remaining))
            if not chunk:
                return
            digest.update(chunk)
            remaining -= len(chunk)
        body = json.dumps({"bytes": expected, "sha256": digest.hexdigest()}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True


def proxy_handler(upstream_port: int, requests: list[dict], lock: threading.Lock):
    class ProxyHandler(QuietHandler):
        def do_GET(self) -> None:
            self.relay(streaming=True)

        def do_OPTIONS(self) -> None:
            self.relay(streaming=False)

        def relay(self, streaming: bool) -> None:
            size = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(size) if size else None
            with lock:
                requests.append(
                    {
                        "method": self.command,
                        "size": size,
                        "padding": self.headers.get("X-Cache", ""),
                    }
                )
            hop_headers = {
                "connection",
                "transfer-encoding",
                "keep-alive",
                "proxy-connection",
                "te",
                "trailer",
                "upgrade",
            }
            headers = {
                k: v for k, v in self.headers.items() if k.lower() not in hop_headers
            }
            connection = http.client.HTTPConnection(
                "127.0.0.1", upstream_port, timeout=30
            )
            try:
                method = "POST" if self.command == "OPTIONS" else self.command
                connection.request(method, self.path, body=body, headers=headers)
                response = connection.getresponse()
                self.send_response(response.status)
                for key, value in response.getheaders():
                    if key.lower() not in hop_headers | {"content-length"}:
                        self.send_header(key, value)
                if streaming:
                    self.send_header("Transfer-Encoding", "chunked")
                    self.end_headers()
                    while True:
                        chunk = response.read1(65536)
                        if not chunk:
                            break
                        self.wfile.write(
                            f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n"
                        )
                        self.wfile.flush()
                    self.wfile.write(b"0\r\n\r\n")
                    self.wfile.flush()
                else:
                    result = response.read()
                    self.send_header("Content-Length", str(len(result)))
                    self.end_headers()
                    self.wfile.write(result)
                    self.wfile.flush()
            except (OSError, http.client.HTTPException):
                # Client disconnects normally when the test closes Xray.
                self.close_connection = True
            finally:
                connection.close()

    return ProxyHandler


@contextlib.contextmanager
def serve(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield server.server_port
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)


def validate_config(binary: Path, directory: Path, name: str, config: dict) -> Path:
    config_path = directory / f"{name}.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    validation = subprocess.run(
        [str(binary), "run", "-test", "-config", str(config_path)],
        capture_output=True,
        text=True,
        timeout=20,
    )
    if validation.returncode:
        raise TestFailure(
            f"{name} config validation failed: {validation.stdout}{validation.stderr}"
        )
    return config_path


@contextlib.contextmanager
def core_process(binary: Path, directory: Path, name: str, config: dict, port: int):
    config_path = validate_config(binary, directory, name, config)
    log_path = directory / f"{name}.log"
    with log_path.open("w", encoding="utf-8") as output:
        process = subprocess.Popen(
            [str(binary), "run", "-config", str(config_path)],
            stdout=output,
            stderr=subprocess.STDOUT,
        )
        try:
            deadline = time.monotonic() + 15
            while True:
                if process.poll() is not None:
                    raise TestFailure(f"{name} exited before listening")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise TestFailure(f"{name} did not start listening")
                    time.sleep(0.05)
            yield
        except Exception as error:
            output.flush()
            log = log_path.read_text(encoding="utf-8", errors="replace")
            raise TestFailure(f"{error}\n{name} log:\n{log}") from error
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def upload(socks_port: int, destination_port: int, payload: bytes) -> dict:
    with socket.create_connection(("127.0.0.1", socks_port), timeout=30) as sock:
        sock.sendall(b"\x05\x01\x00")
        if read_exact(sock, 2) != b"\x05\x00":
            raise TestFailure("SOCKS server rejected no-auth negotiation")
        sock.sendall(
            b"\x05\x01\x00\x01"
            + socket.inet_aton("127.0.0.1")
            + struct.pack("!H", destination_port)
        )
        reply = read_exact(sock, 4)
        if reply[:2] != b"\x05\x00":
            raise TestFailure(f"SOCKS connect failed: {reply.hex()}")
        if reply[3] == 1:
            read_exact(sock, 4)
        elif reply[3] == 4:
            read_exact(sock, 16)
        elif reply[3] == 3:
            read_exact(sock, read_exact(sock, 1)[0])
        else:
            raise TestFailure("Unknown SOCKS reply address type")
        read_exact(sock, 2)
        sock.sendall(
            (
                f"POST /echo HTTP/1.1\r\nHost: localhost\r\n"
                f"Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n"
            ).encode()
        )
        sock.sendall(payload)
        response = http.client.HTTPResponse(sock)
        response.begin()
        if response.status != 200:
            raise TestFailure(f"Echo server returned {response.status}")
        return json.loads(response.read())


def run_case(binary: Path, profile: str, chained: bool, certificate: dict) -> None:
    origin_port, client_port, relay_port = unused_ports(3)
    topology = "two-server" if chained else "single-server"
    config = {
        "origin": {"host": "127.0.0.1", "user": "root", "port": 22},
        "origin_domain": "origin.example.com",
        "cdn_domain": "cdn.example.com",
        "email": "admin@example.com",
        "uuid": "39296dbd-d3db-47e0-a618-2bd24d105942",
        "path": "/smoke-test",
        "padding_key": "dc",
        "profile": profile,
        "xray_version": "26.5.9",
        "exit": {"host": "127.0.0.1", "user": "root", "port": 22} if chained else None,
        "exit_domain": "relay.example.com" if chained else None,
    }
    origin = origin_xray(config)
    origin["inbounds"][0]["listen"] = "127.0.0.1"
    origin["inbounds"][0]["port"] = origin_port
    origin["log"] = {"loglevel": "info"}
    exit_config = None
    if chained:
        exit_config = exit_xray(config)
        exit_config["inbounds"][0]["listen"] = "127.0.0.1"
        exit_config["inbounds"][0]["port"] = relay_port
        exit_config["inbounds"][0]["streamSettings"]["tlsSettings"]["certificates"] = [
            certificate
        ]
        relay = next(out for out in origin["outbounds"] if out["protocol"] == "vless")
        relay["settings"]["vnext"][0]["address"] = "127.0.0.1"
        relay["settings"]["vnext"][0]["port"] = relay_port
        tls = relay["streamSettings"]["tlsSettings"]
        tls["serverName"] = "localhost"
        der = ssl.PEM_cert_to_DER_cert("\n".join(certificate["certificate"]))
        tls["pinnedPeerCertSha256"] = hashlib.sha256(der).hexdigest()
    requests: list[dict] = []
    lock = threading.Lock()
    payload = (
        bytes(range(256)) * 12289
    )  # 3 MiB + 256 bytes: crosses 1 MB packet boundaries.
    with tempfile.TemporaryDirectory(prefix="cdn-xhttp-smoke-") as temporary:
        directory = Path(temporary)
        # Check the unmodified generated client TLS configuration too; the
        # actual transport exercise below swaps the CDN for a cleartext shim.
        validate_config(binary, directory, "generated-client", client_xray(config))
        validate_config(binary, directory, "generated-origin", origin_xray(config))
        with contextlib.ExitStack() as stack:
            sink_port = stack.enter_context(serve(EchoHandler))
            proxy_port = stack.enter_context(
                serve(proxy_handler(origin_port, requests, lock))
            )
            # v26.5.9 blocks private destinations in freedom by default. Allow
            # only this local test sink in the temporary test configuration.
            internet = next(
                item
                for item in (exit_config or origin)["outbounds"]
                if item["protocol"] == "freedom"
            )
            internet.setdefault("settings", {})["finalRules"] = [
                {
                    "action": "allow",
                    "network": "tcp",
                    "ip": ["127.0.0.1/32"],
                    "port": str(sink_port),
                }
            ]
            if exit_config is not None:
                stack.enter_context(
                    core_process(binary, directory, "exit", exit_config, relay_port)
                )
            stack.enter_context(
                core_process(binary, directory, "origin", origin, origin_port)
            )
            client = client_xray(config)
            inbound = next(
                item for item in client["inbounds"] if item["protocol"] == "socks"
            )
            client["inbounds"] = [inbound]
            inbound["listen"] = "127.0.0.1"
            inbound["port"] = client_port
            outbound = next(
                item for item in client["outbounds"] if item["protocol"] == "vless"
            )
            outbound["settings"]["vnext"][0]["address"] = "127.0.0.1"
            outbound["settings"]["vnext"][0]["port"] = proxy_port
            outbound["streamSettings"]["security"] = "none"
            outbound["streamSettings"].pop("tlsSettings", None)
            client["log"] = {"loglevel": "info"}
            stack.enter_context(
                core_process(binary, directory, "client", client, client_port)
            )
            result = upload(client_port, sink_port, payload)
            if result != {
                "bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }:
                raise TestFailure("Upload payload was truncated or corrupted")
            with lock:
                uploads = [item for item in requests if item["method"] == "OPTIONS"]
                downloads = [item for item in requests if item["method"] == "GET"]
            if len(uploads) < 4 or not downloads:
                raise TestFailure(
                    "Expected multi-packet OPTIONS upload and streaming GET download"
                )
            if any("dc=" not in item["padding"] for item in uploads + downloads):
                raise TestFailure(
                    "X-Cache query padding did not survive generated XHTTP extra"
                )
            if any(item["size"] > 1_000_000 for item in uploads):
                raise TestFailure("An upload exceeded configured 1 MB packet maximum")
            print(
                f"PASS {topology}/{profile}: {len(payload)} bytes SHA256 verified, "
                f"{len(uploads)} OPTIONS packets, X-Cache padding preserved"
            )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--xray", required=True, type=Path)
    args = parser.parse_args()
    binary = args.xray.resolve(strict=True)
    output = subprocess.run(
        [str(binary), "tls", "cert", "--domain=localhost", "--expire=24h"],
        capture_output=True,
        text=True,
        check=True,
        timeout=20,
    )
    certificate = json.loads(output.stdout)
    for profile in ("original", "fast"):
        for chained in (False, True):
            run_case(binary, profile, chained, certificate)
    print(
        "Local core/transport checks passed. Real nginx/CDN/ACME/VPS behavior remains untested."
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (TestFailure, OSError, subprocess.SubprocessError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
