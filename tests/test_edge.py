"""Offline edge-selection, route-binding and temporary-runtime contracts."""

import contextlib
import copy
import hashlib
import io
import ipaddress
import json
import os
import socket
import struct
import threading
import unittest
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from cdn_xhttp import edge
from cdn_xhttp.edge_network import Route, TCPRelay, connect_route
from cdn_xhttp.edge_runtime import (
    ProbeError,
    XrayRuntime,
    asset_name,
    checksum_sha256,
    options_probe,
    socks_connect,
)


def spec():
    return {
        "origin": {"host": "8.8.8.8", "user": "root", "port": 22},
        "origin_domain": "origin.example.com",
        "cdn_domain": "cdn.example.com",
        "email": "owner@example.com",
        "uuid": "74c60a43-dd09-48e8-aad1-9ab48c7fdd71",
    }


class CandidateTests(unittest.TestCase):
    def test_feed_is_strict_public_ipv4_and_does_not_enumerate_ipv6(self):
        networks = edge.parse_prefixes(
            json.dumps(
                {"prefixes": ["8.8.8.0/29", "2001:4860::/32", "8.8.8.0/29"]}
            ).encode()
        )
        self.assertEqual([ipaddress.ip_network("8.8.8.0/29")], networks)
        for value in (
            "10.0.0.0/8",
            "127.0.0.0/8",
            "224.0.0.0/8",
            "8.8.8.1/29",
            "8.8.8.8",
            "https://example.com",
        ):
            with self.assertRaises(ProbeError, msg=value):
                edge.parse_prefixes(json.dumps({"prefixes": [value]}).encode())

    def test_feed_shape_and_size_are_bounded(self):
        for value in (
            [],
            {},
            {"prefixes": "8.8.8.0/29"},
            {"prefixes": [None]},
            {"prefixes": ["8.8.8.0/29"] * 2049},
        ):
            with self.assertRaises(ProbeError):
                edge.parse_prefixes(json.dumps(value).encode())
        with self.assertRaises(ProbeError):
            edge.parse_prefixes(b" " * (edge.MAX_PREFIX_BYTES + 1))

    def test_previous_and_dns_precede_interleaved_prefix_hosts(self):
        networks = [
            ipaddress.ip_network("8.8.8.0/29"),
            ipaddress.ip_network("9.9.9.0/31"),
        ]
        addresses = edge.candidate_addresses(
            "1.1.1.1", ["8.8.4.4", "1.1.1.1", "127.0.0.1"], networks
        )
        self.assertEqual(
            ["1.1.1.1", "8.8.4.4", "9.9.9.1", "8.8.8.3", "9.9.9.0", "8.8.8.2"],
            addresses[:6],
        )
        self.assertNotIn("8.8.8.0", addresses)
        self.assertNotIn("8.8.8.7", addresses)
        self.assertEqual(len(addresses), len(set(addresses)))

    def test_large_networks_are_sampled_with_a_hard_address_limit(self):
        networks = [ipaddress.ip_network("8.0.0.0/8")]
        self.assertLessEqual(len(edge.candidate_addresses(None, [], networks)), 8)
        networks = [ipaddress.ip_network(f"11.{index}.0.0/16") for index in range(256)]
        self.assertEqual(
            edge.MAX_CANDIDATES, len(edge.candidate_addresses(None, [], networks))
        )


class SelectionTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(
            patch.object(
                edge, "_prefix_reference", return_value=([], b"public reference")
            )
        )
        self.stack.enter_context(
            patch.object(edge, "_current_dns", return_value=["1.1.1.1", "8.8.4.4"])
        )
        self.routes = self.stack.enter_context(
            patch.object(
                edge,
                "ethernet_routes",
                return_value=[Route("ethernet", "Ethernet", 4, "192.168.1.2")],
            )
        )
        self.runtime = self.stack.enter_context(patch.object(edge, "XrayRuntime"))
        self.filter = self.stack.enter_context(
            patch.object(edge, "_prefilter", return_value=True)
        )
        self.probe = self.stack.enter_context(
            patch.object(
                edge, "_probe_candidate", return_value=[{"name": "exit_ip", "ok": True}]
            )
        )
        self.logs = []

    def test_ethernet_full_success_preserves_configuration(self):
        config = spec()
        before = copy.deepcopy(config)
        result = edge.select_edge(config, log=self.logs.append)
        self.assertEqual(before, config)
        self.assertEqual("ethernet", result["route"])
        self.assertTrue(result["endpoint_verified"])
        self.assertTrue(result["vless_tunnel_verified"])
        self.assertEqual("1.1.1.1", result["connect_address"])
        self.probe.assert_called_once()
        self.assertNotIn(config["uuid"], str(self.logs) + json.dumps(result))

    def test_http_success_never_counts_as_a_working_vless_tunnel(self):
        self.probe.side_effect = ProbeError("VLESS authentication failed")
        with self.assertRaises(edge.EdgeSelectionError) as caught:
            edge.select_edge(spec(), log=self.logs.append)
        self.assertEqual(4, self.probe.call_count)
        self.assertTrue(caught.exception.checks)
        self.assertFalse(any(check.get("ok") for check in caught.exception.checks))

    def test_failed_ethernet_explicitly_falls_back_to_default_route(self):
        def probe(config, address, route, runtime, reference):
            if route.name == "ethernet":
                raise OSError("No usable bound route")
            return [{"ok": True}]

        self.probe.side_effect = probe
        result = edge.select_edge(spec(), log=self.logs.append)
        self.assertEqual("default", result["route"])
        self.assertTrue(any("default route" in line for line in self.logs))
        self.assertEqual(
            ["ethernet", "ethernet", "default"],
            [call.args[2].name for call in self.probe.call_args_list],
        )

    def test_missing_ethernet_is_not_reported_as_ethernet_success(self):
        self.routes.return_value = []
        result = edge.select_edge(spec(), log=self.logs.append)
        self.assertEqual("default", result["route"])
        self.assertTrue(any("не обнаружен" in line for line in self.logs))

    def test_no_filtered_endpoint_means_no_xray_start_and_no_success(self):
        self.filter.return_value = False
        with self.assertRaises(edge.EdgeSelectionError):
            edge.select_edge(spec(), log=self.logs.append)
        self.probe.assert_not_called()
        self.runtime.return_value.__enter__.return_value.prepare.assert_not_called()

    def test_xray_download_failure_aborts_instead_of_retrying_every_ip(self):
        self.runtime.return_value.__enter__.return_value.prepare.side_effect = (
            ProbeError("checksum failed")
        )
        with self.assertRaises(edge.EdgeSelectionError):
            edge.select_edge(spec(), log=self.logs.append)
        self.probe.assert_not_called()
        self.assertEqual(
            1, self.runtime.return_value.__enter__.return_value.prepare.call_count
        )

    def test_cancel_is_not_converted_to_fallback_or_success(self):
        self.probe.side_effect = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            edge.select_edge(spec(), log=self.logs.append)
        self.assertEqual(1, self.probe.call_count)
        self.runtime.return_value.__exit__.assert_called_once()


class RouteAndRelayTests(unittest.TestCase):
    def test_windows_binds_both_source_and_interface(self):
        with (
            patch("cdn_xhttp.edge_network.os.name", "nt"),
            patch("cdn_xhttp.edge_network.socket.socket") as factory,
        ):
            sock = factory.return_value
            result = connect_route(
                "1.1.1.1", 443, Route("ethernet", "wired", 17, "192.168.1.2"), 4
            )
            self.assertIs(sock, result)
            sock.setsockopt.assert_called_once_with(
                socket.IPPROTO_IP, 31, struct.pack("!I", 17)
            )
            sock.bind.assert_called_once_with(("192.168.1.2", 0))
            sock.connect.assert_called_once_with(("1.1.1.1", 443))

    def test_binding_failure_closes_socket_without_unbound_retry(self):
        with (
            patch("cdn_xhttp.edge_network.os.name", "nt"),
            patch("cdn_xhttp.edge_network.socket.socket") as factory,
        ):
            sock = factory.return_value
            sock.setsockopt.side_effect = PermissionError("denied")
            with self.assertRaises(PermissionError):
                connect_route(
                    "1.1.1.1", 443, Route("ethernet", "wired", 17, "192.168.1.2"), 4
                )
            sock.close.assert_called_once()
            sock.connect.assert_not_called()

    def test_relay_transfers_bytes_and_cleans_listeners_workers(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(3)

        def echo():
            with listener:
                client, _ = listener.accept()
                with client:
                    while True:
                        data = client.recv(65536)
                        if not data:
                            return
                        client.sendall(data)

        worker = threading.Thread(target=echo, daemon=True)
        worker.start()
        route = Route("ethernet", "wired", 7, "192.168.1.2")
        destination = listener.getsockname()
        with patch(
            "cdn_xhttp.edge_network.connect_route",
            side_effect=lambda address, port, selected, timeout: (
                socket.create_connection(destination, timeout=timeout)
            ),
        ) as connect:
            with TCPRelay("1.1.1.1", route, timeout=2) as relay:
                with socket.create_connection(
                    ("127.0.0.1", relay.port), timeout=2
                ) as client:
                    payload = bytes(range(256)) * 256
                    client.sendall(payload)
                    received = bytearray()
                    while len(received) < len(payload):
                        received.extend(client.recv(65536))
                    self.assertEqual(payload, bytes(received))
                self.assertEqual(("1.1.1.1", 443, route, 2), connect.call_args.args)
            self.assertFalse(relay.thread.is_alive())
            self.assertFalse(any(thread.is_alive() for thread in relay.workers))
            self.assertEqual(-1, relay.listener.fileno())
        worker.join(timeout=3)
        self.assertFalse(worker.is_alive())


class RuntimeTests(unittest.TestCase):
    def test_assets_are_pinned_for_supported_platforms(self):
        self.assertEqual("Xray-windows-64.zip", asset_name("Windows", "AMD64"))
        self.assertEqual("Xray-linux-arm64-v8a.zip", asset_name("Linux", "aarch64"))
        with self.assertRaises(ProbeError):
            asset_name("Linux", "armv7")

    def test_checksum_requires_one_sha256(self):
        digest = "a" * 64
        for line in (f"SHA2-256= {digest}\n", f"SHA256(xray.zip)= {digest}\r\n"):
            self.assertEqual(digest, checksum_sha256(line.encode()))
        for data in (b"SHA256= nope", (f"SHA256= {digest}\n" * 2).encode()):
            with self.assertRaises(ProbeError):
                checksum_sha256(data)

    def test_archive_is_verified_before_extracting_anything(self):
        with XrayRuntime() as runtime:
            folder = runtime.directory
            with (
                patch(
                    "cdn_xhttp.edge_runtime._download",
                    side_effect=[b"SHA256= " + b"0" * 64, b"not an archive"],
                ),
                self.assertRaises(ProbeError),
            ):
                runtime.prepare()
            self.assertEqual([], list(folder.iterdir()))
        self.assertFalse(folder.exists())

    def test_binary_is_cached_only_in_private_selection_directory(self):
        archive = io.BytesIO()
        executable = "xray.exe" if os.name == "nt" else "xray"
        with zipfile.ZipFile(archive, "w") as package:
            package.writestr(executable, b"fake executable; never run")
            package.writestr("../../outside", b"must never be extracted")
        raw = archive.getvalue()
        checksum = ("SHA256= " + hashlib.sha256(raw).hexdigest()).encode()
        with XrayRuntime() as runtime:
            folder = runtime.directory
            with patch(
                "cdn_xhttp.edge_runtime._download", side_effect=[checksum, raw]
            ) as download:
                binary = runtime.prepare()
                self.assertEqual(binary, runtime.prepare())
                self.assertEqual(2, download.call_count)
                self.assertEqual([executable], [path.name for path in folder.iterdir()])
        self.assertFalse(folder.exists())

    def test_temporary_process_and_profile_are_cleaned_on_cancel(self):
        from cdn_xhttp.config import validate

        with XrayRuntime() as runtime:
            runtime.binary = Path("unused-verified-xray")
            process = MagicMock()
            process.poll.return_value = None
            with (
                patch("cdn_xhttp.edge_runtime.subprocess.run") as run,
                patch("cdn_xhttp.edge_runtime.subprocess.Popen", return_value=process),
                patch("cdn_xhttp.edge_runtime.socket.create_connection"),
            ):
                run.return_value.returncode = 0
                with (
                    self.assertRaises(KeyboardInterrupt),
                    runtime.tunnel(validate(spec()), 19001),
                ):
                    profile = json.loads(
                        (runtime.directory / "probe.json").read_text(encoding="utf-8")
                    )
                    outbound = profile["outbounds"][0]
                    self.assertEqual(
                        "127.0.0.1", outbound["settings"]["vnext"][0]["address"]
                    )
                    self.assertEqual(
                        "cdn.example.com",
                        outbound["streamSettings"]["tlsSettings"]["serverName"],
                    )
                    self.assertFalse(
                        outbound["streamSettings"]["tlsSettings"]["allowInsecure"]
                    )
                    self.assertEqual(
                        "password", profile["inbounds"][0]["settings"]["auth"]
                    )
                    raise KeyboardInterrupt()
                process.terminate.assert_called_once()
                process.wait.assert_called_once_with(timeout=4)
                self.assertFalse((runtime.directory / "probe.json").exists())

    def test_socks_refuses_an_unauthenticated_or_wrong_listener(self):
        with patch("cdn_xhttp.edge_runtime.socket.create_connection") as connect:
            sock = connect.return_value
            sock.recv.return_value = b"\x05\x00"
            with self.assertRaises(ProbeError):
                socks_connect(1234, "user", "password", "example.com", 443, 1)
            sock.close.assert_called_once()
            sock.sendall.assert_called_once_with(b"\x05\x01\x02")


class IntegrityTests(unittest.TestCase):
    def test_wrong_options_digest_is_rejected(self):
        response = (
            200,
            {
                "x-cdn-origin": "ok",
                "cache-control": "no-store",
                "content-type": "application/json",
            },
            json.dumps({"method": "OPTIONS", "length": 4, "sha256": "wrong"}).encode(),
        )
        with (
            patch("cdn_xhttp.edge_runtime.request_https", return_value=response),
            self.assertRaises(ProbeError),
        ):
            options_probe("cdn.example.com", lambda *args: None, size=4)

    def test_dynamic_download_reference_is_refreshed_once(self):
        with patch.object(
            edge,
            "_download_document",
            side_effect=[(200, b"new"), (200, b"new"), (200, b"new")],
        ) as request:
            result = edge._download_integrity(object(), b"old", None)
            self.assertTrue(result["ok"])
            self.assertEqual(3, request.call_count)
        with (
            patch.object(
                edge,
                "_download_document",
                side_effect=[(200, b"bad"), (200, b"new"), (200, b"bad")],
            ),
            self.assertRaises(ProbeError),
        ):
            edge._download_integrity(object(), b"old", None)

    def test_exit_must_match_origin_or_configured_exit(self):
        config = spec()
        with patch.object(edge, "request_https", return_value=(200, {}, b"8.8.8.8\n")):
            self.assertTrue(edge._egress_probe(config, object())["ok"])
        with (
            patch.object(edge, "request_https", return_value=(200, {}, b"1.1.1.1\n")),
            self.assertRaisesRegex(ProbeError, "differs"),
        ):
            edge._egress_probe(config, object())
        config["exit"] = {"host": "1.1.1.1"}
        with patch.object(edge, "request_https", return_value=(200, {}, b"1.1.1.1\n")):
            self.assertEqual(
                "1.1.1.1", edge._egress_probe(config, object())["observed"]
            )


if __name__ == "__main__":
    unittest.main()
