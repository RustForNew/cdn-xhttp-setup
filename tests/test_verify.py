"""Offline contracts of the informational check and its temporary runtime."""

import contextlib
import copy
import hashlib
import io
import json
import os
import unittest
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from cdn_xhttp import verify
from cdn_xhttp.config import validate
from cdn_xhttp.xray_runtime import (
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


def endpoint(ok=True):
    return {
        "domain": "cdn.example.com",
        "ok": ok,
        "status": 200 if ok else 413,
        "errors": [] if ok else ["16 bytes: HTTP 413"],
        "probes": [],
    }


class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.endpoint = self.stack.enter_context(
            patch.object(verify, "check_endpoint", return_value=endpoint())
        )
        self.runtime = self.stack.enter_context(patch.object(verify, "XrayRuntime"))
        self.probes = self.stack.enter_context(
            patch.object(
                verify,
                "_tunnel_probes",
                return_value=[{"name": "exit_ip", "ok": True}],
            )
        )
        self.logs = []

    def test_success_reports_both_checks_without_changing_configuration(self):
        config = spec()
        before = copy.deepcopy(config)
        result = verify.verify_connection(config, log=self.logs.append)
        self.assertEqual(before, config)
        self.assertTrue(result["endpoint_verified"])
        self.assertTrue(result["vless_tunnel_verified"])
        self.endpoint.assert_called_once_with("cdn.example.com")
        self.assertEqual("cdn.example.com", self.probes.call_args.args[0]["cdn_domain"])
        self.assertNotIn(config["uuid"], str(self.logs) + json.dumps(result))
        self.assertNotIn("connect_address", json.dumps(result))

    def test_endpoint_failure_does_not_skip_the_tunnel_check(self):
        self.endpoint.return_value = endpoint(ok=False)
        result = verify.verify_connection(spec(), log=self.logs.append)
        self.assertFalse(result["endpoint_verified"])
        self.assertTrue(result["vless_tunnel_verified"])
        self.probes.assert_called_once()

    def test_unavailable_runtime_is_a_result_not_an_error(self):
        self.runtime.return_value.__enter__.return_value.prepare.side_effect = (
            ProbeError("Official Xray archive SHA256 verification failed")
        )
        result = verify.verify_connection(spec(), log=self.logs.append)
        self.assertFalse(result["vless_tunnel_verified"])
        self.probes.assert_not_called()
        self.assertEqual(
            "Official Xray archive SHA256 verification failed",
            result["checks"][-1]["error"],
        )

    def test_network_errors_are_summarized_by_type_only(self):
        self.probes.side_effect = OSError("connect to 8.8.8.8 with secret-value failed")
        result = verify.verify_connection(spec(), log=self.logs.append)
        self.assertFalse(result["vless_tunnel_verified"])
        self.assertEqual("OSError", result["checks"][-1]["error"])
        self.assertNotIn("secret-value", json.dumps(result) + str(self.logs))

    def test_cancel_is_not_converted_into_a_result(self):
        self.probes.side_effect = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            verify.verify_connection(spec(), log=self.logs.append)
        self.runtime.return_value.__exit__.assert_called_once()


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

    def test_pinned_release_is_downloaded(self):
        with XrayRuntime() as runtime, patch(
            "cdn_xhttp.xray_runtime._download", side_effect=ProbeError("offline")
        ) as download, self.assertRaises(ProbeError):
            runtime.prepare()
        self.assertIn("/releases/download/v26.9.9/", download.call_args.args[0])

    def test_archive_is_verified_before_extracting_anything(self):
        with XrayRuntime() as runtime:
            folder = runtime.directory
            with (
                patch(
                    "cdn_xhttp.xray_runtime._download",
                    side_effect=[b"SHA256= " + b"0" * 64, b"not an archive"],
                ),
                self.assertRaises(ProbeError),
            ):
                runtime.prepare()
            self.assertEqual([], list(folder.iterdir()))
        self.assertFalse(folder.exists())

    def test_binary_is_cached_only_in_private_check_directory(self):
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
                "cdn_xhttp.xray_runtime._download", side_effect=[checksum, raw]
            ) as download:
                binary = runtime.prepare()
                self.assertEqual(binary, runtime.prepare())
                self.assertEqual(2, download.call_count)
                self.assertEqual([executable], [path.name for path in folder.iterdir()])
        self.assertFalse(folder.exists())

    def test_locked_file_during_cleanup_does_not_mask_the_result(self):
        # Antivirus software on Windows may hold xray.exe after the check.
        with patch("cdn_xhttp.xray_runtime.time.sleep") as sleep:
            with XrayRuntime() as runtime:
                folder = runtime.directory
                locked = folder / ("xray.exe" if os.name == "nt" else "xray")
                handle = open(locked, "wb")
            # Leaving the block must not raise even when deletion failed.
            handle.close()
        if folder.exists():
            # Windows: the open handle kept the file through every retry.
            self.assertEqual(4, sleep.call_count)
            for path in sorted(folder.rglob("*"), reverse=True):
                path.unlink()
            folder.rmdir()

    def test_cleanup_is_retried_and_its_failure_is_not_raised(self):
        # Simulate a directory that stays locked for every attempt.
        with (
            patch("cdn_xhttp.xray_runtime.shutil.rmtree"),
            patch("cdn_xhttp.xray_runtime.time.sleep") as sleep,
        ):
            runtime = XrayRuntime().__enter__()
            folder = runtime.directory
            runtime.__exit__(None, None, None)
        self.assertTrue(folder.exists())
        self.assertEqual(4, sleep.call_count)
        folder.rmdir()

    def test_tunnel_uses_the_published_profile_and_cleans_up_on_cancel(self):
        with XrayRuntime() as runtime:
            runtime.binary = Path("unused-verified-xray")
            process = MagicMock()
            process.poll.return_value = None
            with (
                patch("cdn_xhttp.xray_runtime.subprocess.run") as run,
                patch("cdn_xhttp.xray_runtime.subprocess.Popen", return_value=process),
                patch("cdn_xhttp.xray_runtime.socket.create_connection"),
            ):
                run.return_value.returncode = 0
                with (
                    self.assertRaises(KeyboardInterrupt),
                    runtime.tunnel(validate(spec())),
                ):
                    profile = json.loads(
                        (runtime.directory / "probe.json").read_text(encoding="utf-8")
                    )
                    outbound = profile["outbounds"][0]
                    # No relay and no pinned IP: the client's own CDN domain.
                    self.assertEqual(
                        ("cdn.example.com", 443),
                        (
                            outbound["settings"]["vnext"][0]["address"],
                            outbound["settings"]["vnext"][0]["port"],
                        ),
                    )
                    tls = outbound["streamSettings"]["tlsSettings"]
                    self.assertEqual("cdn.example.com", tls["serverName"])
                    self.assertFalse(tls["allowInsecure"])
                    self.assertEqual(
                        "header",
                        outbound["streamSettings"]["xhttpSettings"]["extra"][
                            "uplinkDataPlacement"
                        ],
                    )
                    self.assertEqual(
                        "password", profile["inbounds"][0]["settings"]["auth"]
                    )
                    raise KeyboardInterrupt()
                process.terminate.assert_called_once()
                process.wait.assert_called_once_with(timeout=4)
                self.assertFalse((runtime.directory / "probe.json").exists())

    def test_socks_refuses_an_unauthenticated_or_wrong_listener(self):
        with patch("cdn_xhttp.xray_runtime.socket.create_connection") as connect:
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
            patch("cdn_xhttp.xray_runtime.request_https", return_value=response),
            self.assertRaises(ProbeError),
        ):
            options_probe("origin.example.com", lambda *args: None, size=4)

    def test_tunnel_download_must_match_the_direct_reference(self):
        runtime = MagicMock()
        runtime.download_reference = ("https://example.com/x.dgst", b"reference")
        with patch.object(
            verify, "_download_document", return_value=(200, b"reference")
        ):
            self.assertTrue(verify._download_integrity(object(), runtime)["ok"])
        with (
            patch.object(verify, "_download_document", return_value=(200, b"changed")),
            self.assertRaises(ProbeError),
        ):
            verify._download_integrity(object(), runtime)

    def test_exit_must_match_origin_or_configured_exit(self):
        config = spec()
        with patch.object(verify, "request_https", return_value=(200, {}, b"8.8.8.8\n")):
            self.assertTrue(verify._egress_probe(config, object())["ok"])
        with (
            patch.object(verify, "request_https", return_value=(200, {}, b"1.1.1.1\n")),
            self.assertRaisesRegex(ProbeError, "differs"),
        ):
            verify._egress_probe(config, object())
        config["exit"] = {"host": "1.1.1.1"}
        with patch.object(verify, "request_https", return_value=(200, {}, b"1.1.1.1\n")):
            self.assertEqual(
                "1.1.1.1", verify._egress_probe(config, object())["observed"]
            )


if __name__ == "__main__":
    unittest.main()
