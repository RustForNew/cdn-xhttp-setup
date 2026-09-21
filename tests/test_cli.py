"""Exercise the interactive and exported multiuser contracts without SSH."""

import contextlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, unquote, urlsplit
import uuid

from cdn_xhttp import cli
from cdn_xhttp.config import load, validate


def config():
    return validate(
        {
            "name": "Европа #1 / Дом 🚀",
            "origin": {"host": "192.0.2.10", "user": "root", "port": 22},
            "origin_domain": "origin.example.com",
            "cdn_domain": "cdn.example.com",
            "email": "admin@example.com",
            "uuid": "74c60a43-dd09-48e8-aad1-9ab48c7fdd71",
            "uuids": [
                "74c60a43-dd09-48e8-aad1-9ab48c7fdd71",
                "6b352b91-d2ac-43f9-9ae3-de06673b75f2",
            ],
        }
    )


def client_identity(client):
    return client["outbounds"][0]["settings"]["vnext"][0]["users"][0]["id"]


class WizardTests(unittest.TestCase):
    def test_wizard_prompts_name_count_certificate_email_and_saves_unique_ids(self):
        label = "Европа #1 / Дом 🚀"
        answers = iter(
            [
                label,
                "2",
                "192.0.2.10",
                "",
                "",
                "cdn.example.com",
                "origin.example.com",
                "admin@example.com",
                "нет",
                "",
                "",
            ]
        )
        prompts = []

        def answer(prompt):
            prompts.append(prompt)
            return next(answers)

        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "deployment.json"
            with (
                patch("builtins.input", side_effect=answer),
                patch("getpass.getpass") as password,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                saved = cli.wizard(target)
            password.assert_not_called()
            self.assertEqual(label, saved["name"])
            self.assertEqual(2, len(set(saved["uuids"])))
            self.assertTrue(
                all(uuid.UUID(identity).version == 4 for identity in saved["uuids"])
            )
            self.assertEqual(saved["uuids"][0], saved["uuid"])
            self.assertEqual(saved, load(target))
            self.assertIsNone(saved["exit"])
            self.assertEqual("admin@example.com", saved["email"])
            self.assertIn("Название сервера (VLESS-ссылок) [CDN XHTTP]: ", prompts)
            self.assertIn("Количество ссылок с разными UUID (1–1000) [1]: ", prompts)
            self.assertIn("Email для выпуска сертификата Let's Encrypt: ", prompts)
            self.assertNotIn("password", target.read_text(encoding="utf-8"))

    def test_invalid_counts_do_not_create_a_deployment_file(self):
        for count in ("0", "-1", "1001", "abc", "1.5"):
            with self.subTest(count=count), tempfile.TemporaryDirectory() as directory:
                target = Path(directory) / "deployment.json"
                with (
                    patch("builtins.input", side_effect=["My server", count]),
                    contextlib.redirect_stdout(io.StringIO()),
                    self.assertRaises(ValueError),
                ):
                    cli.wizard(target)
                self.assertFalse(target.exists())

    def test_existing_config_is_preserved_without_prompts(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "deployment.json"
            target.write_text("existing data", encoding="utf-8")
            with patch("builtins.input") as prompt, self.assertRaises(ValueError):
                cli.wizard(target)
            prompt.assert_not_called()
            self.assertEqual("existing data", target.read_text(encoding="utf-8"))


class ExportTests(unittest.TestCase):
    def test_exported_links_and_per_user_clients_share_the_same_identity_and_extra(
        self,
    ):
        value = config()
        checks = {"origin": {"ok": True}, "cdn": {"ok": True}}
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "result"
            cli.write_connection(value, target, verified=True, checks=checks)
            links = (target / "vless.txt").read_text(encoding="utf-8").splitlines()
            self.assertEqual(2, len(links))
            shared_extra = json.loads(
                (target / "xhttp-extra.json").read_text(encoding="utf-8")
            )
            for index, (link, identity) in enumerate(
                zip(links, value["uuids"]), start=1
            ):
                parsed = urlsplit(link)
                self.assertEqual(identity, parsed.username)
                self.assertEqual(f"{value['name']} {index}", unquote(parsed.fragment))
                user_client = json.loads(
                    (target / "clients" / f"client-{index:03d}.json").read_text(
                        encoding="utf-8"
                    )
                )
                self.assertEqual(identity, client_identity(user_client))
                self.assertEqual(
                    shared_extra,
                    user_client["outbounds"][0]["streamSettings"]["xhttpSettings"][
                        "extra"
                    ],
                )
                self.assertEqual(
                    shared_extra, json.loads(parse_qs(parsed.query)["extra"][0])
                )
            primary = json.loads((target / "client.json").read_text(encoding="utf-8"))
            self.assertEqual(value["uuids"][0], client_identity(primary))
            status = json.loads((target / "status.json").read_text(encoding="utf-8"))
            self.assertTrue(status["endpoint_verified"])
            self.assertFalse(status["vless_tunnel_verified"])
            self.assertEqual(checks, status["checks"])
            if os.name != "nt":
                self.assertEqual(0o700, stat.S_IMODE(target.stat().st_mode))
                self.assertEqual(
                    0o700, stat.S_IMODE((target / "clients").stat().st_mode)
                )
                for file in target.rglob("*.json"):
                    self.assertEqual(0o600, stat.S_IMODE(file.stat().st_mode))
                self.assertEqual(
                    0o600, stat.S_IMODE((target / "vless.txt").stat().st_mode)
                )

    def test_shrinking_export_removes_only_stale_managed_client_files(self):
        value = config()
        value["uuids"].append("1de7a7e8-c046-4fdc-b0ef-c03f83133882")
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            cli.write_connection(value, target, verified=False)
            clients = target / "clients"
            for name in ("notes.txt", "client-custom.json", "client-003.json.backup"):
                (clients / name).write_text("preserve this", encoding="utf-8")
            value["uuids"] = value["uuids"][:2]
            cli.write_connection(value, target, verified=False)
            self.assertTrue((clients / "client-001.json").exists())
            self.assertTrue((clients / "client-002.json").exists())
            self.assertFalse((clients / "client-003.json").exists())
            value["uuids"] = value["uuids"][:1]
            cli.write_connection(value, target, verified=False)
            self.assertFalse((clients / "client-001.json").exists())
            self.assertFalse((clients / "client-002.json").exists())
            for name in ("notes.txt", "client-custom.json", "client-003.json.backup"):
                self.assertEqual(
                    "preserve this", (clients / name).read_text(encoding="utf-8")
                )
            self.assertEqual(
                1, len((target / "vless.txt").read_text(encoding="utf-8").splitlines())
            )

    def test_export_rejects_a_symlinked_clients_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "result"
            with (
                patch.object(Path, "is_symlink", return_value=True),
                self.assertRaises(ValueError),
            ):
                cli.write_connection(config(), target, verified=False)
            self.assertFalse((target / "clients").exists())

    def test_unverified_single_link_keeps_exact_label_and_no_claimed_tunnel_check(self):
        value = config()
        value["uuids"] = value["uuids"][:1]
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            cli.write_connection(value, target, verified=False)
            link = (target / "vless.txt").read_text(encoding="utf-8").strip()
            self.assertEqual(value["name"], unquote(urlsplit(link).fragment))
            self.assertFalse((target / "clients").exists())
            status = json.loads((target / "status.json").read_text(encoding="utf-8"))
            self.assertFalse(status["endpoint_verified"])
            self.assertFalse(status["vless_tunnel_verified"])

    def test_link_command_exports_every_user_without_network_or_passwords(self):
        value = config()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            deployment = base / "deployment.json"
            deployment.write_text(json.dumps(value), encoding="utf-8")
            output = io.StringIO()
            with (
                patch("getpass.getpass") as password,
                patch("socket.getaddrinfo") as dns,
                contextlib.redirect_stdout(output),
            ):
                status = cli.main(
                    [
                        "link",
                        "--config",
                        str(deployment),
                        "--output",
                        str(base / "result"),
                    ]
                )
            self.assertEqual(0, status)
            password.assert_not_called()
            dns.assert_not_called()
            printed = [
                line
                for line in output.getvalue().splitlines()
                if line.startswith("vless://")
            ]
            exported = (
                (base / "result" / "vless.txt").read_text(encoding="utf-8").splitlines()
            )
            self.assertEqual(exported, printed)
            self.assertEqual(2, len(printed))

    def test_check_uses_maximum_packet_size_and_reports_partial_failure(self):
        results = [
            {"ok": True, "errors": []},
            {"ok": False, "errors": ["body mismatch"]},
        ]
        with (
            patch("cdn_xhttp.health.check_endpoint", side_effect=results) as endpoint,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            checks = cli.check(config())
        self.assertEqual(results[0], checks["origin"])
        self.assertEqual(results[1], checks["cdn"])
        self.assertEqual(
            [
                (("origin.example.com",), {"max_bytes": 1000000}),
                (("cdn.example.com",), {"max_bytes": 1000000}),
            ],
            [(call.args, call.kwargs) for call in endpoint.call_args_list],
        )


if __name__ == "__main__":
    unittest.main()
