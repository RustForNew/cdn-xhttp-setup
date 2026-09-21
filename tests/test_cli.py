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


def wizard_answers(bridge=False):
    answers = ["y" if bridge else "n", "192.0.2.10", "", "", "origin.example.com"]
    if bridge:
        answers.extend(["192.0.2.20", "operator", "2222", "exit.example.com"])
    answers.extend(["cdn.example.com", "admin@example.com", "Европа #1 / Дом 🚀", "2"])
    return answers


class ConfirmationTests(unittest.TestCase):
    def test_yes_accepts_short_full_and_russian_answers(self):
        for answer in ("y", "Y", " yes ", "YES", "да", "Да"):
            with (
                self.subTest(answer=answer),
                patch("builtins.input", return_value=answer),
            ):
                self.assertTrue(cli.yes("Продолжить?"))
        for answer in ("n", "N", " no ", "NO", "нет", "Нет"):
            with (
                self.subTest(answer=answer),
                patch("builtins.input", return_value=answer),
            ):
                self.assertFalse(cli.yes("Продолжить?", default=True))

    def test_enter_uses_default_and_prompt_shows_y_n(self):
        for default in (False, True):
            with (
                self.subTest(default=default),
                patch("builtins.input", return_value="") as prompt,
            ):
                self.assertEqual(default, cli.yes("Продолжить?", default=default))
                self.assertIn("y/n", prompt.call_args.args[0].lower())

    def test_typo_repeats_question_instead_of_cancelling(self):
        with (
            patch("builtins.input", side_effect=["maybe", "y"]) as prompt,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertTrue(cli.yes("Продолжить?"))
        self.assertEqual(2, prompt.call_count)
        self.assertEqual(prompt.call_args_list[0], prompt.call_args_list[1])


class WizardTests(unittest.TestCase):
    def test_wizard_prompts_name_count_certificate_email_and_saves_unique_ids(self):
        label = "Европа #1 / Дом 🚀"
        answers = iter(wizard_answers())
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
            self.assertIn("мост", prompts[0].lower())
            self.assertTrue(any("Название" in prompt for prompt in prompts))
            self.assertTrue(any("Количество ссылок" in prompt for prompt in prompts))
            self.assertTrue(
                any("Email для выпуска сертификата" in prompt for prompt in prompts)
            )
            self.assertFalse(any("Профиль отправки" in prompt for prompt in prompts))
            self.assertFalse(any("XHTTP path" in prompt for prompt in prompts))
            self.assertEqual("fast", saved["profile"])
            self.assertEqual("/api-test", saved["path"])
            self.assertNotIn("password", target.read_text(encoding="utf-8"))

    def test_invalid_field_is_repeated_without_restarting_wizard(self):
        invalid_fields = [
            (1, "not-an-ip"),
            (2, "root; bad"),
            (3, "0"),
            (3, "65536"),
            (3, "abc"),
            (4, "https://origin.example.com/path"),
            (5, "origin.example.com"),
            (6, "not-an-email"),
            (7, "x" * 81),
            (7, "bad\x00name"),
            *[(8, count) for count in ("0", "-1", "1001", "abc", "1.5")],
        ]
        for position, invalid in invalid_fields:
            with (
                self.subTest(position=position, invalid=invalid),
                tempfile.TemporaryDirectory() as directory,
            ):
                target = Path(directory) / "deployment.json"
                answers = wizard_answers()
                answers.insert(position, invalid)
                with (
                    patch("builtins.input", side_effect=answers) as prompt,
                    contextlib.redirect_stdout(io.StringIO()),
                ):
                    saved = cli.wizard(target)
                self.assertEqual(config()["name"], saved["name"])
                self.assertEqual(2, len(saved["uuids"]))
                self.assertEqual(len(answers), prompt.call_count)
                self.assertEqual(
                    prompt.call_args_list[position],
                    prompt.call_args_list[position + 1],
                )
                self.assertEqual(saved, load(target))

    def test_bridge_credentials_are_requested_next_to_each_server_but_not_saved(self):
        events = []
        answers = iter(wizard_answers(bridge=True))
        secrets = [
            "example-origin-secret",
            "example-exit-secret",
            "example-sudo-secret",
        ]
        passwords = iter(secrets)
        credentials = {}

        def answer(prompt):
            events.append(("input", prompt))
            return next(answers)

        def password(prompt):
            events.append(("password", prompt))
            return next(passwords)

        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "deployment.json"
            output = io.StringIO()
            with (
                patch("builtins.input", side_effect=answer),
                patch("getpass.getpass", side_effect=password),
                contextlib.redirect_stdout(output),
            ):
                saved = cli.wizard(target, credentials=credentials)
            self.assertEqual("192.0.2.10", saved["origin"]["host"])
            self.assertEqual(
                {"host": "192.0.2.20", "user": "operator", "port": 2222},
                saved["exit"],
            )
            self.assertEqual("exit.example.com", saved["exit_domain"])
            self.assertEqual(
                {
                    "origin": {"password": secrets[0], "sudo_password": None},
                    "exit": {"password": secrets[1], "sudo_password": secrets[2]},
                },
                credentials,
            )
            # Password follows the host fields and precedes the origin domain.
            self.assertEqual("password", events[4][0])
            self.assertEqual("input", events[5][0])
            self.assertEqual("password", events[9][0])
            self.assertEqual("password", events[10][0])
            self.assertEqual("input", events[11][0])
            text = target.read_text(encoding="utf-8") + output.getvalue()
            for secret in secrets:
                self.assertNotIn(secret, text)

    def test_existing_config_is_preserved_without_prompts(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "deployment.json"
            target.write_text("existing data", encoding="utf-8")
            with patch("builtins.input") as prompt, self.assertRaises(ValueError):
                cli.wizard(target)
            prompt.assert_not_called()
            self.assertEqual("existing data", target.read_text(encoding="utf-8"))


class InstallationFlowTests(unittest.TestCase):
    def test_deploy_collects_both_server_passwords_before_any_remote_change(self):
        value = config()
        value["exit"] = {"host": "192.0.2.20", "user": "operator", "port": 2222}
        value["exit_domain"] = "exit.example.com"
        secrets = [
            "example-origin-secret",
            "example-exit-secret",
            "example-sudo-secret",
        ]
        received = []
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            target = base / "deployment.json"
            target.write_text(json.dumps(value), encoding="utf-8")

            def deploy_server(value, role, **kwargs):
                self.assertEqual(3, password.call_count)
                received.append((role, kwargs["password"], kwargs["sudo_password"]))

            stderr = io.StringIO()
            with (
                patch("builtins.input", side_effect=["y"]),
                patch("getpass.getpass", side_effect=secrets) as password,
                patch.object(cli, "dns_preflight"),
                patch("cdn_xhttp.remote.deploy_server", side_effect=deploy_server),
                patch.object(
                    cli,
                    "check",
                    return_value={"origin": {"ok": True}, "cdn": {"ok": True}},
                ),
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(stderr),
            ):
                status = cli.main(
                    [
                        "deploy",
                        "--config",
                        str(target),
                        "--output",
                        str(base / "result"),
                    ]
                )
            self.assertEqual(0, status, stderr.getvalue())
            self.assertEqual(
                [("exit", secrets[1], secrets[2]), ("origin", secrets[0], None)],
                received,
            )

    def test_blank_password_keeps_key_auth_without_a_second_prompt(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            with (
                patch("builtins.input", side_effect=wizard_answers() + ["y"]),
                patch("getpass.getpass", return_value="") as password,
                patch.object(cli, "dns_preflight"),
                patch("cdn_xhttp.remote.deploy_server") as deploy,
                patch.object(
                    cli,
                    "check",
                    return_value={"origin": {"ok": True}, "cdn": {"ok": True}},
                ),
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                status = cli.main(
                    [
                        "--config",
                        str(base / "deployment.json"),
                        "--output",
                        str(base / "result"),
                    ]
                )
            self.assertEqual(0, status)
            self.assertEqual(1, password.call_count)
            self.assertIsNone(deploy.call_args.kwargs["password"])
            self.assertIsNone(deploy.call_args.kwargs["sudo_password"])

    def test_default_resume_uses_saved_ids_and_requests_password_again(self):
        value = config()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            target = base / "deployment.json"
            target.write_text(json.dumps(value), encoding="utf-8")
            original = target.read_bytes()
            with (
                patch("builtins.input", side_effect=["", "y"]),
                patch(
                    "getpass.getpass", return_value="example-resume-secret"
                ) as password,
                patch.object(cli, "wizard") as wizard,
                patch.object(cli, "dns_preflight"),
                patch("cdn_xhttp.remote.deploy_server") as deploy,
                patch.object(
                    cli,
                    "check",
                    return_value={"origin": {"ok": True}, "cdn": {"ok": True}},
                ),
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                status = cli.main(
                    [
                        "--config",
                        str(target),
                        "--output",
                        str(base / "result"),
                    ]
                )
            self.assertEqual(0, status)
            wizard.assert_not_called()
            self.assertEqual(1, password.call_count)
            self.assertEqual(value["uuids"], deploy.call_args.args[0]["uuids"])
            self.assertEqual(
                "example-resume-secret", deploy.call_args.kwargs["password"]
            )
            self.assertEqual(original, target.read_bytes())

    def test_existing_config_menu_retries_invalid_choice_and_can_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "deployment.json"
            target.write_text(json.dumps(config()), encoding="utf-8")
            original = target.read_bytes()
            with (
                patch("builtins.input", side_effect=["invalid", "3"]) as prompt,
                patch("getpass.getpass") as password,
                patch("cdn_xhttp.remote.deploy_server") as deploy,
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(0, cli.main(["--config", str(target)]))
            self.assertEqual(2, prompt.call_count)
            password.assert_not_called()
            deploy.assert_not_called()
            self.assertEqual(original, target.read_bytes())

    def test_new_settings_preserve_original_backup_before_installation(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            target = base / "deployment.json"
            previous = config()
            target.write_text(json.dumps(previous), encoding="utf-8")
            original = target.read_bytes()
            with (
                patch("builtins.input", side_effect=["2", *wizard_answers(), "n"]),
                patch("getpass.getpass", return_value="example-new-secret"),
                patch.object(cli, "dns_preflight"),
                patch("cdn_xhttp.remote.deploy_server") as deploy,
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(0, cli.main(["--config", str(target)]))
            deploy.assert_not_called()
            self.assertNotEqual(previous["uuids"], load(target)["uuids"])
            backups = [file for file in base.iterdir() if file != target]
            self.assertEqual(1, len(backups))
            self.assertEqual(original, backups[0].read_bytes())

    def test_interrupted_new_settings_leave_existing_configuration_intact(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            target = base / "deployment.json"
            target.write_text(json.dumps(config()), encoding="utf-8")
            original = target.read_bytes()
            with (
                patch("builtins.input", side_effect=["2", "n", KeyboardInterrupt()]),
                patch("getpass.getpass") as password,
                patch("cdn_xhttp.remote.deploy_server") as deploy,
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(130, cli.main(["--config", str(target)]))
            password.assert_not_called()
            deploy.assert_not_called()
            self.assertEqual(original, target.read_bytes())
            self.assertEqual([target], list(base.iterdir()))

    def test_y_deploys_both_servers_with_the_right_password_once(self):
        secrets = [
            "example-origin-secret",
            "example-exit-secret",
            "example-sudo-secret",
        ]
        received = []
        checks = {"origin": {"ok": True}, "cdn": {"ok": True}}
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            stdout, stderr = io.StringIO(), io.StringIO()

            def deploy_server(value, role, **kwargs):
                self.assertEqual(3, password.call_count)
                received.append((role, kwargs["password"], kwargs["sudo_password"]))

            with (
                patch(
                    "builtins.input", side_effect=wizard_answers(bridge=True) + ["y"]
                ),
                patch("getpass.getpass", side_effect=secrets) as password,
                patch.object(cli, "dns_preflight"),
                patch(
                    "cdn_xhttp.remote.deploy_server", side_effect=deploy_server
                ) as deploy,
                patch.object(cli, "check", return_value=checks),
                contextlib.redirect_stdout(stdout),
                contextlib.redirect_stderr(stderr),
            ):
                status = cli.main(
                    [
                        "wizard",
                        "--config",
                        str(base / "deployment.json"),
                        "--output",
                        str(base / "result"),
                    ]
                )
            self.assertEqual(0, status, stderr.getvalue())
            self.assertEqual(2, deploy.call_count)
            self.assertEqual(
                [("exit", secrets[1], secrets[2]), ("origin", secrets[0], None)],
                received,
            )
            exported = (
                (base / "result" / "vless.txt").read_text(encoding="utf-8").splitlines()
            )
            self.assertEqual(2, len(exported))
            text = stdout.getvalue() + stderr.getvalue()
            for file in base.rglob("*"):
                if file.is_file():
                    text += file.read_text(encoding="utf-8")
            for secret in secrets:
                self.assertNotIn(secret, text)

    def test_cancel_keeps_configuration_and_deploy_retry_preserves_uuids(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            target = base / "deployment.json"
            args = ["--config", str(target), "--output", str(base / "result")]
            with (
                patch("builtins.input", side_effect=wizard_answers() + ["n"]),
                patch("getpass.getpass", return_value="example-password"),
                patch.object(cli, "dns_preflight"),
                patch("cdn_xhttp.remote.deploy_server") as deploy,
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(0, cli.main(["wizard", *args]))
            deploy.assert_not_called()
            self.assertFalse((base / "result").exists())
            cancelled = load(target)
            checks = {"origin": {"ok": True}, "cdn": {"ok": True}}
            with (
                patch("builtins.input", side_effect=["y"]),
                patch("getpass.getpass", return_value="example-password") as password,
                patch.object(cli, "dns_preflight"),
                patch("cdn_xhttp.remote.deploy_server") as deploy,
                patch.object(cli, "check", return_value=checks),
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(0, cli.main(["deploy", *args]))
            self.assertEqual(1, password.call_count)
            self.assertEqual(cancelled["uuids"], deploy.call_args.args[0]["uuids"])
            self.assertEqual(cancelled, load(target))

    def test_installation_exception_does_not_print_credentials(self):
        secret = "example-password-must-not-appear"
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            stdout, stderr = io.StringIO(), io.StringIO()
            with (
                patch("builtins.input", side_effect=wizard_answers() + ["y"]),
                patch("getpass.getpass", return_value=secret),
                patch.object(cli, "dns_preflight"),
                patch(
                    "cdn_xhttp.remote.deploy_server",
                    side_effect=RuntimeError(f"connection failed: {secret}"),
                ),
                contextlib.redirect_stdout(stdout),
                contextlib.redirect_stderr(stderr),
            ):
                status = cli.main(
                    [
                        "wizard",
                        "--config",
                        str(base / "deployment.json"),
                        "--output",
                        str(base / "result"),
                    ]
                )
            self.assertEqual(1, status)
            self.assertIn("connection failed", stderr.getvalue())
            self.assertNotIn(secret, stdout.getvalue() + stderr.getvalue())
            self.assertNotIn(
                secret, (base / "deployment.json").read_text(encoding="utf-8")
            )


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
