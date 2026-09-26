"""Exercise the interactive and exported multiuser contracts without SSH."""

import contextlib
import io
import json
import os
import stat
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, unquote, urlsplit

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


def edge_result():
    return {
        "connect_address": "1.1.1.1",
        "endpoint_verified": True,
        "vless_tunnel_verified": True,
        "route": "ethernet",
        "checks": [{"ok": True}],
    }


def connection_answers(bridge=False):
    answers = wizard_answers(bridge)
    return answers[1:4] + answers[:1] + answers[4:]


class InstallationFlowTests(unittest.TestCase):
    def args(self, base, command="wizard"):
        return [
            command,
            "--config",
            str(base / "deployment.json"),
            "--output",
            str(base / "result"),
        ]

    def test_new_wizard_recovers_before_requesting_domains_or_creating_ids(self):
        value = config()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            events = []
            answers = iter(["192.0.2.10", "", "", "1"])

            def answer(prompt):
                events.append(prompt)
                return next(answers)

            def recovery(*args):
                self.assertEqual(3, len(events))
                self.assertEqual(1, password.call_count)
                return value

            with (
                patch("builtins.input", side_effect=answer),
                patch("getpass.getpass", return_value="example-secret") as password,
                patch.object(cli, "recover", side_effect=recovery),
                patch.object(cli, "check", return_value=edge_result()),
                patch("cdn_xhttp.remote.deploy_server") as deploy,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                status = cli.main(self.args(base))
            self.assertEqual(0, status)
            deploy.assert_not_called()
            self.assertEqual(value["uuids"], load(base / "deployment.json")["uuids"])
            self.assertFalse(any("Домен" in item for item in events))

    def test_new_bridge_collects_both_credentials_before_mutation_and_issues_verified_links(
        self,
    ):
        secrets = ["example-origin", "example-exit", "example-sudo"]
        received = []
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)

            def deploy_server(value, role, **kwargs):
                self.assertEqual(3, password.call_count)
                received.append((role, kwargs["password"], kwargs["sudo_password"]))

            output, errors = io.StringIO(), io.StringIO()
            with (
                patch("builtins.input", side_effect=connection_answers(True) + ["y"]),
                patch("getpass.getpass", side_effect=secrets) as password,
                patch.object(cli, "recover", return_value=None),
                patch.object(cli, "dns_preflight"),
                patch("cdn_xhttp.remote.deploy_server", side_effect=deploy_server),
                patch.object(cli, "check", return_value=edge_result()),
                contextlib.redirect_stdout(output),
                contextlib.redirect_stderr(errors),
            ):
                status = cli.main(self.args(base))
            self.assertEqual(0, status, errors.getvalue())
            self.assertEqual(
                [("exit", secrets[1], secrets[2]), ("origin", secrets[0], None)],
                received,
            )
            saved = load(base / "deployment.json")
            self.assertEqual("1.1.1.1", saved["connect_address"])
            check = json.loads(
                (base / "result" / "status.json").read_text(encoding="utf-8")
            )
            self.assertTrue(check["vless_tunnel_verified"])
            text = output.getvalue() + errors.getvalue()
            for path in base.rglob("*"):
                if path.is_file():
                    text += path.read_text(encoding="utf-8")
            for secret in secrets:
                self.assertNotIn(secret, text)

    def test_local_default_refreshes_server_state_without_reinstalling_or_rotating_uuid(
        self,
    ):
        value = config()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            target = base / "deployment.json"
            target.write_text(json.dumps(value), encoding="utf-8")
            with (
                patch("builtins.input", return_value=""),
                patch("getpass.getpass") as password,
                patch.object(cli, "recover", return_value=value) as recover,
                patch.object(cli, "check", return_value=edge_result()),
                patch("cdn_xhttp.remote.deploy_server") as deploy,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(0, cli.main(self.args(base)))
            password.assert_not_called()
            self.assertEqual(value["origin"], recover.call_args.args[0])
            deploy.assert_not_called()
            self.assertEqual(value["uuids"], load(target)["uuids"])

    def test_existing_menu_retries_invalid_choice_and_exits_without_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            target = base / "deployment.json"
            target.write_text(json.dumps(config()), encoding="utf-8")
            original = target.read_bytes()
            with (
                patch("builtins.input", side_effect=["invalid", "0"]) as prompt,
                patch("getpass.getpass") as password,
                patch.object(cli, "recover") as recover,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(0, cli.main(self.args(base)))
            self.assertEqual(2, prompt.call_count)
            password.assert_not_called()
            recover.assert_not_called()
            self.assertEqual(original, target.read_bytes())

    def test_count_changes_start_from_current_server_state_not_stale_local_copy(self):
        old = config()
        remote = config()
        remote["uuids"].append("1de7a7e8-c046-4fdc-b0ef-c03f83133882")
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            target = base / "deployment.json"
            target.write_text(json.dumps(old), encoding="utf-8")
            with (
                patch("builtins.input", side_effect=["2", "4", "y"]),
                patch("getpass.getpass", return_value=""),
                patch.object(cli, "recover", return_value=remote),
                patch.object(cli, "dns_preflight"),
                patch("cdn_xhttp.remote.deploy_server") as deploy,
                patch.object(cli, "check", return_value=edge_result()),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(0, cli.main(self.args(base)))
            submitted = deploy.call_args.args[0]
            self.assertEqual(remote["uuids"], submitted["uuids"][:3])
            self.assertEqual(4, len(submitted["uuids"]))
            self.assertEqual(remote, deploy.call_args.kwargs["previous"])
            self.assertEqual(submitted["uuids"], load(target)["uuids"])
            self.assertFalse(cli.pending_path(target).exists())

    def test_partial_bridge_failure_preserves_old_config_and_exact_uuid_for_retry(self):
        old = config()
        old["exit"] = {"host": "192.0.2.20", "user": "root", "port": 22}
        old["exit_domain"] = "exit.example.com"
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            target = base / "deployment.json"
            target.write_text(json.dumps(old), encoding="utf-8")
            original = target.read_bytes()
            with (
                patch("builtins.input", side_effect=["2", "3", "y"]),
                patch("getpass.getpass", return_value="example-secret"),
                patch.object(cli, "recover", return_value=old),
                patch.object(cli, "dns_preflight"),
                patch(
                    "cdn_xhttp.remote.deploy_server",
                    side_effect=[None, RuntimeError("failed example-secret")],
                ) as deploy,
                patch.object(cli, "check") as check,
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()) as errors,
            ):
                self.assertEqual(1, cli.main(self.args(base)))
            self.assertEqual(2, deploy.call_count)
            check.assert_not_called()
            self.assertNotIn("example-secret", errors.getvalue())
            self.assertEqual(original, target.read_bytes())
            pending, previous = cli.read_pending(target)
            self.assertEqual(old, previous)
            self.assertEqual(3, len(pending["uuids"]))
            with (
                patch("builtins.input", side_effect=["6", "y"]),
                patch("getpass.getpass", return_value=""),
                patch.object(cli, "recover") as recover,
                patch.object(cli, "dns_preflight"),
                patch("cdn_xhttp.remote.deploy_server") as resumed,
                patch.object(cli, "check", return_value=edge_result()),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(0, cli.main(self.args(base)))
            recover.assert_not_called()
            self.assertEqual(pending, resumed.call_args.args[0])
            self.assertEqual(pending["uuids"], load(target)["uuids"])
            self.assertFalse(cli.pending_path(target).exists())

    def test_new_installation_cancel_retains_config_for_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            with (
                patch("builtins.input", side_effect=connection_answers() + ["n"]),
                patch("getpass.getpass", return_value=""),
                patch.object(cli, "recover", return_value=None),
                patch("cdn_xhttp.remote.deploy_server") as deploy,
                patch.object(cli, "check") as check,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(0, cli.main(self.args(base)))
            deploy.assert_not_called()
            check.assert_not_called()
            self.assertEqual(2, len(load(base / "deployment.json")["uuids"]))
            self.assertFalse((base / "result").exists())

    def test_interrupted_new_wizard_does_not_replace_local_config(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            target = base / "deployment.json"
            target.write_text(json.dumps(config()), encoding="utf-8")
            original = target.read_bytes()
            with (
                patch("builtins.input", side_effect=["5", KeyboardInterrupt()]),
                patch("getpass.getpass") as password,
                patch("cdn_xhttp.remote.deploy_server") as deploy,
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(130, cli.main(self.args(base)))
            password.assert_not_called()
            deploy.assert_not_called()
            self.assertEqual(original, target.read_bytes())

    def test_legacy_recovery_requests_missing_email_and_preserves_known_client_preferences(
        self,
    ):
        local = config()
        local["profile"] = "original"
        raw = {
            **local,
            "_recovered_legacy": True,
            "email": "",
            "name": "CDN XHTTP",
            "profile": "fast",
        }
        with (
            patch("builtins.input", return_value=""),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            recovered = cli.complete_recovered(raw, local)
        self.assertEqual(local, recovered)
        self.assertIn("_recovered_legacy", raw)

    def test_count_reduction_requires_confirmation_and_never_rotates_bridge_uuid(self):
        value = config()
        with (
            patch("builtins.input", side_effect=["1", "n"]),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(value, cli.change_count(value))
        output = io.StringIO()
        with (
            patch("builtins.input", side_effect=["1", "y"]),
            contextlib.redirect_stdout(output),
        ):
            reduced = cli.change_count(value)
        self.assertEqual([value["uuid"]], reduced["uuids"])
        self.assertEqual(value["uuid"], reduced["uuid"])
        self.assertIn("отозваны", output.getvalue())
        self.assertEqual(2, len(value["uuids"]))

    def test_saved_config_preserves_bom_crlf_and_original_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "deployment.json"
            original = b"\xef\xbb\xbf" + (
                json.dumps(config(), indent=2) + "\n"
            ).replace("\n", "\r\n").encode("utf-8")
            target.write_bytes(original)
            changed = {**config(), "connect_address": "1.1.1.1"}
            with contextlib.redirect_stdout(io.StringIO()):
                cli.save_configuration(target, changed, backup=True)
            actual = target.read_bytes()
            self.assertTrue(actual.startswith(b"\xef\xbb\xbf"))
            self.assertEqual(actual.count(b"\n"), actual.count(b"\r\n"))
            self.assertEqual(
                original, target.with_name("deployment.backup-1.json").read_bytes()
            )
            self.assertEqual(changed, load(target))

    def test_pending_target_cannot_be_overwritten_by_a_different_update(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "deployment.json"
            old = config()
            desired = {**old, "name": "Updated"}
            cli.stage_pending(target, desired, old)
            before = cli.pending_path(target).read_bytes()
            with self.assertRaises(ValueError):
                cli.stage_pending(target, {**old, "name": "Other"}, old)
            self.assertEqual(before, cli.pending_path(target).read_bytes())

    def test_pending_only_recovered_installation_can_resume_from_default_entrypoint(
        self,
    ):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            target = base / "deployment.json"
            previous = config()
            desired = {**previous, "name": "Updated after recovery"}
            cli.stage_pending(target, desired, previous)
            self.assertFalse(target.exists())
            with (
                patch("builtins.input", side_effect=["6", "y"]),
                patch("getpass.getpass", return_value=""),
                patch.object(cli, "recover") as recover,
                patch.object(cli, "dns_preflight"),
                patch("cdn_xhttp.remote.deploy_server") as deploy,
                patch.object(cli, "check", return_value=edge_result()),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(0, cli.main(self.args(base)))
            recover.assert_not_called()
            self.assertEqual(desired, deploy.call_args.args[0])
            self.assertEqual(previous, deploy.call_args.kwargs["previous"])
            self.assertEqual(desired["uuids"], load(target)["uuids"])
            self.assertFalse(cli.pending_path(target).exists())

    def test_remote_success_is_saved_even_when_subsequent_edge_check_fails(self):
        from cdn_xhttp.edge import EdgeSelectionError

        old = config()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            target = base / "deployment.json"
            target.write_text(json.dumps(old), encoding="utf-8")
            with (
                patch("builtins.input", side_effect=["2", "3", "y"]),
                patch("getpass.getpass", return_value=""),
                patch.object(cli, "recover", return_value=old),
                patch.object(cli, "dns_preflight"),
                patch("cdn_xhttp.remote.deploy_server") as deploy,
                patch.object(
                    cli, "check", side_effect=EdgeSelectionError("unreachable")
                ),
                contextlib.redirect_stdout(io.StringIO()) as output,
            ):
                self.assertEqual(2, cli.main(self.args(base)))
            self.assertEqual(deploy.call_args.args[0], load(target))
            self.assertEqual(3, len(load(target)["uuids"]))
            self.assertFalse(cli.pending_path(target).exists())
            self.assertFalse((base / "result" / "vless.txt").exists())
            self.assertNotIn("vless://", output.getvalue())

    def test_editing_domains_clears_cached_edge_and_retains_all_client_identities(self):
        value = {**config(), "connect_address": "1.1.1.1"}
        answers = [
            "new-origin.example.com",
            "new-cdn.example.com",
            "New name",
            "",
            "original",
            "/new-path",
            "new_padding",
        ]
        with (
            patch("builtins.input", side_effect=answers),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            changed = cli.change_settings(value)
        self.assertNotIn("connect_address", changed)
        self.assertEqual(value["uuids"], changed["uuids"])
        self.assertEqual(value["origin"], changed["origin"])
        self.assertEqual("new-origin.example.com", changed["origin_domain"])
        self.assertEqual("new-cdn.example.com", changed["cdn_domain"])
        self.assertEqual("original", changed["profile"])
        self.assertEqual("/new-path", changed["path"])
        self.assertEqual("new_padding", changed["padding_key"])
        self.assertEqual("cdn.example.com", value["cdn_domain"])

    def test_legacy_bridge_recovery_requires_exit_ssh_details_and_keeps_exit_host(self):
        raw = {
            **config(),
            "_recovered_legacy": True,
            "email": "",
            "exit": {"host": "192.0.2.20", "user": "root", "port": 22},
            "exit_domain": "exit.example.com",
        }
        with (
            patch(
                "builtins.input", side_effect=["admin@example.com", "operator", "2222"]
            ),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            recovered = cli.complete_recovered(raw)
        self.assertEqual(
            {"host": "192.0.2.20", "user": "operator", "port": 2222}, recovered["exit"]
        )
        self.assertEqual(raw["uuids"], recovered["uuids"])

    def test_recovering_another_origin_keeps_the_previous_local_config_backup(self):
        previous = config()
        recovered = {
            **config(),
            "origin": {"host": "192.0.2.99", "user": "root", "port": 22},
        }
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            target = base / "deployment.json"
            target.write_text(json.dumps(previous), encoding="utf-8")
            original = target.read_bytes()
            with (
                patch("builtins.input", side_effect=["5", "192.0.2.99", "", "", "1"]),
                patch("getpass.getpass", return_value=""),
                patch.object(cli, "recover", return_value=recovered),
                patch.object(cli, "check", return_value=edge_result()),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(0, cli.main(self.args(base)))
            self.assertEqual(recovered["origin"], load(target)["origin"])
            self.assertEqual(
                original, target.with_name("deployment.backup-1.json").read_bytes()
            )


class ExportTests(unittest.TestCase):
    def test_revoked_server_uuids_are_never_reexported_from_a_stale_local_config(self):
        old = config()
        old["uuids"].append("1de7a7e8-c046-4fdc-b0ef-c03f83133882")
        old["connect_address"] = "1.1.1.1"
        current = config()
        current["uuids"] = current["uuids"][:1]
        for command in ("wizard", "link", "check", "repair-edge"):
            with (
                self.subTest(command=command),
                tempfile.TemporaryDirectory() as directory,
            ):
                base = Path(directory)
                target = base / "deployment.json"
                output = base / "result"
                target.write_text(json.dumps(old), encoding="utf-8")
                cli.write_connection(old, output, False)
                with (
                    patch("builtins.input", return_value="1"),
                    patch.object(cli, "recover", return_value=current),
                    patch.object(cli, "check", return_value=edge_result()) as check,
                    patch("cdn_xhttp.remote.deploy_server") as deploy,
                    contextlib.redirect_stdout(io.StringIO()),
                ):
                    self.assertEqual(
                        0,
                        cli.main(
                            [command, "--config", str(target), "--output", str(output)]
                        ),
                    )
                deploy.assert_not_called()
                self.assertEqual(current["uuids"], check.call_args.args[0]["uuids"])
                self.assertEqual(
                    old["connect_address"], check.call_args.args[0]["connect_address"]
                )
                links = (output / "vless.txt").read_text(encoding="utf-8").splitlines()
                self.assertEqual(
                    [current["uuid"]], [urlsplit(link).username for link in links]
                )
                self.assertEqual(current["uuids"], load(target)["uuids"])
                self.assertFalse(any((output / "clients").glob("client-*.json")))

    def test_missing_managed_server_state_prevents_link_export(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            target = base / "deployment.json"
            target.write_text(json.dumps(config()), encoding="utf-8")
            with (
                patch.object(cli, "recover", return_value=None),
                patch.object(cli, "check") as check,
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(
                    1,
                    cli.main(
                        [
                            "link",
                            "--config",
                            str(target),
                            "--output",
                            str(base / "result"),
                        ]
                    ),
                )
            check.assert_not_called()
            self.assertFalse((base / "result" / "vless.txt").exists())

    def test_failed_or_cancelled_ssh_refresh_invalidates_status_but_preserves_links(
        self,
    ):
        secret = "example-ssh-secret"
        for failure, expected_status in (
            (RuntimeError(f"SSH failed: {secret}"), 1),
            (KeyboardInterrupt(), 130),
        ):
            with (
                self.subTest(failure=type(failure).__name__),
                tempfile.TemporaryDirectory() as directory,
            ):
                base = Path(directory)
                target = base / "deployment.json"
                target.write_text(json.dumps(config()), encoding="utf-8")
                original = target.read_bytes()
                output = base / "result"
                cli.write_connection(config(), output, True, vless_verified=True)
                links = (output / "vless.txt").read_bytes()
                with (
                    patch("getpass.getpass", return_value=secret),
                    patch("cdn_xhttp.remote.recover_config", side_effect=failure),
                    patch.object(cli, "check") as check,
                    contextlib.redirect_stdout(io.StringIO()),
                    contextlib.redirect_stderr(io.StringIO()) as errors,
                ):
                    self.assertEqual(
                        expected_status,
                        cli.main(
                            ["link", "--config", str(target), "--output", str(output)]
                        ),
                    )
                check.assert_not_called()
                self.assertEqual(original, target.read_bytes())
                self.assertEqual(links, (output / "vless.txt").read_bytes())
                report = (output / "status.json").read_text(encoding="utf-8")
                status = json.loads(report)
                self.assertFalse(status["endpoint_verified"])
                self.assertFalse(status["vless_tunnel_verified"])
                self.assertNotIn(secret, report + errors.getvalue())

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

    def test_link_command_refreshes_server_copy_then_checks_tunnel_without_reinstalling(
        self,
    ):
        value = config()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            deployment = base / "deployment.json"
            deployment.write_text(json.dumps(value), encoding="utf-8")
            output = io.StringIO()
            with (
                patch("getpass.getpass") as password,
                patch.object(cli, "recover", return_value=value) as recover,
                patch("cdn_xhttp.remote.deploy_server") as deploy,
                patch.object(cli, "check", return_value=edge_result()) as check,
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
            self.assertEqual(value["origin"], recover.call_args.args[0])
            deploy.assert_not_called()
            check.assert_called_once_with(value)
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

    def test_check_delegates_to_full_tunnel_selection(self):
        with (
            patch("cdn_xhttp.edge.select_edge", return_value=edge_result()) as select,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            checks = cli.check(config())
        self.assertEqual(edge_result(), checks)
        self.assertEqual(config(), select.call_args.args[0])

    def test_failed_tunnel_never_issues_new_links_or_replaces_previous_config(self):
        from cdn_xhttp.edge import EdgeSelectionError

        for command in ("link", "check", "repair-edge"):
            with (
                self.subTest(command=command),
                tempfile.TemporaryDirectory() as directory,
            ):
                base = Path(directory)
                target = base / "deployment.json"
                target.write_text(json.dumps(config()), encoding="utf-8")
                original = target.read_bytes()
                result = base / "result"
                result.mkdir()
                (result / "vless.txt").write_text(
                    "previous verified links", encoding="utf-8"
                )
                output = io.StringIO()
                with (
                    patch.object(cli, "recover", return_value=config()),
                    patch.object(
                        cli, "check", side_effect=EdgeSelectionError("No working edge")
                    ),
                    patch("cdn_xhttp.remote.deploy_server") as deploy,
                    contextlib.redirect_stdout(output),
                ):
                    status = cli.main(
                        [command, "--config", str(target), "--output", str(result)]
                    )
                self.assertEqual(2, status)
                deploy.assert_not_called()
                self.assertEqual(original, target.read_bytes())
                self.assertEqual(
                    "previous verified links",
                    (result / "vless.txt").read_text(encoding="utf-8"),
                )
                self.assertNotIn("vless://", output.getvalue())
                self.assertFalse((result / "client.json").exists())
                self.assertFalse(
                    json.loads((result / "status.json").read_text(encoding="utf-8"))[
                        "vless_tunnel_verified"
                    ]
                )

    def test_endpoint_success_without_tunnel_proof_does_not_publish(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            target = base / "deployment.json"
            target.write_text(json.dumps(config()), encoding="utf-8")
            with (
                patch.object(cli, "recover", return_value=config()),
                patch.object(
                    cli,
                    "check",
                    return_value={**edge_result(), "vless_tunnel_verified": False},
                ),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(
                    2,
                    cli.main(
                        [
                            "link",
                            "--config",
                            str(target),
                            "--output",
                            str(base / "result"),
                        ]
                    ),
                )
            self.assertFalse((base / "result" / "vless.txt").exists())

    def test_offline_plan_does_not_call_edge_selector_or_ssh(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            target = base / "deployment.json"
            target.write_text(json.dumps(config()), encoding="utf-8")
            with (
                patch.object(cli, "check") as check,
                patch.object(cli, "recover") as recover,
                contextlib.redirect_stdout(io.StringIO()) as output,
            ):
                self.assertEqual(
                    0,
                    cli.main(
                        [
                            "plan",
                            "--config",
                            str(target),
                            "--output",
                            str(base / "preview"),
                        ]
                    ),
                )
            check.assert_not_called()
            recover.assert_not_called()
            self.assertIn("Непроверенный", output.getvalue())
            status = json.loads(
                (base / "preview" / "status.json").read_text(encoding="utf-8")
            )
            self.assertFalse(status["vless_tunnel_verified"])


if __name__ == "__main__":
    unittest.main()
