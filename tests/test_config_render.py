"""Safety and interoperability contracts of the generated deployment artifacts."""

import ast
import copy
import json
import re
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from cdn_xhttp.config import domain, load, validate, write_private
from cdn_xhttp.health import HEALTH_SERVER_SOURCE
from cdn_xhttp.render import (
    client_xray,
    exit_xray,
    extra,
    nginx_config,
    origin_xray,
    vless_uri,
)


def spec(**changes):
    value = {
        "origin": {"host": "192.0.2.10", "user": "root", "port": 22},
        "origin_domain": "origin.example.com",
        "cdn_domain": "cdn.example.com",
        "email": "admin@example.com",
        "uuid": "74c60a43-dd09-48e8-aad1-9ab48c7fdd71",
    }
    value.update(changes)
    return value


class ValidationTests(unittest.TestCase):
    def test_defaults_are_one_server_and_do_not_store_credentials(self):
        config = validate(spec())
        self.assertIsNone(config["exit"])
        self.assertIsNone(config["exit_domain"])
        self.assertEqual("fast", config["profile"])
        self.assertEqual("dc", config["padding_key"])
        self.assertEqual("CDN XHTTP", config["name"])
        self.assertEqual([config["uuid"]], config["uuids"])
        for value in (
            spec(password="secret"),
            spec(origin={"host": "192.0.2.10", "password": "secret"}),
        ):
            with self.assertRaises(ValueError):
                validate(value)

    def test_nginx_and_shell_metacharacters_are_rejected(self):
        bad_values = {
            "origin_domain": [
                "origin.example.com;id",
                "origin.example.com\ninclude /tmp/bad;",
                "$(id).example.com",
                "https://origin.example.com",
            ],
            "cdn_domain": [
                "cdn.example.com#fragment",
                "cdn.example.com/path",
                "cdn.example.com:443",
                "cdn.example.com\r\nX: bad",
            ],
            "path": [
                "/api; return 200;",
                "/api\n}",
                "/$(id)",
                "/api?arg=1",
                "/api#x",
                "/cdn-check",
                "/../../etc/passwd",
            ],
            "padding_key": ["dc;id", "dc\nX: bad", "$(id)", "a b", "x" * 33],
            "uuid": ["74c60a43-dd09-48e8-aad1-9ab48c7fdd71;id", "$(id)"],
            "xray_version": ["26.5.9;id", "$(id)", "latest"],
            "email": ["admin@example.com;id", "admin@example.com\n--hook=x"],
        }
        for field, values in bad_values.items():
            for value in values:
                with (
                    self.subTest(field=field, value=value),
                    self.assertRaises(ValueError),
                ):
                    validate(spec(**{field: value}))

    def test_ssh_target_cannot_inject_options_or_shell_commands(self):
        for fields in (
            {"host": "192.0.2.10;id"},
            {"host": "-oProxyCommand=id"},
            {"user": "root;id"},
            {"user": "root\nX"},
            {"user": "-root"},
            {"port": "22;id"},
            {"port": True},
            {"port": 0},
            {"port": 65536},
        ):
            value = spec()
            value["origin"].update(fields)
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                validate(value)

    def test_domains_and_both_servers_must_be_distinct(self):
        for value in (
            spec(cdn_domain="origin.example.com"),
            spec(exit={"host": "192.0.2.10"}, exit_domain="exit.example.com"),
            spec(exit={"host": "192.0.2.20"}, exit_domain="origin.example.com"),
            spec(exit={"host": "192.0.2.20"}, exit_domain="cdn.example.com"),
            spec(exit_domain="exit.example.com"),
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate(value)

    def test_domain_normalization_and_ip_rejection(self):
        self.assertEqual("cdn.example.com", domain("CDN.Example.com."))
        self.assertEqual("xn--e1afmkfd.xn--p1ai", domain("пример.рф"))
        for value in (
            "192.0.2.10",
            "localhost",
            "-cdn.example.com",
            "cdn..example.com",
        ):
            with self.assertRaises(ValueError):
                domain(value)

    def test_edge_override_accepts_only_public_ip_and_leaves_domain_contract_intact(
        self,
    ):
        for address in ("1.1.1.1", "2a02:6b8::1"):
            value = validate(spec(connect_address=address))
            self.assertEqual(address, value["connect_address"])
            self.assertEqual("cdn.example.com", value["cdn_domain"])
        for address in (
            None,
            "",
            "cdn.example.com",
            "https://1.1.1.1",
            "127.0.0.1",
            "10.0.0.1",
            "192.0.2.1",
            "224.0.0.1",
            "::1",
            "fe80::1",
            "ff02::1",
            "2a02:6b8::1%eth0",
        ):
            with self.subTest(address=address), self.assertRaises(ValueError):
                validate(spec(connect_address=address))

    def test_atomic_private_write_does_not_truncate_old_file_if_replace_fails(self):
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "vless.txt"
            target.write_text("old", encoding="utf-8")
            with (
                patch("os.replace", side_effect=OSError("disk error")),
                self.assertRaises(OSError),
            ):
                write_private(target, "new")
            self.assertEqual("old", target.read_text(encoding="utf-8"))
            self.assertEqual([target], list(Path(directory).iterdir()))

    def test_load_handles_utf8_bom_without_modifying_input(self):
        original = spec()
        before = copy.deepcopy(original)
        validate(original)
        self.assertEqual(before, original)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps(original), encoding="utf-8-sig")
            self.assertEqual(validate(original), load(path))

    def test_multiuser_uuid_validation_and_legacy_primary_contract(self):
        first = spec()["uuid"]
        second = "6b352b91-d2ac-43f9-9ae3-de06673b75f2"
        config = validate(spec(uuids=[first, second.upper()]))
        self.assertEqual([first, second], config["uuids"])
        self.assertEqual(first, config["uuid"])
        self.assertEqual(
            config, validate(config), "Revalidation must preserve every client identity"
        )
        without_primary = spec(uuids=[first, second])
        del without_primary["uuid"]
        self.assertEqual(first, validate(without_primary)["uuid"])
        for values in (
            [],
            [first, first.upper()],
            [first, None],
            "not-a-list",
            [first] * 1001,
        ):
            with (
                self.subTest(values_type=type(values).__name__),
                self.assertRaises(ValueError),
            ):
                validate(spec(uuids=values))
        with self.assertRaises(ValueError):
            validate(spec(uuids=[second]))

    def test_names_allow_unicode_and_uri_symbols_but_reject_controls(self):
        label = "Европа / Дом #1 & семья 🚀"
        self.assertEqual(label, validate(spec(name=label))["name"])
        for name in (
            "",
            "   ",
            "x" * 81,
            "one\ntwo",
            "one\r\ntwo",
            "tab\tname",
            "hidden\u202ename",
            "line\u2028name",
            None,
        ):
            with self.subTest(name=repr(name)), self.assertRaises(ValueError):
                validate(spec(name=name))


class RenderTests(unittest.TestCase):
    def test_edge_changes_only_connect_target_and_brackets_ipv6_in_uri(self):
        baseline = validate(spec())
        for address in ("1.1.1.1", "2a02:6b8::1"):
            value = validate(spec(connect_address=address))
            outbound = client_xray(value)["outbounds"][0]
            self.assertEqual(address, outbound["settings"]["vnext"][0]["address"])
            self.assertEqual(
                client_xray(baseline)["outbounds"][0]["streamSettings"],
                outbound["streamSettings"],
            )
            uri = urlsplit(vless_uri(value))
            self.assertEqual((address, 443), (uri.hostname, uri.port))
            params = parse_qs(uri.query)
            self.assertEqual(["cdn.example.com"], params["sni"])
            self.assertEqual(["cdn.example.com"], params["host"])
            self.assertEqual(origin_xray(baseline), origin_xray(value))

    def test_multiuser_links_select_distinct_authorized_identities(self):
        identities = [
            spec()["uuid"],
            "6b352b91-d2ac-43f9-9ae3-de06673b75f2",
            "1de7a7e8-c046-4fdc-b0ef-c03f83133882",
        ]
        value = validate(
            spec(
                uuids=identities,
                name="Европа / Дом #1 & семья 🚀",
                exit={"host": "192.0.2.20"},
                exit_domain="exit.example.com",
            )
        )
        origin = origin_xray(value)
        self.assertEqual(
            identities,
            [user["id"] for user in origin["inbounds"][0]["settings"]["users"]],
        )
        exit_users = exit_xray(value)["inbounds"][0]["settings"]["users"]
        self.assertEqual(identities, [user["id"] for user in exit_users])
        self.assertTrue(all(user["flow"] == "xtls-rprx-vision" for user in exit_users))
        self.assertEqual(
            identities[0],
            origin["outbounds"][0]["settings"]["vnext"][0]["users"][0]["id"],
        )
        for index, identity in enumerate(identities):
            uri = urlsplit(vless_uri(value, index))
            self.assertEqual(identity, uri.username)
            self.assertEqual(f"{value['name']} {index + 1}", unquote(uri.fragment))
            self.assertEqual(
                1,
                vless_uri(value, index).count("#"),
                "Name delimiters must be percent-encoded",
            )
            client = client_xray(value, index)
            users = client["outbounds"][0]["settings"]["vnext"][0]["users"]
            self.assertEqual([{"id": identity, "encryption": "none"}], users)
            self.assertEqual(extra(value), json.loads(parse_qs(uri.query)["extra"][0]))
        for bad_index in (-1, 3, True, "1"):
            for renderer in (vless_uri, client_xray):
                with (
                    self.subTest(index=bad_index, renderer=renderer.__name__),
                    self.assertRaises(ValueError),
                ):
                    renderer(value, bad_index)

    def test_single_link_uses_exact_name_without_number(self):
        value = validate(spec(name="Дом #1 / EU"))
        self.assertEqual(value["name"], unquote(urlsplit(vless_uri(value)).fragment))

    def test_single_server_exits_directly_and_keeps_xray_private(self):
        config = origin_xray(validate(spec()))
        self.assertEqual(
            [{"tag": "internet", "protocol": "freedom"}], config["outbounds"]
        )
        inbound = config["inbounds"][0]
        self.assertEqual(("127.0.0.1", 8003), (inbound["listen"], inbound["port"]))
        self.assertEqual("xhttp", inbound["streamSettings"]["network"])
        self.assertEqual("none", inbound["streamSettings"]["security"])
        self.assertNotIn("flow", inbound["settings"]["users"][0])

    def test_two_servers_have_only_the_authenticated_exit_route(self):
        value = validate(
            spec(exit={"host": "192.0.2.20"}, exit_domain="exit.example.com")
        )
        outbounds = origin_xray(value)["outbounds"]
        self.assertEqual(
            1, len(outbounds), "No direct fallback may bypass the selected exit"
        )
        outbound = outbounds[0]
        self.assertEqual("vless", outbound["protocol"])
        target = outbound["settings"]["vnext"][0]
        self.assertEqual(("192.0.2.20", 10443), (target["address"], target["port"]))
        self.assertEqual("xtls-rprx-vision", target["users"][0]["flow"])
        tls = outbound["streamSettings"]["tlsSettings"]
        self.assertEqual("exit.example.com", tls["serverName"])
        self.assertFalse(tls["allowInsecure"])
        exit_inbound = exit_xray(value)["inbounds"][0]
        self.assertEqual(value["uuid"], exit_inbound["settings"]["users"][0]["id"])
        self.assertEqual("tls", exit_inbound["streamSettings"]["security"])

    def test_ipv6_exit_listens_on_ipv6_when_it_is_accepted(self):
        value = validate(
            spec(
                origin={"host": "2001:db8::10"},
                exit={"host": "2001:db8::20"},
                exit_domain="exit.example.com",
            )
        )
        self.assertIn(exit_xray(value)["inbounds"][0]["listen"], {"::", "2001:db8::20"})

    def test_mixed_address_families_are_rejected_before_deploy(self):
        with self.assertRaises(ValueError):
            validate(
                spec(exit={"host": "2001:db8::20"}, exit_domain="exit.example.com")
            )

    def test_share_uri_extra_round_trip_and_cdn_tls_identity(self):
        value = validate(spec(path="/api-custom/upload", padding_key="pad_42"))
        uri = urlsplit(vless_uri(value))
        self.assertEqual("vless", uri.scheme)
        self.assertEqual(value["uuid"], uri.username)
        self.assertEqual((value["cdn_domain"], 443), (uri.hostname, uri.port))
        query = parse_qs(uri.query, strict_parsing=True)
        self.assertEqual(extra(value), json.loads(query["extra"][0]))
        self.assertEqual([value["path"]], query["path"])
        self.assertEqual(["tls"], query["security"])
        self.assertEqual(["xhttp"], query["type"])
        self.assertEqual([value["cdn_domain"]], query["sni"])
        self.assertEqual([value["cdn_domain"]], query["host"])
        self.assertNotIn("flow", query)
        self.assertNotIn("allowInsecure", query)

    def test_client_has_no_vision_flow_and_matches_share_extra(self):
        value = validate(spec())
        client = client_xray(value)
        self.assertEqual("127.0.0.1", client["inbounds"][0]["listen"])
        outbound = client["outbounds"][0]
        self.assertNotIn("flow", outbound["settings"]["vnext"][0]["users"][0])
        settings = outbound["streamSettings"]
        self.assertEqual(value["cdn_domain"], settings["tlsSettings"]["serverName"])
        self.assertFalse(settings["tlsSettings"]["allowInsecure"])
        self.assertEqual(extra(value), settings["xhttpSettings"]["extra"])

    def test_fast_profile_changes_only_interval_and_avoids_zero_default_trap(self):
        original = extra(validate(spec(profile="original")))
        fast = extra(validate(spec(profile="fast")))
        self.assertEqual(30, original["scMinPostsIntervalMs"])
        self.assertGreater(
            fast["scMinPostsIntervalMs"], 0, "Xray treats zero as its default interval"
        )
        self.assertLess(fast["scMinPostsIntervalMs"], original["scMinPostsIntervalMs"])
        self.assertEqual(1000000, fast["scMaxEachPostBytes"])
        self.assertEqual(30, fast["scMaxBufferedPosts"])
        self.assertEqual(
            {
                key: val
                for key, val in original.items()
                if key != "scMinPostsIntervalMs"
            },
            {key: val for key, val in fast.items() if key != "scMinPostsIntervalMs"},
        )
        with self.assertRaises(ValueError):
            validate(spec(profile=0))

    def test_options_and_padding_are_consistent_at_both_ends(self):
        value = validate(spec(padding_key="pad42"))
        client_extra = extra(value)
        server_extra = origin_xray(value)["inbounds"][0]["streamSettings"][
            "xhttpSettings"
        ]
        self.assertEqual("OPTIONS", client_extra["uplinkHTTPMethod"])
        expected = {
            "mode": "packet-up",
            "xPaddingObfsMode": True,
            "xPaddingKey": "pad42",
            "xPaddingHeader": "X-Cache",
            "xPaddingMethod": "tokenish",
            "xPaddingPlacement": "queryInHeader",
        }
        for key, wanted in expected.items():
            self.assertEqual(wanted, client_extra[key], key)
            self.assertEqual(wanted, server_extra[key], key)

    def test_nginx_converts_options_only_on_xhttp_and_avoids_buffering(self):
        value = validate(spec())
        rendered = nginx_config(value)
        self.assertIn("OPTIONS POST;", rendered)
        xhttp = re.search(r"location /api-test \{(.*?)\n    \}", rendered, re.S).group(
            1
        )
        self.assertIn("proxy_method $cdn_xhttp_proxy_method;", xhttp)
        self.assertIn("proxy_buffering off;", xhttp)
        self.assertIn("proxy_request_buffering off;", xhttp)
        self.assertIn("proxy_pass_request_headers on;", xhttp)
        health = re.search(
            r"location = /cdn-check \{(.*?)\n    \}", rendered, re.S
        ).group(1)
        self.assertNotIn("proxy_method", health)
        self.assertIn("proxy_request_buffering on;", health)
        self.assertIn("127.0.0.1:8004", health)
        self.assertIn("large_client_header_buffers 8 128k;", rendered)
        self.assertIn("gzip off;", rendered)

    def test_acme_bootstrap_does_not_require_unissued_tls_files(self):
        rendered = nginx_config(validate(spec()), tls=False)
        self.assertIn("/.well-known/acme-challenge/", rendered)
        self.assertNotIn("ssl_certificate", rendered)
        self.assertNotIn("listen 443", rendered)


class SyntaxCompatibilityTests(unittest.TestCase):
    def test_project_sources_and_embedded_health_parse_as_python310(self):
        root = Path(__file__).resolve().parents[1]
        for path in (root / "cdn_xhttp").glob("*.py"):
            with self.subTest(file=path.name):
                ast.parse(
                    path.read_text(encoding="utf-8-sig"),
                    filename=str(path),
                    feature_version=(3, 10),
                )
        ast.parse(
            HEALTH_SERVER_SOURCE, filename="remote-health.py", feature_version=(3, 10)
        )


if __name__ == "__main__":
    unittest.main()
