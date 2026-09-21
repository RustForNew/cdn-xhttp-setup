import hashlib
import http.client
import io
import json
import ssl
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest.mock import patch

from cdn_xhttp.health import HEALTH_SERVER_SOURCE, check_endpoint


class FakeConnection:
    requests = []
    status = 200
    mutate = staticmethod(lambda value: value)
    headers = {
        "X-CDN-Origin": "ok",
        "Cache-Control": "no-store",
        "Content-Type": "application/json",
    }

    def __init__(self, host, port, *, timeout, context):
        assert port == 443
        assert context.check_hostname
        assert context.verify_mode == ssl.CERT_REQUIRED
        self.host = host
        self.closed = False

    def request(self, method, path, body, headers):
        self.body = body
        self.requests.append((method, path, body, headers))

    def getresponse(self):
        self.raw = io.BytesIO(
            json.dumps(
                self.mutate(
                    {
                        "method": "OPTIONS",
                        "length": len(self.body),
                        "sha256": hashlib.sha256(self.body).hexdigest(),
                    }
                )
            ).encode()
        )
        return self

    def getheader(self, name):
        return self.headers.get(name)

    def read(self, length):
        return self.raw.read(length)

    def close(self):
        self.closed = True


class EndpointTests(unittest.TestCase):
    def setUp(self):
        FakeConnection.requests = []
        FakeConnection.status = 200
        FakeConnection.mutate = staticmethod(lambda value: value)

    @patch("cdn_xhttp.health.http.client.HTTPSConnection", FakeConnection)
    def test_two_fresh_payloads_and_validated_tls(self):
        result = check_endpoint("cdn.example.com")
        self.assertTrue(result["ok"], result)
        self.assertEqual([4, 65536], [len(item[2]) for item in FakeConnection.requests])
        self.assertNotEqual(
            FakeConnection.requests[0][1], FakeConnection.requests[1][1]
        )
        self.assertTrue(all(item[0] == "OPTIONS" for item in FakeConnection.requests))
        json.dumps(result)

    @patch("cdn_xhttp.health.http.client.HTTPSConnection", FakeConnection)
    def test_a_preserved_content_length_does_not_hide_body_loss(self):
        FakeConnection.mutate = staticmethod(
            lambda value: dict(value, sha256=hashlib.sha256(b"").hexdigest())
        )
        result = check_endpoint("cdn.example.com")
        self.assertFalse(result["ok"])
        self.assertIn("SHA-256 mismatch", result["errors"][0])

    @patch("cdn_xhttp.health.http.client.HTTPSConnection", FakeConnection)
    def test_redirects_are_rejected_without_following_them(self):
        FakeConnection.status = 302
        result = check_endpoint("cdn.example.com")
        self.assertFalse(result["ok"])
        self.assertEqual(1, len(FakeConnection.requests))
        self.assertIn("Redirect rejected", result["errors"][0])

    @patch("cdn_xhttp.health.http.client.HTTPSConnection", FakeConnection)
    def test_wrong_method_is_detected(self):
        FakeConnection.mutate = staticmethod(lambda value: dict(value, method="POST"))
        self.assertFalse(check_endpoint("cdn.example.com")["ok"])

    def test_invalid_domain_cannot_change_request_destination(self):
        for domain in (
            "https://example.com",
            "example.com:443",
            "example.com/path",
            "a.com\r\nX: x",
        ):
            self.assertFalse(check_endpoint(domain)["ok"], domain)

    def test_body_size_is_bounded(self):
        self.assertFalse(check_endpoint("cdn.example.com", max_bytes=1048577)["ok"])
        self.assertFalse(check_endpoint("cdn.example.com", max_bytes=True)["ok"])

    @patch("cdn_xhttp.health.http.client.HTTPSConnection")
    def test_certificate_validation_failure_is_reported(self, connection):
        connection.return_value.request.side_effect = ssl.SSLCertVerificationError(
            "wrong hostname"
        )
        result = check_endpoint("cdn.example.com")
        self.assertFalse(result["ok"])
        self.assertIn("SSLCertVerificationError", result["errors"][0])
        connection.return_value.close.assert_called_once()


class HealthServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        namespace = {"__name__": "health_server_test"}
        exec(compile(HEALTH_SERVER_SOURCE, "health_server.py", "exec"), namespace)
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), namespace["HealthHandler"])
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection(*self.server.server_address, timeout=2)
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            return (
                response.status,
                dict(response.getheaders()),
                json.loads(response.read()),
            )
        finally:
            connection.close()

    def test_server_reports_actual_binary_body(self):
        body = bytes(range(256)) * 256
        status, headers, data = self.request("OPTIONS", "/cdn-check?nonce=test", body)
        self.assertEqual(200, status)
        self.assertEqual(
            {
                "method": "OPTIONS",
                "length": 65536,
                "sha256": hashlib.sha256(body).hexdigest(),
            },
            data,
        )
        self.assertEqual("no-store", headers["Cache-Control"])
        self.assertEqual("ok", headers["X-CDN-Origin"])

    def test_server_restricts_path_method_and_size(self):
        self.assertEqual(404, self.request("OPTIONS", "/another-path")[0])
        self.assertEqual(405, self.request("POST", "/cdn-check")[0])
        self.assertEqual(
            413,
            self.request(
                "OPTIONS", "/cdn-check", headers={"Content-Length": "1048577"}
            )[0],
        )

    def test_server_rejects_missing_and_ambiguous_body_lengths(self):
        self.assertEqual(411, self.request("OPTIONS", "/cdn-check")[0])
        self.assertEqual(
            400,
            self.request(
                # This rejects the framing from headers alone. Sending a body
                # after the server closes would race a TCP reset on Windows.
                "OPTIONS",
                "/cdn-check",
                headers={"Transfer-Encoding": "chunked"},
            )[0],
        )


if __name__ == "__main__":
    unittest.main()
