"""Tests of the risky parts: page downloads, settings, sign-in, mail, a check without Deeper's rules.
No network, no Deeper, no mail server: `python3 -m unittest discover tests`."""
import base64
import http.client
import importlib.util
import json
import os
import socket
import sys
import tempfile
import threading
import unittest
from unittest import mock

DATA = tempfile.mkdtemp(prefix="dw-test-")
os.environ.update(DATA_DIR=DATA, DEEPER_HOST="127.0.0.1", DEEPER_PASS="", SMTP_ENABLED="false", WEB_PASSWORD="")
_spec = importlib.util.spec_from_file_location(
    "dw", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "deeper_watchdog.py"))
dw = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dw)


def body_of(server_bytes):
    a, b = socket.socketpair()
    a.sendall(server_bytes)
    a.close()
    try:
        return dw.read_body(b, b"", 64 * 1024, 3)
    finally:
        b.close()


class ReadBody(unittest.TestCase):
    HEAD = b"HTTP/1.1 200 OK\r\nContent-Length: 50000\r\n\r\n"

    def test_cut_short_is_a_stall(self):
        stall = body_of(self.HEAD + b"x" * 1000)
        self.assertIsInstance(stall, dw.Stall)
        self.assertTrue(stall.sized)

    def test_whole_page(self):
        self.assertIsNone(body_of(self.HEAD + b"x" * 50000))

    def test_unsized_page_ends_with_the_connection(self):
        self.assertIsNone(body_of(b"HTTP/1.1 200 OK\r\n\r\n" + b"x" * 1000))

    def test_chunked_end(self):
        self.assertIsNone(body_of(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n"))


class Settings(unittest.TestCase):
    def test_bounds(self):
        self.assertEqual(dw.parse_setting("MAX_LATENCY_MS", "100"), 100)
        with self.assertRaises(ValueError):
            dw.parse_setting("MAX_LATENCY_MS", "99")
        with self.assertRaises(ValueError):
            dw.parse_setting("CHECK_METHOD", "ping")
        self.assertIs(dw.parse_setting("SMTP_ENABLED", "yes"), True)


class LoginLimit(unittest.TestCase):
    def setUp(self):
        dw.LOGIN_FAILS.clear()
        dw.set_password("right-password")

    def test_blocked_after_wrong_passwords(self):
        for _ in range(dw.LOGIN_MAX_FAILS):
            self.assertFalse(dw.checked_password("10.0.0.9", "wrong"))
        # Even the right password waits now, and other addresses don't
        self.assertFalse(dw.checked_password("10.0.0.9", "right-password"))
        self.assertTrue(dw.checked_password("10.0.0.8", "right-password"))

    def test_block_ends(self):
        for _ in range(dw.LOGIN_MAX_FAILS):
            dw.checked_password("10.0.0.7", "wrong")
        with mock.patch.object(dw.time, "time", return_value=dw.time.time() + dw.LOGIN_LOCK_SECONDS + 1):
            self.assertTrue(dw.checked_password("10.0.0.7", "right-password"))


class WebServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        dw.LOGIN_FAILS.clear()
        dw.set_password("right-password")
        cls.server = dw.ThreadingHTTPServer(("127.0.0.1", 0), dw.SettingsHandler)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def post(self, path, body, ctype="application/json", password="right-password"):
        con = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=10)
        auth = base64.b64encode(f"x:{password}".encode()).decode()
        con.request("POST", path, json.dumps(body), {"Content-Type": ctype, "Authorization": "Basic " + auth})
        r = con.getresponse()
        data = r.read()
        con.close()
        return r.status, data

    def test_json_type_not_just_mentioned(self):
        status, _ = self.post("/api/logout", {}, ctype="text/plain; x=application/json")
        self.assertEqual(status, 415)

    def test_password_change_needs_current_password(self):
        status, _ = self.post("/api/password", {"password": "new-password"})
        self.assertEqual(status, 403)
        status, _ = self.post("/api/password", {"old_password": "right-password", "password": "new-password"})
        self.assertEqual(status, 200)
        self.assertTrue(dw.password_ok("new-password"))
        dw.set_password("right-password")


class Mail(unittest.TestCase):
    def test_certificate_is_checked(self):
        settings = dict(SMTP_ENABLED=True, SMTP_HOST="smtp.example.com", SMTP_PORT=465, SMTP_USE_SSL=True,
                        SMTP_USER="u", SMTP_PASS="p", SMTP_FROM="u@example.com", SMTP_TO="me@example.com")
        with mock.patch.multiple(dw, **settings), mock.patch.object(dw.smtplib, "SMTP_SSL") as smtp:
            self.assertTrue(dw.send_email_notification("s", "b"))
        ctx = smtp.call_args.kwargs["context"]
        self.assertEqual(ctx.verify_mode, dw.ssl.CERT_REQUIRED)
        self.assertTrue(ctx.check_hostname)
        settings.update(SMTP_PORT=587, SMTP_USE_SSL=False)
        with mock.patch.multiple(dw, **settings), mock.patch.object(dw.smtplib, "SMTP") as smtp:
            self.assertTrue(dw.send_email_notification("s", "b"))
        ctx = smtp.return_value.starttls.call_args.kwargs["context"]
        self.assertEqual(ctx.verify_mode, dw.ssl.CERT_REQUIRED)


class FakeClient:
    """Deeper that lists a tunnel with nodes but fails to give its Smart Route rules."""

    def list_tunnels(self):
        return [{"tunnelCode": "NL", "activeNum": 3, "activeIp": "1.2.3.4"}]

    def get_routed_domains(self, strict=False):
        if strict:
            raise RuntimeError("timeout")
        return {}

    def get_whitelist_domains(self):
        raise RuntimeError("timeout")


class CheckWithoutRules(unittest.TestCase):
    def test_failures_are_kept(self):
        state = os.path.join(DATA, "fails-test.json")
        with open(state, "w") as f:
            json.dump({"NL": 1}, f)
        dw.GREEN_SINCE.pop("NL", None)
        dw.run_watchdog_iteration(FakeClient(), state_file=state)
        with open(state) as f:
            self.assertEqual(json.load(f), {"NL": 1})
        self.assertNotIn("NL", dw.GREEN_SINCE)
        self.assertIn("Smart Route", dw.STATUS["error"])


if __name__ == "__main__":
    unittest.main()
