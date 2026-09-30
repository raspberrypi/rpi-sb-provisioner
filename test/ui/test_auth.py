"""Signing in, sessions, and requests the UI must refuse."""
import http.client
import os
import tempfile
import time
import unittest
import urllib.parse

from ui.harness.browser import Browser, OUTSIDER, OUTSIDER_PASSWORD
from ui.harness.case import UITest

FAILED = "Sign-in failed. Check the username and password"
# The devices pages and the scanner may be public; see test_public.py.
PAGES = ["/options/get", "/customisation/list-scripts", "/services",
         "/manu-db", "/auditlog", "/auth/tokens", "/images/list"]
HOOK = "/etc/rpi-sb-provisioner/scripts/naked-provisioner-post-flash.sh"


def hostile_page(html):
    """A page on another origin (file://), as a site the operator visits."""
    fd, path = tempfile.mkstemp(suffix=".html", prefix="rpi-sb-ui-hostile-")
    with os.fdopen(fd, "w") as f:
        f.write(html)
    return "file://" + path


class SignIn(UITest):
    sign_in_first = False

    def setUp(self):
        self.b.sign_out()

    def test_every_page_asks_for_sign_in(self):
        for page in PAGES:
            self.b.get(page)
            self.assertAtLogin()
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.b.d.current_url).query)
            self.assertEqual([page], query.get("next"), f"{page} should return there after sign-in")

    def test_login_page_is_clean(self):
        self.b.get("/login")
        self.assertClean()

    def test_wrong_password_is_refused(self):
        self.b.sign_in(password="not-the-password")
        self.assertAtLogin()
        self.assertIn(FAILED, self.b.text())
        self.assertFalse(self.b.signed_in())

    def test_unknown_account_gets_the_same_message(self):
        self.b.sign_in(user="no-such-user-4711", password="x")
        self.assertIn(FAILED, self.b.text())
        self.assertFalse(self.b.signed_in())

    @unittest.skipUnless(OUTSIDER, "set RPI_SB_TEST_OUTSIDER to an account outside the group")
    def test_account_outside_the_group_is_refused(self):
        self.b.sign_in(user=OUTSIDER, password=OUTSIDER_PASSWORD)
        self.assertIn(FAILED, self.b.text())
        self.assertFalse(self.b.signed_in())

    def test_failure_is_not_instant(self):
        start = time.time()
        self.b.sign_in(password="not-the-password")
        self.assertIn(FAILED, self.b.last_login_error)
        self.assertGreaterEqual(time.time() - start, 1.5, "a failed sign-in should be slowed")

    def test_empty_form_is_refused(self):
        self.b.sign_in(user="", password="")
        self.assertAtLogin()
        self.assertFalse(self.b.signed_in())

    def test_operator_signs_in_and_returns_to_the_page_asked_for(self):
        self.b.get("/services")
        self.assertAtLogin()
        self.b.sign_in(next_path="/services")
        self.assertEqual("/services", self.b.path(), self.b.last_login_error)
        session = self.assertSignedIn()
        self.assertTrue(session.get("user") or session.get("username"))

    def test_next_cannot_leave_the_site(self):
        for target in ("//evil.example/", "https://evil.example/", "/\\evil.example/",
                       "/%09/evil.example/", "javascript:alert(1)", "/login"):
            self.b.sign_out()
            self.b.sign_in(next_path=urllib.parse.quote(target, safe=""))
            self.assertTrue(self.b.d.current_url.startswith(self.b.base + "/"),
                            f"next={target!r} led to {self.b.d.current_url}")
            self.assertFalse(self.b.path().startswith("/login"), f"next={target!r} stayed at login")
            # A path of our own that does not exist is a same-site 404: fine.
            self.assertClean(f"after next={target!r}", error_page=True)

    def test_session_cookie_is_locked_down(self):
        self.b.sign_in()
        c = self.b.cookie("rpi_sb_session")
        self.assertIsNotNone(c)
        self.assertTrue(c["httpOnly"])
        self.assertEqual("Strict", c["sameSite"])
        self.assertGreaterEqual(len(c["value"]), 32)

    def test_signing_in_replaces_a_planted_session_id(self):
        self.b.get("/login", settle=False)
        self.b.d.add_cookie({"name": "rpi_sb_session", "value": "a" * 64, "path": "/"})
        self.b.sign_in()
        self.assertNotEqual("a" * 64, self.b.cookie("rpi_sb_session")["value"])

    def test_sign_out_ends_the_session_everywhere(self):
        self.b.sign_in()
        old = self.b.cookie("rpi_sb_session")["value"]
        self.b.get("/devices")
        self.b.click(".rpi-signout-button")
        self.b.settle()
        self.assertFalse(self.b.signed_in())
        # The old cookie, replayed, is dead.
        self.b.d.add_cookie({"name": "rpi_sb_session", "value": old, "path": "/"})
        self.b.get("/options/get")
        self.assertAtLogin()


class Refusals(UITest):
    """Requests from other sites, frames and misaddressed hosts."""

    def test_another_site_cannot_save_or_enable_a_hook(self):
        # The original report: a page elsewhere posts to save-script and
        # enable-script, and the hook would run as root.
        self.station.sh(f"rm -f {HOOK}")
        base = self.b.base
        page = hostile_page(f"""
            <form id=a method=post action="{base}/customisation/save-script" target=f1>
              <input name=script value=naked-provisioner-post-flash>
              <input name=content value="touch /tmp/rpi-sb-ui-pwned">
            </form>
            <form id=b method=post action="{base}/customisation/enable-script" target=f2>
              <input name=script value=naked-provisioner-post-flash>
            </form>
            <iframe name=f1></iframe><iframe name=f2></iframe>
            <script>
              document.getElementById('a').submit();
              setTimeout(() => document.getElementById('b').submit(), 800);
              fetch("{base}/customisation/save-script", {{method: 'POST', mode: 'no-cors',
                credentials: 'include', headers: {{'Content-Type': 'text/plain'}},
                body: JSON.stringify({{script: 'naked-provisioner-post-flash', content: 'x'}})}});
            </script>""")
        self.b.d.get(page)
        time.sleep(3)
        self.b.drain_console()
        self.assertEqual("absent", self.station.sh(f"test -e {HOOK} && echo present || echo absent").strip())

    def test_the_ui_cannot_be_framed(self):
        page = hostile_page(f'<iframe id=f src="{self.b.base}/devices" width=800 height=600></iframe>')
        self.b.d.get(page)
        time.sleep(3)
        blocked = [e["message"] for e in self.b.d.get_log("browser")
                   if "frame" in e["message"].lower() or "x-frame-options" in e["message"].lower()]
        self.assertTrue(blocked, "expected the browser to refuse to frame the UI")

    def test_request_without_csrf_token_is_refused(self):
        # The page's own fetch always adds the token, so send the session
        # cookie from outside the page, as a forged same-origin request would.
        self.b.get("/options/get")
        u = urllib.parse.urlsplit(self.b.base)
        conn = http.client.HTTPConnection(u.hostname, u.port, timeout=10)
        conn.request("POST", "/options/set", body='{"RPI_CONNECT_DESCRIPTION": "x"}', headers={
            "Cookie": "rpi_sb_session=" + self.b.cookie("rpi_sb_session")["value"],
            "Content-Type": "application/json", "Origin": self.b.base})
        self.assertEqual(403, conn.getresponse().status)

    def test_request_with_wrong_csrf_token_is_refused(self):
        self.b.get("/options/get")
        status, body = self.b.fetch("/options/set", "POST", {"RPI_CONNECT_DESCRIPTION": "x"},
                                    csrf=False, headers={"X-CSRF-Token": "0" * 64})
        self.assertEqual(403, status, body)

    def test_unknown_host_name_is_refused(self):
        # DNS rebinding: the attacker's name, resolved to this machine.
        u = urllib.parse.urlsplit(self.b.base)
        conn = http.client.HTTPConnection(u.hostname, u.port, timeout=10)
        conn.request("GET", "/login", headers={"Host": "rebind.attacker.example"})
        self.assertEqual(421, conn.getresponse().status)

    def test_internal_endpoints_are_hidden(self):
        u = urllib.parse.urlsplit(self.b.base)
        conn = http.client.HTTPConnection(u.hostname, u.port, timeout=10)
        conn.request("POST", "/internal/state-changed", body="")
        r = conn.getresponse()
        self.assertIn(r.status, (403, 404))
        self.assertEqual(b"", r.read())

    def test_security_headers_are_sent(self):
        u = urllib.parse.urlsplit(self.b.base)
        conn = http.client.HTTPConnection(u.hostname, u.port, timeout=10)
        conn.request("GET", "/login")
        r = conn.getresponse()
        self.assertEqual("DENY", r.getheader("X-Frame-Options"))
        self.assertEqual("nosniff", r.getheader("X-Content-Type-Options"))
        self.assertIn("frame-ancestors 'none'", r.getheader("Content-Security-Policy", ""))
        self.assertIsNone(r.getheader("Access-Control-Allow-Origin"))
