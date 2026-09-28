"""API tokens: made on the tokens page, used by scripts, revoked there."""
import http.client
import json
import re
import urllib.parse

from ui.harness.browser import payload
from ui.harness.case import UITest


class Tokens(UITest):
    def api(self, method, path, token, body=None):
        """A script's request: bearer token only, no browser."""
        u = urllib.parse.urlsplit(self.b.base)
        c = http.client.HTTPConnection(u.hostname, u.port, timeout=30)
        headers = {"Authorization": "Bearer " + token, "Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(body)
        c.request(method, path, body, headers)
        r = c.getresponse()
        return r.status, r.read().decode(errors="replace")

    def create(self, label):
        self.b.get("/auth/tokens")
        self.b.el("#token-label").clear()
        self.b.el("#token-label").send_keys(label)
        self.b.click("#create-form button[type=submit]")
        self.b.visible("#new-token")
        secret = self.b.el("#new-token-value").text.strip()
        self.b.settle()
        return secret

    def row(self, label):
        for tr in self.b.all("#token-rows tr"):
            if label in tr.text:
                return tr
        return None

    def test_created_token_is_shown_once_and_works(self):
        secret = self.create("uitest works")
        self.assertRegex(secret, r"^rpisb_[0-9a-f]{64}$")
        self.assertIn("It will not be shown again", self.b.text())
        self.assertEqual("", self.b.el("#token-label").get_attribute("value"))
        row = self.row("uitest works")
        self.assertIsNotNone(row, "the new token should be listed")
        self.assertIn(self.assertSignedIn()["user"], row.text)
        self.assertNotIn(secret, self.b.text().replace(self.b.el("#new-token-value").text, ""))
        # The secret is gone after a reload.
        self.b.get("/auth/tokens")
        self.assertNotIn(secret, self.b.d.page_source)
        self.assertClean()
        status, _ = self.api("GET", "/api/v2/services", secret)
        self.assertEqual(200, status)

    def test_token_store_keeps_only_a_hash(self):
        secret = self.create("uitest hash")
        store = self.station.sh("cat /etc/rpi-sb-provisioner/api-tokens.json; "
                                "stat -c %a /etc/rpi-sb-provisioner/api-tokens.json")
        self.assertNotIn(secret, store)
        self.assertNotIn(secret[6:], store)
        self.assertTrue(store.strip().endswith("600"), "token store must be root-only")

    def test_token_can_change_settings_without_csrf(self):
        secret = self.create("uitest set")
        status, body = self.api("POST", "/options/set", secret, {"RPI_CONNECT_DESCRIPTION": "set-by-token"})
        self.assertEqual(200, status, body)
        self.assertEqual("set-by-token", self.station.config().get("RPI_CONNECT_DESCRIPTION"))

    def test_token_cannot_manage_tokens(self):
        secret = self.create("uitest manage")
        status, body = self.api("POST", "/api/v2/tokens", secret, {"label": "minted"})
        self.assertEqual(403, status)
        self.assertIn("SESSION_REQUIRED", body)
        status, body = self.api("GET", "/api/v2/tokens", secret)
        self.assertEqual(403, status)

    def test_revoked_token_stops_working(self):
        secret = self.create("uitest revoke")
        self.b.accept_confirm()
        self.row("uitest revoke").find_element("css selector", "button").click()
        self.b.settle()
        self.assertIsNone(self.row("uitest revoke"), "a revoked token should leave the list")
        status, body = self.api("GET", "/api/v2/services", secret)
        self.assertEqual(401, status)
        self.assertIn("INVALID_TOKEN", body)

    def test_revoke_can_be_cancelled(self):
        self.create("uitest keep")
        self.b.d.execute_script("window.confirm = () => false;")
        self.row("uitest keep").find_element("css selector", "button").click()
        self.b.settle()
        self.assertIsNotNone(self.row("uitest keep"))

    def test_made_up_token_is_refused(self):
        status, body = self.api("GET", "/api/v2/services", "rpisb_" + "0" * 64)
        self.assertEqual(401, status)
        self.assertIn("INVALID_TOKEN", body)

    def test_blank_label_is_refused(self):
        self.b.get("/auth/tokens")
        self.b.el("#token-label").send_keys("   ")
        self.b.click("#create-form button[type=submit]")
        self.b.wait_text("#token-error", "label")
        self.assertFalse(self.b.el("#new-token").is_displayed())

    def test_label_is_limited_to_100_characters(self):
        self.assertEqual("100", self.b.el("#token-label").get_attribute("maxlength")
                         if self.b.path() == "/auth/tokens" else self._maxlength())
        status, body = self.b.fetch("/api/v2/tokens", "POST", {"label": "x" * 101})
        self.assertEqual(400, status, body)

    def _maxlength(self):
        self.b.get("/auth/tokens")
        return self.b.el("#token-label").get_attribute("maxlength")

    def test_label_is_shown_as_text(self):
        label = payload(91)[:100]
        status, _ = self.b.fetch("/api/v2/tokens", "POST", {"label": label})
        self.assertEqual(201 if status == 201 else 200, status)
        self.b.get("/auth/tokens")
        self.assertClean()
        self.assertIn("onerror", self.b.text())

    def test_signed_out_browser_cannot_list_tokens(self):
        self.b.sign_out()
        try:
            self.b.get("/auth/tokens")
            self.assertAtLogin()
        finally:
            self.b.sign_in()
