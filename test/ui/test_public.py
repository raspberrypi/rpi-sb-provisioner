"""What a viewer who has not signed in may see: the devices, and the scanner.

Everything else, a device's logs and overrides included, needs an operator,
and turning RPI_SB_PROVISIONER_PUBLIC_DASHBOARD off closes the rest too.
"""
import http.client
import time
import urllib.parse

from ui.harness.browser import payload
from ui.harness.case import UITest

KNOWN = "cafe0000cafe0004"
DUID = "uitest-duid-public"
SECRET_LOG = "uitest-log-line-for-operators-only"
# The UI reads the setting at most every five seconds.
SETTLE = 6


class Public(UITest):
    sign_in_first = False

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        s = cls.station
        s.set_config(RPI_SB_PROVISIONER_PUBLIC_DASHBOARD="1")
        s.sql("/srv/rpi-sb-provisioner/state.db", f"""
            delete from devices where serial='{KNOWN}';
            insert into devices(serial,endpoint,state,image,ip_address,board_type) values
              ('{KNOWN}','3-8','TRIAGE-FINISHED','{payload(1).replace("'", "''")}','10.9.9.8','5');""")
        s.sql("/srv/rpi-sb-provisioner/manufacturing.db", f"""
            delete from devices where serial='pub00001';
            insert into devices(boardname,serial,eth_mac,wifi_mac,bt_mac,mmc_size,mmc_cid,rpi_duid,
              board_revision,processor,memory,manufacturer) values
              ('b','pub00001','','','',0,'','{DUID}','','','','');""")
        s.sh(f"mkdir -p /var/log/rpi-sb-provisioner/{KNOWN} && "
             f"echo {SECRET_LOG} > /var/log/rpi-sb-provisioner/{KNOWN}/triage.log && "
             f"mkdir -p /etc/rpi-sb-provisioner/special-skip-eeprom && "
             f"echo persistent > /etc/rpi-sb-provisioner/special-skip-eeprom/{KNOWN}")
        time.sleep(SETTLE)

    @classmethod
    def tearDownClass(cls):
        cls.station.sh(f"rm -rf /var/log/rpi-sb-provisioner/{KNOWN} "
                       f"/etc/rpi-sb-provisioner/special-skip-eeprom/{KNOWN}")
        super().tearDownClass()

    def setUp(self):
        super().setUp()
        self.b.sign_out()

    def raw(self, method, path, body=None, headers=None):
        u = urllib.parse.urlsplit(self.b.base)
        c = http.client.HTTPConnection(u.hostname, u.port, timeout=30)
        c.request(method, path, body, headers or {})
        r = c.getresponse()
        return r.status, r.read().decode(errors="replace")

    def test_dashboard_is_viewable(self):
        self.b.get("/devices")
        self.assertEqual("/devices", self.b.path())
        self.assertClean()
        self.assertTrue(self.b.all(".device-tile"), "the live device cards should arrive over the WebSocket")
        sign_in = self.b.el("#rpi-sign-in")
        self.assertIn("next=%2Fdevices", sign_in.get_attribute("href"))
        self.assertEqual([], self.b.all(".rpi-signout-button"))
        self.assertEqual([], self.b.all("#rpi-signed-in-user"))
        self.assertEqual([], self.b.all(".security-warning-banner"), "admin banners are for operators")

    def test_root_goes_to_the_dashboard(self):
        self.b.get("/")
        self.assertEqual("/devices", self.b.path())

    def test_device_page_leaves_out_logs_and_overrides(self):
        self.b.get(f"/devices/{KNOWN}")
        self.assertClean()
        self.assertIn(KNOWN, self.b.el("#info-serial").text)
        self.assertEqual([], self.b.all(".log-section"))
        self.assertEqual([], self.b.all(".flags-section"))
        self.assertNotIn(SECRET_LOG, self.b.d.page_source)
        prompt = self.b.el("#signin-for-more")
        self.assertIn(urllib.parse.quote(f"/devices/{KNOWN}", safe=""), prompt.get_attribute("href"))

    def test_device_text_is_still_inert(self):
        self.b.get(f"/devices/{KNOWN}")
        self.assertClean()
        self.assertGreaterEqual(self.b.payloads_shown(), 1, "the planted image name should show as text")

    def test_signing_in_from_a_device_page_returns_to_it(self):
        self.b.get(f"/devices/{KNOWN}")
        self.b.click("#signin-for-more")
        self.b.settle()
        self.assertAtLogin()
        self.b.sign_in(here=True)
        self.assertEqual(f"/devices/{KNOWN}", self.b.path())
        self.assertIn(SECRET_LOG, self.b.text(), "an operator sees the logs")
        self.b.sign_out()

    def test_device_logs_keys_and_flags_stay_closed(self):
        for path in (f"/devices/{KNOWN}/log/triage", f"/devices/{KNOWN}/log/provisioner",
                     f"/devices/{KNOWN}/key/public", f"/devices/{KNOWN}/key/private",
                     f"/devices/{KNOWN}/flags", "/devices/_test"):
            with self.subTest(path=path):
                status, _ = self.raw("GET", path, headers={"Accept": "application/json"})
                self.assertIn(status, (401, 404), path)
        status, _ = self.raw("POST", f"/devices/{KNOWN}/flags", '{"flag":"skip-eeprom","mode":"off"}',
                             {"Content-Type": "application/json", "Origin": self.b.base})
        self.assertEqual(401, status)
        self.assertEqual("persistent", self.station.sh(
            f"cat /etc/rpi-sb-provisioner/special-skip-eeprom/{KNOWN}").strip())

    def test_everything_else_needs_an_operator(self):
        for page in ("/options/get", "/customisation/list-scripts", "/services",
                     f"/service-log/rpi-sb-triage@{KNOWN}.service", "/manu-db", "/auditlog",
                     "/auth/tokens", "/images/list"):
            with self.subTest(page=page):
                self.b.get(page)
                self.assertAtLogin()
        for path in ("/api/v2/manufacturing", "/api/v2/services", "/options/get", "/images/list"):
            with self.subTest(api=path):
                status, _ = self.raw("GET", path, headers={"Accept": "application/json"})
                self.assertEqual(401, status)

    def test_writes_need_an_operator(self):
        for path, body in (("/options/set", '{"RPI_CONNECT_DESCRIPTION":"anon"}'),
                           ("/customisation/enable-script?script=naked-provisioner-post-flash", ""),
                           ("/api/v2/verify-qrcode", '{"qrcode":"%s"}' % DUID)):
            with self.subTest(path=path):
                status, _ = self.raw("POST", path, body, {"Content-Type": "application/json",
                                                          "Origin": self.b.base})
                self.assertEqual(401, status)

    def test_session_reports_nobody(self):
        status, body = self.raw("GET", "/auth/session", headers={"Accept": "application/json"})
        self.assertEqual(200, status)
        self.assertIn('"user":""', body.replace(" ", ""))

    def test_scanner_page_is_viewable(self):
        self.b.get("/scantool")
        self.assertEqual("/scantool", self.b.path())
        self.assertIn("Code Scanner", self.b.text())

    def test_scanner_lookup(self):
        status, body = self.raw("GET", "/api/v2/verify-qrcode?code=" + DUID)
        self.assertEqual(200, status, body)
        self.assertIn('"exists":true', body)
        status, body = self.raw("GET", "/api/v2/verify-qrcode?code=uitest-duid-unknown")
        self.assertIn('"exists":false', body)

    def test_scanner_lookup_refuses_blank_and_hidden_codes(self):
        # Blank, or cut short by a NUL, a code would match any record without a DUID.
        for code in ("", "%20%20", "%00", "%00x", "a%0Ab", "x" * 257):
            with self.subTest(code=code[:12]):
                status, _ = self.raw("GET", "/api/v2/verify-qrcode?code=" + code)
                self.assertEqual(400, status)

    def test_anonymous_sockets_are_capped(self):
        self.b.get("/devices")
        opened = self.b.d.execute_async_script("""
            const done = arguments[0];
            const url = (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/ws/devices';
            const socks = [];
            for (let i = 0; i < 40; i++) socks.push(new WebSocket(url));
            setTimeout(() => {
                const n = socks.filter(s => s.readyState === WebSocket.OPEN).length;
                socks.forEach(s => s.close());
                done(n);
            }, 4000);
        """)
        # The page's own socket counts too, so at most 31 of ours stay open.
        self.assertLessEqual(opened, 32)
        self.assertGreater(opened, 0)

    def test_turning_it_off_closes_everything(self):
        self.station.set_config(RPI_SB_PROVISIONER_PUBLIC_DASHBOARD="")
        try:
            time.sleep(SETTLE)
            for page in ("/devices", f"/devices/{KNOWN}", "/scantool", "/"):
                with self.subTest(page=page):
                    self.b.get(page)
                    self.assertAtLogin()
            status, _ = self.raw("GET", "/api/v2/verify-qrcode?code=" + DUID)
            self.assertEqual(401, status)
        finally:
            self.station.set_config(RPI_SB_PROVISIONER_PUBLIC_DASHBOARD="1")
            time.sleep(SETTLE)


class PublicSetting(UITest):
    """The switch on the options page."""

    def test_switch_saves_the_setting(self):
        self.station.set_config(RPI_SB_PROVISIONER_PUBLIC_DASHBOARD="1")
        self.b.get("/options/get")
        box = self.b.el("#RPI_SB_PROVISIONER_PUBLIC_DASHBOARD")
        self.assertTrue(box.is_selected())
        try:
            self.b.press(box)
            deadline = time.time() + 15
            while time.time() < deadline and self.station.config().get(
                    "RPI_SB_PROVISIONER_PUBLIC_DASHBOARD", "").strip("'") != "":
                time.sleep(0.3)
            self.assertEqual("", self.station.config().get("RPI_SB_PROVISIONER_PUBLIC_DASHBOARD", "").strip("'"))
        finally:
            self.station.set_config(RPI_SB_PROVISIONER_PUBLIC_DASHBOARD="1")

    def test_only_on_or_off(self):
        self.b.get("/options/get")
        for value, ok in (("1", True), ("", True), ("yes", False), ("0", False), ("2", False)):
            with self.subTest(value=value):
                status, body = self.b.fetch("/options/validate", "POST",
                                            {"field": "RPI_SB_PROVISIONER_PUBLIC_DASHBOARD", "value": value})
                self.assertEqual(200, status, body)
                self.assertEqual(ok, body["valid"])
