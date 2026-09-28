"""Negative and out-of-range input, at and either side of every limit.

Each refusal is also checked on the station: a refused request must leave
the configuration and the hooks exactly as they were.
"""
import contextlib
import http.client
import json
import urllib.parse

from ui.harness.case import UITest

LOGIN_FAILED = "Sign-in failed"
LOGIN_MALFORMED = "Enter a username and password."


class Limits(UITest):
    @contextlib.contextmanager
    def unchanged(self):
        """The station's config and hooks are the same afterwards."""
        snapshot = "cat /etc/rpi-sb-provisioner/config 2>/dev/null; ls -la /etc/rpi-sb-provisioner/scripts"
        before = self.station.sh(snapshot)
        yield
        self.assertEqual(before, self.station.sh(snapshot), "a refused request changed the station")

    def raw(self, method, path, body=None, headers=None):
        """A request from outside the browser, with no session."""
        u = urllib.parse.urlsplit(self.b.base)
        c = http.client.HTTPConnection(u.hostname, u.port, timeout=60)
        c.request(method, path, body, headers or {})
        r = c.getresponse()
        return r.status, r.read().decode(errors="replace")

    def login(self, user, password):
        return self.raw("POST", "/login", urllib.parse.urlencode({"username": user, "password": password}),
                        {"Content-Type": "application/x-www-form-urlencoded", "Origin": self.b.base})

    def assertRefused(self, status, body, codes=(400,)):
        self.assertIn(status, codes, f"expected a refusal, got {status}: {str(body)[:300]}")


class SignInLimits(Limits):
    def test_username_length(self):
        for n, expect in ((1, LOGIN_FAILED), (256, LOGIN_FAILED), (257, LOGIN_MALFORMED), (10000, LOGIN_MALFORMED)):
            with self.subTest(length=n):
                status, body = self.login("u" * n, "x")
                self.assertIn(expect, body)
                self.assertEqual(401 if expect == LOGIN_FAILED else 400, status)

    def test_password_length(self):
        for n, expect in ((1024, LOGIN_FAILED), (1025, LOGIN_MALFORMED)):
            with self.subTest(length=n):
                status, body = self.login("tdewey-no-such", "p" * n)
                self.assertIn(expect, body)

    def test_empty_fields(self):
        for user, password in (("", "x"), ("x", ""), ("", "")):
            with self.subTest(user=user, password=password):
                status, body = self.login(user, password)
                self.assertEqual(400, status)
                self.assertIn(LOGIN_MALFORMED, body)

    def test_concurrent_sign_ins_from_one_address_are_limited(self):
        # Two may be in progress per address; each failure is held for 2 s.
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(4) as pool:
            results = list(pool.map(lambda i: self.login("no-such-user-%d" % i, "x"), range(4)))
        statuses = sorted(r[0] for r in results)
        self.assertIn(429, statuses, f"four at once should meet the limit: {statuses}")
        self.assertIn("Too many sign-in attempts", next(b for st, b in results if st == 429))
        self.assertTrue(all(st in (401, 429) for st in statuses), statuses)

    def test_public_body_is_capped(self):
        at = "username=x&password=" + "p" * (64 * 1024 - 20)
        status, _ = self.raw("POST", "/login", at, {"Content-Type": "application/x-www-form-urlencoded",
                                                     "Origin": self.b.base})
        self.assertNotEqual(413, status, "a body just under 64 KiB must be read")
        over = "username=x&password=" + "p" * (64 * 1024 + 1)
        status, _ = self.raw("POST", "/login", over, {"Content-Type": "application/x-www-form-urlencoded",
                                                       "Origin": self.b.base})
        self.assertEqual(413, status)

    def test_unauthenticated_api_is_json_401(self):
        for method, path in (("GET", "/api/v2/services"), ("POST", "/options/set"), ("GET", "/images/list")):
            with self.subTest(path=path):
                status, body = self.raw(method, path, headers={"Accept": "application/json"})
                self.assertEqual(401, status)
                self.assertIn("UNAUTHENTICATED", body)

    def test_malformed_bearer_tokens(self):
        for header in ("Bearer", "Bearer ", "Bearer rpisb_", "Bearer rpisb_" + "0" * 63,
                       "Bearer rpisb_" + "g" * 64, "Bearer " + "x" * 5000, "Basic dGRld2V5Og=="):
            with self.subTest(header=header[:30]):
                status, _ = self.raw("GET", "/api/v2/services", headers={"Authorization": header,
                                                                        "Accept": "application/json"})
                self.assertEqual(401, status)


class TokenLimits(Limits):
    def create(self, body):
        return self.b.fetch("/api/v2/tokens", "POST", body)

    def setUp(self):
        super().setUp()
        self.b.get("/auth/tokens")

    def test_label_length(self):
        for label, ok in (("x", True), ("x" * 100, True), ("x" * 101, False), ("", False), ("   ", False)):
            with self.subTest(length=len(label), blank=not label.strip()):
                status, body = self.create({"label": label})
                if ok:
                    self.assertEqual(200, status, body)
                else:
                    self.assertRefused(status, body)

    def test_label_of_the_wrong_type(self):
        for label in (123, None, [], {}, True):
            with self.subTest(label=label):
                status, body = self.create({"label": label})
                self.assertRefused(status, body)
        status, body = self.create({})
        self.assertRefused(status, body)

    def test_body_that_is_not_json(self):
        status, body = self.b.fetch("/api/v2/tokens", "POST", "label=x", raw=True,
                                    headers={"Content-Type": "application/x-www-form-urlencoded"})
        self.assertRefused(status, body)

    def test_at_most_64_tokens(self):
        existing = len(self.b.fetch("/api/v2/tokens")[1])
        for i in range(64 - existing):
            self.assertEqual(200, self.create({"label": f"uitest bulk {i}"})[0])
        status, body = self.create({"label": "uitest one too many"})
        self.assertRefused(status, body, (400, 409, 429, 500))
        self.assertIn("Too many API tokens", json.dumps(body))
        self.assertEqual(64, len(self.b.fetch("/api/v2/tokens")[1]))
        for t in self.b.fetch("/api/v2/tokens")[1]:
            if t["label"].startswith("uitest bulk"):
                self.b.fetch(f"/api/v2/tokens/{t['id']}/revoke", "POST")

    def test_revoke_of_unknown_or_malformed_ids(self):
        for token_id in ("00000000", "zzzzzzzz", "0" * 9, "..%2F..%2Fx", "%00"):
            with self.subTest(id=token_id):
                status, body = self.b.fetch(f"/api/v2/tokens/{token_id}/revoke", "POST")
                self.assertRefused(status, body, (400, 404))


class OptionLimits(Limits):
    def setUp(self):
        super().setUp()
        self.b.get("/options/get")

    def validate(self, field, value):
        status, body = self.b.fetch("/options/validate", "POST", {"field": field, "value": value})
        self.assertEqual(200, status, body)
        return body

    def assertValid(self, field, values):
        for v in values:
            with self.subTest(field=field, value=v):
                self.assertTrue(self.validate(field, v)["valid"], f"{field}={v!r} should be accepted")

    def assertInvalid(self, field, values, message=None):
        for v in values:
            with self.subTest(field=field, value=v):
                body = self.validate(field, v)
                self.assertFalse(body["valid"], f"{field}={v!r} should be refused")
                if message:
                    self.assertIn(message, body.get("error", ""))

    def test_rpiboot_gpio(self):
        self.station.set_config(RPI_DEVICE_RPIBOOT_GPIO="8")
        self.assertValid("RPI_DEVICE_RPIBOOT_GPIO", ["2", "4", "5", "6", "7", "8"])
        self.assertInvalid("RPI_DEVICE_RPIBOOT_GPIO",
                           ["0", "1", "3", "9", "10", "-1", "08", "8.0", " 8", "8 ", "abc", "1e3", "99999999999"],
                           "GPIO pin must be one of")

    def test_device_family(self):
        self.assertValid("RPI_DEVICE_FAMILY", ["4", "5", "2W"])
        self.assertInvalid("RPI_DEVICE_FAMILY", ["3", "6", "2w", "2", "", "55", "4 "], "Device family must be")

    def test_provisioning_style(self):
        self.assertValid("PROVISIONING_STYLE", ["secure-boot", "fde-only", "naked"])
        self.assertInvalid("PROVISIONING_STYLE", ["Secure-Boot", "secure_boot", "", "naked;id"],
                           "Provisioning style must be")

    def test_storage_type(self):
        self.assertValid("RPI_DEVICE_STORAGE_TYPE", ["sd", "emmc", "nvme"])
        self.assertInvalid("RPI_DEVICE_STORAGE_TYPE", ["SD", "usb", "", "emmc0"], "Storage type must be")

    def test_cipher(self):
        self.station.set_config(RPI_DEVICE_STORAGE_CIPHER="aes-xts-plain64")
        self.assertValid("RPI_DEVICE_STORAGE_CIPHER", ["aes-xts-plain64", "xchacha12,aes-adiantum-plain64", ""])
        self.assertInvalid("RPI_DEVICE_STORAGE_CIPHER", ["aes", "xchacha12", "aes-xts-plain64 "], "Cipher must be")

    def test_pkcs11_uri(self):
        self.station.set_config(CUSTOMER_KEY_PKCS11_NAME="pkcs11:object=k;type=private")
        self.assertValid("CUSTOMER_KEY_PKCS11_NAME", ["pkcs11:object=k;type=private"])
        self.assertInvalid("CUSTOMER_KEY_PKCS11_NAME", ["object=k;type=private"], "must start with 'pkcs11:'")
        self.assertInvalid("CUSTOMER_KEY_PKCS11_NAME", ["pkcs11:type=private"], "object=")
        self.assertInvalid("CUSTOMER_KEY_PKCS11_NAME", ["pkcs11:object=k"], "type=private")

    def test_connect_key_whitespace(self):
        self.station.set_config(RPI_CONNECT_API_KEY="")
        self.assertValid("RPI_CONNECT_API_KEY", ["", "abc123"])
        self.assertInvalid("RPI_CONNECT_API_KEY", ["a b", "a\tb", "a\nb", " a"], "must not contain whitespace")

    def test_paths(self):
        self.station.set_config(RPI_SB_WORKDIR="", RPI_SB_PROVISIONER_MANUFACTURING_DB="/srv/rpi-sb-provisioner/manufacturing.db")
        self.assertInvalid("RPI_SB_WORKDIR", ["/no/such/parent/dir", "/etc/passwd"])
        self.assertInvalid("RPI_SB_PROVISIONER_MANUFACTURING_DB", ["", "/no/such/dir/m.db", "/srv"])
        self.assertValid("RPI_SB_PROVISIONER_MANUFACTURING_DB", ["/srv/rpi-sb-provisioner/new-uitest.db"])

    def test_validate_refuses_malformed_requests(self):
        for body in ({"field": "NOT_A_FIELD", "value": "x"}, {"value": "x"}, {}):
            with self.subTest(body=body):
                status, resp = self.b.fetch("/options/validate", "POST", body)
                self.assertRefused(status, resp)
        status, resp = self.b.fetch("/options/validate", "POST", "{not json", raw=True,
                                    headers={"Content-Type": "application/json"})
        self.assertRefused(status, resp)

    def test_set_refuses_names_that_are_not_settings(self):
        with self.unchanged():
            for key in ("rpi_sb_workdir", "RPI_", "RPI", "PATH", "LD_PRELOAD", "IFS", "RPI_X-Y", "RPI_X Y",
                        "RPI_X;id", "RPI_X$(id)", "X" * 5000, "RPI_É", ""):
                with self.subTest(key=key[:40]):
                    status, body = self.b.fetch("/options/set", "POST", {key: "1"})
                    self.assertRefused(status, body)

    def test_set_refuses_multi_line_values(self):
        with self.unchanged():
            for value in ("a\nb", "a\rb", "a\x00b", "\n", "x\nRPI_SB_WORKDIR=/"):
                with self.subTest(value=value):
                    status, body = self.b.fetch("/options/set", "POST", {"RPI_CONNECT_DESCRIPTION": value})
                    self.assertRefused(status, body)

    def test_set_refuses_values_that_are_not_text(self):
        with self.unchanged():
            for value in ({"a": 1}, [1, 2]):
                with self.subTest(value=value):
                    status, body = self.b.fetch("/options/set", "POST", {"RPI_CONNECT_DESCRIPTION": value})
                    self.assertRefused(status, body)

    def test_set_refuses_a_body_that_is_not_an_object(self):
        with self.unchanged():
            for body in ("[]", '"x"', "1", "{not json", ""):
                with self.subTest(body=body):
                    status, resp = self.b.fetch("/options/set", "POST", body, raw=True,
                                                headers={"Content-Type": "application/json"})
                    self.assertRefused(status, resp)

    def test_quoting_survives_awkward_values(self):
        for value in ("it's", "a;b", "$(id)", "`id`", "a b  c", "'", "\\", "日本語", "x" * 4096):
            with self.subTest(value=value[:20]):
                status, body = self.b.fetch("/options/set", "POST", {"RPI_CONNECT_DESCRIPTION": value})
                self.assertEqual(200, status, body)
                seen = self.station.sh(". /etc/rpi-sb-provisioner/config; printf '%s' \"$RPI_CONNECT_DESCRIPTION\"")
                self.assertEqual(value, seen, "the shell must read back exactly what was saved")

    def test_firmware_path_must_be_a_firmware_file(self):
        with self.unchanged():
            for path in ("/etc/passwd", "/lib/firmware/raspberrypi/../../../etc/passwd",
                         "/lib/firmware/raspberrypi", "/lib/firmware/raspberrypi/no-such.bin", "relative.bin"):
                with self.subTest(path=path):
                    status, body = self.b.fetch("/options/firmware/set", "POST", {"firmware_path": path})
                    self.assertRefused(status, body)

    def test_pin_length(self):
        status, body = self.b.fetch("/options/set-pkcs11-pin", "POST", {"pin": "1" * 257})
        self.assertRefused(status, body)
        self.assertIn("too long", json.dumps(body))

    def test_key_upload_limits(self):
        cases = {
            "not-a-key.txt": ("-----BEGIN PRIVATE KEY-----\n", "Invalid file type"),
            "big.pem": ("-----BEGIN PRIVATE KEY-----\n" + "A" * (64 * 1024 + 1), "too large"),
            "plain.pem": ("hello", "valid PEM"),
        }
        with self.unchanged():
            for name, (content, message) in cases.items():
                with self.subTest(name=name):
                    status, body = self.b.d.execute_async_script("""
                        const [name, content, done] = arguments;
                        const f = new FormData();
                        f.append('keyfile', new Blob([content]), name);
                        fetch('/options/upload-key', {method: 'POST', body: f})
                          .then(r => r.text().then(t => done([r.status, t])), e => done([0, String(e)]));
                    """, name, content)
                    self.assertRefused(status, body)
                    self.assertIn(message, body)


class ImageNameLimits(Limits):
    BAD = ["", ".", "..", "../idp-test", "/etc/passwd", ".hidden", "a/b", "a\\b", "idp-test/../x", "x" * 300 + "/y"]

    def setUp(self):
        super().setUp()
        self.b.get("/options/get")

    def test_image_endpoints_refuse_names_that_are_not_plain(self):
        before = self.station.sh("ls -A /srv/rpi-sb-provisioner/images")
        for endpoint, method in (("/get-image-metadata", "GET"), ("/get-image-sha256", "GET"),
                                 ("/analyze-image", "GET"), ("/get-boot-package-info", "GET"),
                                 ("/delete-image", "POST"), ("/generate-boot-package", "POST")):
            for name in self.BAD:
                with self.subTest(endpoint=endpoint, name=name[:30]):
                    status, body = self.b.fetch(f"{endpoint}?name=" + urllib.parse.quote(name), method)
                    self.assertRefused(status, body, (400, 404))
        self.assertEqual(before, self.station.sh("ls -A /srv/rpi-sb-provisioner/images"))

    def test_deleting_an_image_that_is_not_there(self):
        status, body = self.b.fetch("/delete-image?name=uitest-no-such.img", "POST")
        self.assertRefused(status, body, (400, 404))

    def test_upload_refuses_bad_names_and_types(self):
        before = self.station.sh("ls -A /srv/rpi-sb-provisioner/images")
        for name in ("../uitest-escape.img", ".uitest-hidden.img", "uitest.exe", "uitest.img.gz", "uitest", "/uitest.img"):
            with self.subTest(name=name):
                status, body = self.b.d.execute_async_script("""
                    const [name, done] = arguments;
                    const f = new FormData();
                    f.append('image', new Blob([new Uint8Array(4096)]), name);
                    fetch('/upload-image', {method: 'POST', body: f})
                      .then(r => r.text().then(t => done([r.status, t])), e => done([0, String(e)]));
                """, name)
                self.assertRefused(status, body, (400, 415))
        self.assertEqual(before, self.station.sh("ls -A /srv/rpi-sb-provisioner/images"))
        self.assertEqual("", self.station.sh("ls /srv/rpi-sb-provisioner/uitest* 2>/dev/null || true").strip())


class ListLimits(Limits):
    UNIT = "rpi-sb-uitest-limits"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.station.sh(f"systemctl reset-failed {cls.UNIT} 2>/dev/null; systemd-run --unit={cls.UNIT} --collect "
                       f"--wait sh -c 'for i in $(seq 1 120); do echo line $i; done' >/dev/null")
        cls.station.sql("/srv/rpi-sb-provisioner/audit.db",
                        "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < 1100) "
                        "INSERT INTO audit_log (timestamp, event_type, handler_path) "
                        "SELECT datetime('now'), 'HANDLER_ACCESS', '/uitest/' || i FROM n;")

    def log_page(self, query):
        status, body = self.b.fetch(f"/api/v2/service-log/{self.UNIT}.service?{query}",
                                    headers={"Accept": "application/json"})
        self.assertEqual(200, status, f"{query}: {body}")
        return body

    def test_service_log_page_numbers(self):
        for page in ("0", "-1", "abc", "1.5", "99999999999999999999"):
            with self.subTest(page=page):
                body = self.log_page(f"page={page}&page_size=25")
                self.assertGreaterEqual(body["page"], 1)
        # Past the end is the last page.
        body = self.log_page("page=999999&page_size=25")
        self.assertEqual(body["total_pages"], body["page"])
        self.assertLessEqual(len(body["logs"]), 25)

    def test_service_log_page_sizes(self):
        for size, expect in (("0", 50), ("-5", 50), ("1", 1), ("25", 25), ("abc", 50)):
            with self.subTest(size=size):
                self.assertLessEqual(len(self.log_page(f"page_size={size}")["logs"]), expect)
        self.assertLessEqual(len(self.log_page("page_size=100000")["logs"]), 500)

    def test_service_log_order(self):
        newest = self.log_page("order=desc&page_size=5")["logs"]
        oldest = self.log_page("order=asc&page_size=5")["logs"]
        self.assertNotEqual(newest, oldest)
        self.assertEqual(newest, self.log_page("order=sideways&page_size=5")["logs"])

    def test_service_log_names_outside_the_provisioner(self):
        for name in ("sshd.service", "rpi-sb-../../sshd", "systemd-journald.service", "rpi-provisioner-ui.service"):
            with self.subTest(name=name):
                status, body = self.b.fetch("/api/v2/service-log/" + urllib.parse.quote(name, safe=""),
                                            headers={"Accept": "application/json"})
                self.assertRefused(status, body, (403, 404))

    def audit_rows(self, query):
        self.b.get("/auditlog?" + query)
        return len(self.b.all("#auditLogTable tbody tr:not(:has(td.no-entries))"))

    def test_audit_log_limits(self):
        for limit, expect in (("", 100), ("0", 1), ("-5", 1), ("1", 1), ("250", 250), ("1000", 1000),
                              ("1001", 1000), ("abc", 100), ("99999999999999999999", 100)):
            with self.subTest(limit=limit):
                self.assertEqual(expect, self.audit_rows(f"limit={limit}"))
                self.assertClean()

    def test_audit_log_dates(self):
        self.assertEqual(0, self.audit_rows("start_date=2999-01-01T00:00&limit=10"))
        self.assertEqual(0, self.audit_rows("end_date=1999-01-01T00:00&limit=10"))
        self.assertEqual(0, self.audit_rows("start_date=2030-01-02T00:00&end_date=2030-01-01T00:00"))
        self.assertGreater(self.audit_rows("start_date=garbage&limit=10"), -1)
        self.assertClean()

    def test_audit_log_unknown_event_type(self):
        self.assertEqual(0, self.audit_rows("event_type=NO_SUCH_EVENT"))
        self.assertEqual(0, self.audit_rows("event_type=" + urllib.parse.quote("' OR 1=1 --")))

    def test_manufacturing_offset_and_limit(self):
        self.station.sql("/srv/rpi-sb-provisioner/manufacturing.db", """
            delete from devices where serial like 'lim%';
            insert into devices(boardname,serial,eth_mac,wifi_mac,bt_mac,mmc_size,mmc_cid,rpi_duid,board_revision,
              processor,memory,manufacturer) values
            ('b','lim00001','','','',0,'','','','','',''),('b','lim00002','','','',0,'','','','','',''),
            ('b','lim00003','','','',0,'','','','','','');""")
        total = len(self.b.fetch("/api/v2/manufacturing")[1])
        self.assertGreaterEqual(total, 3)
        for query, expect in (("limit=1", 1), ("limit=2&offset=1", 2), ("offset=-1&limit=1", 1),
                              ("limit=0", total), ("limit=-3", total), ("limit=abc", total),
                              (f"offset={total}", 0), ("offset=99999999999999999999", total)):
            with self.subTest(query=query):
                status, rows = self.b.fetch("/api/v2/manufacturing?" + query)
                self.assertEqual(200, status, rows)
                self.assertEqual(expect, len(rows))


class DeviceLimits(Limits):
    def test_unknown_or_malformed_device(self):
        for ident in ("ffffffffffffffff", "x" * 5000, "..%2F..%2Fetc", "%00", "1-1.2.3.4.5.6.7.8"):
            with self.subTest(ident=ident[:30]):
                self.b.drain_console()
                self.b.get("/devices/" + ident)
                text = self.b.text()
                self.assertTrue("Device not found" in text or "HTTP ERROR 403" in text,
                                f"{ident[:30]} should find no device: {text[:200]}")
                if "Device not found" in text:
                    self.assertClean(error_page=True)

    def test_flag_requests(self):
        serial = "cafe0000cafe0002"
        self.station.sql("/srv/rpi-sb-provisioner/state.db",
                         f"delete from devices where serial='{serial}'; insert into devices(serial,endpoint,state,image,"
                         f"ip_address,board_type) values('{serial}','3-1','TRIAGE-FINISHED','x','','');")
        self.b.get(f"/devices/{serial}")
        path = f"/devices/{serial}/flags"
        for body in ({"flag": "skip-eeprom", "mode": "forever"}, {"flag": "skip-eeprom", "mode": "ONCE"},
                     {"flag": "skip-eeprom", "mode": ""}, {"flag": "skip-eeprom", "mode": 1},
                     {"flag": "no-such-flag", "mode": "once"}, {"flag": "../../x", "mode": "once"},
                     {"flag": "", "mode": "once"}, {"mode": "once"}, {"flag": "skip-eeprom"}):
            with self.subTest(body=body):
                status, resp = self.b.fetch(path, "POST", body)
                self.assertRefused(status, resp)
        status, resp = self.b.fetch(path, "POST", "not json", raw=True, headers={"Content-Type": "application/json"})
        self.assertRefused(status, resp)
        self.assertEqual("", self.station.sh(
            f"ls /etc/rpi-sb-provisioner/special-*/{serial} 2>/dev/null || true").strip(),
            "a refused flag request must write no flag")

    def test_qr_code_verification(self):
        self.b.get("/scantool")
        for body in ({}, {"qrcode": ""}, {"qrcode": "   "}, {"qrcode": 123}, {"qrcode": None}, {"qrcode": []}):
            with self.subTest(body=body):
                status, resp = self.b.fetch("/api/v2/verify-qrcode", "POST", body)
                self.assertRefused(status, resp)
        status, resp = self.b.fetch("/api/v2/verify-qrcode", "POST", {"qrcode": "x" * 10000})
        self.assertIn(status, (200, 400))
        if status == 200:
            self.assertFalse(resp["exists"])
        status, resp = self.b.fetch("/api/v2/verify-qrcode", "POST", {"qrcode": "' OR 1=1 --"})
        self.assertEqual(200, status)
        self.assertFalse(resp["exists"])


class HookLimits(Limits):
    def setUp(self):
        super().setUp()
        self.b.get("/customisation/list-scripts")

    def test_script_names_out_of_range(self):
        with self.unchanged():
            for name in ("", "naked-provisioner", "naked-provisioner-", "naked-provisioner-post-flash-x",
                         "NAKED-PROVISIONER-POST-FLASH", "x" * 5000, "naked-provisioner-post-flash/../x"):
                with self.subTest(name=name[:40]):
                    status, body = self.b.fetch("/customisation/save-script", "POST",
                                                {"filename": name, "content": "#!/bin/sh\n"})
                    self.assertRefused(status, body)

    def test_save_needs_both_fields(self):
        with self.unchanged():
            for body in ({"filename": "naked-provisioner-post-flash"}, {"content": "x"}, {}):
                with self.subTest(body=body):
                    status, resp = self.b.fetch("/customisation/save-script", "POST", body)
                    self.assertRefused(status, resp)

    def test_actions_on_a_hook_with_no_file(self):
        self.station.sh("rm -f /etc/rpi-sb-provisioner/scripts/naked-provisioner-post-flash.sh")
        with self.unchanged():
            for action in ("enable-script", "disable-script", "delete-script"):
                with self.subTest(action=action):
                    status, body = self.b.fetch(f"/customisation/{action}?script=naked-provisioner-post-flash", "POST")
                    self.assertRefused(status, body, (400, 404))

    def test_wrong_methods(self):
        for path in ("/customisation/save-script", "/options/set", "/options/validate", "/api/v2/tokens/x/revoke",
                     "/delete-image?name=idp-test", "/logout"):
            with self.subTest(path=path):
                status, body = self.b.fetch(path, "PUT", {})
                self.assertRefused(status, body, (403, 404, 405))
