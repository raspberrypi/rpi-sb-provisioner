"""The pages that show records: services and their logs, the manufacturing
database, the audit log, and the code scanner."""
import csv
import glob
import io
import os
import tempfile
import time

from selenium.common.exceptions import StaleElementReferenceException
from selenium.webdriver.support.ui import Select

from ui.harness.browser import Browser, USER
from ui.harness.case import UITest, station

MFG = "/srv/rpi-sb-provisioner/manufacturing.db"
AUDIT = "/srv/rpi-sb-provisioner/audit.db"
UNIT = "rpi-sb-uitest-records"


class Services(UITest):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.station.sh(f"systemctl reset-failed {UNIT} 2>/dev/null; systemd-run --unit={UNIT} --collect --wait "
                       f"sh -c 'for i in $(seq 1 120); do echo uitest line $i; done' >/dev/null")

    def test_table_lists_the_provisioning_units(self):
        self.b.get("/services")
        self.b.el("#services-table-container table")
        self.assertClean()
        links = self.b.all("#services-table-container a.log-link")
        self.assertTrue(links, "expected provisioning units with log links")
        for a in links:
            self.assertRegex(a.get_attribute("href"), r"/service-log/rpi-(sb|naked|fde|idp)-")

    def test_auto_refresh_can_be_paused(self):
        self.b.get("/services")
        self.assertIn("Enabled", self.b.el("#refresh-status").text)
        self.b.press(self.b.el("#auto-refresh"))
        self.assertIn("Disabled", self.b.el("#refresh-status").text)
        table = self.b.el("#services-table-container table")
        time.sleep(2.5)
        try:
            table.is_displayed()
        except StaleElementReferenceException:
            self.fail("the table was rebuilt while auto-refresh was off")

    def test_log_link_opens_the_log(self):
        self.b.get("/services")
        self.b.press(self.b.el("#auto-refresh"))
        link = self.b.el("#services-table-container a.log-link")
        target = link.get_attribute("href")
        self.b.press(link)
        self.b.settle()
        self.assertEqual(target, self.b.d.current_url)
        self.assertIn("Service Log:", self.b.text())
        self.assertClean()


class ServiceLog(UITest):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.station.sh(f"systemctl reset-failed {UNIT} 2>/dev/null; systemd-run --unit={UNIT} --collect --wait "
                       f"sh -c 'for i in $(seq 1 120); do echo uitest line $i; done' >/dev/null")

    def setUp(self):
        super().setUp()
        self.b.get(f"/service-log/{UNIT}.service")
        self.b.press(self.b.el("#auto-refresh"))
        self.b.settle()

    def entries(self):
        return [e.text for e in self.b.all("#logContainer .log-entry")]

    def test_newest_first_by_default_and_oldest_on_request(self):
        first = self.entries()[0]
        Select(self.b.el("#orderSelect")).select_by_value("asc")
        self.b.settle()
        self.assertNotEqual(first, self.entries()[0])

    def test_page_size(self):
        Select(self.b.el("#pageSizeSelect")).select_by_value("25")
        self.b.settle()
        self.assertEqual(25, len(self.entries()))
        self.assertEqual("1", self.b.el("#currentPage").text)

    def test_paging_buttons(self):
        Select(self.b.el("#pageSizeSelect")).select_by_value("25")
        self.b.settle()
        total = int(self.b.el("#totalPages").text)
        self.assertGreater(total, 1)
        self.assertFalse(self.b.el("#prevPageBtn").is_enabled())
        self.assertFalse(self.b.el("#firstPageBtn").is_enabled())
        first_page = self.entries()
        self.b.click("#nextPageBtn")
        self.b.settle()
        self.assertEqual("2", self.b.el("#currentPage").text)
        self.assertNotEqual(first_page, self.entries())
        self.b.click("#lastPageBtn")
        self.b.settle()
        self.assertEqual(str(total), self.b.el("#currentPage").text)
        self.assertFalse(self.b.el("#nextPageBtn").is_enabled())
        self.b.click("#firstPageBtn")
        self.b.settle()
        self.assertEqual("1", self.b.el("#currentPage").text)
        self.assertEqual(first_page, self.entries())

    def test_changing_size_returns_to_the_first_page(self):
        Select(self.b.el("#pageSizeSelect")).select_by_value("25")
        self.b.settle()
        self.b.click("#nextPageBtn")
        self.b.settle()
        Select(self.b.el("#pageSizeSelect")).select_by_value("50")
        self.b.settle()
        self.assertEqual("1", self.b.el("#currentPage").text)

    def test_other_units_are_refused(self):
        self.b.get("/service-log/ssh.service")
        self.assertIn("Only logs for rpi-sb", self.b.text())
        self.assertClean(error_page=True)


class Manufacturing(UITest):
    ROWS = 60

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        values = ",".join(
            f"('uitest board {i}','man{i:05d}','d8:3a:dd:00:00:{i % 100:02d}','','',{i * 1024},'cid{i}','duid-{i}',"
            f"'1.0','BCM2712','8GB','Sony UK',1,{i % 2},NULL,1,0,1,'uitest.img')"
            for i in range(cls.ROWS))
        cls.station.sql(MFG, f"""
            delete from devices where serial like 'man%';
            insert into devices(boardname,serial,eth_mac,wifi_mac,bt_mac,mmc_size,mmc_cid,rpi_duid,board_revision,
              processor,memory,manufacturer,secure,jtag_locked,eeprom_write_protected,pubkey_programmed,
              devkey_revoked,signed_boot_enabled,os_image_filename) values {values};""")
        cls.total = int(cls.station.sql(MFG, "select count(*) from devices;").strip())

    def setUp(self):
        super().setUp()
        self.b.get("/manu-db")
        self.b.el("#manufacturingTable")
        self.b.press(self.b.el("#auto-refresh"))

    def rows(self):
        return self.b.all("#manufacturingTable tbody tr")

    def test_table_and_pages(self):
        self.assertClean()
        self.assertEqual(min(50, self.total), len(self.rows()))
        self.assertIn(f"of {self.total}", self.b.el("#pagination-controls").text)
        self.b.click("#pg-next")
        self.assertEqual(min(50, self.total - 50), len(self.rows()))
        self.b.click("#pg-prev")
        self.assertEqual(min(50, self.total), len(self.rows()))

    def test_page_size(self):
        Select(self.b.el("#pg-size")).select_by_value("25")
        self.assertEqual(25, len(self.rows()))
        pages = self.b.all("button.pg-goto")
        self.assertGreaterEqual(len(pages), (self.total + 24) // 25 if self.total < 250 else 3)

    def test_security_cells_say_yes_and_no(self):
        text = self.b.text()
        self.assertIn("Requested", text)
        self.assertTrue(self.b.all(".security-enabled[aria-label=Yes]"))
        self.assertTrue(self.b.all(".security-disabled[aria-label=No]"))

    def test_csv_export_holds_every_row(self):
        for f in glob.glob(os.path.join(self.b.downloads, "*.csv")):
            os.remove(f)
        self.b.click("#exportCsv")
        deadline = time.time() + 15
        files = []
        while not files and time.time() < deadline:
            files = [f for f in glob.glob(os.path.join(self.b.downloads, "manufacturing_data_*.csv"))]
            time.sleep(0.5)
        self.assertTrue(files, "no CSV was downloaded")
        raw = open(files[0], "rb").read()
        self.assertIn(b"\r\n", raw, "the CSV should use CRLF line endings")
        rows = list(csv.reader(io.StringIO(raw.decode("utf-8-sig"))))
        self.assertIn("eMMC Size (bytes)", rows[0])
        self.assertEqual(self.total, len(rows) - 1, "the export must hold every row, not one page")
        serials = {r[rows[0].index("Serial")] for r in rows[1:]}
        self.assertIn("man00059", serials)

    def test_missing_database_is_reported(self):
        self.station.set_config(RPI_SB_PROVISIONER_MANUFACTURING_DB="/srv/rpi-sb-provisioner/uitest-absent.db")
        try:
            self.b.get("/manu-db")
            self.b.wait_text("#error-container", "Error loading data")
        finally:
            self.station.set_config(RPI_SB_PROVISIONER_MANUFACTURING_DB=MFG)


class AuditLog(UITest):
    def rows(self):
        return self.b.all("#auditLogTable tbody tr:not(:has(td.no-entries))")

    def column(self, name):
        heads = [h.text for h in self.b.all("#auditLogTable thead th")]
        i = heads.index(name)
        return [r.find_elements("css selector", "td")[i].text for r in self.rows()]

    def test_opens_with_entries(self):
        self.b.get("/auditlog")
        self.assertClean()
        self.assertTrue(self.rows(), "the audit log should show entries when first opened")
        self.assertLessEqual(len(self.rows()), 100)
        stamps = self.column("Timestamp")
        self.assertEqual(sorted(stamps, reverse=True), stamps, "newest first")

    def test_a_page_visit_is_recorded(self):
        self.b.get("/services")
        self.b.get("/auditlog")
        self.assertIn("/services", " ".join(self.column("Endpoint / Operation")))

    def test_filter_by_event_type(self):
        self.b.get("/auditlog")
        for value, cls in (("FILE_ACCESS", "event-type-file"), ("HANDLER_ACCESS", "event-type-handler"),
                           ("AUTHENTICATION", "event-type-auth")):
            with self.subTest(event=value):
                Select(self.b.el("#event_type")).select_by_value(value)
                self.b.click("#filterForm button[type=submit]")
                self.b.settle()
                self.assertTrue(self.rows())
                for r in self.rows():
                    self.assertTrue(r.find_elements("css selector", "." + cls), r.text)
                self.assertEqual(value, Select(self.b.el("#event_type")).first_selected_option.get_attribute("value"),
                                 "the chosen filter should stay chosen")

    def test_sign_ins_are_recorded_with_who_and_how(self):
        self.b.sign_out()
        self.b.sign_in(password="not-the-password")
        self.b.sign_in()
        self.b.get("/auditlog?event_type=AUTHENTICATION&limit=50")
        self.assertClean()
        rows = list(zip(self.column("Event Type"), self.column("User"),
                        self.column("Endpoint / Operation"), self.column("Success")))
        # Newest first: this sign-in, then the refused one before it.
        self.assertEqual(("Sign-in", USER, "LOGIN", "Success"), rows[0])
        self.assertEqual(("Sign-in", USER, "LOGIN", "Failed"), rows[1])

    def test_limit_choice(self):
        self.station.sql(AUDIT, "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < 300) "
                                "INSERT INTO audit_log (timestamp, event_type, handler_path) "
                                "SELECT datetime('now','localtime'), 'HANDLER_ACCESS', '/uitest/' || i FROM n;")
        self.b.get("/auditlog")
        for limit in ("50", "250"):
            with self.subTest(limit=limit):
                Select(self.b.el("#limit")).select_by_value(limit)
                self.b.click("#filterForm button[type=submit]")
                self.b.settle()
                self.assertEqual(int(limit), len(self.rows()))

    # A day nothing else writes to, so other tests' entries cannot crowd the
    # planted one out of the page.
    DAY = "2020-06-15"

    def test_end_date_is_a_time_not_a_day(self):
        self.station.sql(AUDIT, f"INSERT INTO audit_log (timestamp, event_type, handler_path) "
                                f"VALUES ('{self.DAY} 12:00:00', 'HANDLER_ACCESS', '/uitest/noon');")
        self.b.get(f"/auditlog?start_date={self.DAY}T00:00&end_date={self.DAY}T11:00&limit=1000")
        self.assertNotIn("/uitest/noon", self.b.text(), "an entry at 12:00 is after an end of 11:00")
        self.b.get(f"/auditlog?start_date={self.DAY}T00:00&end_date={self.DAY}T13:00&limit=1000")
        self.assertIn("/uitest/noon", self.b.text())

    def test_start_date_is_a_time_not_a_day(self):
        self.station.sql(AUDIT, f"INSERT INTO audit_log (timestamp, event_type, handler_path) "
                                f"VALUES ('{self.DAY} 12:00:00', 'HANDLER_ACCESS', '/uitest/midday');")
        self.b.get(f"/auditlog?start_date={self.DAY}T13:00&end_date={self.DAY}T23:00&limit=1000")
        self.assertNotIn("/uitest/midday", self.b.text(), "12:00 is before a start of 13:00")
        self.b.get(f"/auditlog?start_date={self.DAY}T11:00&end_date={self.DAY}T13:00&limit=1000")
        self.assertIn("/uitest/midday", self.b.text(), "12:00 is between 11:00 and 13:00")


def qr_video(text, width=640, height=480):
    """A camera feed showing a QR code of text, for Chromium's fake camera."""
    import qrcode
    import subprocess
    d = tempfile.mkdtemp(prefix="rpi-sb-ui-qr-")
    png, y4m = os.path.join(d, "qr.png"), os.path.join(d, "qr.y4m")
    qrcode.make(text, border=4, box_size=10).save(png)
    subprocess.run(["ffmpeg", "-loglevel", "error", "-y", "-loop", "1", "-i", png, "-t", "4", "-r", "10",
                    "-vf", f"scale={width}:{height}:force_original_aspect_ratio=decrease,"
                           f"pad={width}:{height}:(ow-iw)/2:(oh-ih)/2:white",
                    "-pix_fmt", "yuv420p", y4m], check=True)
    return y4m


class Scanner(UITest):
    """The scanner, reading a real QR code from Chromium's fake camera."""
    KNOWN = "uitest-duid-scan"

    @classmethod
    def setUpClass(cls):
        cls.station = station()
        cls.station.sql(MFG, "delete from devices where serial='scan0001'; "
                             "insert into devices(boardname,serial,eth_mac,wifi_mac,bt_mac,mmc_size,mmc_cid,"
                             "rpi_duid,board_revision,processor,memory,manufacturer) values "
                             f"('b','scan0001','','','',0,'','{cls.KNOWN}','','','','');")

    @classmethod
    def tearDownClass(cls):
        pass  # each test opens, and closes, its own browser

    def setUp(self):
        pass

    def open_scanner(self, code, width=640, height=480):
        self.b = Browser(self.station.url, extra_args=(
            "--use-fake-ui-for-media-stream", "--use-fake-device-for-media-stream",
            "--use-file-for-fake-video-capture=" + qr_video(code, width, height)))
        self.addCleanup(self.b.quit)
        self.b.sign_in()
        self.b.get("/scantool")

    def test_a_recorded_device_is_found(self):
        self.open_scanner(self.KNOWN)
        self.b.wait_text("#success-container", self.KNOWN, timeout=30)
        self.assertIn("recorded in the manufacturing database", self.b.el("#success-container").text)
        self.assertClean()

    def test_an_hd_camera_works_too(self):
        # 640x480 above is a basic webcam, which a 720p minimum once refused.
        self.open_scanner(self.KNOWN, 1280, 720)
        self.b.wait_text("#success-container", self.KNOWN, timeout=30)

    def test_an_unknown_code_is_reported(self):
        self.open_scanner("uitest-duid-none")
        self.b.wait_text("#error-container", "No record for uitest-duid-none", timeout=30)

    def test_stop_ends_scanning(self):
        self.open_scanner(self.KNOWN)
        self.b.wait_text("#success-container", self.KNOWN, timeout=30)
        self.b.click("#stop-button")
        self.assertFalse(self.b.el("#success-container").is_displayed())

    def test_debug_panel_toggles(self):
        self.open_scanner(self.KNOWN)
        self.b.click("#toggle-debug")
        self.assertTrue(self.b.el("#debug-panel").is_displayed())
        self.b.click("#toggle-debug")
        self.assertFalse(self.b.el("#debug-panel").is_displayed())

    def test_verification_api(self):
        self.open_scanner(self.KNOWN)
        self.assertTrue(self.b.fetch("/api/v2/verify-qrcode", "POST", {"qrcode": self.KNOWN})[1]["exists"])
        self.assertFalse(self.b.fetch("/api/v2/verify-qrcode", "POST", {"qrcode": "uitest-duid-none"})[1]["exists"])
