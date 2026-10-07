"""The bootloader configuration editor: what devices' EEPROMs are set to.

Saving writes /etc/rpi-sb-provisioner/bootloader.<kind>, which bootstrap
signs into the EEPROM, so every step is checked on the station too.
"""
from ui.harness.case import UITest

EDITED = "/etc/rpi-sb-provisioner/bootloader."
DEFAULT = "/var/lib/rpi-sb-provisioner/bootloader."


class BootloaderConfig(UITest):
    def setUp(self):
        super().setUp()
        self.station.sh(f"rm -f {EDITED}secure {EDITED}naked")
        self.station.set_config(RPI_DEVICE_BOOTLOADER_CONFIG_FILE="")

    def open(self, kind="secure"):
        self.b.get(f"/options/bootloader-config?kind={kind}")
        self.b.el("#bl-save")

    def set_text(self, text):
        self.b.d.execute_script("""
            const t = arguments[0];
            if (window.ace && !document.getElementById('ace-editor').hidden) ace.edit('ace-editor').setValue(t, -1);
            else document.getElementById('editor').value = t;""", text)

    def check(self, content, kind="secure"):
        status, body = self.b.fetch("/options/bootloader-config/check", "POST", {"kind": kind, "content": content})
        self.assertEqual(200, status, body)
        return body

    def test_opens_on_the_package_default(self):
        self.open()
        self.assertClean()
        default = self.station.sh(f"cat {DEFAULT}secure")
        shown = self.b.d.execute_script("return ace.edit('ace-editor').getValue()")
        self.assertEqual(default.strip(), shown.strip())
        self.assertIn("package default", self.b.el("#bl-source").text)
        self.assertFalse(self.b.el("#bl-reset").is_enabled())

    def test_tabs_choose_the_kind_of_device(self):
        self.open("naked")
        self.assertIn("naked", self.b.el(".bl-tabs a[aria-current=page]").text)
        self.b.get("/options/bootloader-config?kind=../../etc/passwd")
        self.assertIn("Secure boot", self.b.el(".bl-tabs a[aria-current=page]").text)

    def test_help_follows_the_setting_under_the_cursor(self):
        self.open()
        self.set_text("# a comment\nBOOT_UART=1\nBOOT_ORDER=0xf41\n")
        self.b.d.execute_script("const e = ace.edit('ace-editor'); e.gotoLine(3, 0, false);")
        self.b.wait_text("#bl-help-body h3", "BOOT_ORDER")
        self.assertIn("boot mode", self.b.el("#bl-help-body").text.lower())
        self.b.d.execute_script("ace.edit('ace-editor').gotoLine(2, 0, false);")
        self.b.wait_text("#bl-help-body h3", "BOOT_UART")
        self.assertIn("CC BY-SA 4.0", self.b.el("#bl-attribution").text)

    def test_search_finds_a_setting_and_shows_it(self):
        self.open()
        search = self.b.el("#bl-search")
        search.send_keys("watchdog")
        names = [b.text for b in self.b.all("#bl-setting-list button")]
        self.assertTrue(names)
        self.assertTrue(all("WATCHDOG" in n for n in names), names)
        self.b.press(self.b.all("#bl-setting-list button")[0])
        self.b.wait_text("#bl-help-body h3", "WATCHDOG")

    def test_checks_each_line(self):
        body = self.check("[all]\nBOOT_UART=1\nnot a setting\nBOOT_ORDER=first\nNO_SUCH_THING=1\n[pi5\n")
        errors = {(e["line"], e["message"].split(" ")[0]) for e in body["errors"]}
        self.assertIn((3, "Not"), errors)
        self.assertIn((4, "BOOT_ORDER"), errors)
        self.assertIn((6, "A"), errors)
        self.assertEqual([5], [w["line"] for w in body["warnings"]])

    def test_counts_what_bootstrap_adds_against_the_eeprom_limit(self):
        body = self.check("BOOT_UART=1")
        self.assertEqual(len("BOOT_UART=1\nSIGNED_BOOT=1\n"), body["bytes"])
        self.assertEqual(len("BOOT_UART=1\n"), self.check("BOOT_UART=1", "naked")["bytes"])
        big = "# " + "x" * 4100 + "\n"
        self.assertTrue(any("at most 4076" in e["message"] for e in self.check(big)["errors"]))
        warn = self.check("SIGNED_BOOT=0\n")["warnings"]
        self.assertTrue(any("SIGNED_BOOT=1" in w["message"] for w in warn), warn)

    def test_refuses_control_characters(self):
        self.assertTrue(self.check("BOOT_UART=1\x1b[31m\n")["errors"])

    def test_save_writes_the_file_and_reset_removes_it(self):
        self.open()
        self.set_text("[all]\nBOOT_UART=1\nBOOT_ORDER=0xf14")
        self.b.click("#bl-save")
        self.b.wait_text("#bl-status", "Saved")
        self.assertEqual("[all]\nBOOT_UART=1\nBOOT_ORDER=0xf14\n", self.station.sh(f"cat {EDITED}secure"))
        self.assertEqual("644", self.station.sh(f"stat -c %a {EDITED}secure").strip())
        self.assertTrue(self.b.el("#bl-reset").is_enabled())
        self.b.get("/options/get")
        tile = self.b.el("#bootloader-tile-secure")
        self.assertIn("Edited", tile.text)
        self.assertIn("USB \u2192 SD/eMMC \u2192 restart", tile.text, "0xf14, read right to left, in words")
        self.open()
        self.b.d.execute_script("window.confirm = () => true")
        self.b.click("#bl-reset")
        self.b.wait_text("#bl-status", "Reset")
        self.assertEqual("absent", self.station.sh(f"test -e {EDITED}secure && echo present || echo absent").strip())
        self.b.get("/auditlog?event_type=FILE_ACCESS&limit=50")
        text = self.b.text()
        self.assertIn("BOOTLOADER_CONFIG_SAVE", text)
        self.assertIn("BOOTLOADER_CONFIG_RESET", text)

    def test_a_config_with_errors_is_not_saved(self):
        self.open()
        self.set_text("BOOT_ORDER=soon\n")
        self.b.click("#bl-save")
        self.b.wait_text("#bl-status", "Not saved")
        self.assertIn("BOOT_ORDER", self.b.el("#bl-findings").text)
        self.assertEqual("absent", self.station.sh(f"test -e {EDITED}secure && echo present || echo absent").strip())

    def test_says_when_a_named_file_is_used_instead(self):
        self.station.set_config(RPI_DEVICE_BOOTLOADER_CONFIG_FILE=f"{DEFAULT}naked")
        try:
            self.open()
            self.assertIn("Not in use", self.b.el(".bl-notice").text)
            self.b.get("/options/get")
            self.assertIn("Overridden", self.b.el("#bootloader-tile-secure").text)
            self.assertIn(f"{DEFAULT}naked", self.b.el(".bootloader-config-advanced").text)
        finally:
            self.station.set_config(RPI_DEVICE_BOOTLOADER_CONFIG_FILE="")

    def test_the_tile_in_use_follows_the_provisioning_style(self):
        for style, kind, other in (("secure-boot", "secure", "naked"), ("naked", "naked", "secure")):
            with self.subTest(style=style):
                self.station.set_config(PROVISIONING_STYLE=style)
                self.b.get("/options/get")
                self.assertIn("In use", self.b.el(f"#bootloader-tile-{kind}").text)
                self.assertNotIn("In use", self.b.el(f"#bootloader-tile-{other}").text)
                self.assertTrue(self.b.el(f"#bootloader-tile-{kind}").get_attribute("href").endswith(f"kind={kind}"))
        self.station.set_config(PROVISIONING_STYLE="naked")

    def test_bad_requests_are_refused(self):
        self.open()
        for payload in ({"kind": "other", "content": ""}, {"kind": "secure"}, {"content": "x"},
                        {"kind": "secure", "content": "x" * 70000}):
            status, _ = self.b.fetch("/options/bootloader-config/save", "POST", payload)
            self.assertIn(status, (400, 413), payload)
        self.assertEqual("absent", self.station.sh(f"test -e {EDITED}secure && echo present || echo absent").strip())
