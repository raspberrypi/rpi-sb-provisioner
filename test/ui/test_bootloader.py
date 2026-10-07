"""The bootloader configuration: the package default, or one custom file.

Saving writes /etc/rpi-sb-provisioner/bootloader.conf and names it in
RPI_DEVICE_BOOTLOADER_CONFIG_FILE, which bootstrap signs into the EEPROM, so
every step is checked on the station too.
"""
from ui.harness.case import UITest

CUSTOM = "/etc/rpi-sb-provisioner/bootloader.conf"
DEFAULT = "/var/lib/rpi-sb-provisioner/bootloader."
SETTING = "RPI_DEVICE_BOOTLOADER_CONFIG_FILE"


class BootloaderConfig(UITest):
    def setUp(self):
        super().setUp()
        self.station.sh(f"rm -f {CUSTOM}")
        self.station.set_config(**{SETTING: "", "PROVISIONING_STYLE": "secure-boot", "RPI_DEVICE_STORAGE_TYPE": "emmc",
                                   "RPI_DEVICE_BOOT_ORDER_MATCH_STORAGE": ""})

    def tearDown(self):
        self.station.set_config(**{SETTING: "", "PROVISIONING_STYLE": "naked"})
        super().tearDown()

    def setting(self):
        return self.station.config().get(SETTING, "").strip("'")

    def custom_exists(self):
        return self.station.sh(f"test -e {CUSTOM} && echo yes || echo no").strip() == "yes"

    def open(self):
        self.b.get("/options/bootloader-config")
        self.b.el("#bl-save")

    def set_text(self, text):
        self.b.d.execute_script("""
            const t = arguments[0];
            if (window.ace && !document.getElementById('ace-editor').hidden) ace.edit('ace-editor').setValue(t, -1);
            else document.getElementById('editor').value = t;""", text)

    def save(self, text):
        self.open()
        self.set_text(text)
        self.b.click("#bl-save")
        self.b.wait_text("#bl-status", "Saved")

    def check(self, content):
        status, body = self.b.fetch("/options/bootloader-config/check", "POST", {"content": content})
        self.assertEqual(200, status, body)
        return body

    def tile(self, choice):
        return self.b.el(f"#bootloader-tile-{choice}")

    # --- the editor ---------------------------------------------------------

    def test_a_new_custom_configuration_starts_from_the_default(self):
        self.open()
        self.assertClean()
        default = self.station.sh(f"cat {DEFAULT}secure")
        shown = self.b.d.execute_script("return ace.edit('ace-editor').getValue()")
        self.assertEqual(default.strip(), shown.strip())
        self.assertIn("copy of the package default", self.b.el("#bl-source").text)
        self.assertFalse(self.b.el("#bl-default").is_enabled(), "the default is already in use")

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
        self.b.el("#bl-search").send_keys("watchdog")
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

    def test_signed_boot_is_not_the_operators_concern(self):
        # Secure boot is set by the key in OTP; the setting is redundant.
        self.assertEqual([], self.check("SIGNED_BOOT=0\n")["warnings"])

    def test_counts_what_reaches_the_eeprom_against_its_limit(self):
        self.assertEqual(len("BOOT_UART=1\nSIGNED_BOOT=1\n"), self.check("BOOT_UART=1")["bytes"],
                         "bootstrap still adds SIGNED_BOOT=1 for secure boot, so it must fit")
        self.station.set_config(PROVISIONING_STYLE="naked")
        self.assertEqual(len("BOOT_UART=1\n"), self.check("BOOT_UART=1")["bytes"])
        big = "# " + "x" * 4100 + "\n"
        self.assertTrue(any("at most 4076" in e["message"] for e in self.check(big)["errors"]))

    def test_refuses_control_characters(self):
        self.assertTrue(self.check("BOOT_UART=1\x1b[31m\n")["errors"])

    def test_saving_writes_the_file_and_puts_it_in_use(self):
        self.save("[all]\nBOOT_UART=1\nBOOT_ORDER=0xf14")
        self.assertEqual("[all]\nBOOT_UART=1\nBOOT_ORDER=0xf14\n", self.station.sh(f"cat {CUSTOM}"))
        self.assertEqual("644", self.station.sh(f"stat -c %a {CUSTOM}").strip())
        self.assertEqual(CUSTOM, self.setting())
        self.assertIn("In use", self.b.el("#bl-source").text)
        self.assertTrue(self.b.el("#bl-default").is_enabled())

    def test_using_the_default_keeps_the_custom_file(self):
        self.save("BOOT_ORDER=0xf41\n")
        self.b.click("#bl-default")
        self.b.wait_text("#bl-status", "package default")
        self.assertEqual("", self.setting())
        self.assertTrue(self.custom_exists(), "the custom configuration is kept for later")
        self.b.get("/auditlog?event_type=FILE_ACCESS&limit=50")
        self.assertIn("BOOTLOADER_CONFIG_SAVE", self.b.text())
        self.assertIn("BOOTLOADER_CONFIG_USE", self.b.text())

    def test_a_config_with_errors_is_not_saved(self):
        self.open()
        self.set_text("BOOT_ORDER=soon\n")
        self.b.click("#bl-save")
        self.b.wait_text("#bl-status", "Not saved")
        self.assertIn("BOOT_ORDER", self.b.el("#bl-findings").text)
        self.assertFalse(self.custom_exists())
        self.assertEqual("", self.setting())

    def test_says_when_a_file_managed_elsewhere_is_in_use(self):
        self.station.set_config(**{SETTING: f"{DEFAULT}naked"})
        self.open()
        self.assertIn("Not in use", self.b.el(".bl-notice").text)
        self.b.get("/options/get")
        self.assertIn("selected", self.tile("custom").get_attribute("class"))
        self.assertIn(f"{DEFAULT}naked", self.tile("custom").text)

    def test_bad_requests_are_refused(self):
        self.open()
        for path, payload in (("save", {}), ("save", {"content": 1}), ("save", {"content": "x" * 70000}),
                              ("use", {}), ("use", {"choice": "other"}), ("use", {"choice": "custom"})):
            status, _ = self.b.fetch(f"/options/bootloader-config/{path}", "POST", payload)
            self.assertIn(status, (400, 409, 413), (path, payload))
        self.assertFalse(self.custom_exists())
        self.assertEqual("", self.setting())

    # --- the Options page's tiles ---------------------------------------------

    def test_the_tiles_choose_default_or_custom(self):
        self.save("BOOT_ORDER=0xf641\n")
        self.b.get("/options/get")
        self.assertIn("selected", self.tile("custom").get_attribute("class"))
        self.assertIn("Edit", self.tile("custom").text)
        self.b.press(self.tile("default"))
        self.b.wait_text("body", "default bootloader configuration")
        self.assertEqual("", self.setting())
        self.b.press(self.tile("custom"))
        self.b.wait_text("body", "custom bootloader configuration")
        self.assertEqual(CUSTOM, self.setting())

    def test_only_the_link_opens_the_editor(self):
        # Before a custom configuration exists the tile cannot be chosen,
        # and clicking it goes nowhere; its Create link opens the editor.
        self.b.get("/options/get")
        self.assertIn("unavailable", self.tile("custom").get_attribute("class"))
        self.b.press(self.tile("custom").find_element("css selector", ".tile-description"))
        self.assertEqual("/options/get", self.b.path())
        self.assertNotIn("selected", self.tile("custom").get_attribute("class"))
        self.assertEqual("", self.setting())
        self.b.press(self.tile("custom").find_element("css selector", ".bootloader-edit"))
        self.b.el("#bl-save")
        self.assertEqual("/options/bootloader-config", self.b.path())
        # Once there is one, clicking the tile chooses it and stays on Options.
        self.save("BOOT_ORDER=0xf41\n")
        self.b.click("#bl-default")
        self.b.wait_text("#bl-status", "package default")
        self.b.get("/options/get")
        self.b.press(self.tile("custom").find_element("css selector", ".tile-description"))
        self.b.wait_text("body", "custom bootloader configuration")
        self.assertEqual("/options/get", self.b.path())
        self.assertEqual(CUSTOM, self.setting())

    def test_the_boot_order_follows_the_storage_switch(self):
        self.save("BOOT_ORDER=0xf416\n")
        self.b.get("/options/get")
        order = lambda: self.tile("custom").find_element("css selector", ".bootloader-order").text
        self.assertIn("NVMe → SD/eMMC → USB → Restart", order(), "0xf416, read right to left")
        self.b.press(self.b.el("#RPI_DEVICE_BOOT_ORDER_MATCH_STORAGE"))
        self.assertIn("SD/eMMC → NVMe → USB → Restart", order(), "eMMC moved to the front")
        self.assertEqual("SD/eMMC", self.tile("custom").find_element("css selector", ".order-promoted").text)
