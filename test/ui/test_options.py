"""The options page: every control saves what it shows, and only that."""
import os
import time

from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys

from ui.harness.case import UITest

WORKDIR = "/srv/rpi-sb-provisioner/uitest-workdir"


class Options(UITest):
    def setUp(self):
        super().setUp()
        self.station.set_config(PROVISIONING_STYLE="naked", RPI_DEVICE_FAMILY="5", RPI_DEVICE_STORAGE_TYPE="emmc",
                                RPI_DEVICE_RPIBOOT_GPIO="", RPI_CONNECT_API_KEY="", RPI_CONNECT_DESCRIPTION="",
                                RPI_DEVICE_LOCK_JTAG="", RPI_DEVICE_EEPROM_WP_SET="", RPI_SB_WORKDIR="",
                                RPI_DEVICE_FIRMWARE_FILE="", GOLD_MASTER_OS_FILE="")
        self.b.get("/options/get")

    def cfg(self, key):
        return self.station.config().get(key, "").strip("'")

    def type_and_leave(self, field, text):
        el = self.b.el("#" + field)
        el.clear()
        el.send_keys(text)
        el.send_keys(Keys.TAB)

    def saved(self, field, value=None):
        """Waits for the save to reach the station. The page's "Saved" can
        vanish at once when saves come quickly, since each save's timer to
        clear it is not cancelled by the next, so it is only a fallback."""
        if value is None:
            self.b.wait_text(f"#feedback-{field}", "Saved")
            return
        deadline = time.time() + 15
        while time.time() < deadline:
            if self.cfg(field) == value:
                self.assertNotIn("error", self.b.el(f"#feedback-{field}").get_attribute("class"))
                return
            time.sleep(0.3)
        self.fail(f"{field} never reached {value!r} on the station; it is {self.cfg(field)!r}")

    def refused(self, field, message):
        self.b.wait_text(f"#feedback-{field}", message)
        self.assertIn("invalid", self.b.el("#" + field).get_attribute("class"))

    def choose(self, name, value):
        radio = self.b.d.find_element(By.CSS_SELECTOR, f"input[name='{name}'][value='{value}']")
        self.b.press(radio.find_element(By.XPATH, "./ancestor::label[1]"))
        self.saved(name, value)

    def shown(self, css):
        els = self.b.all(css)
        return bool(els) and els[0].is_displayed()

    def test_page_is_clean_and_shows_the_config(self):
        self.assertClean()
        self.assertTrue(self.b.d.find_element(By.CSS_SELECTOR, "input[name=PROVISIONING_STYLE][value=naked]").is_selected())
        self.assertTrue(self.b.d.find_element(By.CSS_SELECTOR, "input[name=RPI_DEVICE_FAMILY][value='5']").is_selected())
        self.assertTrue(self.b.d.find_element(By.CSS_SELECTOR, "input[name=RPI_DEVICE_STORAGE_TYPE][value=emmc]").is_selected())
        for section in ("#section-os-image", "#section-device-firmware", "#section-security"):
            self.assertTrue(self.b.all(section), f"{section} is missing")

    def test_text_field_saves_on_leaving_it(self):
        self.type_and_leave("RPI_CONNECT_DESCRIPTION", "line 2 station")
        self.saved("RPI_CONNECT_DESCRIPTION")
        self.assertEqual("line 2 station", self.cfg("RPI_CONNECT_DESCRIPTION"))
        self.b.get("/options/get")
        self.assertEqual("line 2 station", self.b.el("#RPI_CONNECT_DESCRIPTION").get_attribute("value"))

    def test_invalid_text_is_refused_and_not_saved(self):
        self.type_and_leave("RPI_CONNECT_API_KEY", "has a space")
        self.refused("RPI_CONNECT_API_KEY", "must not contain whitespace")
        self.assertEqual("", self.cfg("RPI_CONNECT_API_KEY"))

    def test_connect_key_is_hidden_until_asked(self):
        el = self.b.el("#RPI_CONNECT_API_KEY")
        self.assertEqual("password", el.get_attribute("type"))
        self.b.click("[aria-label='Toggle access token visibility']")
        self.assertEqual("text", el.get_attribute("type"))

    def test_checkboxes_save_one_or_nothing(self):
        for field in ("RPI_DEVICE_LOCK_JTAG", "RPI_DEVICE_EEPROM_WP_SET", "RPI_DEVICE_BOOT_ORDER_MATCH_STORAGE"):
            with self.subTest(field=field):
                box = self.b.el("#" + field)
                before = box.is_selected()
                self.b.press(box)
                self.saved(field, "" if before else "1")
                self.b.press(box)
                self.saved(field, "1" if before else "")

    def test_provisioning_style_tiles(self):
        for style in ("secure-boot", "fde-only", "naked"):
            with self.subTest(style=style):
                self.choose("PROVISIONING_STYLE", style)
                self.assertEqual(style, self.cfg("PROVISIONING_STYLE"))
                self.assertEqual(style == "secure-boot", self.shown("#key-config-group"),
                                 "signing keys are for secure boot only")
                self.assertEqual(style != "naked", self.shown("#cipher-group"), "a cipher is for encrypted styles")

    def test_zero_2_w_has_no_secure_boot_or_nvme(self):
        self.choose("RPI_DEVICE_FAMILY", "2W")
        self.assertEqual("2W", self.cfg("RPI_DEVICE_FAMILY"))
        self.assertFalse(self.shown("#secure-boot-tile"))
        self.assertTrue(self.shown("#no-secure-boot-notice"))
        self.assertFalse(self.shown("#nvme-tile"))
        self.choose("RPI_DEVICE_FAMILY", "5")
        self.assertTrue(self.shown("#secure-boot-tile"))
        self.assertTrue(self.shown("#nvme-tile"))

    def test_rpiboot_gpio_only_for_pi_4_secure_boot(self):
        self.choose("PROVISIONING_STYLE", "secure-boot")
        self.choose("RPI_DEVICE_FAMILY", "4")
        self.assertTrue(self.shown("#rpibootGpioGroup"))
        from selenium.webdriver.support.ui import Select
        Select(self.b.el("#RPI_DEVICE_RPIBOOT_GPIO")).select_by_value("7")
        self.saved("RPI_DEVICE_RPIBOOT_GPIO", "7")
        self.choose("RPI_DEVICE_FAMILY", "5")
        self.assertFalse(self.shown("#rpibootGpioGroup"))

    def test_storage_type_tiles(self):
        for kind in ("sd", "nvme", "emmc"):
            with self.subTest(kind=kind):
                self.choose("RPI_DEVICE_STORAGE_TYPE", kind)
                self.assertEqual(kind, self.cfg("RPI_DEVICE_STORAGE_TYPE"))

    def test_cipher(self):
        self.choose("PROVISIONING_STYLE", "fde-only")
        for cipher in ("xchacha12,aes-adiantum-plain64", "aes-xts-plain64"):
            with self.subTest(cipher=cipher):
                self.choose("RPI_DEVICE_STORAGE_CIPHER", cipher)
                self.assertEqual(cipher, self.cfg("RPI_DEVICE_STORAGE_CIPHER"))

    def test_workdir_is_checked_and_emptied_on_save(self):
        self.type_and_leave("RPI_SB_WORKDIR", "/no/such/parent/workdir")
        self.refused("RPI_SB_WORKDIR", "Parent directory does not exist")
        self.station.sh(f"install -d -m 0755 {WORKDIR} && touch {WORKDIR}/stale.sig")
        self.b.get("/options/get")
        self.type_and_leave("RPI_SB_WORKDIR", WORKDIR)
        self.saved("RPI_SB_WORKDIR")
        self.assertEqual(WORKDIR, self.cfg("RPI_SB_WORKDIR"))
        self.assertEqual("", self.station.sh(f"ls -A {WORKDIR}").strip(), "a save empties the cache")
        self.station.sh(f"rm -rf {WORKDIR}")

    def test_a_workdir_that_holds_the_images_is_never_emptied(self):
        self.station.set_config(RPI_SB_WORKDIR="/srv/rpi-sb-provisioner")
        self.b.get("/options/get")
        before = self.station.sh("ls /srv/rpi-sb-provisioner/images")
        self.type_and_leave("RPI_CONNECT_DESCRIPTION", "save with an unsafe workdir")
        self.saved("RPI_CONNECT_DESCRIPTION")
        self.assertEqual(before, self.station.sh("ls /srv/rpi-sb-provisioner/images"))
        self.assertTrue(before.strip(), "the station should have an image to protect")

    def test_manufacturing_database_path(self):
        self.type_and_leave("RPI_SB_PROVISIONER_MANUFACTURING_DB", "")
        self.refused("RPI_SB_PROVISIONER_MANUFACTURING_DB", "mandatory")
        self.type_and_leave("RPI_SB_PROVISIONER_MANUFACTURING_DB", "/srv")
        self.refused("RPI_SB_PROVISIONER_MANUFACTURING_DB", "directory")

    def test_key_tabs_switch_panels(self):
        self.choose("PROVISIONING_STYLE", "secure-boot")
        for tab in ("pkcs11", "pem"):
            with self.subTest(tab=tab):
                self.b.click(f"button.key-tab[data-tab={tab}]")
                self.assertIn("active", self.b.el(f".key-panel[data-panel={tab}]").get_attribute("class"))

    def test_pin_needs_a_value(self):
        self.choose("PROVISIONING_STYLE", "secure-boot")
        self.b.click("button.key-tab[data-tab=pkcs11]")
        self.b.click("#pin-save-btn")
        self.b.wait_text("#feedback-pkcs11-pin", "Please enter a PIN")

    def test_status_panels_fill_in(self):
        self.choose("PROVISIONING_STYLE", "secure-boot")
        self.b.click("button.key-tab[data-tab=pkcs11]")
        self.b.settle()
        self.assertTrue(self.b.el("#pkcs11-provider-status").text.strip())
        self.assertTrue(self.b.el("#pin-status").text.strip())
        self.assertClean()


class IdpImage(UITest):
    """An IDP artefact fixes the board and cipher; the page must say so."""

    def setUp(self):
        super().setUp()
        idp = self.station.sh("ls -d /srv/rpi-sb-provisioner/images/*/ 2>/dev/null | head -1").strip().rstrip("/")
        if not idp:
            self.skipTest("no IDP artefact on the station")
        self.station.set_config(GOLD_MASTER_OS_FILE=idp, PROVISIONING_STYLE="naked")
        self.b.get("/options/get")

    def test_fixed_settings_are_marked(self):
        self.assertTrue(self.b.all(".idp-locked-badge"), "settings the artefact fixes should say 'Set by image'")
        self.assertIn("Set by image", self.b.text())
        self.assertTrue(self.b.all(".idp-locked"))
        self.assertClean()

    def test_full_disk_encryption_only_is_not_offered(self):
        self.assertFalse(self.b.el("#fde-only-tile").is_displayed())


class Firmware(UITest):
    def setUp(self):
        super().setUp()
        self.station.set_config(RPI_DEVICE_FIRMWARE_FILE="", RPI_DEVICE_FAMILY="5", GOLD_MASTER_OS_FILE="")
        self.b.get("/options/get")
        self.b.click("#firmware-expand-btn")
        self.b.settle()

    def items(self):
        return self.b.all("#firmware-list .firmware-item")

    def test_browser_lists_the_installed_firmware(self):
        if not self.items():
            self.skipTest("no bootloader firmware installed on the station")
        self.assertTrue(self.b.el("#firmware-browser").is_displayed())
        self.assertIn("expanded", self.b.el("#firmware-expand-btn").get_attribute("class"))
        for item in self.items():
            # /lib is a link to /usr/lib on merged-/usr systems.
            self.assertRegex(item.get_attribute("data-path"), r"^(/usr)?/lib/firmware/raspberrypi/bootloader-")
        self.assertClean()

    def test_notes_show_for_the_chosen_version(self):
        if not self.items():
            self.skipTest("no bootloader firmware installed on the station")
        item = self.items()[0]
        version = item.get_attribute("data-version")
        self.b.press(item)
        self.b.wait_text("#firmware-notes", version)

    def test_choose_and_revert(self):
        if not self.items():
            self.skipTest("no bootloader firmware installed on the station")
        item = self.items()[0]
        path = item.get_attribute("data-path")
        self.b.press(item)
        self.b.settle()
        self.b.press(self.b.d.find_element(By.XPATH, "//div[@id='firmware-notes']//button[contains(., 'Use This Firmware')]"))
        self.b.settle()
        self.assertEqual(path, self.station.config().get("RPI_DEVICE_FIRMWARE_FILE", "").strip("'"))
        self.assertIn("Selected", self.b.el(f"#firmware-list .firmware-item[data-path='{path}']").text)
        self.b.press(self.b.d.find_element(By.XPATH, "//div[@id='firmware-notes']//button[contains(., 'Use Default Firmware')]"))
        self.b.settle()
        self.assertEqual("", self.station.config().get("RPI_DEVICE_FIRMWARE_FILE", "").strip("'"))

    def test_button_names_the_firmware_that_will_be_used(self):
        if not self.items():
            self.skipTest("no bootloader firmware installed on the station")
        newest = self.station.sh("ls /lib/firmware/raspberrypi/bootloader-2712/latest/ | "
                                 "grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' | sort | tail -n 1").strip()
        self.assertIn(f"Automatic: {newest}", self.b.el("#firmware-current").text)
        item = self.items()[-1]
        version = item.get_attribute("data-version")
        self.b.press(item)
        self.b.settle()
        self.b.press(self.b.d.find_element(By.XPATH, "//div[@id='firmware-notes']//button[contains(., 'Use This Firmware')]"))
        self.b.settle()
        self.assertIn(f"Selected: {version}", self.b.el("#firmware-current").text)
        self.b.get("/options/get")
        self.b.wait_text("#firmware-current", f"Selected: {version}")


class KeyUpload(UITest):
    """Adding a signing key works as adding an OS image does. The test VM has
    no firmware crypto to wrap a key at rest, so the upload is intercepted."""

    def setUp(self):
        super().setUp()
        # A Pi 5 with no IDP image, the only setup that shows the key section.
        self.station.set_config(PROVISIONING_STYLE="secure-boot", RPI_DEVICE_FAMILY="5", GOLD_MASTER_OS_FILE="")
        self.b.get("/options/get")
        # An HSM key left by another test opens the PKCS#11 tab instead.
        self.b.click(".key-tab[data-tab=pem]")

    def tearDown(self):
        self.station.set_config(PROVISIONING_STYLE="naked")
        super().tearDown()

    def test_the_panel_opens_from_the_keyboard(self):
        toggle = self.b.el("#key-upload-toggle")
        self.assertEqual("false", toggle.get_attribute("aria-expanded"))
        self.assertFalse(self.b.el("#key-upload-container").is_displayed())
        toggle.send_keys(Keys.ENTER)
        self.assertEqual("true", toggle.get_attribute("aria-expanded"))
        self.assertTrue(self.b.el("#key-upload-container").is_displayed())
        toggle.send_keys(Keys.TAB)
        self.assertIn("upload-choose", self.b.d.switch_to.active_element.get_attribute("class"))

    def upload_answered(self, activated):
        self.b.d.execute_script("""
            window.__sent = null;
            const real = window.fetch;
            window.fetch = function (url, init) {
                if (String(url).includes('/options/upload-key')) {
                    window.__sent = {activate: init.body.get('activate'), name: init.body.get('keyfile').name};
                    return Promise.resolve(new Response(JSON.stringify({success: true, activated: arguments[0]}),
                                                        {status: 200, headers: {'Content-Type': 'application/json'}}));
                }
                return real.apply(this, arguments);
            };""".replace("arguments[0]}", "%s}" % ("true" if activated else "false")))
        self.b.click("#key-upload-toggle")
        path = os.path.join(self.b.downloads, "uitest-upload.pem")
        with open(path, "w") as f:
            f.write("-----BEGIN PRIVATE KEY-----\nnot really\n-----END PRIVATE KEY-----\n")
        self.b.el("#key-file-input").send_keys(path)
        deadline = time.time() + 10
        while time.time() < deadline and not self.b.d.execute_script("return window.__sent"):
            time.sleep(0.2)
        return self.b.d.execute_script("return window.__sent")

    def test_a_new_key_does_not_replace_the_one_in_use(self):
        sent = self.upload_answered(activated=False)
        self.assertEqual({"activate": "if-none", "name": "uitest-upload.pem"}, sent)
        self.b.wait_text("body", "Choose Use beside it")
        self.assertFalse(self.b.el("#key-upload-container").is_displayed(), "the panel closes once the key is added")

    def test_the_first_key_is_used_straight_away(self):
        self.upload_answered(activated=True)
        self.b.wait_text("body", "the only key")
