"""A station whose firmware is too old for rpi-fw-crypto is offered a button
that stages a bootloader update; one without /dev/vcio_crypto is told to
update its OS instead. rpi-eeprom-update is replaced by a stand-in, and a
plain file stands in for /dev/vcio_crypto, which then cannot answer."""

import time

from ui.harness.case import UITest

UNIT = "rpi-sb-station-bootloader-update.service"
DROPIN = f"/run/systemd/system/{UNIT}.d/uitest.conf"
# Not /var/tmp, private to the unit, nor /run, which is noexec.
FAKE = "/usr/local/bin/uitest-eeprom-update"
STATUS = "/run/rpi-sb-provisioner/station-bootloader-update.status"

# What rpi-eeprom-update prints, and its exit status, for each result.
OUTCOMES = {
    # A Pi 5 writes with flashrom there and then, as the CM5 jig showed.
    "updated": ("flashrom -p linux_spi:dev=/dev/spidev10.0,spispeed=16000 -w /boot/firmware/pieeprom.upd\n"
                "Verifying update\nVERIFY: SUCCESS\nUPDATE SUCCESSFUL", 0),
    "staged": ("BOOTLOADER: update available\nEEPROM updates pending. Please reboot to apply the update.", 0),
    "current": ("BOOTLOADER: up to date", 0),
    "not-enabled": ("rpi-eeprom-update is not enabled by default on CM4(S).", 0),
    "frozen": ("EEPROM version is frozen. Skipping automatic update", 3),
    "failed": ("UPDATE FAILED: no space left on /boot/firmware", 2),
}


class StationBootloader(UITest):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.station.set_config(PROVISIONING_STYLE="secure-boot")

    @classmethod
    def tearDownClass(cls):
        cls.station.sh(f"rm -f /dev/vcio_crypto {FAKE} {STATUS}; rm -rf $(dirname {DROPIN}); "
                       "systemctl daemon-reload", check=False)
        cls.station.restart_ui()
        super().tearDownClass()

    def plant(self, node):
        self.station.sh(("touch /dev/vcio_crypto" if node else "rm -f /dev/vcio_crypto"))
        self.station.restart_ui()
        self.b.sign_in(here=False)

    def outcome(self, name):
        text, rc = OUTCOMES[name]
        self.station.put(FAKE, f"#!/bin/sh\nprintf '%s\\n' '{text}'\nexit {rc}\n", mode="0755")
        self.station.sh(f"mkdir -p $(dirname {DROPIN})")
        self.station.put(DROPIN, f"[Service]\nEnvironment=RPI_EEPROM_UPDATE={FAKE}\n")
        self.station.sh("systemctl daemon-reload")

    def result(self):
        for _ in range(30):
            status, body = self.b.fetch("/options/station-bootloader-update")
            if body.get("state") not in ("running", "none"):
                return body
            time.sleep(1)
        return body

    def test_without_the_device_the_os_is_blamed(self):
        self.plant(node=False)
        status, body = self.b.fetch("/options/device-key-status")
        self.assertFalse(body["can_update_bootloader"], body)
        self.assertIn("no /dev/vcio_crypto", body["reason"])
        self.assertIn("update Raspberry Pi OS", body["remedy"])
        status, body = self.b.fetch("/options/update-station-bootloader", method="POST")
        self.assertEqual(409, status, body)

    def test_each_result_is_reported(self):
        self.plant(node=True)
        status, body = self.b.fetch("/options/device-key-status")
        self.assertTrue(body["can_update_bootloader"], body)
        self.assertIn("does not answer the crypto service", body["reason"])
        for name in OUTCOMES:
            with self.subTest(name):
                self.outcome(name)
                status, body = self.b.fetch("/options/update-station-bootloader", method="POST")
                self.assertEqual(202, status, body)
                body = self.result()
                self.assertEqual(name, body["state"], body)
                self.assertIn(OUTCOMES[name][0].splitlines()[-1], body["output"])

    def test_only_a_post_starts_it(self):
        self.plant(node=True)
        status, _ = self.b.fetch("/options/update-station-bootloader")
        self.assertEqual(405, status)

    def test_the_button_stages_and_asks_for_a_reboot(self):
        self.plant(node=True)
        self.outcome("staged")
        self.b.get("/options/get")
        self.b.visible("#station-bootloader-btn", timeout=20)
        self.b.accept_confirm()
        self.b.click("#station-bootloader-btn")
        self.b.wait_text("#device-key-feedback", "Reboot this station", timeout=40)
        self.assertClean()
