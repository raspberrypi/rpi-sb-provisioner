"""OS images on the options page: upload, inspect, select, clear, delete."""
import base64
import lzma
import os
import tempfile
import time

from selenium.webdriver.common.by import By

from ui.harness.case import UITest

IMAGES = "/srv/rpi-sb-provisioner/images"


def local_file(name, data):
    d = tempfile.mkdtemp(prefix="rpi-sb-ui-img-")
    path = os.path.join(d, name)
    with open(path, "wb") as f:
        f.write(data)
    return path


class Images(UITest):
    def setUp(self):
        super().setUp()
        self.station.sh(f"rm -rf {IMAGES}/uitest-*")
        self.station.set_config(GOLD_MASTER_OS_FILE="", PROVISIONING_STYLE="naked",
                                RPI_SB_WORKDIR="")
        self.b.get("/options/get")

    def on_station(self, name):
        return self.station.sh(f"test -e {IMAGES}/{name} && echo yes || echo no").strip() == "yes"

    def upload(self, path, timeout=120):
        if not self.b.el("#image-upload-container").is_displayed():
            self.b.click("button.image-upload-btn")
        self.b.el("#image-file-input").send_keys(path)
        self.b.wait_text("#success-message, #error-message", "", timeout=5)
        deadline = time.time() + timeout
        while time.time() < deadline:
            ok = self.b.el("#success-text").text
            bad = self.b.el("#error-text").text
            if "uploaded successfully" in ok:
                return
            if bad:
                self.fail(f"upload failed: {bad}")
            time.sleep(0.5)
        self.fail("upload did not finish")

    def item(self, name, timeout=15):
        return self.b.el(f"#image-list .firmware-item[data-name='{name}']", timeout)

    def open_details(self, name):
        self.b.press(self.item(name))
        self.b.wait_text("#image-details", name)

    def detail_button(self, text):
        return self.b.d.find_element(By.XPATH, f"//*[@id='image-details']//button[contains(., '{text}')]")

    def test_list_shows_the_station_images(self):
        names = [i.get_attribute("data-name") for i in self.b.all("#image-list .firmware-item")]
        on_disk = self.station.sh(f"ls {IMAGES} | grep -v '\\.sha256$'").split()
        self.assertEqual(sorted(on_disk), sorted(names))
        self.assertClean()

    def test_upload_a_plain_image(self):
        self.upload(local_file("uitest-plain.img", os.urandom(2 * 1024 * 1024)))
        self.assertTrue(self.on_station("uitest-plain.img"))
        self.item("uitest-plain.img")
        self.assertFalse(self.b.el("#image-upload-container").is_displayed(), "the upload panel should close")
        self.assertClean()

    def test_upload_a_compressed_image(self):
        raw = os.urandom(1024 * 1024) + bytes(3 * 1024 * 1024)
        self.upload(local_file("uitest-packed.img.xz", lzma.compress(raw)))
        self.assertTrue(self.on_station("uitest-packed.img"), "the image should be stored decompressed")
        self.assertEqual(str(len(raw)), self.station.sh(f"stat -c %s {IMAGES}/uitest-packed.img").strip())

    def test_upload_an_idp_artefact(self):
        src = self.station.sh(f"ls -d {IMAGES}/*/ 2>/dev/null | grep -v uitest | head -1").strip().rstrip("/")
        if not src:
            self.skipTest("no IDP artefact on the station to copy")
        archive = base64.b64decode(self.station.sh(f"tar -C {src} -cf - . | xz | base64 -w0"))
        self.upload(local_file("uitest-idp.tar.xz", archive))
        self.assertTrue(self.on_station("uitest-idp"))
        self.b.get("/options/get")
        self.assertIn("IDP", self.item("uitest-idp").text)
        self.open_details("uitest-idp")
        self.b.wait_text("#image-details", "IDP Metadata", timeout=20)

    def test_the_same_name_twice_keeps_both(self):
        self.upload(local_file("uitest-twice.img", b"a" * 4096))
        self.upload(local_file("uitest-twice.img", b"b" * 4096))
        self.assertTrue(self.on_station("uitest-twice.img"))
        self.assertTrue(self.on_station("uitest-twice_1.img"))

    def test_unsupported_type_is_refused_in_the_browser(self):
        self.b.click("button.image-upload-btn")
        self.b.el("#image-file-input").send_keys(local_file("uitest-bad.exe", b"MZ"))
        self.b.wait_text("#error-text", "Unsupported file type")
        self.assertFalse(self.on_station("uitest-bad.exe"))

    def test_details_of_a_plain_image(self):
        self.station.sh(f"head -c 1048576 /dev/urandom > {IMAGES}/uitest-detail.img")
        expected = self.station.sh(f"sha256sum {IMAGES}/uitest-detail.img").split()[0]
        self.b.get("/options/get")
        self.open_details("uitest-detail.img")
        self.assertIn("Plain image", self.b.el("#image-details").text)
        deadline = time.time() + 60
        while expected not in self.b.el("#image-details").text and time.time() < deadline:
            time.sleep(2)
            self.b.get("/options/get")
            self.open_details("uitest-detail.img")
        self.assertIn(expected, self.b.el("#image-details").text, "the SHA256 shown must be the file's")
        self.assertIn("Not applicable", self.b.el("#image-details").text, "naked style needs no boot package")

    def test_select_and_deselect(self):
        self.station.sh(f"head -c 65536 /dev/zero > {IMAGES}/uitest-select.img")
        self.b.get("/options/get")
        self.open_details("uitest-select.img")
        self.b.press(self.detail_button("Use This Image"))
        self.b.wait_text("#success-text", "selected")
        self.assertEqual(f"{IMAGES}/uitest-select.img",
                         self.station.config().get("GOLD_MASTER_OS_FILE", "").strip("'"))
        self.b.wait_text("#image-details", "Currently selected")
        self.assertIn("Selected", self.item("uitest-select.img").text)
        self.b.press(self.detail_button("Deselect Image"))
        self.b.wait_text("#success-text", "cleared")
        self.assertEqual("", self.station.config().get("GOLD_MASTER_OS_FILE", "").strip("'"))

    def test_delete_asks_and_removes(self):
        self.station.sh(f"head -c 65536 /dev/zero > {IMAGES}/uitest-delete.img")
        self.b.get("/options/get")
        self.open_details("uitest-delete.img")
        self.b.d.execute_script("window.confirm = () => false;")
        self.b.press(self.detail_button("Delete Image"))
        time.sleep(1)
        self.assertTrue(self.on_station("uitest-delete.img"), "cancelling must keep the image")
        self.b.accept_confirm()
        self.b.press(self.detail_button("Delete Image"))
        self.b.wait_text("#success-text", "deleted")
        self.assertFalse(self.on_station("uitest-delete.img"))
        self.assertEqual([], self.b.all("#image-list .firmware-item[data-name='uitest-delete.img']"))

    def test_deleting_the_selected_image_clears_the_selection(self):
        self.station.sh(f"head -c 65536 /dev/zero > {IMAGES}/uitest-chosen.img")
        self.station.set_config(GOLD_MASTER_OS_FILE=f"{IMAGES}/uitest-chosen.img")
        self.b.get("/options/get")
        self.open_details("uitest-chosen.img")
        self.b.accept_confirm()
        self.b.press(self.detail_button("Delete Image"))
        self.b.wait_text("#success-text", "deleted")
        self.assertEqual("", self.station.config().get("GOLD_MASTER_OS_FILE", "").strip("'"))

    def test_clear_cached_files(self):
        workdir = "/srv/rpi-sb-provisioner/uitest-cache"
        self.station.sh(f"install -d -m 0755 {workdir} && touch {workdir}/boot.img "
                        f"&& head -c 65536 /dev/zero > {IMAGES}/uitest-cache.img")
        self.station.set_config(RPI_SB_WORKDIR=workdir)
        self.b.get("/options/get")
        self.open_details("uitest-cache.img")
        self.b.accept_confirm()
        self.b.press(self.detail_button("Clear Cached Files"))
        self.b.wait_text("#success-text", "Cache cleared")
        self.assertEqual("", self.station.sh(f"ls -A {workdir}").strip())
        self.station.sh(f"rm -rf {workdir}")

    def test_clear_cached_files_refuses_an_unsafe_workdir(self):
        self.station.sh(f"head -c 65536 /dev/zero > {IMAGES}/uitest-unsafe.img")
        self.station.set_config(RPI_SB_WORKDIR="/srv/rpi-sb-provisioner")
        self.b.get("/options/get")
        self.open_details("uitest-unsafe.img")
        self.b.accept_confirm()
        self.b.press(self.detail_button("Clear Cached Files"))
        self.b.wait_text("#error-text", "Failed to clear cache")
        self.assertTrue(self.on_station("uitest-unsafe.img"))

    def test_boot_package_needs_a_signing_key(self):
        self.station.set_config(PROVISIONING_STYLE="secure-boot", CUSTOMER_KEY_FILE_PEM="", CUSTOMER_KEY_PKCS11_NAME="")
        self.station.sh(f"head -c 65536 /dev/zero > {IMAGES}/uitest-boot.img")
        self.b.get("/options/get")
        self.open_details("uitest-boot.img")
        self.b.wait_text("#image-details", "Needs a signing key", timeout=20)
        self.assertEqual([], self.b.all("[id^='generate-boot-btn-']"), "no generate button without a key")
