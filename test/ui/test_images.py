"""OS images on the options page: upload, inspect, select, clear, delete."""
import base64
import hashlib
import lzma
import os
import struct
import tempfile
import time

from selenium.webdriver.common.by import By

from ui.harness.case import UITest

IMAGES = "/srv/rpi-sb-provisioner/images"
LOCKS = "/srv/rpi-sb-provisioner/locks/os-image"


def disk_image(length, declared=4 * 1024 * 1024):
    """A disk image whose MBR declares partitions ending at declared bytes,
    truncated or padded to length: shorter than declared is cut short."""
    mbr = bytearray(512)
    struct.pack_into("<4xB3xII", mbr, 446, 0x0C, 2048, declared // 512 - 2048)
    mbr[510:512] = b"\x55\xaa"
    body = bytes(mbr) + os.urandom(64 * 1024)
    return (body + bytes(max(0, length - len(body))))[:length]


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
        # The last upload's message stays in the page, hidden.
        self.b.d.execute_script("for (const id of ['success-text', 'error-text'])"
                                " document.getElementById(id).textContent = '';")
        self.b.el("#image-file-input").send_keys(path)
        self.b.wait_text("#success-message, #error-message", "", timeout=5)
        deadline = time.time() + timeout
        while time.time() < deadline:
            ok = self.b.el("#success-text").text
            bad = self.b.el("#error-text").text
            if ok.startswith(("Uploaded ", "Replaced ")):
                return ok
            if bad:
                self.fail(f"upload failed: {bad}")
            time.sleep(0.5)
        self.fail("upload did not finish")

    def upload_refused(self, path, timeout=120):
        """Uploads, expecting the station to refuse; returns why."""
        if not self.b.el("#image-upload-container").is_displayed():
            self.b.click("button.image-upload-btn")
        # The last upload's message stays in the page, hidden.
        self.b.d.execute_script("for (const id of ['success-text', 'error-text'])"
                                " document.getElementById(id).textContent = '';")
        self.b.el("#image-file-input").send_keys(path)
        deadline = time.time() + timeout
        while time.time() < deadline:
            bad = self.b.el("#error-text").text
            if bad:
                return bad
            ok = self.b.el("#success-text").text
            if ok.startswith(("Uploaded ", "Replaced ")):
                self.fail(f"upload should have been refused: {ok}")
            time.sleep(0.5)
        self.fail("upload neither finished nor failed")

    def restart_ui(self):
        """Restarts the web UI. Sessions live in its memory, so sign in again."""
        self.station.restart_ui()
        self.b.sign_in()

    def sha_on_station(self, name):
        return self.station.sh(f"sha256sum {IMAGES}/{name}").split()[0]

    def leftovers(self):
        return self.station.sh(f"ls -A {IMAGES} | grep '^\\.' || true").split()

    def item(self, name, timeout=15):
        return self.b.el(f"#image-list .firmware-item[data-name='{name}']", timeout)

    def open_details(self, name):
        self.b.press(self.item(name))
        self.b.wait_text("#image-details", name)

    def detail_button(self, text):
        return self.b.d.find_element(By.XPATH, f"//*[@id='image-details']//button[contains(., '{text}')]")

    def test_list_shows_the_station_images(self):
        names = [i.get_attribute("data-name") for i in self.b.all("#image-list .firmware-item")]
        on_disk = self.station.sh(f"ls {IMAGES} | grep -v '\\.sha256$' | grep -vx bootimg-output").split()
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
        src = self.station.sh(f"ls -d {IMAGES}/*/ 2>/dev/null | grep -v -e uitest -e bootimg-output | head -1").strip().rstrip("/")
        if not src:
            self.skipTest("no IDP artefact on the station to copy")
        archive = base64.b64decode(self.station.sh(f"tar -C {src} -cf - . | xz | base64 -w0"))
        self.upload(local_file("uitest-idp.tar.xz", archive))
        self.assertTrue(self.on_station("uitest-idp"))
        self.b.get("/options/get")
        self.assertIn("IDP", self.item("uitest-idp").text)
        self.open_details("uitest-idp")
        self.b.wait_text("#image-details", "IDP Metadata", timeout=20)

    def test_the_same_name_replaces_it(self):
        self.upload(local_file("uitest-twice.img", b"a" * 4096))
        said = self.upload(local_file("uitest-twice.img", b"b" * 8192))
        self.assertIn("Replaced uitest-twice.img (was 4096 bytes, now 8192 bytes)", said)
        self.assertEqual([], self.station.sh(f"ls {IMAGES} | grep '^uitest-twice_' || true").split(),
                         "no renamed copy alongside")
        want = hashlib.sha256(b"b" * 8192).hexdigest()
        self.assertEqual(want, self.sha_on_station("uitest-twice.img"))
        # The sidecar speaks for this image, and says which one it is.
        sidecar = self.station.sh(f"cat {IMAGES}/uitest-twice.img.sha256").split()
        identity = self.station.sh(f"stat -c '%d:%i:%s:%.9Y' {IMAGES}/uitest-twice.img").strip()
        self.assertEqual([want, identity], sidecar)
        self.assertEqual([], self.leftovers())

    def test_a_cut_short_image_is_refused(self):
        whole = disk_image(4 * 1024 * 1024)
        self.upload(local_file("uitest-short.img", whole))
        why = self.upload_refused(local_file("uitest-short.img", whole[:3 * 1024 * 1024]))
        self.assertIn("cut short", why)
        self.assertIn("3.1 MB, but its MBR partition table needs 4.2 MB", why)
        self.assertEqual(hashlib.sha256(whole).hexdigest(), self.sha_on_station("uitest-short.img"),
                         "the image already there must be untouched")
        self.assertEqual([], self.leftovers())

    def hold_image(self, name):
        """Holds an image as a provisioning run does, until the test ends."""
        self.station.sh(f"""
            systemctl stop uitest-hold 2>/dev/null || true
            systemd-run --quiet --collect --unit=uitest-hold sh -c \
                '. /usr/bin/rpi-sb-common.sh; hold_gold_master_os {IMAGES}/{name} && exec sleep 600'
            for i in $(seq 50); do
                flock -n -x {LOCKS}/{name}.lock true || exit 0
                sleep 0.1
            done
            echo never held >&2; exit 1
        """)
        self.addCleanup(lambda: self.station.sh("systemctl stop uitest-hold 2>/dev/null || true", check=False))

    def test_an_image_in_use_is_neither_replaced_nor_deleted(self):
        self.upload(local_file("uitest-busy.img", b"a" * 4096))
        self.hold_image("uitest-busy.img")
        self.b.get("/options/get")
        why = self.upload_refused(local_file("uitest-busy.img", b"b" * 4096))
        self.assertIn("being provisioned", why)
        status, _ = self.b.fetch("/delete-image?name=uitest-busy.img", "POST")
        self.assertEqual(409, status)
        self.assertEqual(hashlib.sha256(b"a" * 4096).hexdigest(), self.sha_on_station("uitest-busy.img"))

        # The run ends: its lock goes with it, with nothing to clean up.
        self.station.sh("systemctl stop uitest-hold")
        self.b.get("/options/get")
        self.assertIn("Replaced", self.upload(local_file("uitest-busy.img", b"b" * 4096)))
        self.assertEqual([], self.leftovers())

    def test_restart_mid_upload_keeps_the_old_image(self):
        self.upload(local_file("uitest-kill.img", b"a" * 4096))
        self.b.get("/options/get")
        # Slow enough to be caught part way, gentle on the station's network.
        self.b.d.set_network_conditions(offline=False, latency=0, download_throughput=-1,
                                        upload_throughput=1024 * 1024)
        self.addCleanup(self.b.d.delete_network_conditions)
        self.b.click("button.image-upload-btn")
        self.b.el("#image-file-input").send_keys(local_file("uitest-kill.img", os.urandom(16 * 1024 * 1024)))
        staging = f"{IMAGES}/.uitest-kill.img.uploading"
        self.station.sh(f"for i in $(seq 100); do [ -s {staging} ] && exit 0; sleep 0.1; done; exit 1")
        self.station.sh("systemctl kill -s KILL rpi-provisioner-ui")
        self.b.wait_text("#error-text", "connection to the station was lost", timeout=60)

        self.station.wait_for_ui()
        self.b.sign_in()
        self.assertEqual(hashlib.sha256(b"a" * 4096).hexdigest(), self.sha_on_station("uitest-kill.img"))
        self.assertEqual([], self.leftovers(), "the restart must sweep the partial upload")

    def test_startup_sweeps_what_a_crash_left(self):
        self.station.sh(f"""
            head -c 4096 /dev/zero > {IMAGES}/uitest-keep.img
            head -c 4096 /dev/zero > {IMAGES}/.uitest-crash.img.uploading
            mkdir -p {IMAGES}/.uitest-crash.extracting {IMAGES}/.uitest-gone.old
            touch {IMAGES}/.uitest-crash.extracting/part {IMAGES}/.uitest-keep.img.sha256.Ab12Cd.tmp
        """)
        self.b.get("/options/get")
        names = [i.get_attribute("data-name") for i in self.b.all("#image-list .firmware-item")]
        self.assertFalse([n for n in names if n.startswith(".")], "a partial upload is not an image")

        since = self.station.now()
        self.restart_ui()
        self.assertEqual([], self.leftovers())
        self.assertTrue(self.on_station("uitest-keep.img"))
        self.assertIn("Removed .uitest-crash.img.uploading", self.station.journal("rpi-provisioner-ui", since))

    def test_a_sidecar_counts_only_for_the_image_it_describes(self):
        fake = "f" * 64
        # Stopped, or the running UI hashes the new image over the planted sidecar.
        self.station.sh(f"""
            systemctl stop rpi-provisioner-ui
            head -c 65536 /dev/urandom > {IMAGES}/uitest-side.img
            printf '%s %s\\n' {fake} "$(stat -c '%d:%i:%s:%.9Y' {IMAGES}/uitest-side.img)" \
                > {IMAGES}/uitest-side.img.sha256
        """)
        self.restart_ui()
        self.b.get("/options/get")
        self.open_details("uitest-side.img")
        self.assertIn(fake, self.b.el("#image-details").text, "a matching sidecar saves hashing again")

        # A bare hash, as earlier releases wrote, could be about any image.
        self.station.sh(f"printf '%s\\n' {fake} > {IMAGES}/uitest-side.img.sha256")
        self.restart_ui()
        real = self.sha_on_station("uitest-side.img")
        deadline = time.time() + 60
        while time.time() < deadline:
            self.b.get("/options/get")
            self.open_details("uitest-side.img")
            if real in self.b.el("#image-details").text:
                break
            time.sleep(2)
        self.assertIn(real, self.b.el("#image-details").text)
        self.assertNotIn(fake, self.b.el("#image-details").text)

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

    def test_fde_only_has_no_boot_package(self):
        # The generator signs boot.img, and makes nothing for fde-only.
        self.station.set_config(PROVISIONING_STYLE="fde-only")
        self.station.sh(f"head -c 65536 /dev/zero > {IMAGES}/uitest-fde.img")
        self.b.get("/options/get")
        self.open_details("uitest-fde.img")
        self.b.wait_text("#image-details", "Not applicable", timeout=20)
        self.assertEqual([], self.b.all("[id^='generate-boot-btn-']"))
        status, _ = self.b.fetch("/generate-boot-package?name=uitest-fde.img", "POST", {})
        self.assertEqual(400, status)

    def test_boot_package_needs_a_signing_key(self):
        self.station.set_config(PROVISIONING_STYLE="secure-boot", CUSTOMER_KEY_FILE_PEM="", CUSTOMER_KEY_PKCS11_NAME="")
        self.station.sh(f"head -c 65536 /dev/zero > {IMAGES}/uitest-boot.img")
        self.b.get("/options/get")
        self.open_details("uitest-boot.img")
        self.b.wait_text("#image-details", "Needs a signing key", timeout=20)
        self.assertEqual([], self.b.all("[id^='generate-boot-btn-']"), "no generate button without a key")


class ImageCaches(UITest):
    """The provisioners' per-image caches, driven through rpi-sb-common.sh."""
    WORKDIR = "/srv/rpi-sb-provisioner/uitest-workdir"

    def setUp(self):
        super().setUp()
        self.station.sh(f"rm -rf {self.WORKDIR} {IMAGES}/uitest-cache* && install -d -m 0700 {self.WORKDIR}")
        self.addCleanup(lambda: self.station.sh(
            f"systemctl stop uitest-cache-hold 2>/dev/null; rm -rf {self.WORKDIR} {IMAGES}/uitest-cache*",
            check=False))

    def cache_for(self, image):
        """The directory a provisioning run would cache in, for image now."""
        return self.station.sh(f"""
            . /usr/bin/rpi-sb-common.sh
            GOLD_MASTER_OS_FILE={IMAGES}/{image} RPI_SB_WORKDIR={self.WORKDIR}
            use_workdir_for_gold_master || exit 1
            touch "$RPI_SB_WORKDIR/rootfs-temporary.simg"
            echo "$RPI_SB_WORKDIR"
        """).strip()

    def replace(self, image):
        self.station.sh(f"head -c 4096 /dev/urandom > {IMAGES}/.{image}.new && mv {IMAGES}/.{image}.new {IMAGES}/{image}")

    def test_a_replaced_image_gets_a_fresh_cache(self):
        self.station.sh(f"touch {self.WORKDIR}/rootfs-temporary.simg")
        self.replace("uitest-cache.img")
        first = self.cache_for("uitest-cache.img")
        self.assertTrue(first.startswith(f"{self.WORKDIR}/image-"))
        self.assertEqual(first, self.cache_for("uitest-cache.img"), "the same image keeps its cache")
        self.assertEqual("", self.station.sh(f"ls {self.WORKDIR}/rootfs-temporary.simg 2>/dev/null || true").strip(),
                         "a cache from before per-image directories is of an unknown image")

        self.replace("uitest-cache.img")
        second = self.cache_for("uitest-cache.img")
        self.assertNotEqual(first, second)
        self.assertEqual("no", self.station.sh(f"test -e {first} && echo yes || echo no").strip(),
                         "nothing holds the old cache, so it goes")

    def test_a_cache_in_use_is_kept(self):
        self.replace("uitest-cache.img")
        first = self.cache_for("uitest-cache.img")
        self.station.sh(f"systemd-run --quiet --collect --unit=uitest-cache-hold flock -s {first}/.in-use sleep 600"
                        f" && sleep 1")
        self.replace("uitest-cache.img")
        self.cache_for("uitest-cache.img")
        self.assertEqual("yes", self.station.sh(f"test -e {first}/rootfs-temporary.simg && echo yes || echo no").strip(),
                         "a run still flashing from the old image keeps its cache")
        self.station.sh("systemctl stop uitest-cache-hold")
        self.cache_for("uitest-cache.img")
        self.assertEqual("no", self.station.sh(f"test -e {first} && echo yes || echo no").strip())


class BootPackages(UITest):
    """A boot package is offered only while it was built from the image now at
    its name. Needs a signing key: RPI_SB_TEST_SIGNING_KEY names a PEM file,
    such as usbboot's secure-boot-example/example-private.pem."""
    KEY = "/etc/rpi-sb-provisioner/keys/uitest-signing.pem"
    OUTPUT = f"{IMAGES}/bootimg-output"

    def setUp(self):
        super().setUp()
        source = os.environ.get("RPI_SB_TEST_SIGNING_KEY")
        if not source:
            self.skipTest("set RPI_SB_TEST_SIGNING_KEY to a PEM signing key")
        with open(source, "rb") as f:
            self.station.put(self.KEY, f.read(), mode="0600")
        self.station.set_config(PROVISIONING_STYLE="secure-boot", RPI_DEVICE_FAMILY="5",
                                CUSTOMER_KEY_FILE_PEM=self.KEY, CUSTOMER_KEY_PKCS11_NAME="",
                                GOLD_MASTER_OS_FILE="", RPI_SB_WORKDIR="")
        # The generator makes the output directory; leave none where there was none.
        had_output = self.station.sh(f"test -d {self.OUTPUT} && echo yes || echo no").strip() == "yes"
        self.addCleanup(lambda: self.station.sh(
            f"rm -f {self.KEY} {IMAGES}/uitest-sb* {self.OUTPUT}/uitest-sb*"
            + ("" if had_output else f"; rm -rf {self.OUTPUT}"), check=False))

    def put_image(self, name, cmdline):
        """A small Raspberry Pi OS shaped image, put in place as an upload is."""
        self.station.sh(f"""
            set -e
            I=$(mktemp /var/tmp/uitest-sb.XXXXXX)
            truncate -s 48M "$I"
            echo 'start=2048, size=81920, type=c' | sfdisk -q "$I"
            L=$(losetup --show -f -P "$I")
            mkfs.vfat -n BOOT "${{L}}p1" >/dev/null
            M=$(mktemp -d)
            mount "${{L}}p1" "$M"
            printf 'arm_64bit=1\\nauto_initramfs=1\\n' > "$M/config.txt"
            echo '{cmdline}' > "$M/cmdline.txt"
            umount "$M"; rmdir "$M"; losetup -d "$L"
            mv "$I" {IMAGES}/.{name}.new
            mv {IMAGES}/.{name}.new {IMAGES}/{name}
        """)

    def package(self, name, want, timeout=240):
        deadline = time.time() + timeout
        while True:
            status, info = self.b.fetch(f"/get-boot-package-info?name={name}")
            if status == 200 and info.get("status") == want:
                return info
            if time.time() > deadline:
                self.fail(f"boot package for {name} never became {want!r}: {status} {info}")
            time.sleep(2)

    def generate(self, name):
        status, body = self.b.fetch(f"/generate-boot-package?name={name}", "POST", {})
        self.assertIn(status, (200, 202), body)
        return self.package(name, "available")

    def source_identity(self, name):
        base = name.rsplit(".", 1)[0]
        return self.station.sh(f"sed -n 's/^Source identity: //p' {self.OUTPUT}/{base}.package-info.txt").strip()

    def test_a_boot_package_follows_its_image(self):
        self.put_image("uitest-sb.img", "console=serial0 root=PARTUUID=one rootfstype=ext4")
        self.generate("uitest-sb.img")
        identity = self.station.sh(f"stat -c '%d:%i:%s:%.9Y' {IMAGES}/uitest-sb.img").strip()
        self.assertEqual(identity, self.source_identity("uitest-sb.img"))

        # Replaced without regenerating: the old package must not pass for it.
        self.put_image("uitest-sb.img", "console=serial0 root=PARTUUID=two rootfstype=ext4")
        self.package("uitest-sb.img", "stale", timeout=10)
        self.b.get("/options/get")
        self.b.press(self.b.el("#image-list .firmware-item[data-name='uitest-sb.img']"))
        self.b.wait_text("#image-details", "Out of date", timeout=20)
        self.assertClean()

        self.generate("uitest-sb.img")
        self.assertNotEqual(identity, self.source_identity("uitest-sb.img"))

    def test_an_unfinished_package_is_not_offered(self):
        self.put_image("uitest-sb2.img", "console=serial0 root=PARTUUID=three rootfstype=ext4")
        self.generate("uitest-sb2.img")
        # The generator removes the info file first and writes it last; a run
        # cut short in between leaves the package files without it.
        self.station.sh(f"rm {self.OUTPUT}/uitest-sb2.package-info.txt")
        status, info = self.b.fetch("/get-boot-package-info?name=uitest-sb2.img")
        self.assertEqual(200, status)
        self.assertNotEqual("available", info.get("status"))
