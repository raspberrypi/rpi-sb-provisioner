"""The devices page and a device's own page, over real USB devices."""
import time

from ui.harness.case import UITest

GADGET = "/sys/kernel/config/usb_gadget/fastboot"
KNOWN = "cafe0000cafe0003"


class Devices(UITest):
    def usb_devices(self):
        """USB paths of the devices the station can see, from sysfs."""
        return self.station.sh("for d in /sys/bus/usb/devices/[0-9]*-[0-9]*; do "
                               "case $(basename $d) in *:*) ;; *) basename $d;; esac; done").split()

    def gadget_present(self):
        return self.station.sh(f"test -d {GADGET} && echo yes || true").strip() == "yes"

    def test_a_card_for_every_device(self):
        self.b.get("/devices")
        self.assertClean()
        tiles = {t.get_attribute("data-usb-path") for t in self.b.all(".device-tile")}
        for path in self.usb_devices():
            self.assertIn(path, tiles, f"USB device {path} has no card")

    def test_empty_state_is_hidden_when_devices_exist(self):
        self.b.get("/devices")
        if self.b.all(".device-tile"):
            self.assertFalse(self.b.el("#tiles-empty").is_displayed())

    def test_views_switch_and_are_remembered(self):
        self.b.get("/devices")
        for tab, panel, frag in (("#tab-rel", "#rel-view", "rel"), ("#tab-topo", "#topo-view", "topo"),
                                 ("#tab-tiles", "#tiles-view", "tiles")):
            with self.subTest(tab=tab):
                self.b.click(tab)
                self.assertTrue(self.b.el(panel).is_displayed())
                self.assertEqual("true", self.b.el(tab).get_attribute("aria-selected"))
                self.assertTrue(self.b.d.current_url.endswith("#" + frag))
                self.assertEqual(frag, self.b.d.execute_script("return localStorage['devices-active-tab-v2']"))
                self.assertClean()
        self.b.click("#tab-topo")
        self.b.get("/devices")
        self.assertTrue(self.b.el("#topo-view").is_displayed(), "the last view should come back")
        self.b.get("/services")  # a fresh load, as following a link would be
        self.b.d.get(self.b.base + "/devices#rel")
        self.b.settle()
        self.assertTrue(self.b.el("#rel-view").is_displayed(), "a link's view wins over the remembered one")
        self.b.click("#tab-tiles")

    def test_topology_and_port_tree_draw_the_devices(self):
        self.b.get("/devices#rel")
        self.assertTrue(self.b.all("#d3-graph-svg circle.d3-node-circle"), "the map should draw nodes")
        self.b.click("#tab-topo")
        ids = {n.get_attribute("data-id") for n in self.b.all("#topology-root .node.device")}
        for path in self.usb_devices():
            self.assertIn(path, ids, f"USB device {path} is missing from the port tree")
        self.b.click("#tab-tiles")

    def test_card_opens_the_device(self):
        self.b.get("/devices")
        tile = next((t for t in self.b.all(".device-tile") if t.get_attribute("data-serial")), None)
        if tile is None:
            self.skipTest("no device with a serial is connected")
        serial = tile.get_attribute("data-serial")
        self.b.press(tile)
        self.b.settle()
        self.assertEqual(f"/devices/{serial}", self.b.path())
        self.assertClean()

    def test_test_panel_drives_the_cards(self):
        self.b.get("/devices?test=1")
        self.assertIn("visible", self.b.el("#test-panel").get_attribute("class"))
        self.b.wait_text("#test-status", "Status:")
        before = len(self.b.all(".device-tile"))
        try:
            self.b.press(self.b.d.find_element("xpath", "//button[contains(@class,'test-btn') and contains(@onclick,'hub')]"))
            deadline = time.time() + 15
            while len(self.b.all(".device-tile")) <= before and time.time() < deadline:
                time.sleep(0.5)
            self.assertGreater(len(self.b.all(".device-tile")), before, "a test scenario should add cards")
            self.b.wait_text("#test-status", "TEST MODE")
            self.assertClean()
        finally:
            self.b.press(self.b.d.find_element("xpath", "//button[contains(@class,'test-btn') and contains(@onclick,'clear')]"))
            self.b.wait_text("#test-status", "Normal")

    def test_cards_follow_provisioning_live(self):
        if not self.gadget_present():
            self.skipTest("no fastboot gadget on the station to re-plug")
        self.b.get("/devices")
        tile_css = ".device-tile[data-usb-path='3-1']"
        self.b.el(tile_css)
        self.station.sh(f"echo '' > {GADGET}/UDC; sleep 2; echo $(ls /sys/class/udc | head -1) > {GADGET}/UDC")
        seen = set()
        deadline = time.time() + 120
        while time.time() < deadline:
            tiles = self.b.all(tile_css)
            if tiles:
                seen.add(tiles[0].get_attribute("data-state") or "")
                # A card left "finished" by an earlier run must not end the wait
                # before this one has been seen in triage.
                if any("TRIAGE" in s for s in seen) and \
                        any("COMPLETE" in s or "FINISHED" in s and "PROVISIONER" in s for s in seen):
                    break
            time.sleep(0.5)
        self.assertTrue(any("TRIAGE" in s for s in seen), f"the card never showed triage: {seen}")
        self.assertTrue(any("PROVISIONER" in s for s in seen), f"the card never showed provisioning: {seen}")
        self.assertClean()


class DeviceDetail(UITest):
    SERIAL = KNOWN

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.station.sql("/srv/rpi-sb-provisioner/state.db", f"""
            delete from devices where serial='{KNOWN}';
            insert into devices(serial,endpoint,state,image,ip_address,board_type) values
              ('{KNOWN}','3-7','TRIAGE-STARTED','uitest.img','10.9.9.9','5'),
              ('{KNOWN}','3-7','TRIAGE-FINISHED','uitest.img','10.9.9.9','5');""")
        cls.station.sh(f"mkdir -p /var/log/rpi-sb-provisioner/{KNOWN} && "
                       f"echo 'uitest triage line' > /var/log/rpi-sb-provisioner/{KNOWN}/triage.log")

    @classmethod
    def tearDownClass(cls):
        cls.station.sh(f"rm -rf /var/log/rpi-sb-provisioner/{KNOWN} /etc/rpi-sb-provisioner/special-*/{KNOWN}")
        super().tearDownClass()

    def setUp(self):
        super().setUp()
        self.station.sh(f"rm -f /etc/rpi-sb-provisioner/special-*/{KNOWN}")
        self.b.get(f"/devices/{KNOWN}")

    def flag_file(self, flag):
        return self.station.sh(f"cat /etc/rpi-sb-provisioner/special-{flag}/{KNOWN} 2>/dev/null || true").strip()

    def test_shows_what_is_recorded(self):
        self.assertClean()
        self.assertIn(KNOWN, self.b.el("#info-serial").text)
        self.assertIn("3-7", self.b.el("#info-port").text)
        self.assertIn("10.9.9.9", self.b.el("#info-ip").text)
        self.assertIn("uitest.img", self.b.el("#info-image").text)
        history = self.b.el(".state-history-section").text
        self.assertIn("TRIAGE-STARTED", history)
        self.assertIn("TRIAGE-FINISHED", history)
        self.assertIn("uitest triage line", self.b.text())
        self.assertEqual(3, len(self.b.all(".log-section .log-content")))

    def test_live_indicator_connects(self):
        self.b.wait_text("#ws-label", "Live")

    def test_reachable_by_usb_path(self):
        self.b.get("/devices/3-7")
        self.assertIn(KNOWN, self.b.el("#info-serial").text)

    def test_back_link(self):
        self.b.click("#back-link")
        self.b.settle()
        self.assertEqual("/devices", self.b.path())

    def test_back_link_returns_to_the_view_in_use(self):
        self.b.get("/devices")
        self.b.click("#tab-topo")
        self.b.get(f"/devices/{KNOWN}")
        self.assertTrue(self.b.el("#back-link").get_attribute("href").endswith("/devices#topo"))
        self.b.click("#back-link")
        self.b.settle()
        self.assertTrue(self.b.el("#topo-view").is_displayed())
        self.b.click("#tab-tiles")

    def test_flags_set_once_persistent_and_off(self):
        for flag in ("skip-eeprom", "reprovision-device"):
            for mode in ("once", "persistent", "off"):
                with self.subTest(flag=flag, mode=mode):
                    self.b.press(self.b.el(f"#label-{flag}-{mode}"))
                    self.b.wait_text(f"#flag-feedback-{flag}", "Saved")
                    self.assertEqual("" if mode == "off" else mode, self.flag_file(flag))
                    card = self.b.el(f"#flag-card-{flag}").get_attribute("class")
                    self.assertEqual(mode == "persistent", "flag-active " in card + " ")
                    self.assertEqual(mode == "once", "flag-active-once" in card)

    def test_flags_are_shown_after_a_reload(self):
        self.station.sh(f"mkdir -p /etc/rpi-sb-provisioner/special-skip-eeprom && "
                        f"echo persistent > /etc/rpi-sb-provisioner/special-skip-eeprom/{KNOWN}")
        self.b.get(f"/devices/{KNOWN}")
        self.assertTrue(self.b.el("input[name='flag-skip-eeprom'][value=persistent]").is_selected())

    def test_unknown_device_is_an_error_page(self):
        self.b.get("/devices/ffffffffffffffff")
        self.assertIn("Device not found", self.b.text())
        self.assertClean(error_page=True)
