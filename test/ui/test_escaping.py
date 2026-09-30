"""Every page, over text somebody else wrote.

Markup that closes an attribute, a script and a JS string is planted wherever
others control what the UI shows: what boards report and record, what a USB
device says it is, image and log names, hooks, the journal, and the audit log.
Each page must show it as text and never run it. Each test also counts the
payloads shown, so a page that stops displaying the data fails rather than
passing by showing nothing.
"""
import http.client
import shlex
import urllib.parse

from ui.harness.browser import payload
from ui.harness.case import UITest

SERIAL = "cafe0000cafe0001"
LOGDIR = f"/var/log/rpi-sb-provisioner/{SERIAL}"
GADGET = "/sys/kernel/config/usb_gadget/uitest-hostile"
UNIT = "rpi-sb-uitest-hostile"


def short(n):
    """For names that cannot hold '/' and strings USB caps at 126 bytes."""
    return ('"><img src=x onerror=window.__xss=(window.__xss||[]).concat(%d)>'
            "';window.__xss=(window.__xss||[]).concat(%d);x='") % (n, n)


def q(s):
    return s.replace("'", "''")


IMAGE = "uitest-" + short(31) + ".img"


class Escaping(UITest):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        s = cls.station
        p = {n: q(payload(n)) for n in range(1, 30)}
        s.sql("/srv/rpi-sb-provisioner/state.db", f"""
            delete from devices where serial like 'cafe%' or serial like '%onerror%';
            insert into devices(serial,endpoint,state,image,ip_address,board_type) values
              ('{SERIAL}','{p[1]}','{p[2]}','{p[3]}','{p[4]}','{p[5]}'),
              ('{p[6]}','3-9','{p[7]}','x','x','x');""")
        s.sql("/srv/rpi-sb-provisioner/manufacturing.db", f"""
            delete from devices where serial='cafe0001';
            insert into devices(boardname,serial,eth_mac,wifi_mac,bt_mac,mmc_size,mmc_cid,rpi_duid,
              board_revision,processor,memory,manufacturer,os_image_filename,connect_device_id,
              customer_key_label)
            values('{p[11]}','cafe0001','{p[12]}','{p[13]}','{p[14]}',0,'{p[15]}','{p[16]}','{p[17]}',
              '{p[18]}','{p[19]}','{p[20]}','{p[21]}','{p[22]}','{p[23]}');""")
        s.sh(f"head -c 1048576 /dev/zero > /srv/rpi-sb-provisioner/images/{shlex.quote(IMAGE)}")
        s.put("/etc/rpi-sb-provisioner/scripts/naked-provisioner-post-flash.sh", payload(41))
        s.sh(f"mkdir -p {LOGDIR}")
        s.put(f"{LOGDIR}/triage.log", payload(71) + "\n")
        s.sh(f"systemctl reset-failed {UNIT} 2>/dev/null; "
             f"systemd-run --unit={UNIT} --collect --wait printf '%s\\n' {shlex.quote(payload(51))} >/dev/null")
        # The audit log records the username of a failed sign-in.
        u = urllib.parse.urlsplit(cls.b.base)
        c = http.client.HTTPConnection(u.hostname, u.port, timeout=30)
        c.request("POST", "/login", urllib.parse.urlencode({"username": short(61), "password": "x"}),
                  {"Content-Type": "application/x-www-form-urlencoded", "Origin": cls.b.base})
        c.getresponse().read()
        cls.gadget = cls._hostile_usb_device()

    @classmethod
    def _hostile_usb_device(cls):
        """A USB device whose descriptor strings are payloads, if the
        station has a spare gadget controller (dummy_hcd num=2)."""
        out = cls.station.sh(f"""
            modprobe usb_f_acm 2>/dev/null
            U=$(ls /sys/class/udc 2>/dev/null | while read u; do
                  grep -qx "$u" /sys/kernel/config/usb_gadget/*/UDC 2>/dev/null || echo "$u"; done | head -1)
            [ -n "$U" ] || exit 0
            G={GADGET}
            mkdir -p $G/strings/0x409 $G/configs/c.1/strings/0x409 $G/functions/acm.0
            echo 0x1d6b > $G/idVendor; echo 0x0104 > $G/idProduct
            printf '%s' {shlex.quote(short(81))} > $G/strings/0x409/manufacturer
            printf '%s' {shlex.quote(short(82))} > $G/strings/0x409/product
            printf '%s' {shlex.quote(short(83))} > $G/strings/0x409/serialnumber
            echo c > $G/configs/c.1/strings/0x409/configuration
            [ -e $G/configs/c.1/acm.0 ] || ln -s $G/functions/acm.0 $G/configs/c.1/
            echo $U > $G/UDC && sleep 2 && echo attached
        """, check=False)
        return "attached" in out

    @classmethod
    def tearDownClass(cls):
        cls.station.sh(f"""
            G={GADGET}
            if [ -d $G ]; then echo "" > $G/UDC 2>/dev/null; rm -f $G/configs/c.1/acm.0
              rmdir $G/configs/c.1/strings/0x409 $G/configs/c.1 $G/functions/acm.0 $G/strings/0x409 $G; fi
            rm -rf {LOGDIR}
        """, check=False)
        super().tearDownClass()

    def check(self, page, at_least):
        self.b.get(page)
        self.assertClean(page)
        self.assertGreaterEqual(self.b.payloads_shown(), at_least,
                                f"{page} no longer shows the planted text, so proves nothing")

    def test_devices(self):
        if not self.gadget:
            self.skipTest("no spare USB gadget controller for a hostile device")
        self.check("/devices", 2)
        for view in self.b.all("[data-view], .view-toggle button, .tab-button"):
            try:
                view.click()
            except Exception:
                continue
            self.b.settle()
            self.assertClean(f"/devices, view {view.text!r}")

    def test_device_detail(self):
        self.check(f"/devices/{SERIAL}", 5)

    def test_device_log(self):
        self.check(f"/devices/{SERIAL}/log/triage", 1)

    def test_images(self):
        self.check("/images/list", 1)

    def test_image_metadata(self):
        self.check("/get-image-metadata?name=" + urllib.parse.quote(IMAGE), 1)

    def test_options(self):
        self.check("/options/get", 1)

    def test_hook(self):
        self.check("/customisation/get-script?script=naked-provisioner-post-flash", 1)

    def test_hook_list(self):
        self.check("/customisation/list-scripts", 0)

    def test_service_log(self):
        self.check(f"/service-log/{UNIT}.service", 1)

    def test_manufacturing(self):
        self.check("/manu-db", 12)

    def test_audit_log(self):
        self.check("/auditlog", 1)
