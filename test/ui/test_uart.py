"""UART capture: the console of the board on a jig head, kept beside its
other logs. The daemon's handling of a real terminal is tested in CTest
against a pseudo-terminal; this tests the unit, the scripts and the page."""
import time

from ui.harness.case import UITest

STATE = "/srv/rpi-sb-provisioner/state.db"
SERIAL = "uart0001"
CONF = "/etc/rpi-sb-provisioner/uart.d/90-ui-test.conf"
PORT = "9-9"


class Service(UITest):
    sign_in_first = False

    def tearDown(self):
        self.station.sh(f"rm -f {CONF} /var/log/rpi-sb-provisioner/uart/{PORT}.log*; "
                        "systemctl reset-failed rpi-sb-uart-capture; systemctl restart rpi-sb-uart-capture; true")
        super().tearDown()

    def restart(self):
        since = self.station.sh("date '+%Y-%m-%d %H:%M:%S'").strip()
        # Tests restart it more often than systemd's start limit allows.
        self.station.sh("systemctl reset-failed rpi-sb-uart-capture; systemctl restart rpi-sb-uart-capture")
        time.sleep(2)
        return since

    def journal(self, since):
        return self.station.sh(f"journalctl -u rpi-sb-uart-capture --since '{since}' --no-pager -o cat")

    def test_it_is_enabled(self):
        self.assertEqual("enabled", self.station.sh(
            "systemctl is-enabled rpi-sb-uart-capture", check=False).strip())

    def test_with_nothing_mapped_it_exits_cleanly(self):
        self.station.sh(f"rm -f {CONF}")
        since = self.restart()
        state = self.station.sh("systemctl show -p ActiveState -p Result -p ExecMainStatus rpi-sb-uart-capture")
        self.assertIn("ActiveState=inactive", state)
        self.assertIn("Result=success", state)
        self.assertIn("nothing to capture", self.journal(since))

    def test_a_mapped_port_gets_a_log_and_the_uart_is_reached(self):
        # The VM's ttyS0 has no hardware behind it, so opening it fails with
        # an I/O error, not the permission error the unit's device policy
        # would give.
        self.station.sh(f"printf '{PORT} /dev/ttyS0\\n' > {CONF}")
        since = self.restart()
        self.assertEqual("active", self.station.sh(
            "systemctl is-active rpi-sb-uart-capture", check=False).strip())
        said = self.journal(since)
        self.assertIn(f"{PORT} (/dev/ttyS0): cannot", said)
        self.assertIn("Input/output error; retrying", said)
        self.assertNotIn("not permitted", said)
        self.assertEqual("yes", self.station.sh(
            f"[ -f /var/log/rpi-sb-provisioner/uart/{PORT}.log ] && echo yes || echo no").strip())

    def test_a_bad_line_is_reported_and_skipped(self):
        self.station.sh(f"printf '{PORT} /dev/ttyS0\\n4-* /dev/ttyS1\\n' > {CONF}")
        since = self.restart()
        said = self.journal(since)
        self.assertIn("is not a USB port path", said)
        self.assertIn(f"{PORT} (/dev/ttyS0)", said)


# Runs uart_window, through record_state, from the installed state-recording,
# as each stage would, with the capture's directories moved aside.
STAGES = r"""
set -e
W=$(mktemp -d)
export UART_WINDOW_DIR=$W/run UART_LOG_DIR=$W/log
mkdir -p $W/log && touch $W/log/{port}.log
. /var/lib/rpi-sb-provisioner/state-recording
show() {{ echo "== $1"; cat $UART_WINDOW_DIR/{port}.window 2>/dev/null | tr '\n' ' '; echo; }}
{body}
rm -rf $W
"""


class Windows(UITest):
    sign_in_first = False

    def tearDown(self):
        self.station.sql(STATE, f"delete from devices where serial in ('{SERIAL}', '/dev/bus/usb/009/009');")
        super().tearDown()

    def stages(self, body, port=PORT):
        return self.station.sh(STAGES.format(port=port, body=body))

    def section(self, out, name):
        return out.split(f"== {name}\n", 1)[1].split("\n", 1)[0]

    def test_a_board_is_followed_from_bootstrap_to_its_provisioner_finishing(self):
        out = self.stages(f"""
            record_state /dev/bus/usb/009/009 BOOTSTRAP-STARTED {PORT}; show bootstrap
            record_state {SERIAL} BOOTSTRAP-FINISHED {PORT}; show bootstrapped
            record_state {SERIAL} TRIAGE-STARTED {PORT}; show triage
            record_state {SERIAL} SB-PROVISIONER-FINISHED {PORT}; show finished
            record_state {SERIAL} SB-PROVISIONER-ABORTED {PORT}; show again
        """)
        boot = self.section(out, "bootstrap")
        self.assertRegex(boot, r"^start=\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.000Z ")
        # Known only by its device path, the board's log is kept by port.
        self.assertIn(f"log=/var/log/rpi-sb-provisioner/{PORT}/uart.log", boot)
        self.assertEqual(boot, self.section(out, "bootstrapped"))
        start = boot.split()[0]
        self.assertEqual(f"{start} log=/var/log/rpi-sb-provisioner/{SERIAL}/uart.log",
                         self.section(out, "triage").strip())
        finished = self.section(out, "finished")
        self.assertRegex(finished, rf"^{start} end=\S+Z log=/var/log/rpi-sb-provisioner/{SERIAL}/uart.log")
        self.assertEqual(finished, self.section(out, "again"), "a closed window stays closed")

    def test_the_next_board_starts_after_the_last_ones_tail(self):
        out = self.stages(f"""
            record_state {SERIAL} BOOTSTRAP-STARTED {PORT}
            record_state {SERIAL} TRIAGE-ABORTED {PORT}; show aborted
            record_state {SERIAL} BOOTSTRAP-STARTED {PORT}; show next
        """)
        end = self.section(out, "aborted").split("end=")[1].split()[0]
        start = self.section(out, "next").split("start=")[1].split()[0]
        self.assertGreater(start, end)
        self.assertNotIn("end=", self.section(out, "next"))

    def test_an_unmapped_port_is_left_alone(self):
        out = self.station.sh(f"""
            W=$(mktemp -d)
            export UART_WINDOW_DIR=$W/run UART_LOG_DIR=$W/log
            . /var/lib/rpi-sb-provisioner/state-recording
            set -e
            record_state {SERIAL} BOOTSTRAP-STARTED {PORT}
            record_state {SERIAL} BOOTSTRAP-STARTED ../../etc
            echo "survived: $(ls $W)"
            rm -rf $W
        """)
        self.assertIn("survived: \n", out + "\n")


class Page(UITest):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.station.sql(STATE, f"""
            delete from devices where serial='{SERIAL}';
            insert into devices(serial,endpoint,state,image,ip_address,board_type) values
              ('{SERIAL}','{PORT}','SB-PROVISIONER-FINISHED','','','18');""")
        cls.station.sh(f"mkdir -p /var/log/rpi-sb-provisioner/{SERIAL} && printf '%s\\n' "
                       f"'2026-11-04T14:38:09.000Z   5.94 MFG_VER: 3' "
                       f"'2026-11-04T14:38:29.000Z [    8.92] fastbootd: <b>Couldn'\"'\"'t</b> read command' "
                       f"> /var/log/rpi-sb-provisioner/{SERIAL}/uart.log")

    @classmethod
    def tearDownClass(cls):
        cls.station.sql(STATE, f"delete from devices where serial='{SERIAL}';")
        cls.station.sh(f"rm -rf /var/log/rpi-sb-provisioner/{SERIAL}")
        super().tearDownClass()

    def test_the_device_page_shows_what_the_board_printed(self):
        self.b.get(f"/devices/{SERIAL}")
        log = self.b.el("#uart-log .log-content").text
        self.assertIn("MFG_VER: 3", log)
        self.assertIn("fastbootd: <b>Couldn't</b> read command", log, "shown as text, not markup")
        self.assertClean()

    def test_the_log_route_serves_it(self):
        status, body = self.b.fetch(f"/devices/{SERIAL}/log/uart")
        self.assertEqual(200, status)
        self.assertIn("fastbootd:", body if isinstance(body, str) else str(body))

    def test_a_device_with_nothing_captured_has_no_section(self):
        self.station.sh(f"mv /var/log/rpi-sb-provisioner/{SERIAL}/uart.log /var/log/rpi-sb-provisioner/{SERIAL}/uart.keep")
        try:
            self.b.get(f"/devices/{SERIAL}")
            self.assertEqual([], self.b.all("#uart-log"))
        finally:
            self.station.sh(f"mv /var/log/rpi-sb-provisioner/{SERIAL}/uart.keep /var/log/rpi-sb-provisioner/{SERIAL}/uart.log")
