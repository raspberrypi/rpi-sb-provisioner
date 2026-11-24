"""Bootstrap's own log reaches the device's directory whether the run finishes
or fails, with the port's log linked to it, and is never written anywhere
else once triage has taken it over."""

from ui.harness.case import UITest

# file_bootstrap_logs and log, taken from the installed script and run against
# a log root of their own: one early directory, one serial, one port.
FILING = r"""
set -e
B=/usr/bin/rpi-sb-bootstrap.sh
W=$(mktemp -d)
trap 'rm -rf $W' EXIT
eval "$(sed -n '/^log() {/,/^}/p; /^file_bootstrap_logs() {/,/^}/p' $B | sed "s|/var/log/rpi-sb-provisioner|$W/log|g")"
announce_start() { :; }
EARLY_LOG_DIRECTORY=$W/log/early/dev/bus/usb/004/012
TARGET_DEVICE_PATH=/dev/bus/usb/004/012 TARGET_DEVICE_SERIAL=2d0550d4 TARGET_USB_PATH=4-1
REQUESTED_LOCKS=$EARLY_LOG_DIRECTORY/requested-locks MFG_VERSIONS=$EARLY_LOG_DIRECTORY/mfg-versions
mkdir -p $EARLY_LOG_DIRECTORY/metadata $W/log/2d0550d4/metadata $W/log/4-1
echo new > $EARLY_LOG_DIRECTORY/metadata/board.json
echo old > $W/log/2d0550d4/metadata/board.json
echo 'board_mfg_version=3' > $MFG_VERSIONS
ln -sf $EARLY_LOG_DIRECTORY/bootstrap.log $W/log/2d0550d4/bootstrap.log
ln -sf $EARLY_LOG_DIRECTORY/bootstrap.log $W/log/4-1/bootstrap.log
{setup}
"""


class BootstrapLogFiling(UITest):
    sign_in_first = False

    def filing(self, setup):
        return self.station.sh(FILING.replace("{setup}", setup), check=False)

    def test_the_log_and_its_records_reach_the_device(self):
        out = self.filing(r"""
            log "before filing" > /dev/null
            file_bootstrap_logs
            log "after filing" > /dev/null
            [ -L $W/log/2d0550d4/bootstrap.log ] || echo "REAL FILE"
            cat $W/log/2d0550d4/bootstrap.log
            echo "metadata=$(cat $W/log/2d0550d4/metadata/board.json) nested=$(ls $W/log/2d0550d4/metadata | tr '\n' ' ')"
            echo "versions=$(cat $W/log/2d0550d4/mfg-versions)"
            echo "port=$(readlink $W/log/4-1/bootstrap.log)"
            ls $EARLY_LOG_DIRECTORY
        """)
        self.assertIn("REAL FILE", out)
        self.assertIn("] before filing", out)
        self.assertIn("] after filing", out)
        self.assertIn("metadata=new nested=board.json ", out)
        self.assertIn("versions=board_mfg_version=3", out)
        self.assertRegex(out, r"port=/tmp/[^/]+/log/2d0550d4/bootstrap.log")

    def test_filing_twice_changes_nothing(self):
        out = self.filing(r"""
            log "first" > /dev/null
            file_bootstrap_logs
            echo again > $EARLY_LOG_DIRECTORY/bootstrap.log
            file_bootstrap_logs
            cat $W/log/2d0550d4/bootstrap.log
        """)
        self.assertIn("] first", out)
        self.assertNotIn("again", out)

    def test_without_a_serial_the_log_is_filed_by_port(self):
        out = self.filing(r"""
            TARGET_DEVICE_SERIAL=$TARGET_DEVICE_PATH
            log "by port" > /dev/null
            file_bootstrap_logs
            [ -L $W/log/4-1/bootstrap.log ] || echo "REAL FILE"
            cat $W/log/4-1/bootstrap.log
        """)
        self.assertIn("REAL FILE", out)
        self.assertIn("] by port", out)

    def test_a_merged_directory_is_not_recreated(self):
        out = self.filing(r"""
            file_bootstrap_logs
            rm -rf $W/log/2d0550d4
            log "after triage merged it"
            [ -e $W/log/2d0550d4 ] && echo RECREATED || echo ABSENT
        """)
        self.assertIn("] after triage merged it", out)
        self.assertIn("ABSENT", out)

    def test_the_early_log_is_set_before_anything_is_logged(self):
        out = self.station.sh(r"""
            B=/usr/bin/rpi-sb-bootstrap.sh
            first_log=$(grep -n '^ *log ' $B | head -n 1 | cut -d: -f1)
            early=$(grep -n '^EARLY_LOG_DIRECTORY=' $B | cut -d: -f1)
            [ "$early" -lt "$first_log" ] && echo ORDERED
        """, check=False)
        self.assertIn("ORDERED", out)


class DuplicateDescriptor(UITest):
    """A board offers several USB descriptors, and each starts a bootstrap;
    those that find the board taken end cleanly, not as failed units."""
    sign_in_first = False

    def test_a_duplicate_ends_cleanly(self):
        # The VM's USB keyboard stands in for the board; holding its lock
        # makes this run the duplicate.
        out = self.station.sh(r"""
            S=10000000fedcba98
            for d in /dev/bus/usb/*/*; do
                [ "$(udevadm info --name=$d --query=property --property=ID_SERIAL_SHORT --value 2>/dev/null)" = $S ] && D=$d
            done
            L=/var/lock/rpi-sb-bootstrap/$S
            # Its own unit name, so the journal holds this run alone.
            U=uitest-duplicate-$$
            Q="select count(*) from devices where serial='$S'"
            before=$(sqlite3 /srv/rpi-sb-provisioner/state.db "$Q")
            mkdir -p $L
            systemd-run --wait --quiet -p Type=notify -p NotifyAccess=all --unit $U /usr/bin/rpi-sb-bootstrap.sh $D; echo "rc=$?"
            echo "result=$(systemctl show -p Result --value $U 2>/dev/null)"
            journalctl --no-pager -o cat -u $U | grep -E '^\[.*already in progress' | head -1
            echo "new rows=$(( $(sqlite3 /srv/rpi-sb-provisioner/state.db "$Q") - before ))"
            rmdir $L; systemctl reset-failed $U 2>/dev/null; true
        """, check=False)
        self.assertIn("rc=0", out)
        self.assertNotIn("result=exit-code", out)
        self.assertIn("leaving the board to it", out)
        self.assertIn("new rows=0", out)
