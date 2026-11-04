"""Bootloader manufacture versions: a board's OTP names the oldest bootloader
it runs, and bootstrap refuses an older one before writing anything."""
from ui.harness.case import UITest

SERIAL = "mfgv0001"

# Runs check_bootloader_mfg_version from the installed rpi-sb-common.sh, as
# bootstrap would, against a stand-in rpiboot that reports {hardware} and
# prints what it was asked to serve. Bootstrap's own log, die and
# record_state print instead.
CHECK = r"""
. /usr/bin/rpi-sb-common.sh
W=$(mktemp -d)
RPI_SB_WORKDIR=$W METADATA_DIR=$W/meta MFG_VERSIONS=$W/mfg-versions MFG_VERSION_CACHE=$W/cache
BOARD_MFG_VER="" BOARD_MFG_VER_READ="" BOOTSTRAP_ABORTED=BOOTSTRAP-ABORTED
TARGET_DEVICE_SERIAL={serial} TARGET_DEVICE_PATH=/dev/bus/usb/001/009 TARGET_USB_PATH=1-1
BOOTLOADER_UPDATE_IMAGE=/usr/lib/firmware/raspberrypi/bootloader-2712/default/pieeprom-2026-09-12.bin
PROVISION_FAILURE_FLAG=$W/permanent
mkdir -p "$METADATA_DIR" "$MFG_VERSION_CACHE"
{remembered}
log() {{ echo "LOG: $*"; }}
die() {{ echo "DIE: $* [reason=$PROVISION_FAILED_REASON permanent=$PROVISION_FAILURE_PERMANENT]"; exit 3; }}
record_state() {{ echo "STATE: $2"; }}
timeout_fatal_secs() {{ shift; "$@"; }}
rpiboot() {{
    echo "RPIBOOT: $(ls "$4" | tr '\n' ' ')| $(tr '\n' ';' < "$4/config.txt")"
    printf '{{\n\t"USER_SERIAL_NUM": "{serial}"{hardware}\n}}\n' > "$2/{serial}.json"
}}
S=$W/serve
mkdir -p "$S"
printf 'program_pubkey=1\nbootloader_allow_mfg_downgrade=1\nrecovery_reboot=1\n' > "$S/config.txt"
echo code > "$S/bootcode5.bin"
echo sig > "$S/pieeprom.sig"
{image}
trap 'echo "VERSIONS: $(tr "\n" ";" < $MFG_VERSIONS 2>/dev/null)"; echo "CACHE: $(cat $MFG_VERSION_CACHE/* 2>/dev/null)"; echo "CONFIG: $(tr "\n" ";" < $S/config.txt)"; rm -rf $W' EXIT
check_bootloader_mfg_version "$S"
echo PASSED
"""


def hardware_info(version):
    return f',\n\t"HARDWARE_INFO": "{version << 16:08x}"' if version is not None else ""


def image(version):
    """A pieeprom.bin declaring MFG_VER: version, or none for an old image."""
    if version is None:
        return 'printf "\\0BUILD_TIMESTAMP=1\\0" > "$S/pieeprom.bin"'
    return f'printf "\\0MFG_VER: {version}\\0" > "$S/pieeprom.bin"'


class BootstrapCheck(UITest):
    sign_in_first = False

    def run_check(self, board, served, serial=SERIAL, remembered=None, no_image=False):
        script = CHECK.format(
            serial=serial, hardware=hardware_info(board),
            image="" if no_image else image(served),
            remembered=f"echo {remembered} > $MFG_VERSION_CACHE/{serial}" if remembered is not None else "")
        return self.station.sh(script, check=False)

    def test_an_older_bootloader_is_refused_before_anything_is_written(self):
        out = self.run_check(board=2, served=1)
        self.assertIn("needs bootloader manufacture version 2 or later", out)
        self.assertIn("pieeprom-2026-09-12.bin, is version 1", out)
        self.assertIn("reason=bootloader-too-old permanent=1", out)
        self.assertIn("STATE: BOOTSTRAP-ABORTED", out)
        self.assertNotIn("PASSED", out)
        # One pass, serving the recovery code alone: no image, no OTP request.
        passes = [l for l in out.splitlines() if l.startswith("RPIBOOT:")]
        self.assertEqual(["RPIBOOT: bootcode5.bin config.txt | set_reboot_order=0x3;recovery_reboot=1;"], passes)
        self.assertIn("CACHE: 2", out)

    def test_a_new_enough_bootloader_goes_ahead(self):
        out = self.run_check(board=2, served=3)
        self.assertIn("PASSED", out)
        self.assertIn("VERSIONS: board_mfg_version=2;bootloader_mfg_version=3;", out)
        self.assertIn("CACHE: 2", out)

    def test_equal_versions_go_ahead(self):
        self.assertIn("PASSED", self.run_check(board=1, served=1))

    def test_an_image_from_before_versions_counts_as_none(self):
        out = self.run_check(board=1, served=None)
        self.assertIn("is version 0", out)
        self.assertNotIn("PASSED", out)
        self.assertIn("PASSED", self.run_check(board=0, served=None))

    def test_a_board_that_does_not_say_goes_ahead(self):
        out = self.run_check(board=None, served=1)
        self.assertIn("PASSED", out)
        self.assertIn("not checked", out)
        self.assertIn("VERSIONS: board_mfg_version=;bootloader_mfg_version=1;", out)
        self.assertIn("CACHE: \n", out + "\n", "an unknown version is not remembered")

    def test_a_remembered_version_needs_no_extra_pass(self):
        out = self.run_check(board=0, served=2, remembered=3)
        self.assertNotIn("RPIBOOT:", out)
        self.assertIn("as read before", out)
        self.assertIn("needs bootloader manufacture version 3", out)

    def test_a_device_path_is_not_remembered_as_a_serial(self):
        out = self.run_check(board=2, served=2, serial="/dev/bus/usb/001/009")
        self.assertIn("PASSED", out)
        self.assertIn("CACHE: \n", out + "\n")

    def test_nothing_to_write_means_nothing_to_check(self):
        out = self.run_check(board=9, served=None, no_image=True)
        self.assertIn("PASSED", out)
        self.assertNotIn("RPIBOOT:", out)

    def test_the_downgrade_override_is_never_sent(self):
        out = self.run_check(board=1, served=1)
        self.assertIn("CONFIG: program_pubkey=1;recovery_reboot=1;", out)

    def test_mfg_ver_is_read_before_hardware_info(self):
        out = self.station.sh(r"""
            . /usr/bin/rpi-sb-common.sh
            J=$(mktemp)
            printf '{\n\t"HARDWARE_INFO": "00050000",\n\t"MFG_VER": "4"\n}\n' > $J
            echo "both=$(board_mfg_version $J)"
            printf '{\n\t"HARDWARE_INFO": "00051234"\n}\n' > $J
            echo "hardware=$(board_mfg_version $J)"
            printf '{\n\t"HARDWARE_INFO": "zz"\n}\n' > $J
            echo "bad=[$(board_mfg_version $J)]"
            printf 'xMFG_VER: 7\0' > $J
            echo "embedded=$(bootloader_image_mfg_version $J)"
            rm -f $J
        """)
        self.assertIn("both=4", out)
        self.assertIn("hardware=5", out)
        self.assertIn("bad=[]", out)
        self.assertIn("embedded=0", out, "MFG_VER: must start a string, as strings(1) shows it")

