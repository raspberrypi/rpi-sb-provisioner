"""Bootstrap's fastboot assets: rpiboot's bootfiles.bin is given the customer
public key, as pubkey.bin, and rebuilt when anything it came from changes."""

from ui.harness.case import UITest

# The installed functions, with bootstrap's own log, die and log_stderr made
# to print, and a stand-in for rpi-sign-bootcode.
PRELUDE = r"""
set -e
. /usr/bin/rpi-sb-common.sh
. /var/lib/rpi-sb-provisioner/state-recording
W=$(mktemp -d)
trap 'rm -rf $W' EXIT
log() { echo "LOG: $*"; }
log_stderr() { "$@"; }
die() { echo "DIE: $* [reason=$PROVISION_FAILED_REASON permanent=$PROVISION_FAILURE_PERMANENT]"; exit 3; }
mkdir $W/bin
printf '#!/bin/sh\nwhile [ "$1" != -o ]; do shift; done\necho signed > "$2"\n' > $W/bin/rpi-sign-bootcode
chmod +x $W/bin/rpi-sign-bootcode
PATH=$W/bin:$PATH
get_sign_bootcode_key_args() { :; }
PROVISION_FAILURE_FLAG=$W/permanent
openssl genrsa -out $W/key.pem 2048 2>/dev/null
openssl rsa -in $W/key.pem -pubout -out $W/pub.pem 2>/dev/null
CUSTOMER_PUBLIC_KEY_FILE=$W/pub.pem
TARGET_DEVICE_FAMILY=2712
"""

class FastbootBootfiles(UITest):
    sign_in_first = False

    def test_each_chip_gets_the_public_key(self):
        out = self.station.sh(PRELUDE + r"""
            build_fastboot_bootfiles $W/out.bin
            tar -tf $W/out.bin | grep -E 'pubkey|bootcode5' | sort | tr '\n' ' '; echo
            mkdir $W/x && tar -xf $W/out.bin -C $W/x
            cmp $W/x/2711/pubkey.bin $W/x/2712/pubkey.bin && echo SAME
            rpi-bootloader-key-convert $W/pub.pem --output $W/expect.bin && cmp $W/expect.bin $W/x/2712/pubkey.bin && echo MATCHES
            echo "bootcode=$(cat $W/x/2712/bootcode5.bin)"
        """, check=False)
        self.assertIn("2711/pubkey.bin 2712/bootcode5.bin 2712/pubkey.bin", out)
        self.assertIn("SAME", out)
        self.assertIn("MATCHES", out)
        self.assertIn("bootcode=signed", out)

    def test_a_pi4_is_not_given_signed_bootcode(self):
        out = self.station.sh(PRELUDE + r"""
            TARGET_DEVICE_FAMILY=2711
            build_fastboot_bootfiles $W/out.bin
            mkdir $W/x && tar -xf $W/out.bin -C $W/x
            tar -xOf "$RPIBOOT_BOOTFILES" 2712/bootcode5.bin | cmp - $W/x/2712/bootcode5.bin && echo UNSIGNED
            ls $W/x/2711/pubkey.bin
        """, check=False)
        self.assertIn("UNSIGNED", out)
        self.assertIn("2711/pubkey.bin", out)

    def test_a_failed_build_leaves_nothing(self):
        out = self.station.sh(PRELUDE + r"""
            CUSTOMER_PUBLIC_KEY_FILE=$W/absent.pem
            build_fastboot_bootfiles $W/out.bin || echo REFUSED
            ls $W/out.bin $W/out.bin.tmp 2>&1 | grep -c 'No such' || true
        """, check=False)
        self.assertIn("REFUSED", out)
        self.assertIn("2\n", out)

    def test_the_cache_follows_rpiboot_the_gadget_and_the_key(self):
        out = self.station.sh(PRELUDE + r"""
            get_fastboot_gadget() { echo $W/gadget.img; }
            echo one > $W/gadget.img
            cp "$(readlink -f "$RPIBOOT_BOOTFILES")" $W/bootfiles.bin
            RPIBOOT_BOOTFILES=$W/bootfiles.bin
            a=$(fastboot_assets_identity)
            [ "$a" = "$(fastboot_assets_identity)" ] && echo STEADY
            echo extra >> $W/bootfiles.bin
            b=$(fastboot_assets_identity); [ "$b" != "$a" ] && echo RPIBOOT
            echo two > $W/gadget.img
            c=$(fastboot_assets_identity); [ "$c" != "$b" ] && echo GADGET
            openssl genrsa 2048 2>/dev/null | openssl rsa -pubout -out $W/pub.pem 2>/dev/null
            d=$(fastboot_assets_identity); [ "$d" != "$c" ] && echo KEY
            TARGET_DEVICE_FAMILY=2711
            e=$(fastboot_assets_identity); [ "$e" != "$d" ] && echo FAMILY
        """, check=False)
        for word in ("STEADY", "RPIBOOT", "GADGET", "KEY", "FAMILY"):
            self.assertIn(word, out)

