"""Values a device reports are checked before they are used. A size comes as
fastboot gives it, "0x1B0C00000", and must still be accepted (#376)."""

from ui.harness.case import UITest

CASES = {
    # As fastbootd reports partition-size, and in either case.
    "0x1B0C00000": "7260340224",
    "0X1b0c00000": "7260340224",
    "0x00000001B0C00000": "7260340224",
    "7260340224": "7260340224",
    # Not octal.
    "07260340224": "7260340224",
    "4398046511104": "4398046511104",
    "0x40000000000": "4398046511104",
    "": None, "0x": None, "0xZZ": None, "12 MiB": None, "-5": None, " 0x10": None,
    # fastbootd's answer for a zero-length partition.
    "0x0": None, "0": None,
    # More than 4 TiB, and more than shell arithmetic holds.
    "0x40000000001": None, "4398046511105": None,
    "0xFFFFFFFFFFFFFFFF": None, "99999999999999999999": None,
}


class DeviceSizes(UITest):
    sign_in_first = False

    def test_sizes_are_read_in_hex_or_decimal(self):
        script = ". /usr/bin/rpi-sb-common.sh\n" + "".join(
            f"printf '%s=' '{v}'; device_size_bytes '{v}' || echo REFUSED\n" for v in CASES)
        out = dict(line.split("=", 1) for line in self.station.sh(script).splitlines())
        for value, want in CASES.items():
            with self.subTest(value=value):
                self.assertEqual(want or "REFUSED", out[value])

    def test_both_provisioners_use_it(self):
        for script in ("rpi-sb-provisioner.sh", "rpi-fde-provisioner.sh"):
            with self.subTest(script):
                text = self.station.sh(f"cat /usr/bin/{script}")
                self.assertIn('device_size_bytes "${_root_extent_reported}"', text)
                self.assertNotIn("implausible root partition size", text)
