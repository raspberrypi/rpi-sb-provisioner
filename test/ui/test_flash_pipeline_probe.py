"""Deferred flash writes are used only when fastbootd says it has them. fastboot
exits 0 even when the device answers FAIL, so the probe reads the answer."""

from ui.harness.case import UITest

# probe_flash_pipeline from the installed common script, with fastboot and
# timeout replaced by functions answering as {answer} says.
PROBE = r"""
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
eval "$(sed -n '/^probe_flash_pipeline() {/,/^}/p' /usr/bin/rpi-sb-common.sh)"
log() { echo "LOG: $*"; }
timeout() { shift 3; "$@"; }
FASTBOOT_CONTROL_TIMEOUT=30
fastboot() {
    echo "$*" >> "$W/asked"
    case "{answer}" in
        FAIL) echo "getvar:rpi-flash-pipeline FAILED (remote: 'Unknown variable')" >&2 ;;
        *) printf 'rpi-flash-pipeline: %s\r\nFinished. Total time: 0.001s\n' "{answer}" >&2 ;;
    esac
    return 0
}
probe_flash_pipeline "{specifier}"
echo "FLASH_PIPELINE=$FLASH_PIPELINE"
[ -e "$W/asked" ] && echo "ASKED $(cat "$W/asked")"
"""


class FlashPipelineProbe(UITest):
    sign_in_first = False

    def probe(self, answer, specifier="e462ebd76b1d1c93"):
        script = PROBE.replace("{answer}", answer).replace("{specifier}", specifier)
        return self.station.sh(script, check=False)

    def test_a_device_without_the_variable_is_not_used_deferred(self):
        out = self.probe("FAIL")
        self.assertIn("FLASH_PIPELINE=0", out)
        self.assertIn("does not offer", out)

    def test_supported_or_enabled_turns_it_on(self):
        for answer in ("supported", "enabled"):
            out = self.probe(answer)
            self.assertIn("FLASH_PIPELINE=1", out, answer)

    def test_any_other_answer_leaves_it_off(self):
        for answer in ("", "maybe", "supported-ish"):
            self.assertIn("FLASH_PIPELINE=0", self.probe(answer), repr(answer))

    def test_a_network_specifier_is_never_asked(self):
        out = self.probe("supported", "tcp:10.0.0.2")
        self.assertIn("FLASH_PIPELINE=0", out)
        self.assertNotIn("ASKED", out)
