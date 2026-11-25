"""A provisioner starts on a station with only python3, and knows which board it
is working on before any check that can stop it."""

from ui.harness.case import UITest

PROVISIONERS = ("/usr/bin/rpi-sb-provisioner.sh", "/usr/bin/rpi-fde-provisioner.sh")


class ProvisionerStartup(UITest):
    sign_in_first = False

    def test_python3_is_what_the_station_has(self):
        for script in PROVISIONERS:
            out = self.station.sh(rf"""
                grep -vE '^ *#' {script} | grep -E '(^|[^a-z_])python( |$)' || echo NO_BARE_PYTHON
                command -v python3 > /dev/null && echo HAS_PYTHON3
            """, check=False)
            self.assertIn("NO_BARE_PYTHON", out, script)
            self.assertIn("HAS_PYTHON3", out, script)

    def test_the_board_is_identified_before_any_check(self):
        for script in PROVISIONERS:
            out = self.station.sh(rf"""
                ident=$(grep -n '^setup_fastboot_and_id_vars "\$1"' {script} | cut -d: -f1)
                check=$(grep -nE '^check_[a-z_]+ ' {script} | grep -v 'check_command_exists fastboot' | head -n 1 | cut -d: -f1)
                [ -n "$ident" ] && [ "$ident" -lt "$check" ] && echo ORDERED
            """, check=False)
            self.assertIn("ORDERED", out, script)
