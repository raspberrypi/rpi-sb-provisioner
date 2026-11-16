#!/bin/sh
#
# Updates this provisioning station's bootloader, for the web UI, with
# rpi-eeprom-update -a. A Pi 5 writes the EEPROM there and then with flashrom;
# a Pi 4 stages it for the next boot. Either way the new bootloader runs from
# the next reboot, which the operator makes, not this.
#
# The result is written to STATUS as key=value lines, then "---" and the
# tool's output. state is one of: running, updated (written now), staged,
# current (already up to date), not-enabled (rpi-eeprom-update is off on
# CM4), frozen (FREEZE_VERSION=1) or failed.

set -u

STATUS="${RPI_SB_STATION_UPDATE_STATUS:-/run/rpi-sb-provisioner/station-bootloader-update.status}"
UPDATE="${RPI_EEPROM_UPDATE:-rpi-eeprom-update}"

write_status() {
    _ws_tmp="${STATUS}.tmp"
    { printf 'state=%s\n' "$1"; [ -z "${2:-}" ] || printf 'exit=%s\n---\n' "$2"; [ -z "${3:-}" ] || cat "$3"; } > "${_ws_tmp}" &&
        mv -f "${_ws_tmp}" "${STATUS}"
}

mkdir -p "$(dirname "${STATUS}")"
write_status running

OUT=$(mktemp)
trap 'rm -f "${OUT}"' EXIT
"${UPDATE}" -a > "${OUT}" 2>&1
rc=$?
cat "${OUT}"

if [ "${rc}" -eq 3 ]; then
    state=frozen
elif [ "${rc}" -ne 0 ]; then
    state=failed
elif grep -q 'not enabled by default' "${OUT}"; then
    state=not-enabled
elif grep -q 'UPDATE SUCCESSFUL' "${OUT}"; then
    state=updated
elif grep -q -e 'updates pending' -e 'installed at the next reboot' "${OUT}"; then
    state=staged
elif grep -q 'BOOTLOADER: up to date' "${OUT}"; then
    state=current
else
    state=failed
fi

write_status "${state}" "${rc}" "${OUT}"
echo "Station bootloader update: ${state}"
[ "${state}" != failed ]
