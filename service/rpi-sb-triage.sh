#!/bin/sh

set -e
set -x

OPENSSL=${OPENSSL:-openssl}

export TRIAGE_FINISHED="TRIAGE-FINISHED"
export TRIAGE_ABORTED="TRIAGE-ABORTED"
export TRIAGE_STARTED="TRIAGE-STARTED"

# Source common helper functions
# shellcheck disable=SC1091
. "$(dirname "$0")/rpi-sb-common.sh"
# shellcheck disable=SC1091
. /var/lib/rpi-sb-provisioner/state-recording

TARGET_DEVICE_SERIAL="${1}"
TARGET_DEVICE_SERIAL32=$(echo "${TARGET_DEVICE_SERIAL}" | cut -c $((${#TARGET_DEVICE_SERIAL}/2+1))-)
LOG_DIRECTORY="/var/log/rpi-sb-provisioner/${TARGET_DEVICE_SERIAL}"

log() {
    mkdir -p "${LOG_DIRECTORY}"
    echo "$@" >> "${LOG_DIRECTORY}"/triage.log
    printf "%s\n" "$@"
}

die() {
    log "${TRIAGE_ABORTED}"
    record_state "${TARGET_DEVICE_SERIAL}" "${TRIAGE_ABORTED}" "${TARGET_USB_PATH}"
    # shellcheck disable=SC2086
    echo "$@" ${DEBUG}
    exit 1
}

TARGET_USB_PATH=$(get_usb_path_for_serial "${TARGET_DEVICE_SERIAL32}")

# Record state changes atomically
record_state "${TARGET_DEVICE_SERIAL}" "${TRIAGE_STARTED}" "${TARGET_USB_PATH}"

if [ -d "/var/log/rpi-sb-provisioner/${TARGET_DEVICE_SERIAL32}" ]; then
    cp -rf "/var/log/rpi-sb-provisioner/${TARGET_DEVICE_SERIAL32}/." "${LOG_DIRECTORY}/"
    rm -rf "/var/log/rpi-sb-provisioner/${TARGET_DEVICE_SERIAL32}"
fi

read_config

# Based on the provisioning style, we can determine which systemd unit to trigger.
# All systemd must be parameterised with the device serial number.
echo "${TRIAGE_STARTED}" >> "${LOG_DIRECTORY}"/triage.log
case ${PROVISIONING_STYLE} in
    "secure-boot")
        log "Selecting Secure Boot Provisioner"
        systemctl start rpi-sb-provisioner@"${TARGET_DEVICE_SERIAL}".service
    ;;
    "fde-only")
        log "Selecting Full-Disk Encryption Provisioner"
        systemctl start rpi-fde-provisioner@"${TARGET_DEVICE_SERIAL}".service
    ;;
    "naked")
        log "Selecting Naked Provisioner"
        systemctl start rpi-naked-provisioner@"${TARGET_DEVICE_SERIAL}".service
    ;;
    *)
        log "Fatal: Unknown provisioning style: ${PROVISIONING_STYLE}"
        exit 1
    ;;
esac
log "${TRIAGE_FINISHED}" >> "${LOG_DIRECTORY}"/triage.log
record_state "${TARGET_DEVICE_SERIAL}" "${TRIAGE_FINISHED}" "${TARGET_USB_PATH}"

cleanup