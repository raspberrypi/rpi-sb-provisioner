#!/bin/sh

set -e
set -x

OPENSSL=${OPENSSL:-openssl}

export TRIAGE_FINISHED="TRIAGE-FINISHED"
export TRIAGE_ABORTED="TRIAGE-ABORTED"
export TRIAGE_STARTED="TRIAGE-STARTED"

# shellcheck disable=SC1091
. /var/lib/rpi-sb-provisioner/state-recording

TARGET_DEVICE_SERIAL="${1}"
TARGET_DEVICE_SERIAL32=$(echo "${TARGET_DEVICE_SERIAL}" | cut -c $((${#TARGET_DEVICE_SERIAL}/2+1))-)

TARGET_USB_PATH=$(get_usb_path_for_serial "${TARGET_DEVICE_SERIAL32}")

# Source common helper functions
# shellcheck disable=SC1091
. "$(dirname "$0")/rpi-sb-common.sh"

# Initialize required directories
init_directories

# Check resource limits before proceeding
if ! check_provisioner_limit; then
    die "Maximum number of concurrent triage operations ($MAX_CONCURRENT_PROVISIONERS) reached"
fi

# Create device-specific lock
DEVICE_LOCK="${LOCK_BASE}/${TARGET_DEVICE_SERIAL}"
if atomic_mkdir "$DEVICE_LOCK"; then
    HOLDING_LOCKFILE=1
else
    die "Triage already in progress for ${TARGET_DEVICE_SERIAL}"
fi

# Setup log directory with proper permissions
if ! setup_log_directory "${TARGET_DEVICE_SERIAL}"; then
    die "Failed to setup log directory for ${TARGET_DEVICE_SERIAL}"
fi

# Record state changes atomically
record_state "${TARGET_DEVICE_SERIAL}" "${TRIAGE_STARTED}" "${TARGET_USB_PATH}"
LOG_DIRECTORY="/var/log/rpi-sb-provisioner/${TARGET_DEVICE_SERIAL}"

if [ -d "/var/log/rpi-sb-provisioner/${TARGET_DEVICE_SERIAL32}" ]; then
    cp -rf "/var/log/rpi-sb-provisioner/${TARGET_DEVICE_SERIAL32}/." "${LOG_DIRECTORY}/"
    rm -rf "/var/log/rpi-sb-provisioner/${TARGET_DEVICE_SERIAL32}"
fi

mkdir -p "${LOG_DIRECTORY}"

die() {
    echo "${TRIAGE_ABORTED}" >> "${LOG_DIRECTORY}"/triage.log
    record_state "${TARGET_DEVICE_SERIAL}" "${TRIAGE_ABORTED}" "${TARGET_USB_PATH}"
    # shellcheck disable=SC2086
    echo "$@" ${DEBUG}
    exit 1
}


read_config

log() {
    echo "$@" >> "${LOG_DIRECTORY}"/triage.log
    printf "%s\n" "$@"
}

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