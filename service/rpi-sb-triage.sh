#!/bin/sh

set -e
set -x

OPENSSL=${OPENSSL:-openssl}

export TRIAGE_FINISHED="BOOTSTRAP-FINISHED"
export TRIAGE_ABORTED="BOOTSTRAP-ABORTED"
export TRIAGE_STARTED="BOOTSTRAP-STARTED"

TARGET_DEVICE_SERIAL="${1}"

LOG_DIRECTORY="/var/log/rpi-sb-provisioner/${TARGET_DEVICE_SERIAL}"
mkdir -p "${LOG_DIRECTORY}"

die() {
    echo "${TRIAGE_ABORTED}" >> "${LOG_DIRECTORY}"/triage.log
    # shellcheck disable=SC2086
    echo "$@" ${DEBUG}
    exit 1
}

read_config() {
    if [ -f /etc/rpi-sb-provisioner/config ]; then
        . /etc/rpi-sb-provisioner/config
    else
        die "%s\n" "Failed to load config. Please use configuration tool."
    fi
}

read_config

announce_start() {
    triage_log "================================================================================"

    triage_log "Starting $1"

    triage_log "================================================================================"
}

announce_stop() {
    triage_log "================================================================================"

    triage_log "Stopping $1"

    triage_log "================================================================================"
}

triage_log() {
    echo "$@" >> "${LOG_DIRECTORY}"/triage.log
    printf "%s\n" "$@"
}

cleanup() {
    if [ -n "${CUSTOMER_PUBLIC_KEY_FILE}" ]; then
        announce_start "Deleting public key"
        # shellcheck disable=SC2086
        rm -f "${CUSTOMER_PUBLIC_KEY_FILE}" ${DEBUG}
        CUSTOMER_PUBLIC_KEY_FILE=
        announce_stop "Deleting public key"
    fi

    if [ -n "${DELETE_PRIVATE_TMPDIR}" ]; then
        announce_start "Deleting customised intermediates"
        # shellcheck disable=SC2086
        rm -rf "${DELETE_PRIVATE_TMPDIR}" ${DEBUG}
        DELETE_PRIVATE_TMPDIR=
        announce_stop "Deleting customised intermediates"
    fi
}
trap cleanup EXIT

# Based on the provisioning style, we can determine which systemd unit to trigger.
# All systemd must be parameterised with the device serial number.
echo "${TRIAGE_STARTED}" >> "${LOG_DIRECTORY}"/triage.log
case ${PROVISIONING_STYLE} in
    "secure-boot")
        echo "Selecting Secure Boot Provisioner" >> "${LOG_DIRECTORY}"/triage.log
        systemctl start rpi-sb-provisioner@"${TARGET_DEVICE_SERIAL}".service
    ;;
    "fde-only")
        echo "Selecting Secure Boot Provisioner" >> "${LOG_DIRECTORY}"/triage.log
        systemctl start rpi-fde-provisioner@"${TARGET_DEVICE_SERIAL}".service
    ;;
    "naked")
        echo "Selecting Secure Boot Provisioner" >> "${LOG_DIRECTORY}"/triage.log
        systemctl start rpi-naked-provisioner@"${TARGET_DEVICE_SERIAL}".service
    ;;
    *)
        echo "Fatal: Unknown provisioning style: ${PROVISIONING_STYLE}" >> "${LOG_DIRECTORY}"/triage.log
        exit 1
    ;;
esac
echo "${TRIAGE_FINISHED}" >> "${LOG_DIRECTORY}"/triage.log
