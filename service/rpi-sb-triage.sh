#!/bin/sh

set -e
set -x

OPENSSL=${OPENSSL:-openssl}

export TRIAGE_FINISHED="BOOTSTRAP-FINISHED"
export TRIAGE_ABORTED="BOOTSTRAP-ABORTED"
export TRIAGE_STARTED="BOOTSTRAP-STARTED"

TARGET_DEVICE_SERIAL="${1}"
TARGET_DEVICE_SERIAL32=$(echo "${TARGET_DEVICE_SERIAL}" | cut -c $((${#TARGET_DEVICE_SERIAL}/2+1))-)

LOG_DIRECTORY="/var/log/rpi-sb-provisioner/${TARGET_DEVICE_SERIAL}"

if [ -d "/var/log/rpi-sb-provisioner/${TARGET_DEVICE_SERIAL32}" ]; then
    cp -rf "/var/log/rpi-sb-provisioner/${TARGET_DEVICE_SERIAL32}/." "/var/log/rpi-sb-provisioner/${TARGET_DEVICE_SERIAL}/"
    rm -rf "/var/log/rpi-sb-provisioner/${TARGET_DEVICE_SERIAL32}"
fi

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

# Based on the provisioning style, we can determine which systemd unit to trigger.
# All systemd must be parameterised with the device serial number.
echo "${TRIAGE_STARTED}" >> "${LOG_DIRECTORY}"/triage.log
case ${PROVISIONING_STYLE} in
    "secure-boot")
        triage_log "Selecting Secure Boot Provisioner"
        systemctl start rpi-sb-provisioner@"${TARGET_DEVICE_SERIAL}".service
    ;;
    "fde-only")
        triage_log "Selecting Full-Disk Encryption Provisioner"
        systemctl start rpi-fde-provisioner@"${TARGET_DEVICE_SERIAL}".service
    ;;
    "naked")
        triage_log "Selecting Naked Provisioner"
        systemctl start rpi-naked-provisioner@"${TARGET_DEVICE_SERIAL}".service
    ;;
    *)
        triage_log "Fatal: Unknown provisioning style: ${PROVISIONING_STYLE}"
        exit 1
    ;;
esac
triage_log "${TRIAGE_FINISHED}" >> "${LOG_DIRECTORY}"/triage.log
