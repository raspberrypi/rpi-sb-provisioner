#!/bin/sh

set -e
set -x

DEBUG=

OPENSSL=${OPENSSL:-openssl}

export TRIAGE_FINISHED="BOOTSTRAP-FINISHED"
export TRIAGE_ABORTED="BOOTSTRAP-ABORTED"
export TRIAGE_STARTED="BOOTSTRAP-STARTED"

TARGET_DEVICE_SERIAL="$(get_variable serialno)"

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

ring_bell() {
    tput bel
}

announce_start() {
    bootstrap_log "================================================================================"

    bootstrap_log "Starting $1"

    bootstrap_log "================================================================================"
}

announce_stop() {
    bootstrap_log "================================================================================"

    bootstrap_log "Stopping $1"

    bootstrap_log "================================================================================"
}

bootstrap_log() {
    echo "$@" >> "${LOG_DIRECTORY}"/triage.log
    printf "%s\n" "$@"
}

get_fastboot_gadget() {
    if [ -f /etc/rpi-sb-provisioner/fastboot-gadget.img ]; then
        echo "/etc/rpi-sb-provisioner/fastboot-gadget.img"
    else
        echo "/var/lib/rpi-sb-provisioner/fastboot-gadget.img"
    fi
}

get_fastboot_config_file() {
    if [ -f /etc/rpi-sb-provisioner/boot_ramdisk_config.txt ]; then
        echo "/etc/rpi-sb-provisioner/boot_ramdisk_config.txt"
    else
        echo "/var/lib/rpi-sb-provisioner/boot_ramdisk_config.txt"
    fi
}

# check_file_is_expected ${path_to_file} ${expected_file_extension}
# Checks if a file exists, is not a directory, is not zero and has the right extension.
# If any of those checks fail, exit the script entirely and print a debug message
# If all checks succeed, supply the filepath via stdout
check_file_is_expected() {
    filepath="$1"
    ext="$2"

    if [ ! -e "${filepath}" ]; then
        die "Specified file does not exist: ${filepath}"
    fi

    if [ -d "${filepath}" ]; then
        die "Expected a file, got a directory for ${filepath}"
    fi

    if [ -z "${filepath}" ]; then
        die "Provided file is empty: ${filepath}"
    fi

    if [ -z "${ext}" ] || echo "${filepath}" | grep -q "${ext}"; then
        echo "${filepath}"
        return 0
    else
        die "Provided file is of the wrong extension, wanted ${ext}, provided ${filepath}"
    fi
}

check_command_exists() {
    command_to_test=$1
    if ! command -v "${command_to_test}" 1> /dev/null; then
        die "${command_to_test} could not be found"
    else
        echo "$command_to_test"
    fi
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
