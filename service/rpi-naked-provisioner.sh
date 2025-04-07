#!/bin/sh

set -e
set -x

# shellcheck disable=SC1091
. /var/lib/rpi-sb-provisioner/manufacturing-data
# shellcheck disable=SC1091
. /var/lib/rpi-sb-provisioner/state-recording

DEBUG=

export PROVISIONER_FINISHED="NAKED-PROVISIONER-FINISHED"
export PROVISIONER_ABORTED="NAKED-PROVISIONER-ABORTED"
export PROVISIONER_STARTED="NAKED-PROVISIONER-STARTED"

# Source common helper functions
# shellcheck disable=SC1091
. "$(dirname "$0")/rpi-sb-common.sh"

die() {
    record_state "${TARGET_DEVICE_SERIAL}" "${PROVISIONER_ABORTED}" "${TARGET_USB_PATH}"
    # shellcheck disable=SC2086
    echo "$@" ${DEBUG}
    exit 1
}

log() {
    echo "$@" >> /var/log/rpi-sb-provisioner/"${TARGET_DEVICE_SERIAL}"/provisioner.log
    printf "%s\n" "$@"
}

setup_fastboot_and_id_vars "$1"

read_config

TMP_DIR=""

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

check_pidevice_storage_type() {
    case "${1}" in
        "sd")
            echo "mmcblk0"
            ;;
        "emmc")
            echo "mmcblk0"
            ;;
        "nvme")
            echo "nvme0n1"
            ;;
        ?)
            die "Unexpected storage device type. Wanted sd, nvme or emmc, got $1"
            ;;
    esac
}

# TODO: Refactor these two functions to use the same logic, but with different consequences for failure.
timeout_nonfatal() {
    command="$*"
    set +e
    # shellcheck disable=SC2086
    timeout 10 ${command}
    command_exit_status=$?
    if [ ${command_exit_status} -eq 124 ]; then
        log "\"${command}\" failed, timed out."
    elif [ ${command_exit_status} -ne 0 ]; then
        log "\"${command}\" failed, exit status: ${command_exit_status}"
    else
        log "\"$command\" succeeded."
    fi
    set -e
    return ${command_exit_status}
}

timeout_fatal() {
    command="$*"
    set +e
    # shellcheck disable=SC2086
    timeout 120 ${command}
    command_exit_status=$?
    if [ ${command_exit_status} -eq 124 ]; then
        record_state "${TARGET_DEVICE_SERIAL}" "${PROVISIONER_ABORTED}" "${TARGET_USB_PATH}"
        die "\"${command}\" failed, timed out."
    elif [ ${command_exit_status} -ne 0 ]; then
        record_state "${TARGET_DEVICE_SERIAL}" "${PROVISIONER_ABORTED}" "${TARGET_USB_PATH}"
        die "\"$command\" failed, exit status: ${command_exit_status}"
    else
        log "\"$command\" succeeded."
    fi
    set -e
}

cleanup() {
    if [ -d "${TMP_DIR}" ]; then
        rm -rf "${TMP_DIR}"
    fi

    if [ -n "${DELETE_PRIVATE_TMPDIR}" ]; then
        announce_start "Deleting customised intermediates"
        # shellcheck disable=SC2086
        rm -rf "${DELETE_PRIVATE_TMPDIR}" ${DEBUG}
        DELETE_PRIVATE_TMPDIR=
        announce_stop "Deleting customised intermediates"
    fi
}
trap cleanup INT TERM

# Start the provisioner phase

record_state "${TARGET_DEVICE_SERIAL}" "${PROVISIONER_STARTED}" "${TARGET_USB_PATH}"
# These tools are used to modify the supplied images, and deal with mounting and unmounting the images.
check_command_exists losetup
check_command_exists mknod
check_command_exists lsblk
check_command_exists cut
check_command_exists findmnt

# Fastboot is used as a transfer mechanism to get images and metadata to and from the Raspberry Pi device
check_command_exists fastboot

check_command_exists blockdev

check_command_exists grep

get_variable() {
    fastboot getvar "$1" 2>&1 | grep -oP "${1}"': \K[^\r\n]*'
}

TMP_DIR=$(mktemp -d)
RPI_DEVICE_STORAGE_TYPE="$(check_pidevice_storage_type "${RPI_DEVICE_STORAGE_TYPE}")"
DELETE_PRIVATE_TMPDIR=
announce_start "Finding the cache directory"
if [ -z "${RPI_SB_WORKDIR}" ]; then
    RPI_SB_WORKDIR=$(mktemp -d "rpi-naked-provisioner.XXX" --tmpdir="/srv/")
    announce_stop "Finding the cache directory: Created a new one as unspecified"
    DELETE_PRIVATE_TMPDIR="true"
elif [ ! -d "${RPI_SB_WORKDIR}" ]; then
    RPI_SB_WORKDIR=$(mktemp -d "rpi-naked-provisioner.XXX" --tmpdir="/srv/")
    announce_stop "Finding the cache directory: Created a new one in /srv, as supplied path isn't a directory"
    DELETE_PRIVATE_TMPDIR="true"
else
    # Deliberately do nothing
    announce_stop "Finding the cache directory: Using specified name"
fi

prepare_image_file() {
    if [ ! -f "${RPI_SB_WORKDIR}/image-temporary.simg" ] ||
       [ ! -s "${RPI_SB_WORKDIR}/image-temporary.simg" ]; then
        announce_start "Sparsing the OS image"
        img2simg -s "${GOLD_MASTER_OS_FILE}" "${RPI_SB_WORKDIR}"/image-temporary.simg
        announce_stop "Sparsing the OS image"
    fi
}

with_lock "${LOCK_BASE}/sparse-image-generation.lock" 120 prepare_image_file

announce_start "Writing OS images"

announce_start "Erase Device Storage"
fastboot -s "${FASTBOOT_DEVICE_SPECIFIER}" erase "${RPI_DEVICE_STORAGE_TYPE}"
sleep 2
announce_stop "Erase Device Storage"

fastboot -s "${FASTBOOT_DEVICE_SPECIFIER}" flash "${RPI_DEVICE_STORAGE_TYPE}" "${RPI_SB_WORKDIR}"/image-temporary.simg
announce_stop "Writing OS images"

announce_start "Set LED status"
fastboot -s "${FASTBOOT_DEVICE_SPECIFIER}" oem led PWR 0
announce_stop "Set LED status"

metadata_gather
record_state "${TARGET_DEVICE_SERIAL}" "${PROVISIONER_FINISHED}" "${TARGET_USB_PATH}"

announce_start "Cleaning up"
cleanup
announce_stop "Cleaning up"

log "Provisioning completed. Remove the device from this machine."

# Indicate successful completion to systemd
# This is used when the script is run as a systemd service
# The special exit code 0 indicates success to systemd
# Additionally, we can use systemd-notify if available to indicate completion
if command -v systemd-notify >/dev/null 2>&1; then
    systemd-notify --ready --status="Provisioning completed successfully"
fi

# Exit with success code for systemd
exit 0
