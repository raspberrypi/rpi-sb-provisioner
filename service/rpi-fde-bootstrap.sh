#!/bin/sh

set -e
set -x

DEBUG=

OPENSSL=${OPENSSL:-openssl}

export BOOTSTRAP_FINISHED="BOOTSTRAP-FINISHED"
export BOOTSTRAP_ABORTED="BOOTSTRAP-ABORTED"
export BOOTSTRAP_STARTED="BOOTSTRAP-STARTED"

TARGET_DEVICE_PATH="$1"

read_config() {
    if [ -f /etc/rpi-sb-provisioner/config ]; then
        . /etc/rpi-sb-provisioner/config
    else
        printf "%s\n" "Failed to load config. Please use configuration tool." >&2
        return 1
    fi
}

read_config

ring_bell() {
    tput bel
}

announce_start() {
    provisioner_log "================================================================================"

    provisioner_log "Starting $1"

    provisioner_log "================================================================================"
}

announce_stop() {
    provisioner_log "================================================================================"

    provisioner_log "Stopping $1"

    provisioner_log "================================================================================"
}

: "${RPI_DEVICE_STORAGE_CIPHER:=xchacha12,aes-adiantum-plain64}"

die() {
    [ -n "${TARGET_DEVICE_SERIAL}" ] && echo "${PROVISIONER_ABORTED}" >> /var/log/rpi-fde-provisioner/"${TARGET_DEVICE_SERIAL}"/progress
    # shellcheck disable=SC2086
    echo "$@" ${DEBUG}
    exit 1
}

provisioner_log() {
    [ -n "${TARGET_DEVICE_SERIAL}" ] && echo "$@" >> /var/log/rpi-fde-provisioner/"${TARGET_DEVICE_SERIAL}"/provisioner.log
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
        provisioner_log "${command_to_test} could not be found"
        exit 1
    else
        echo "$command_to_test"
    fi
}

cleanup() {
    if [ -n "${DELETE_PRIVATE_TMPDIR}" ]; then
        announce_start "Deleting customised intermediates"
        # shellcheck disable=SC2086
        rm -rf "${DELETE_PRIVATE_TMPDIR}" ${DEBUG}
        DELETE_PRIVATE_TMPDIR=
        announce_stop "Deleting customised intermediates"
    fi
}
trap cleanup EXIT

# These tools are used to modify the supplied images, and deal with mounting and unmounting the images.
check_command_exists losetup
check_command_exists mknod
check_command_exists lsblk
check_command_exists cut
check_command_exists findmnt
check_command_exists grep

get_variable() {
    [ -z "${DEMO_MODE_ONLY}" ] && fastboot getvar "$1" 2>&1 | grep -oP "${1}"': \K[^\r\n]*'
}

DELETE_PRIVATE_TMPDIR=
announce_start "Finding the cache directory"
if [ -z "${RPI_SB_WORKDIR}" ]; then
    RPI_SB_WORKDIR=$(mktemp -d "rpi-fde-bootstrap.XXX" --tmpdir="/srv/")
    announce_stop "Finding the cache directory: Created a new one as unspecified"
    DELETE_PRIVATE_TMPDIR="true"
elif [ ! -d "${RPI_SB_WORKDIR}" ]; then
    RPI_SB_WORKDIR=$(mktemp -d "rpi-fde-bootstrap.XXX" --tmpdir="/srv/")
    announce_stop "Finding the cache directory: Created a new one in /srv, as supplied path isn't a directory"
    DELETE_PRIVATE_TMPDIR="true"
else
    # Deliberately do nothing
    announce_stop "Finding the cache directory: Using specified name"
fi

announce_start "Staging fastboot image"

cp /usr/share/rpiboot/mass-storage-gadget64/bootfiles.bin "${RPI_SB_WORKDIR}/bootfiles.bin"
cp "$(get_fastboot_gadget)" "${RPI_SB_WORKDIR}"/boot.img
cp "$(get_fastboot_config_file)" "${RPI_SB_WORKDIR}"/config.txt
announce_stop "Staging fastboot image"

announce_start "Starting fastboot"
set +e
[ -z "${DEMO_MODE_ONLY}" ] && timeout 120 rpiboot -v -d "${RPI_SB_WORKDIR}" -p "${TARGET_DEVICE_PATH}"
set -e
FLASHING_GADGET_EXIT_STATUS=$?
if [ $FLASHING_GADGET_EXIT_STATUS -eq 124 ]; then
    provisioner_log "Loading Fastboot failed, timed out."
    return 124
elif [ $FLASHING_GADGET_EXIT_STATUS -ne 0 ]; then
    provisioner_log "Fastboot failed to load: ${FLASHING_GADGET_EXIT_STATUS}"
else
    provisioner_log "Fastboot loaded."
fi
announce_stop "Starting fastboot"