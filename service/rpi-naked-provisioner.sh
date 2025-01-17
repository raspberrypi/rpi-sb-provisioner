#!/bin/sh

set -e
set -x

DEBUG=

export PROVISIONER_FINISHED="PROVISIONER-FINISHED"
export PROVISIONER_ABORTED="PROVISIONER-ABORTED"
export PROVISIONER_STARTED="PROVISIONER-STARTED"

read_config() {
    if [ -f /etc/rpi-sb-provisioner/config ]; then
        . /etc/rpi-sb-provisioner/config
    else
        die "Failed to load config. Please use configuration tool."
    fi
}

read_config

TARGET_DEVICE_SERIAL="$(udevadm info --name="$1" --query=property --property=ID_SERIAL_SHORT --value)"

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

die() {
    echo "${PROVISIONER_ABORTED}" >> /var/log/rpi-sb-provisioner/"${TARGET_DEVICE_SERIAL}"/progress
    # shellcheck disable=SC2086
    echo "$@" ${DEBUG}
    exit 1
}

provisioner_log() {
    echo "$@" >> /var/log/rpi-sb-provisioner/"${TARGET_DEVICE_SERIAL}"/provisioner.log
    printf "%s\n" "$@"
}

TMP_DIR=""

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

check_python_module_exists() {
    module_name=$1
    if ! python -c "import ${module_name}" 1> /dev/null; then
        die "Failed to load Python module '${module_name}'"
    else
        echo "${module_name}"
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

# Lifted from pi-gen/scripts/common, unsure under what circumstances this would be necessary
ensure_next_loopdev() {
    loopdev="$(losetup -f)"
    loopmaj="$(echo "$loopdev" | sed -E 's/.*[0-9]*?([0-9]+)$/\1/')"
    [ -b "$loopdev" ] || mknod "$loopdev" b 7 "$loopmaj"
}

# Lifted from pi-gen/scripts/common, unsure under what circumstances this would be necessary
ensure_loopdev_partitions() {
    lsblk -r -n -o "NAME,MAJ:MIN" "$1" | grep -v "^${1#/dev/}" | while read -r line; do
        partition="${line%% *}"
        majmin="${line#* }"
        if [ ! -b "/dev/$partition" ]; then
            mknod "/dev/$partition" b "${majmin%:*}" "${majmin#*:}"
        fi
    done
}

# Lifted from pi-gen/scripts/common
unmount() {
    if [ -z "$1" ]; then
        DIR=$PWD
    else
        DIR=$1
    fi

    while mount | grep -q "$DIR"; do
        locs=$(mount | grep "$DIR" | cut -f 3 -d ' ' | sort -r)
        for loc in $locs; do
            umount "$loc"
        done
    done
}

# Lifted from pi-gen/scripts/common
unmount_image() {
    sync
    sleep 1
    LOOP_DEVICE=$(losetup --list | grep "$1" | cut -f1 -d' ')
    if [ -n "$LOOP_DEVICE" ]; then
        for part in "$LOOP_DEVICE"p*; do
            if DIR=$(findmnt -n -o target -S "$part"); then
                unmount "$DIR"
            fi
        done
        losetup -d "$LOOP_DEVICE"
    fi
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
trap cleanup EXIT

# Start the provisioner phase

[ -n "${TARGET_DEVICE_SERIAL}" ] && echo "${PROVISIONER_STARTED}" >> /var/log/rpi-sb-provisioner/"${TARGET_DEVICE_SERIAL}"/progress

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
    [ -z "${DEMO_MODE_ONLY}" ] && fastboot getvar "$1" 2>&1 | grep -oP "${1}"': \K[^\r\n]*'
}

TMP_DIR=$(mktemp -d)
RPI_DEVICE_STORAGE_TYPE="$(check_pidevice_storage_type "${RPI_DEVICE_STORAGE_TYPE}")"
DELETE_PRIVATE_TMPDIR=
announce_start "Finding the cache directory"
if [ -z "${RPI_SB_WORKDIR}" ]; then
    RPI_SB_WORKDIR=$(mktemp -d "rpi-sb-provisioner.XXX" --tmpdir="/srv/")
    announce_stop "Finding the cache directory: Created a new one as unspecified"
    DELETE_PRIVATE_TMPDIR="true"
elif [ ! -d "${RPI_SB_WORKDIR}" ]; then
    RPI_SB_WORKDIR=$(mktemp -d "rpi-sb-provisioner.XXX" --tmpdir="/srv/")
    announce_stop "Finding the cache directory: Created a new one in /srv, as supplied path isn't a directory"
    DELETE_PRIVATE_TMPDIR="true"
else
    # Deliberately do nothing
    announce_stop "Finding the cache directory: Using specified name"
fi

# Fast path: If we've already generated the assets, just move to flashing.
if [ ! -e "${RPI_SB_WORKDIR}"/bootfs-temporary.img ] ||
   [ ! -e "${TMP_DIR}"/rpi-rootfs-img-mount ]; then

    announce_start "OS Image Mounting"
    # Mount the 'complete' image as a series of partitions 
    cnt=0
    until ensure_next_loopdev && LOOP_DEV="$(losetup --show --find --partscan "${GOLD_MASTER_OS_FILE}")"; do
        if [ $cnt -lt 5 ]; then
            cnt=$((cnt + 1))
            provisioner_log "Error in losetup.  Retrying..."
            sleep 5
        else
            provisioner_log "ERROR: losetup failed; exiting"
            sleep 5
        fi
    done

    ensure_loopdev_partitions "$LOOP_DEV"
    BOOT_DEV="${LOOP_DEV}"p1
    ROOT_DEV="${LOOP_DEV}"p2

    # shellcheck disable=SC2086
    # mkdir -p "${TMP_DIR}"/rpi-boot-img-mount ${DEBUG}
    # shellcheck disable=SC2086
    mkdir -p "${TMP_DIR}"/rpi-rootfs-img-mount ${DEBUG}

    # OS Images are, by convention, packed as a MBR whole-disk file,
    # containing two partitions: A FAT boot partition, which contains the kernel, command line,
    # and supporting boot infrastructure for the Raspberry Pi Device.
    # And in partition 2, the OS rootfs itself.
    # Note that this mechanism is _assuming_ Linux. We may revise that in the future, but
    # to do so would require a concrete support commitment from the vendor - and Raspberry Pi only
    # support Linux.
    # shellcheck disable=SC2086
    # mount -t vfat "${BOOT_DEV}" "${TMP_DIR}"/rpi-boot-img-mount ${DEBUG}
    # shellcheck disable=SC2086
    mount -t ext4 "${ROOT_DEV}" "${TMP_DIR}"/rpi-rootfs-img-mount ${DEBUG}

    # Immediately copy the boot files to the boot partition
    dd if="${BOOT_DEV}" of="${RPI_SB_WORKDIR}"/bootfs-temporary.img
    announce_stop "OS Image Mounting"
fi

announce_start "Erase / Partition Device Storage"

# Arbitrary sleeps to handle lack of correct synchronisation in fastbootd.
set +e
[ -z "${DEMO_MODE_ONLY}" ] && timeout 30 fastboot wait-for-device getvar version
set -e
FASTBOOT_EXIT_STATUS=$?
if [ $FASTBOOT_EXIT_STATUS -eq 124 ]; then
    provisioner_log "Loading Fastboot failed, timed out."
    [ -n "${TARGET_DEVICE_SERIAL}" ] && echo "${PROVISIONER_ABORTED}" >> /var/log/rpi-sb-provisioner/"${TARGET_DEVICE_SERIAL}"/progress
    return 124
elif [ $FASTBOOT_EXIT_STATUS -ne 0 ]; then
    die "Fastboot failed to load: ${FASTBOOT_EXIT_STATUS}"
else
    provisioner_log "Fastboot loaded."
fi

[ -z "${DEMO_MODE_ONLY}" ] && fastboot erase "${RPI_DEVICE_STORAGE_TYPE}"
sleep 2
[ -z "${DEMO_MODE_ONLY}" ] && fastboot oem partinit "${RPI_DEVICE_STORAGE_TYPE}" DOS
sleep 2
[ -z "${DEMO_MODE_ONLY}" ] && fastboot oem partapp "${RPI_DEVICE_STORAGE_TYPE}" 0c "$(stat -c%s "${BOOT_DEV}")"
sleep 2
[ -z "${DEMO_MODE_ONLY}" ] && fastboot oem partapp "${RPI_DEVICE_STORAGE_TYPE}" 11 # Grow to fill storage
sleep 2
announce_stop "Erase / Partition Device Storage"

announce_start "Resizing OS images"
# Need mke2fs with '-E android_sparse' support
# Debian's 'android-sdk-platform-tools' provides the option but is not correctly
# built against libsparse: https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1008107
#
# https://dl.google.com/android/repository/platform-tools-latest-linux.zip
# https://dl.google.com/android/repository/platform-tools-latest-darwin.zip
# https://dl.google.com/android/repository/platform-tools-latest-windows.zip
TARGET_STORAGE_ROOT_EXTENT="$(get_variable partition-size:"${RPI_DEVICE_STORAGE_TYPE}"p2)"
if [ -f "${RPI_SB_WORKDIR}/rootfs-temporary.simg" ] && [ "$((TARGET_STORAGE_ROOT_EXTENT))" -eq "$(stat -c%b*%B "${RPI_SB_WORKDIR}"/rootfs-temporary.simg)" ]; then
    announce_stop "Resizing OS images: Not required, already the correct size"
else
    mke2fs -t ext4 -b 4096 -d "${TMP_DIR}"/rpi-rootfs-img-mount "${RPI_SB_WORKDIR}"/rootfs-temporary.img $((TARGET_STORAGE_ROOT_EXTENT / 4096))
    img2simg "${RPI_SB_WORKDIR}"/rootfs-temporary.img "${RPI_SB_WORKDIR}"/rootfs-temporary.simg
    rm -f "${RPI_SB_WORKDIR}"/rootfs-temporary.img
    #TODO: Re-enable android_sparse
    #mke2fs -t ext4 -b 4096 -d ${TMP_DIR}/rpi-rootfs-img-mount -E android_sparse ${RPI_SB_WORKDIR}/rootfs-temporary.simg $((TARGET_STORAGE_ROOT_EXTENT / 4096))
    announce_stop "Resizing OS images: Resized to $((TARGET_STORAGE_ROOT_EXTENT))"
fi

announce_start "Writing OS images"
[ -z "${DEMO_MODE_ONLY}" ] && fastboot flash "${RPI_DEVICE_STORAGE_TYPE}"p1 "${RPI_SB_WORKDIR}"/bootfs-temporary.img
[ -z "${DEMO_MODE_ONLY}" ] && fastboot flash "${RPI_DEVICE_STORAGE_TYPE}"p2 "${RPI_SB_WORKDIR}"/rootfs-temporary.simg
announce_stop "Writing OS images"

announce_start "Cleaning up"
[ -d "${TMP_DIR}/rpi-rootfs-img-mount" ] && umount "${TMP_DIR}"/rpi-rootfs-img-mount
# shellcheck disable=SC2086
# We also delete the temporary directory - preserving the cached generated asset
# shellcheck disable=SC2086
rm -rf "${TMP_DIR}" ${DEBUG}
announce_stop "Cleaning up"

announce_start "Set LED status"
[ -z "${DEMO_MODE_ONLY}" ] && fastboot oem led PWR 0
announce_stop "Set LED status"

echo "${PROVISIONER_FINISHED}" >> /var/log/rpi-sb-provisioner/"${TARGET_DEVICE_SERIAL}"/progress

provisioner_log "Provisioning completed. Remove the device from this machine."
