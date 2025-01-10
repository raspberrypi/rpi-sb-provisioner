#!/bin/sh

set -e
set -x

DEBUG=

export PROVISIONER_FINISHED="PROVISIONER-FINISHED"
export PROVISIONER_ABORTED="PROVISIONER-ABORTED"
export PROVISIONER_STARTED="PROVISIONER-STARTED"

read_config() {
    if [ -f /etc/rpi-naked-provisioner/config ]; then
        . /etc/rpi-naked-provisioner/config
    else
        printf "%s\n" "Failed to load config. Please use configuration tool." >&2
        return 1
    fi
}

read_config

TARGET_DEVICE_SERIAL="$(udevadm info --name="$1" --query=property --property=ID_SERIAL_SHORT --value)"
mkdir -p /var/log/rpi-naked-provisioner/"${TARGET_DEVICE_SERIAL}"/

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
    [ -n "${TARGET_DEVICE_SERIAL}" ] && echo "${PROVISIONER_ABORTED}" >> /var/log/rpi-naked-provisioner/"${TARGET_DEVICE_SERIAL}"/progress
    # shellcheck disable=SC2086
    echo "$@" ${DEBUG}
    exit 1
}

provisioner_log() {
    [ -n "${TARGET_DEVICE_SERIAL}" ] && echo "$@" >> /var/log/rpi-naked-provisioner/"${TARGET_DEVICE_SERIAL}"/provisioner.log
    printf "%s\n" "$@"
}

TMP_DIR=""

get_fastboot_gadget() {
    if [ -f /etc/rpi-naked-provisioner/fastboot-gadget.img ]; then
        echo "/etc/rpi-naked-provisioner/fastboot-gadget.img"
    else
        echo "/var/lib/rpi-naked-provisioner/fastboot-gadget.img"
    fi
}

get_fastboot_config_file() {
    if [ -f /etc/rpi-naked-provisioner/boot_ramdisk_config.txt ]; then
        echo "/etc/rpi-naked-provisioner/boot_ramdisk_config.txt"
    else
        echo "/var/lib/rpi-naked-provisioner/boot_ramdisk_config.txt"
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

check_python_module_exists() {
    module_name=$1
    if ! python -c "import ${module_name}" 1> /dev/null; then
        provisioner_log "Failed to load Python module '${module_name}'"
        exit 1
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

[ -n "${TARGET_DEVICE_SERIAL}" ] && echo "${PROVISIONER_STARTED}" >> /var/log/rpi-naked-provisioner/"${TARGET_DEVICE_SERIAL}"/progress

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

announce_start "Staging fastboot image"

cp /usr/share/rpiboot/mass-storage-gadget64/bootfiles.bin "${RPI_SB_WORKDIR}/bootfiles.bin"
cp "$(get_fastboot_gadget)" "${RPI_SB_WORKDIR}"/boot.img
cp "$(get_fastboot_config_file)" "${RPI_SB_WORKDIR}"/config.txt
announce_stop "Staging fastboot image"

announce_start "Starting fastboot"
set +e
[ -z "${DEMO_MODE_ONLY}" ] && timeout 120 rpiboot -v -d "${RPI_SB_WORKDIR}" -i "${TARGET_DEVICE_SERIAL}" -j "/var/log/rpi-naked-provisioner/${TARGET_DEVICE_SERIAL}/metadata/"
set -e
FLASHING_GADGET_EXIT_STATUS=$?
if [ $FLASHING_GADGET_EXIT_STATUS -eq 124 ]; then
    provisioner_log "Loading Fastboot failed, timed out."
    echo "${PROVISIONER_ABORTED}" >> /var/log/rpi-naked-provisioner/"${TARGET_DEVICE_SERIAL}"/progress
    return 124
elif [ $FLASHING_GADGET_EXIT_STATUS -ne 0 ]; then
    provisioner_log "Fastboot failed to load: ${FLASHING_GADGET_EXIT_STATUS}"
else
    provisioner_log "Fastboot loaded."
fi
announce_stop "Starting fastboot"

if [ -z "${DEMO_MODE_ONLY}" ] && [ -n "${RPI_DEVICE_FETCH_METADATA}" ]; then
    USER_BOARDREV="0x$(jq -r '.USER_BOARDREV' < /var/log/rpi-naked-provisioner/"${TARGET_DEVICE_SERIAL}"/metadata/"${TARGET_DEVICE_SERIAL}".json)"
    MAC_ADDRESS=$(jq -r '.MAC_ADDR' < /var/log/rpi-naked-provisioner/"${TARGET_DEVICE_SERIAL}"/metadata/"${TARGET_DEVICE_SERIAL}".json)
    CUSTOMER_KEY_HASH=$(jq -r '.CUSTOMER_KEY_HASH' < /var/log/rpi-naked-provisioner/"${TARGET_DEVICE_SERIAL}"/metadata/"${TARGET_DEVICE_SERIAL}".json)
    JTAG_LOCKED=$(jq -r '.JTAG_LOCKED' < /var/log/rpi-naked-provisioner/"${TARGET_DEVICE_SERIAL}"/metadata/"${TARGET_DEVICE_SERIAL}".json)
    ADVANCED_BOOT=$(jq -r '.ADVANCED_BOOT' < /var/log/rpi-naked-provisioner/"${TARGET_DEVICE_SERIAL}"/metadata/"${TARGET_DEVICE_SERIAL}".json)
    BOOT_ROM=$(jq -r '.BOOT_ROM' < /var/log/rpi-naked-provisioner/"${TARGET_DEVICE_SERIAL}"/metadata/"${TARGET_DEVICE_SERIAL}".json)
    BOARD_ATTR=$(jq -r '.BOARD_ATTR' < /var/log/rpi-naked-provisioner/"${TARGET_DEVICE_SERIAL}"/metadata/"${TARGET_DEVICE_SERIAL}".json)

    TYPE=$(printf "0x%X\n" $(((USER_BOARDREV & 0xFF0) >> 4)))
    PROCESSOR=$(printf "0x%X\n" $(((USER_BOARDREV & 0xF000) >> 12)))
    MEMORY=$(printf "0x%X\n" $(((USER_BOARDREV & 0x700000) >> 20)))
    MANUFACTURER=$(printf "0x%X\n" $(((USER_BOARDREV & 0xF0000) >> 16)))
    REVISION=$((USER_BOARDREV & 0xF))

    case ${TYPE} in
        "0x06") BOARD_STR="CM1" ;;
        "0x08") BOARD_STR="3B" ;;
        "0x09") BOARD_STR="Zero" ;;
        "0x0A") BOARD_STR="CM3" ;;
        "0x0D") BOARD_STR="3B+" ;;
        "0x0E") BOARD_STR="3A+" ;;
        "0x10") BOARD_STR="CM3+" ;;
        "0x11") BOARD_STR="4B" ;;
        "0x12") BOARD_STR="Zero 2 W" ;;
        "0x13") BOARD_STR="400" ;;
        "0x14") BOARD_STR="CM4" ;;
        "0x15") BOARD_STR="CM4S" ;;
        "0x17") BOARD_STR="5" ;;
        *)
            BOARD_STR="Unsupported Board"
    esac

    case ${PROCESSOR} in
        "0x0") PROCESSOR_STR="BCM2835" ;;
        "0x1") PROCESSOR_STR="BCM2836" ;;
        "0x2") PROCESSOR_STR="BCM2837" ;;
        "0x3") PROCESSOR_STR="BCM2711" ;;
        "0x4") PROCESSOR_STR="BCM2712" ;;
        *)
            PROCESSOR_STR="Unknown"
    esac

    case ${MEMORY} in
        "0x0") MEMORY_STR="256MB" ;;
        "0x1") MEMORY_STR="512MB" ;;
        "0x2") MEMORY_STR="1GB" ;;
        "0x3") MEMORY_STR="2GB" ;;
        "0x4") MEMORY_STR="4GB" ;;
        "0x5") MEMORY_STR="8GB" ;;
        *)
            MEMORY_STR="Unknown"
    esac

    case ${MANUFACTURER} in
        "0x0") MANUFACTURER_STR="Sony UK" ;;
        "0x1") MANUFACTURER_STR="Egoman" ;;
        "0x2") MANUFACTURER_STR="Embest" ;;
        "0x3") MANUFACTURER_STR="Sony Japan" ;;
        "0x4") MANUFACTURER_STR="Embest" ;;
        "0x5") MANUFACTURER_STR="Stadium" ;;
        *)
            MANUFACTURER_STR="Unknown"
    esac

    keywriter_log "Board is: ${BOARD_STR}, with revision number ${REVISION}. Has Processor ${PROCESSOR_STR} with Memory ${MEMORY_STR}. Was manufactured by ${MANUFACTURER_STR}"

    if [ -f "${RPI_SB_PROVISONER_MANUFACTURING_DB}" ]; then
        check_command_exists sqlite3
        sqlite3 "${RPI_SB_PROVISONER_MANUFACTURING_DB}"         \
            -cmd "PRAGMA journal_mode=WAL;"                     \
            "CREATE TABLE IF NOT EXISTS rpi_sb_provisioner(     \
                id              integer primary key,   \
                boardname       varchar(255)        not null,   \
                serial          char(8)             not null,   \
                keyhash         char(64)            not null,   \
                mac             char(17)            not null,   \
                jtag_locked     int2                not null,   \
                advanced_boot   char(8)             not null,   \
                boot_rom        char(8)             not null,   \
                board_attr      char(8)             not null,   \
                board_revision  varchar(255)        not null,   \
                processor       varchar(255)        not null,   \
                memory          varchar(255)        not null,   \
                manufacturer    varchar(255)        not null    \
                );"
        sqlite3 "${RPI_SB_PROVISONER_MANUFACTURING_DB}" \
            "INSERT INTO rpi_sb_provisioner(\
                boardname,                  \
                serial,                     \
                keyhash,                    \
                mac,                        \
                jtag_locked,                \
                advanced_boot,              \
                boot_rom,                   \
                board_attr,                 \
                board_revision,             \
                processor,                  \
                memory,                     \
                manufacturer                \
            ) VALUES (                      \
                '${BOARD_STR}',               \
                '${TARGET_DEVICE_SERIAL}',    \
                '${CUSTOMER_KEY_HASH}',       \
                '${MAC_ADDRESS}',             \
                '${JTAG_LOCKED}',             \
                '${ADVANCED_BOOT}',           \
                '${BOOT_ROM}',                \
                '${BOARD_ATTR}',              \
                '${REVISION}',                \
                '${PROCESSOR_STR}',           \
                '${MEMORY_STR}',              \
                '${MANUFACTURER_STR}'        \
            );"
    fi
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
    [ -n "${TARGET_DEVICE_SERIAL}" ] && echo "${PROVISIONER_ABORTED}" >> /var/log/rpi-naked-provisioner/"${TARGET_DEVICE_SERIAL}"/progress
    return 124
elif [ $FASTBOOT_EXIT_STATUS -ne 0 ]; then
    provisioner_log "Fastboot failed to load: ${FASTBOOT_EXIT_STATUS}"
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
if [ -f "${RPI_SB_WORKDIR}/rootfs-temporary.simg" ] && [ "$((TARGET_STORAGE_ROOT_EXTENT))" -eq "$(stat -c%s "${RPI_SB_WORKDIR}"/rootfs-temporary.simg)" ]; then
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

echo "${PROVISIONER_FINISHED}" >> /var/log/rpi-naked-provisioner/"${TARGET_DEVICE_SERIAL}"/progress

provisioner_log "Provisioning completed. Remove the device from this machine."
