#!/bin/sh

set -e
set -x

DEBUG=

OPENSSL=${OPENSSL:-openssl}

export PROVISIONER_FINISHED="FDE-PROVISIONER-FINISHED"
export PROVISIONER_ABORTED="FDE-PROVISIONER-ABORTED"
export PROVISIONER_STARTED="FDE-PROVISIONER-STARTED"

TARGET_DEVICE_SERIAL="${1}"

read_config() {
    if [ -f /etc/rpi-sb-provisioner/config ]; then
        . /etc/rpi-sb-provisioner/config
    else
        printf "%s\n" "Failed to load config. Please use configuration tool." >&2
        return 1
    fi
}

read_config

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
    echo "${PROVISIONER_ABORTED}" >> /var/log/rpi-sb-provisioner/"${TARGET_DEVICE_SERIAL}"/progress
    # shellcheck disable=SC2086
    printf "%s\n" "$@"
    exit 1
}

provisioner_log() {
    echo "$@" >> /var/log/rpi-sb-provisioner/"${TARGET_DEVICE_SERIAL}"/provisioner.log
    printf "%s\n" "$@"
}

TMP_DIR=""

get_cryptroot() {
    if [ -f /etc/rpi-sb-provisioner/cryptroot_initramfs ]; then
        echo "/etc/rpi-sb-provisioner/cryptroot_initramfs"
    else
        echo "/var/lib/rpi-sb-provisioner/cryptroot_initramfs"
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
    unmount_image "${COPY_OS_COMBINED_FILE}"
    if [ -d "${TMP_DIR}" ]; then
        rm -rf "${TMP_DIR}"
    fi

    if [ -f "${COPY_OS_COMBINED_FILE}" ]; then
        rm -rf "${COPY_OS_COMBINED_FILE}"
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

# These tools are used to modify the supplied images, and deal with mounting and unmounting the images.
check_command_exists losetup
check_command_exists mknod
check_command_exists lsblk
check_command_exists cut
check_command_exists findmnt

# python is used by the Raspberry Pi usbboot scripts, and used as part of transforming the supplied key.
check_command_exists python
# pycryptodome is a python module used by the Raspberry Pi usbboot scripts
check_python_module_exists Cryptodome

# These tools are used for modifying and packaging the initramfs
check_command_exists zstd
check_command_exists cpio
check_command_exists sed
check_command_exists cp
check_command_exists mount

# Fastboot is used as a transfer mechanism to get images and metadata to and from the Raspberry Pi device
check_command_exists fastboot

check_command_exists blockdev

check_command_exists grep

get_variable() {
    fastboot -s "${TARGET_DEVICE_SERIAL}" getvar "$1" 2>&1 | grep -oP "${1}"': \K[^\r\n]*'
}

echo "${PROVISIONER_STARTED}" >> /var/log/rpi-sb-provisioner/"${TARGET_DEVICE_SERIAL}"/progress

TMP_DIR=$(mktemp -d)
RPI_DEVICE_STORAGE_TYPE="$(check_pidevice_storage_type "${RPI_DEVICE_STORAGE_TYPE}")"
DELETE_PRIVATE_TMPDIR=
announce_start "Finding the cache directory"
if [ -z "${RPI_SB_WORKDIR}" ]; then
    RPI_SB_WORKDIR=$(mktemp -d "rpi-fde-provisioner.XXX" --tmpdir="/srv/")
    announce_stop "Finding the cache directory: Created a new one as unspecified"
    DELETE_PRIVATE_TMPDIR="true"
elif [ ! -d "${RPI_SB_WORKDIR}" ]; then
    RPI_SB_WORKDIR=$(mktemp -d "rpi-fde-provisioner.XXX" --tmpdir="/srv/")
    announce_stop "Finding the cache directory: Created a new one in /srv, as supplied path isn't a directory"
    DELETE_PRIVATE_TMPDIR="true"
else
    # Deliberately do nothing
    announce_stop "Finding the cache directory: Using specified name"
fi

# Prior to this point, we cannot know the device serial. From here, provisioner_log can do the Right Thing.
mkdir -p /var/log/rpi-sb-provisioner/"${TARGET_DEVICE_SERIAL}"/

# Fast path: If we've already generated the assets, just move to flashing.
if [ ! -e "${RPI_SB_WORKDIR}/bootfs-temporary.simg" ] ||
   [ ! -e "${RPI_SB_WORKDIR}/rootfs-temporary.simg" ]; then

    announce_start "OS Image Mounting"
    COPY_OS_COMBINED_FILE=$(mktemp "working-os-image.XXX" --tmpdir="/srv/")
    announce_start "OS Image Copying (potentially slow)"
    cp "${GOLD_MASTER_OS_FILE}" "${COPY_OS_COMBINED_FILE}"
    announce_stop "OS Image Copying (potentially slow)"
    # Mount the 'complete' image as a series of partitions 
    cnt=0
    until ensure_next_loopdev && LOOP_DEV="$(losetup --show --find --partscan "${COPY_OS_COMBINED_FILE}")"; do
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
    mkdir -p "${TMP_DIR}"/rpi-boot-img-mount ${DEBUG}
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
    mount -t vfat "${BOOT_DEV}" "${TMP_DIR}"/rpi-boot-img-mount ${DEBUG}
    # shellcheck disable=SC2086
    mount -t ext4 "${ROOT_DEV}" "${TMP_DIR}"/rpi-rootfs-img-mount ${DEBUG}

    announce_stop "OS Image Mounting"

    # We supply a pre-baked Raspberry Pi Pre-boot-authentication initramfs, which we insert here.
    # This image is maintained by Raspberry Pi, with sources available on our GitHub pages.
    announce_start "Insert pre-boot authentication initramfs"
    cp "$(get_cryptroot)" "${TMP_DIR}"/rpi-boot-img-mount/initramfs8
    announce_stop "Insert pre-boot authentication initramfs"

    announce_start "Initramfs modification"

    augment_initramfs() {
        # shellcheck disable=SC2155
        initramfs_compressed_file=$(check_file_is_expected "$1" "")
        # shellcheck disable=SC2086
        mkdir -p "${TMP_DIR}"/initramfs ${DEBUG}
        # shellcheck disable=SC2086
        zstd --rm -f -d "${initramfs_compressed_file}" -o "${TMP_DIR}"/initramfs.cpio ${DEBUG}
        # shellcheck disable=SC2155
        rootfs_mount=$(realpath "${TMP_DIR}"/rpi-rootfs-img-mount)
        cd "${TMP_DIR}"/initramfs 
        # shellcheck disable=SC2086
        cpio -id < ../initramfs.cpio ${DEBUG}
        # shellcheck disable=SC2086
        rm ../initramfs.cpio ${DEBUG}

        initramfs_dir="$PWD"/ # trailing '/' is meaningful

        # Remove any pre-existing kernel modules in initramfs
        rm -rf "${initramfs_dir}usr/lib/modules"
        mkdir -p "${initramfs_dir}usr/lib/modules"

        # Insert required kernel modules
        cd "${rootfs_mount}"
        find usr/lib/modules \
            \( \
                -name 'dm-mod.*' \
                -o \
                -name 'dm-crypt.*' \
                -o \
                -name 'af_alg.*' \
                -o \
                -name 'algif_skcipher.*' \
                -o \
                -name 'libaes.*' \
                -o \
                -name 'aes_generic.*' \
                -o \
                -name 'aes-arm64.*' \
                -o \
                -name 'libpoly1305.*' \
                -o \
                -name 'nhpoly1305.*' \
                -o \
                -name 'adiantum.*' \
                -o \
                -name 'libchacha.*' \
                -o \
                -name 'chacha-neon.*' \
                -o \
                -name 'chacha_generic.*' \
            \) \
            -exec cp -r --parents "{}" "${initramfs_dir}" \;
        cd -

        # Generate depmod information
        for kernel in $(find "${initramfs_dir}usr/lib/modules" -mindepth 1 -maxdepth 1 -type d -printf '%f\n'); do
            depmod --basedir "${initramfs_dir}" "${kernel}"
        done

        find . -print0 | cpio --null -ov --format=newc > ../initramfs.cpio
        cd "${TMP_DIR}"
        rm -rf "${TMP_DIR}"/initramfs
        zstd --no-progress --rm -f -6 "${TMP_DIR}"/initramfs.cpio -o "${initramfs_compressed_file}"
    }

    # Use subshells to avoid polluting our CWD.
    if check_file_is_expected "${TMP_DIR}"/rpi-boot-img-mount/initramfs_2712 ""; then
        ( augment_initramfs "${TMP_DIR}"/rpi-boot-img-mount/initramfs_2712 )
    fi
    if check_file_is_expected "${TMP_DIR}"/rpi-boot-img-mount/initramfs8 ""; then
        ( augment_initramfs "${TMP_DIR}"/rpi-boot-img-mount/initramfs8 )
    fi
    announce_stop "Initramfs modification"

    announce_start "cmdline.txt modification"
    sed --in-place 's%\b\(root=\)\S*%\1/dev/ram0%' "${TMP_DIR}"/rpi-boot-img-mount/cmdline.txt
    sed --in-place 's%\binit=\S*%%' "${TMP_DIR}"/rpi-boot-img-mount/cmdline.txt
    sed --in-place 's%\brootfstype=\S*%%' "${TMP_DIR}"/rpi-boot-img-mount/cmdline.txt
    # TODO: Consider deleting quiet
    sed --in-place 's%\bquiet\b%%' "${TMP_DIR}"/rpi-boot-img-mount/cmdline.txt
    announce_stop "cmdline.txt modification"

    announce_start "config.txt modification"
    sed --in-place 's%^\(auto_initramfs=\S*\)%#\1%' "${TMP_DIR}"/rpi-boot-img-mount/config.txt

    echo 'initramfs initramfs8' >> "${TMP_DIR}"/rpi-boot-img-mount/config.txt
    
    announce_stop "config.txt modification"

    # Move the fastboot rpiboot configuration file into the flashing directory
    cp "$(get_fastboot_config_file)" "${TMP_DIR}"/config.txt

    announce_start "Copying boot image to working directory"
    dd if="${BOOT_DEV}" of="${RPI_SB_WORKDIR}"/bootfs-temporary.img
    sync; sync; sync;
    announce_stop "Copying boot image to working directory"
fi # Slow path

announce_start "Erase / Partition Device Storage"

# Arbitrary sleeps to handle lack of correct synchronisation in fastbootd.
set +e
timeout 30 fastboot getvar version
set -e
FASTBOOT_EXIT_STATUS=$?
if [ $FASTBOOT_EXIT_STATUS -eq 124 ]; then
    provisioner_log "Loading Fastboot failed, timed out."
    echo "${PROVISIONER_ABORTED}" >> /var/log/rpi-sb-provisioner/"${TARGET_DEVICE_SERIAL}"/progress
    return 124
elif [ $FASTBOOT_EXIT_STATUS -ne 0 ]; then
    echo "${PROVISIONER_ABORTED}" >> /var/log/rpi-sb-provisioner/"${TARGET_DEVICE_SERIAL}"/progress
    die "Fastboot failed to load: ${FASTBOOT_EXIT_STATUS}"
else
    provisioner_log "Fastboot loaded."
fi

fastboot erase "${RPI_DEVICE_STORAGE_TYPE}"
sleep 2
fastboot oem partinit "${RPI_DEVICE_STORAGE_TYPE}" DOS
sleep 2
fastboot oem partapp "${RPI_DEVICE_STORAGE_TYPE}" 0c "$(stat -c%s "${RPI_SB_WORKDIR}"/bootfs-temporary.img)"
sleep 2
fastboot oem partapp "${RPI_DEVICE_STORAGE_TYPE}" 83 # Grow to fill storage
sleep 2
fastboot oem cryptinit "${RPI_DEVICE_STORAGE_TYPE}"p2 root "${RPI_DEVICE_STORAGE_CIPHER}"
sleep 2
fastboot oem cryptopen "${RPI_DEVICE_STORAGE_TYPE}"p2 cryptroot
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
TARGET_STORAGE_ROOT_EXTENT="$(get_variable partition-size:mapper/cryptroot)"
if [ -f "${RPI_SB_WORKDIR}/rootfs-temporary.simg" ] && [ "$((TARGET_STORAGE_ROOT_EXTENT))" -eq "$(stat -c%b*%B "${RPI_SB_WORKDIR}"/rootfs-temporary.simg)" ]; then
    announce_stop "Resizing OS images: Not required, already the correct size"
else
    mke2fs -t ext4 -b 4096 -d "${TMP_DIR}"/rpi-rootfs-img-mount "${RPI_SB_WORKDIR}"/rootfs-temporary.img $((TARGET_STORAGE_ROOT_EXTENT / 4096))
    img2simg -s "${RPI_SB_WORKDIR}"/rootfs-temporary.img "${RPI_SB_WORKDIR}"/rootfs-temporary.simg
    rm -f "${RPI_SB_WORKDIR}"/rootfs-temporary.img
    #TODO: Re-enable android_sparse
    #mke2fs -t ext4 -b 4096 -d ${TMP_DIR}/rpi-rootfs-img-mount -E android_sparse ${RPI_SB_WORKDIR}/rootfs-temporary.simg $((TARGET_STORAGE_ROOT_EXTENT / 4096))
    announce_stop "Resizing OS images: Resized to $((TARGET_STORAGE_ROOT_EXTENT))"
fi

announce_start "Writing OS images"
fastboot flash "${RPI_DEVICE_STORAGE_TYPE}"p1 "${RPI_SB_WORKDIR}"/bootfs-temporary.img
fastboot flash mapper/cryptroot "${RPI_SB_WORKDIR}"/rootfs-temporary.simg
announce_stop "Writing OS images"

if [ -d "${RPI_DEVICE_RETRIEVE_KEYPAIR}" ]; then
    announce_start "Capturing device keypair to ${RPI_DEVICE_RETRIEVE_KEYPAIR}"
    N_ALREADY_PROVISIONED=0
    get_variable private-key > "${RPI_DEVICE_RETRIEVE_KEYPAIR}/${TARGET_DEVICE_SERIAL}.der" || N_ALREADY_PROVISIONED=$?
    if [ 0 -ne "$N_ALREADY_PROVISIONED" ]; then
        provisioner_log "Warning: Unable to retrieve device private key; already provisioned"
    fi
    get_variable public-key > "${RPI_DEVICE_RETRIEVE_KEYPAIR}/${TARGET_DEVICE_SERIAL}.pub"
    announce_stop "Capturing device keypair to ${RPI_DEVICE_RETRIEVE_KEYPAIR}"
fi

announce_start "Cleaning up"
[ -d "${TMP_DIR}/rpi-boot-img-mount" ] && umount "${TMP_DIR}"/rpi-boot-img-mount
[ -d "${TMP_DIR}/rpi-rootfs-img-mount" ] && umount "${TMP_DIR}"/rpi-rootfs-img-mount
# shellcheck disable=SC2086
unmount_image "${COPY_OS_COMBINED_FILE}" ${DEBUG}
# We also delete the temporary directory - preserving the cached generated asset
# shellcheck disable=SC2086
rm -rf "${TMP_DIR}" ${DEBUG}
announce_stop "Cleaning up"

announce_start "Set LED status"
fastboot oem led PWR 0
announce_stop "Set LED status"

echo "${PROVISIONER_FINISHED}" >> /var/log/rpi-sb-provisioner/"${TARGET_DEVICE_SERIAL}"/progress

provisioner_log "Provisioning completed. Remove the device from this machine."
