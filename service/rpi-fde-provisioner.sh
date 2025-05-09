#!/bin/sh

set -e
set -x

# shellcheck disable=SC1091
. /var/lib/rpi-sb-provisioner/manufacturing-data
# shellcheck disable=SC1091
. /var/lib/rpi-sb-provisioner/state-recording

DEBUG=

OPENSSL=${OPENSSL:-openssl}

export PROVISIONER_FINISHED="FDE-PROVISIONER-FINISHED"
export PROVISIONER_ABORTED="FDE-PROVISIONER-ABORTED"
export PROVISIONER_STARTED="FDE-PROVISIONER-STARTED"

# shellcheck disable=SC1091
. "$(dirname "$0")/rpi-sb-common.sh"

read_config

: "${RPI_DEVICE_STORAGE_CIPHER:=aes-xts-plain64}"

die() {
    record_state "${TARGET_DEVICE_SERIAL}" "${PROVISIONER_ABORTED}" "${TARGET_USB_PATH}"
    # shellcheck disable=SC2086
    echo "$@" ${DEBUG}
    exit 1
}

simg_expanded_size() {
    echo "$(($(simg_dump "$1" | sed -E 's/.*?Total of ([0-9]+) ([0-9]+)-byte .*/\1 * \2/')))"
}

log() {
    timestamp=$(date +"%Y-%m-%d %H:%M:%S.$(date +%N | cut -c1-3)")
    echo "[${timestamp}] $*" >> /var/log/rpi-sb-provisioner/"${TARGET_DEVICE_SERIAL}"/provisioner.log
}

timeout_nonfatal() {
    command="$*"
    set +e
    log "Running command with 10-second timeout: \"${command}\""
    # shellcheck disable=SC2086
    timeout 10 ${command}
    command_exit_status=$?
    
    # Handle different exit codes from the timeout command
    case ${command_exit_status} in
        0)
            # Command completed successfully within the time limit
            log "\"$command\" succeeded with exit code 0."
            ;;
        124)
            # Exit code 124 means the command timed out (TERM signal sent but command didn't exit)
            log "\"${command}\" FAILED: Timed out after 10 seconds (exit code 124)."
            ;;
        125)
            # Exit code 125 means the timeout command itself failed
            log "\"${command}\" FAILED: The timeout command itself failed (exit code 125)."
            ;;
        126)
            # Exit code 126 means the command was found but could not be executed
            log "\"${command}\" FAILED: Command found but could not be executed (exit code 126)."
            ;;
        127)
            # Exit code 127 means the command was not found
            log "\"${command}\" FAILED: Command not found (exit code 127)."
            ;;
        137)
            # Exit code 137 (128+9) means the command was killed by SIGKILL (kill -9)
            log "\"${command}\" FAILED: Command was killed by SIGKILL (exit code 137)."
            ;;
        *)
            # Any other non-zero exit code is a general failure
            log "\"${command}\" FAILED: Command returned exit code ${command_exit_status}."
            ;;
    esac
    set -e
    return ${command_exit_status}
}

timeout_fatal() {
    command="$*"
    set +e
    log "Running command with 30-second timeout: \"${command}\""
    # shellcheck disable=SC2086
    timeout 30 ${command}
    command_exit_status=$?
    
    # Handle different exit codes from the timeout command
    case ${command_exit_status} in
        0)
            # Command completed successfully within the time limit
            log "\"$command\" succeeded with exit code 0."
            ;;
        124)
            # Exit code 124 means the command timed out (TERM signal sent but command didn't exit)
            record_state "${TARGET_DEVICE_SERIAL}" "${PROVISIONER_ABORTED}" "${TARGET_USB_PATH}"
            die "\"${command}\" FAILED: Timed out after 30 seconds (exit code 124)."
            ;;
        125)
            # Exit code 125 means the timeout command itself failed
            record_state "${TARGET_DEVICE_SERIAL}" "${PROVISIONER_ABORTED}" "${TARGET_USB_PATH}"
            die "\"${command}\" FAILED: The timeout command itself failed (exit code 125)."
            ;;
        126)
            # Exit code 126 means the command was found but could not be executed
            record_state "${TARGET_DEVICE_SERIAL}" "${PROVISIONER_ABORTED}" "${TARGET_USB_PATH}"
            die "\"${command}\" FAILED: Command found but could not be executed (exit code 126)."
            ;;
        127)
            # Exit code 127 means the command was not found
            record_state "${TARGET_DEVICE_SERIAL}" "${PROVISIONER_ABORTED}" "${TARGET_USB_PATH}"
            die "\"${command}\" FAILED: Command not found (exit code 127)."
            ;;
        137)
            # Exit code 137 (128+9) means the command was killed by SIGKILL (kill -9)
            record_state "${TARGET_DEVICE_SERIAL}" "${PROVISIONER_ABORTED}" "${TARGET_USB_PATH}"
            die "\"${command}\" FAILED: Command was killed by SIGKILL (exit code 137)."
            ;;
        *)
            # Any other non-zero exit code is a general failure
            record_state "${TARGET_DEVICE_SERIAL}" "${PROVISIONER_ABORTED}" "${TARGET_USB_PATH}"
            die "\"${command}\" FAILED: Command returned exit code ${command_exit_status}."
            ;;
    esac
    set -e
}
TMP_DIR=""

get_cryptroot() {
    if [ -f /etc/rpi-sb-provisioner/cryptroot_initramfs ]; then
        echo "/etc/rpi-sb-provisioner/cryptroot_initramfs"
    else
        echo "/var/lib/rpi-sb-provisioner/cryptroot_initramfs"
    fi
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
        log "${command_to_test} could not be found"
        exit 1
    else
        echo "$command_to_test"
    fi
}

check_python_module_exists() {
    module_name=$1
    if ! python -c "import ${module_name}" 1> /dev/null; then
        log "Failed to load Python module '${module_name}'"
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
    set +e
    loopdev="$(losetup -f)"
    loopmaj="$(echo "$loopdev" | sed -E 's/.*[0-9]*?([0-9]+)$/\1/')"
    [ -b "$loopdev" ] || mknod "$loopdev" b 7 "$loopmaj"
    set -e
}

# Lifted from pi-gen/scripts/common, unsure under what circumstances this would be necessary
ensure_loopdev_partitions() {
    set +e
    lsblk -r -n -o "NAME,MAJ:MIN" "$1" | grep -v "^${1#/dev/}" | while read -r line; do
        partition="${line%% *}"
        majmin="${line#* }"
        if [ ! -b "/dev/$partition" ]; then
            mknod "/dev/$partition" b "${majmin%:*}" "${majmin#*:}"
        fi
    done
    set -e
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
    returnvalue=$?
    [ -d "${TMP_DIR}/rpi-boot-img-mount" ] && umount "${TMP_DIR}"/rpi-boot-img-mount && sync
    [ -d "${TMP_DIR}/rpi-rootfs-img-mount" ] && umount "${TMP_DIR}"/rpi-rootfs-img-mount && sync
    [ -d "${TMP_DIR}" ] && rm -rf "${TMP_DIR}" && sync
    rm -f "${CUSTOMER_PUBLIC_KEY_FILE}"

    unmount_image "${GOLD_MASTER_OS_FILE}"
    [ -d "${TMP_DIR}" ] && rm -rf "${TMP_DIR}" && sync

    if [ -n "${DELETE_PRIVATE_TMPDIR}" ]; then
        announce_start "Deleting customised intermediates"
        rm -rf "${RPI_SB_WORKDIR}" ${DEBUG}
        sync
        DELETE_PRIVATE_TMPDIR=
        announce_stop "Deleting customised intermediates"
    fi

    exit ${returnvalue}
}
trap cleanup INT TERM

### Start the provisioner phase

# These tools are used to modify the supplied images, and deal with mounting and unmounting the images.
check_command_exists losetup
check_command_exists mknod
check_command_exists lsblk
check_command_exists cut
check_command_exists findmnt

# openssl is used to verify and transform the supplied key
check_command_exists openssl

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
check_command_exists simg_dump

check_command_exists blockdev

check_command_exists grep

check_command_exists mke2fs
check_command_exists img2simg
check_command_exists mkfs.fat
check_command_exists truncate

check_command_exists systemd-notify

get_variable() {
    fastboot -s "${FASTBOOT_DEVICE_SPECIFIER}" getvar "$1" 2>&1 | grep -oP "${1}"': \K[^\r\n]*'
}

setup_fastboot_and_id_vars "$1"

record_state "${TARGET_DEVICE_SERIAL}" "${PROVISIONER_STARTED}" "${TARGET_USB_PATH}"

systemd-notify --ready --status="Provisioning started"

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

    # Configure the cryptroot script to use the correct storage device
    sed -i "s/mmcblk0/${RPI_DEVICE_STORAGE_TYPE}/g" "${initramfs_dir}usr/bin/init_cryptroot.sh"

    find . -print0 | cpio --null -ov --format=newc > ../initramfs.cpio
    cd "${TMP_DIR}"
    rm -rf "${TMP_DIR}"/initramfs
    zstd --no-progress --rm -f -6 "${TMP_DIR}"/initramfs.cpio -o "${initramfs_compressed_file}"
}

prepare_pre_boot_auth_images_as_filesystems() {
    # If the bootfs-temporary hasn't been generated, we are the first to run,
    # and need to generate the bootfs-temporary.simg file, which will also create the
    # mount points for the boot and root partitions.
    if [ ! -f "${RPI_SB_WORKDIR}/rootfs-temporary.simg" ] || [ ! -f "${RPI_SB_WORKDIR}/bootfs-temporary.simg" ]; then
        announce_start "OS Image Mounting"

        # Mount the 'complete' image as a series of partitions 
        cnt=0
        until ensure_next_loopdev && LOOP_DEV="$(losetup --show --find --partscan "${GOLD_MASTER_OS_FILE}")"; do
            if [ $cnt -lt 5 ]; then
                cnt=$((cnt + 1))
                log "Error in losetup.  Retrying..."
                sleep 5
            else
                log "ERROR: losetup failed; exiting"
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

        # shellcheck disable=SC2086
        mkdir -p "${TMP_DIR}"/rpi-cryptroot-bootfs-img-mount ${DEBUG}

        announce_start "OS Image Copying (potentially slow)"
        dd if="${BOOT_DEV}" of="${TMP_DIR}"/bootfs-original.img bs=1M status=progress
        dd if="${ROOT_DEV}" of="${TMP_DIR}"/rootfs-original.img bs=1M status=progress
        announce_stop "OS Image Copying (potentially slow)"

        unmount_image "${GOLD_MASTER_OS_FILE}"

        # Use the size of the original boot image, or the size of the cryptroot initramfs, whichever is larger.
        BOOTFS_ORIGINAL_SIZE_MB=$(( ($(stat -c%s "${TMP_DIR}"/bootfs-original.img) + 1048575) / 1048576 ))
        CRYPTROOT_MINIMUM_SIZE_MB=$(( ($(stat -c%s "$(get_cryptroot)") + 1048575) / 1048576 ))
        BOOTFS_SIZE_MB=$(( BOOTFS_ORIGINAL_SIZE_MB > CRYPTROOT_MINIMUM_SIZE_MB ? BOOTFS_ORIGINAL_SIZE_MB : CRYPTROOT_MINIMUM_SIZE_MB ))
        # Using 1M which is 1 MiB (1048576 bytes) as the block size
        CRYPTROOT_BOOTFS_FILE="${RPI_SB_WORKDIR}/cryptroot-bootfs.img"
        truncate -s "${BOOTFS_SIZE_MB}M" "${CRYPTROOT_BOOTFS_FILE}"
        mkfs.fat -n "BOOT" "${CRYPTROOT_BOOTFS_FILE}"

        # OS Images are, by convention, packed as a MBR whole-disk file,
        # containing two partitions: A FAT boot partition, which contains the kernel, command line,
        # and supporting boot infrastructure for the Raspberry Pi Device.
        # And in partition 2, the OS rootfs itself.
        # Note that this mechanism is _assuming_ Linux. We may revise that in the future, but
        # to do so would require a concrete support commitment from the vendor - and Raspberry Pi only
        # support Linux.
        # shellcheck disable=SC2086
        mount -t vfat "${TMP_DIR}"/bootfs-original.img "${TMP_DIR}"/rpi-boot-img-mount ${DEBUG}
        # shellcheck disable=SC2086
        mount -t ext4 "${TMP_DIR}"/rootfs-original.img "${TMP_DIR}"/rpi-rootfs-img-mount ${DEBUG}

        # shellcheck disable=SC2086
        mount -t vfat "${CRYPTROOT_BOOTFS_FILE}" "${TMP_DIR}"/rpi-cryptroot-bootfs-img-mount ${DEBUG}

        announce_stop "OS Image Mounting"

        cp -R "${TMP_DIR}"/rpi-boot-img-mount/* "${TMP_DIR}"/rpi-cryptroot-bootfs-img-mount/

        # We supply a pre-baked Raspberry Pi Pre-boot-authentication initramfs, which we insert here.
        # This image is maintained by Raspberry Pi, with sources available on our GitHub pages.
        announce_start "Insert pre-boot authentication initramfs"
        cp "$(get_cryptroot)" "${TMP_DIR}"/rpi-cryptroot-bootfs-img-mount/initramfs8
        announce_stop "Insert pre-boot authentication initramfs"

        announce_start "Cryptroot synthesis"

        # Use subshells to avoid polluting our CWD.
        ( augment_initramfs "${TMP_DIR}"/rpi-cryptroot-bootfs-img-mount/initramfs8 )
        announce_stop "Cryptroot synthesis"

        announce_start "cmdline.txt modification"
        sed --in-place 's%\b\(root=\)\S*%\1/dev/ram0%' "${TMP_DIR}"/rpi-cryptroot-bootfs-img-mount/cmdline.txt
        sed --in-place 's%\binit=\S*%%' "${TMP_DIR}"/rpi-cryptroot-bootfs-img-mount/cmdline.txt
        sed --in-place 's%\brootfstype=\S*%%' "${TMP_DIR}"/rpi-cryptroot-bootfs-img-mount/cmdline.txt
        # TODO: Consider deleting quiet
        sed --in-place 's%\bquiet\b%%' "${TMP_DIR}"/rpi-cryptroot-bootfs-img-mount/cmdline.txt
        announce_stop "cmdline.txt modification"

        # Run customisation script for bootfs-mounted stage
        run_customisation_script "fde-provisioner" "bootfs-mounted" "${TMP_DIR}/rpi-cryptroot-bootfs-img-mount" "${TMP_DIR}/rpi-rootfs-img-mount"

        # Run customisation script for rootfs-mounted stage
        run_customisation_script "fde-provisioner" "rootfs-mounted" "${TMP_DIR}/rpi-cryptroot-bootfs-img-mount" "${TMP_DIR}/rpi-rootfs-img-mount"

        umount "${TMP_DIR}"/rpi-boot-img-mount
        umount "${TMP_DIR}"/rpi-rootfs-img-mount
        umount "${TMP_DIR}"/rpi-cryptroot-bootfs-img-mount

        sync; sync; sync;

        img2simg -s "${CRYPTROOT_BOOTFS_FILE}" "${RPI_SB_WORKDIR}"/bootfs-temporary.simg
        rm -f "${CRYPTROOT_BOOTFS_FILE}"
        announce_stop "Boot Image partition extraction"
    fi # Slow path
} # prepare_pre_boot_auth_images_as_bootfiles

prepare_pre_boot_auth_images_as_bootimg() {
    # If the bootfs-temporary hasn't been generated, we are the first to run,
    # and need to generate the bootfs-temporary.simg file, which will also create the
    # mount points for the boot and root partitions.
    if [ ! -f "${RPI_SB_WORKDIR}/rootfs-temporary.simg" ] || [ ! -f "${RPI_SB_WORKDIR}/bootfs-temporary.simg" ]; then
        announce_start "OS Image Mounting"

        # Mount the 'complete' image as a series of partitions 
        cnt=0
        until ensure_next_loopdev && LOOP_DEV="$(losetup --show --find --partscan "${GOLD_MASTER_OS_FILE}")"; do
            if [ $cnt -lt 5 ]; then
                cnt=$((cnt + 1))
                log "Error in losetup.  Retrying..."
                sleep 5
            else
                log "ERROR: losetup failed; exiting"
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

        announce_start "OS Image Copying (potentially slow)"
        dd if="${BOOT_DEV}" of="${TMP_DIR}"/bootfs-original.img bs=1M status=progress
        dd if="${ROOT_DEV}" of="${TMP_DIR}"/rootfs-original.img bs=1M status=progress
        announce_stop "OS Image Copying (potentially slow)"

        unmount_image "${GOLD_MASTER_OS_FILE}"

        # OS Images are, by convention, packed as a MBR whole-disk file,
        # containing two partitions: A FAT boot partition, which contains the kernel, command line,
        # and supporting boot infrastructure for the Raspberry Pi Device.
        # And in partition 2, the OS rootfs itself.
        # Note that this mechanism is _assuming_ Linux. We may revise that in the future, but
        # to do so would require a concrete support commitment from the vendor - and Raspberry Pi only
        # support Linux.
        # shellcheck disable=SC2086
        mount -t vfat "${TMP_DIR}"/bootfs-original.img "${TMP_DIR}"/rpi-boot-img-mount ${DEBUG}
        # shellcheck disable=SC2086
        mount -t ext4 "${TMP_DIR}"/rootfs-original.img "${TMP_DIR}"/rpi-rootfs-img-mount ${DEBUG}

        announce_stop "OS Image Mounting"

        # We supply a pre-baked Raspberry Pi Pre-boot-authentication initramfs, which we insert here.
        # This image is maintained by Raspberry Pi, with sources available on our GitHub pages.
        announce_start "Insert pre-boot authentication initramfs"
        cp "$(get_cryptroot)" "${TMP_DIR}"/rpi-boot-img-mount/initramfs8
        announce_stop "Insert pre-boot authentication initramfs"

        announce_start "Initramfs modification"

        # Use subshells to avoid polluting our CWD.
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

        # Run customisation script for bootfs-mounted stage
        run_customisation_script "fde-provisioner" "bootfs-mounted" "${TMP_DIR}/rpi-boot-img-mount" "${TMP_DIR}/rpi-rootfs-img-mount"

        # Run customisation script for rootfs-mounted stage
        run_customisation_script "fde-provisioner" "rootfs-mounted" "${TMP_DIR}/rpi-boot-img-mount" "${TMP_DIR}/rpi-rootfs-img-mount"

        announce_start "boot.img creation"
        cp "$(get_fastboot_config_file)" "${TMP_DIR}"/config.txt

        rpi-make-boot-image -b "pi${RPI_DEVICE_FAMILY}" -a 64 -d "${TMP_DIR}"/rpi-boot-img-mount -o "${TMP_DIR}"/boot.img
        announce_stop "boot.img creation"

        announce_start "Boot Image partition extraction"

        # Get the size of the original boot image in MiB (rounded up)
        BOOTFS_SIZE_MB=$(( ($(stat -c%s "${TMP_DIR}"/bootfs-original.img) + 1048575) / 1048576 ))
        # Using 1M which is 1 MiB (1048576 bytes) as the block size
        truncate -s "${BOOTFS_SIZE_MB}M" "${TMP_DIR}"/bootfs-temporary.img
        mkfs.fat -n "BOOT" "${TMP_DIR}"/bootfs-temporary.img

        META_BOOTIMG_MOUNT_PATH=$(mktemp -d)
        mount -o loop "${TMP_DIR}"/bootfs-temporary.img "${META_BOOTIMG_MOUNT_PATH}"
        cp "${TMP_DIR}"/boot.img "${META_BOOTIMG_MOUNT_PATH}"/boot.img
        cp "${TMP_DIR}"/config.txt "${META_BOOTIMG_MOUNT_PATH}"/config.txt

        umount "${TMP_DIR}"/rpi-boot-img-mount
        umount "${TMP_DIR}"/rpi-rootfs-img-mount

        sync; sync; sync;

        umount "${META_BOOTIMG_MOUNT_PATH}"
        rm -rf "${META_BOOTIMG_MOUNT_PATH}"
        img2simg -s "${TMP_DIR}"/bootfs-temporary.img "${RPI_SB_WORKDIR}"/bootfs-temporary.simg
        rm -f "${TMP_DIR}"/bootfs-temporary.img
        announce_stop "Boot Image partition extraction"
    fi # Slow path
} # prepare_pre_boot_auth_images_as_bootimg

case "${RPI_DEVICE_FAMILY}" in
    "4" | "5")
        with_lock "${LOCK_BASE}/pre-boot-auth-images.lock" 600 prepare_pre_boot_auth_images_as_bootimg
        ;;
    "2W")
        with_lock "${LOCK_BASE}/pre-boot-auth-images.lock" 600 prepare_pre_boot_auth_images_as_filesystems
        ;;
    *)
        die "Unsupported device family: ${RPI_DEVICE_FAMILY}"
        ;;
esac

announce_start "Erase / Partition Device Storage"

# Arbitrary sleeps to handle lack of correct synchronisation in fastbootd.
fastboot -s "${FASTBOOT_DEVICE_SPECIFIER}" erase "${RPI_DEVICE_STORAGE_TYPE}"
sleep 2
fastboot -s "${FASTBOOT_DEVICE_SPECIFIER}" oem partinit "${RPI_DEVICE_STORAGE_TYPE}" DOS
sleep 2
fastboot -s "${FASTBOOT_DEVICE_SPECIFIER}" oem partapp "${RPI_DEVICE_STORAGE_TYPE}" 0c "$(simg_expanded_size "${RPI_SB_WORKDIR}"/bootfs-temporary.simg)"
sleep 2
fastboot -s "${FASTBOOT_DEVICE_SPECIFIER}" oem partapp "${RPI_DEVICE_STORAGE_TYPE}" 83 # Grow to fill storage
sleep 2
fastboot -s "${FASTBOOT_DEVICE_SPECIFIER}" oem cryptinit "${RPI_DEVICE_STORAGE_TYPE}"p2 root "${RPI_DEVICE_STORAGE_CIPHER}"
sleep 2
fastboot -s "${FASTBOOT_DEVICE_SPECIFIER}" oem cryptopen "${RPI_DEVICE_STORAGE_TYPE}"p2 cryptroot
sleep 2
announce_stop "Erase / Partition Device Storage"

prepare_rootfs_image() {
    if [ -f "${RPI_SB_WORKDIR}/rootfs-temporary.simg" ] && [ "$((TARGET_STORAGE_ROOT_EXTENT))" -eq "$(simg_expanded_size "${RPI_SB_WORKDIR}"/rootfs-temporary.simg)" ]; then
        announce_stop "Resizing OS images: Not required, already the correct size"
    else
        mount -t ext4 "${TMP_DIR}"/rootfs-original.img "${TMP_DIR}"/rpi-rootfs-img-mount
        mke2fs -t ext4 -b 4096 -d "${TMP_DIR}"/rpi-rootfs-img-mount "${RPI_SB_WORKDIR}"/rootfs-temporary.img $((TARGET_STORAGE_ROOT_EXTENT / 4096))
        img2simg -s "${RPI_SB_WORKDIR}"/rootfs-temporary.img "${RPI_SB_WORKDIR}"/rootfs-temporary.simg
        umount "${TMP_DIR}"/rpi-rootfs-img-mount
        rm -f "${RPI_SB_WORKDIR}"/rootfs-temporary.img
        announce_stop "Resizing OS images: Resized to $((TARGET_STORAGE_ROOT_EXTENT))"
    fi
}

announce_start "Resizing rootfs image"
# Need mke2fs with '-E android_sparse' support
# Debian's 'android-sdk-platform-tools' provides the option but is not correctly
# built against libsparse: https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1008107
#
# https://dl.google.com/android/repository/platform-tools-latest-linux.zip
# https://dl.google.com/android/repository/platform-tools-latest-darwin.zip
# https://dl.google.com/android/repository/platform-tools-latest-windows.zip
TARGET_STORAGE_ROOT_EXTENT="$(get_variable partition-size:mapper/cryptroot)"
with_lock "${LOCK_BASE}/rootfs-image.lock" 600 prepare_rootfs_image
announce_stop "Resizing rootfs image"

# Re-check the fastboot devices specifier, as it may take a while for a device to gain IP connectivity
setup_fastboot_and_id_vars "${FASTBOOT_DEVICE_SPECIFIER}"

announce_start "Writing OS images"
fastboot -s "${FASTBOOT_DEVICE_SPECIFIER}" flash "${RPI_DEVICE_STORAGE_TYPE}"p1 "${RPI_SB_WORKDIR}"/bootfs-temporary.simg
fastboot -s "${FASTBOOT_DEVICE_SPECIFIER}" flash mapper/cryptroot "${RPI_SB_WORKDIR}"/rootfs-temporary.simg
announce_stop "Writing OS images"

# Run customisation script for post-flash stage
run_customisation_script "fde-provisioner" "post-flash"

announce_start "Set LED status"
fastboot -s "${FASTBOOT_DEVICE_SPECIFIER}" oem led PWR 0
announce_stop "Set LED status"

metadata_gather

record_state "${TARGET_DEVICE_SERIAL}" "${PROVISIONER_FINISHED}" "${TARGET_USB_PATH}"
log "Provisioning completed. Remove the device from this machine."

# Indicate successful completion to systemd
# This is used when the script is run as a systemd service
# The special exit code 0 indicates success to systemd
# Additionally, we can use systemd-notify if available to indicate completion
systemd-notify --status="Provisioning completed successfully" STOPPING=1

# Exit with success code for systemd
true
cleanup
