#!/bin/sh

set -e
set -x

DEBUG=

OPENSSL=${OPENSSL:-openssl}

export KEYWRITER_FINISHED="KEYWRITER-FINISHED"
export KEYWRITER_ABORTED="KEYWRITER-ABORTED"
export KEYWRITER_STARTED="KEYWRITER-STARTED"
export PROVISIONER_FINISHED="PROVISIONER-FINISHED"
export PROVISIONER_ABORTED="PROVISIONER-ABORTED"
export PROVISIONER_STARTED="PROVISIONER-STARTED"


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

read_config() {
    if [ -f /etc/rpi-sb-provisioner/config ]; then
        . /etc/rpi-sb-provisioner/config
    else
        echo "Failed to load config. Please use configuration tool." >&2
        return 1
    fi
}

: "${RPI_DEVICE_STORAGE_CIPHER:=aes-xts-plain64}"

get_signing_directives() {
    if [ -n "${CUSTOMER_KEY_PKCS11_NAME}" ]; then
        echo "${CUSTOMER_KEY_PKCS11_NAME} -engine pkcs11 -keyform engine"
    else
        if [ -n "${CUSTOMER_KEY_FILE_PEM}" ]; then
            if [ -f "${CUSTOMER_KEY_FILE_PEM}" ]; then
                echo "${CUSTOMER_KEY_FILE_PEM} -keyform PEM"
            else
                echo "RSA private key \"${CUSTOMER_KEY_FILE_PEM}\" not a file. Aborting." >&2
                exit 1
            fi
        else
            echo "Neither PKCS11 key name, or PEM key file specified. Aborting." >&2
            exit 1
        fi
    fi
}

echo "${KEYWRITER_STARTED}" >> /var/log/rpi-sb-provisioner/"${TARGET_DEVICE_SERIAL}"/progress

read_config

die() {
    echo "${PROVISIONER_ABORTED}" >> /var/log/rpi-sb-provisioner/"${TARGET_DEVICE_SERIAL}"/progress
    # shellcheck disable=SC2086
    echo "$@" ${DEBUG}
    exit 1
}

provisioner_log() {
    echo "$@" >> /var/log/rpi-sb-provisioner/"${TARGET_DEVICE_SERIAL}"/provisioner.log
}

TMP_DIR=""

writeSig() {
   SIG_TMP="$(mktemp)"
   IMAGE="$1"
   OUTPUT="$2"
   sha256sum "${IMAGE}" | awk '{print $1}' > "${OUTPUT}"

   # Include the update-timestamp
   echo "ts: $(date -u +%s)" >> "${OUTPUT}"

   if [ -n "$(get_signing_directives)" ]; then
      # shellcheck disable=SC2046
      "${OPENSSL}" dgst -sign $(get_signing_directives) -sha256 -out "${SIG_TMP}" "${IMAGE}"
      echo "rsa2048: $(xxd -c 4096 -p < "${SIG_TMP}")" >> "${OUTPUT}"
   fi
   rm "${SIG_TMP}"
}

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

# TODO: Refactor these two functions to use the same logic, but with different consequences for failure.
timeout_nonfatal() {
    command="$*"
    set +e
    [ -z "${DEMO_MODE_ONLY}" ] && timeout 120 "${command}"
    set -e
    command_exit_status=$?
    if [ ${command_exit_status} -eq 124 ]; then
        provisioner_log "\"${command}\" failed, timed out."
        echo "${PROVISIONER_ABORTED}" >> /var/log/rpi-sb-provisioner/"${TARGET_DEVICE_SERIAL}"/progress
        return 124
    elif [ ${command_exit_status} -ne 0 ]; then
        echo "${PROVISIONER_ABORTED}" >> /var/log/rpi-sb-provisioner/"${TARGET_DEVICE_SERIAL}"/progress
        provisioner_log "\"$command\" failed: ${command_exit_status}"
    else
        provisioner_log "\"$command\" succeeded."
    fi
}

timeout_fatal() {
    command="$*"
    set +e
    [ -z "${DEMO_MODE_ONLY}" ] && timeout 120 "${command}"
    set -e
    command_exit_status=$?
    if [ ${command_exit_status} -eq 124 ]; then
        echo "${PROVISIONER_ABORTED}" >> /var/log/rpi-sb-provisioner/"${TARGET_DEVICE_SERIAL}"/progress
        die "\"${command}\" failed, timed out."
    elif [ ${command_exit_status} -ne 0 ]; then
        echo "${PROVISIONER_ABORTED}" >> /var/log/rpi-sb-provisioner/"${TARGET_DEVICE_SERIAL}"/progress
        die "\"$command\" failed: ${command_exit_status}"
    else
        provisioner_log "\"$command\" succeeded."
    fi
}

cleanup() {
    if [ -d "${TMP_DIR}" ]; then
        rm -rf "${TMP_DIR}"
    fi
    rm "${CUSTOMER_PUBLIC_KEY_FILE}"

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

### Start the provisioner phase

echo "${PROVISIONER_STARTED}" >> /var/log/rpi-sb-provisioner/"${TARGET_DEVICE_SERIAL}"/progress

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

check_command_exists blockdev

check_command_exists grep

get_variable() {
    [ -z "${DEMO_MODE_ONLY}" ] && fastboot getvar "$1" 2>&1 | grep -oP "${1}"': \K[^\r\n]*'
}

TARGET_DEVICE_SERIAL="$(get_variable serialno)"

TMP_DIR=$(mktemp -d)
RPI_DEVICE_STORAGE_TYPE="$(check_pidevice_storage_type "${RPI_DEVICE_STORAGE_TYPE}")"
DELETE_PRIVATE_TMPDIR=
announce_start "Finding the cache directory"
if [ -z "${RPI_SB_WORKDIR}" ]; then
    RPI_SB_WORKDIR=$(mktemp -d "pi-sb-provisioner.XXX" --tmpdir="/srv/")
    announce_stop "Finding the cache directory: Created a new one as unspecified"
    DELETE_PRIVATE_TMPDIR="true"
elif [ ! -d "${RPI_SB_WORKDIR}" ]; then
    RPI_SB_WORKDIR=$(mktemp -d "pi-sb-provisioner.XXX" --tmpdir="/srv/")
    announce_stop "Finding the cache directory: Created a new one in /srv, as supplied path isn't a directory"
    DELETE_PRIVATE_TMPDIR="true"
else
    # Deliberately do nothing
    announce_stop "Finding the cache directory: Using specified name"
fi

announce_start "Selecting and interrogating device"

#announce_start "Getting target information"
#TARGET_STORAGE_LIST_RESULT="$(get_variable storage-types-list)"
#TARGET_PI_GENERATION="$(get_variable hw-generation)"
#TARGET_DUID="$(get_variable device-uuid)"
#TARGET_SERIAL="$(get_variable serialno)"
#announce_stop "Getting target information"

#announce_start "Storage device check"
#STORAGE_FOUND=0
#for device in ${TARGET_STORAGE_LIST_RESULT}
#do
#    if [ ${device} == ${RPI_DEVICE_STORAGE_TYPE} ]; then
#        STORAGE_FOUND=1
#    fi
#done

#if ! ${STORAGE_FOUND}; then
#    die "Selected storage type is not available, wanted one of [${TARGET_STORAGE_LIST_RESULT}], got ${RPI_DEVICE_STORAGE_TYPE}"
#fi

#announce_stop "Storage device check"

#announce_start "Raspberry Pi Generation check"
#if ${RPI_DEVICE_FAMILY} != ${TARGET_PI_GENERATION}; then
#    die "Raspberry Pi Generation mismatch. Expected a Raspberry Pi ${TARGET_PI_GENERATION} class device, you supplied ${RPI_DEVICE_FAMILY}"
#fi
#announce_stop "Raspberry Pi Generation check"

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
    cp "$(get_cryptroot)" "${TMP_DIR}"/rpi-boot-img-mount/initramfs_2712
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

    case "${RPI_DEVICE_FAMILY}" in
        4)
            echo 'initramfs initramfs8' >> "${TMP_DIR}"/rpi-boot-img-mount/config.txt
            ;;
        5)
            echo 'initramfs initramfs_2712' >> "${TMP_DIR}"/rpi-boot-img-mount/config.txt
            ;;
    esac
    
    announce_stop "config.txt modification"

    announce_start "boot.img creation"
    cp "$(get_fastboot_config_file)" "${TMP_DIR}"/config.txt

    make-boot-image -b "pi${RPI_DEVICE_FAMILY}" -d "${TMP_DIR}"/rpi-boot-img-mount -o "${TMP_DIR}"/boot.img
    announce_stop "boot.img creation"

    announce_start "boot.img signing"
    # N.B. rpi-eeprom-digest could be used here but it includes a timestamp that is not required for this use-case
    sha256sum "${TMP_DIR}"/boot.img | awk '{print $1}' > "${TMP_DIR}"/boot.sig
    printf 'rsa2048: ' >> "${TMP_DIR}"/boot.sig
    # shellcheck disable=SC2046
    ${OPENSSL} dgst -sign $(get_signing_directives) -sha256 "${TMP_DIR}"/boot.img | xxd -c 4096 -p >> "${TMP_DIR}"/boot.sig
    announce_stop "boot.img signing"

    announce_start "Boot Image partition extraction"

    REQUIRED_BOOTIMG_SIZE="$(stat -c%s "${TMP_DIR}"/boot.img)"
    REQUIRED_BOOTSIG_SIZE="$(stat -c%s "${TMP_DIR}"/boot.sig)"
    REQUIRED_CONFIGTXT_SIZE="$(stat -c%s "${TMP_DIR}"/config.txt)"
    SECTOR_SIZE=512
    TOTAL_SIZE=$((REQUIRED_BOOTIMG_SIZE + REQUIRED_BOOTSIG_SIZE + REQUIRED_CONFIGTXT_SIZE))
    TOTAL_SIZE=$((TOTAL_SIZE + 64))
    TOTAL_SIZE=$(((TOTAL_SIZE + 1023) / 1024))
    SECTORS=$((TOTAL_SIZE / SECTOR_SIZE))
    SECTORS=$((SECTORS / 2))
    # HACK: pi-gen is producing 512mib boot images, but we should _really_ calculate this from the base image.
    dd if=/dev/zero of="${TMP_DIR}"/bootfs-temporary.img bs=1M count=512
    mkfs.fat -n "BOOT" "${TMP_DIR}"/bootfs-temporary.img

    META_BOOTIMG_MOUNT_PATH=$(mktemp -d)
    mount -o loop "${TMP_DIR}"/bootfs-temporary.img "${META_BOOTIMG_MOUNT_PATH}"
    cp "${TMP_DIR}"/boot.img "${META_BOOTIMG_MOUNT_PATH}"/boot.img
    cp "${TMP_DIR}"/boot.sig "${META_BOOTIMG_MOUNT_PATH}"/boot.sig
    cp "${TMP_DIR}"/config.txt "${META_BOOTIMG_MOUNT_PATH}"/config.txt

    sync; sync; sync;

    umount "${META_BOOTIMG_MOUNT_PATH}"
    rm -rf "${META_BOOTIMG_MOUNT_PATH}"
    img2simg "${TMP_DIR}"/bootfs-temporary.img "${RPI_SB_WORKDIR}"/bootfs-temporary.simg
    announce_stop "Boot Image partition extraction"
fi # Slow path

announce_start "Erase / Partition Device Storage"

# Arbitrary sleeps to handle lack of correct synchronisation in fastbootd.

[ -z "${DEMO_MODE_ONLY}" ] && timeout_fatal fastboot getvar version

[ -z "${DEMO_MODE_ONLY}" ] && fastboot erase "${RPI_DEVICE_STORAGE_TYPE}"
sleep 2
[ -z "${DEMO_MODE_ONLY}" ] && fastboot oem partinit "${RPI_DEVICE_STORAGE_TYPE}" DOS
sleep 2
[ -z "${DEMO_MODE_ONLY}" ] && fastboot oem partapp "${RPI_DEVICE_STORAGE_TYPE}" 0c "$(stat -c%s "${RPI_SB_WORKDIR}"/bootfs-temporary.img)"
sleep 2
[ -z "${DEMO_MODE_ONLY}" ] && fastboot oem partapp "${RPI_DEVICE_STORAGE_TYPE}" 83 # Grow to fill storage
sleep 2
[ -z "${DEMO_MODE_ONLY}" ] && fastboot oem cryptinit "${RPI_DEVICE_STORAGE_TYPE}"p2 root "${RPI_DEVICE_STORAGE_CIPHER}"
sleep 2
[ -z "${DEMO_MODE_ONLY}" ] && fastboot oem cryptopen "${RPI_DEVICE_STORAGE_TYPE}"p2 cryptroot
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
    img2simg "${RPI_SB_WORKDIR}"/rootfs-temporary.img "${RPI_SB_WORKDIR}"/rootfs-temporary.simg
    rm -f "${RPI_SB_WORKDIR}"/rootfs-temporary.img
    #TODO: Re-enable android_sparse
    #mke2fs -t ext4 -b 4096 -d ${TMP_DIR}/rpi-rootfs-img-mount -E android_sparse ${RPI_SB_WORKDIR}/rootfs-temporary.simg $((TARGET_STORAGE_ROOT_EXTENT / 4096))
    announce_stop "Resizing OS images: Resized to $((TARGET_STORAGE_ROOT_EXTENT))"
fi

announce_start "Testing Fastboot IP connectivity"
USE_IPV4=
USE_IPV6=
[ -z "${DEMO_MODE_ONLY}" ] && IPV6_ADDRESS="$(timeout_nonfatal fastboot getvar ipv6-address_0)"
[ -z "${DEMO_MODE_ONLY}" ] && timeout_nonfatal fastboot -s tcp:"${IPV6_ADDRESS}" getvar version && USE_IPV6=$?
[ -z "${DEMO_MODE_ONLY}" ] && IPV4_ADDRESS="$(timeout_nonfatal fastboot getvar ipv4-address_0)"
[ -z "${DEMO_MODE_ONLY}" ] && timeout_nonfatal fastboot -s tcp:"${IPV4_ADDRESS}" getvar version && USE_IPV4=$?
announce_stop "Testing Fastboot IP connectivity"

announce_start "Writing OS images"
# Favour using IPv6 if available, and ethernet regardless to get 1024-byte chunks in Fastboot without USB3
FASTBOOT_DEVICE_SPECIFIER=
if [ -n "${USE_IPV6}" ]; then
FASTBOOT_DEVICE_SPECIFIER="tcp:${IPV6_ADDRESS}"
elif [ -n "${USE_IPV4}" ]; then
FASTBOOT_DEVICE_SPECIFIER="tcp:${IPV4_ADDRESS}"
else
FASTBOOT_DEVICE_SPECIFIER="${TARGET_DEVICE_SERIAL}"
fi
[ -z "${DEMO_MODE_ONLY}" ] && fastboot -s "${FASTBOOT_DEVICE_SPECIFIER}" flash "${RPI_DEVICE_STORAGE_TYPE}"p1 "${RPI_SB_WORKDIR}"/bootfs-temporary.simg
[ -z "${DEMO_MODE_ONLY}" ] && fastboot -s "${FASTBOOT_DEVICE_SPECIFIER}" flash mapper/cryptroot "${RPI_SB_WORKDIR}"/rootfs-temporary.simg
announce_stop "Writing OS images"

if [ -z "${DEMO_MODE_ONLY}" ] && [ -d "${RPI_DEVICE_RETRIEVE_KEYPAIR}" ]; then
    announce_start "Capturing device keypair to ${RPI_DEVICE_RETRIEVE_KEYPAIR}"
    N_ALREADY_PROVISIONED=0
    get_variable private-key > "${RPI_DEVICE_RETRIEVE_KEYPAIR}/${TARGET_DEVICE_SERIAL}.der" || N_ALREADY_PROVISIONED=$?
    if [ 0 -ne "$N_ALREADY_PROVISIONED" ]; then
        keywriter_log "Warning: Unable to retrieve device private key; already provisioned"
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
[ -z "${DEMO_MODE_ONLY}" ] && fastboot oem led PWR 0
announce_stop "Set LED status"

echo "${PROVISIONER_FINISHED}" >> /var/log/rpi-sb-provisioner/"${TARGET_DEVICE_SERIAL}"/progress

provisioner_log "Provisioning completed. Remove the device from this machine."
