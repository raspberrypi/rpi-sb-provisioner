#!/usr/bin/env bash

set -e
set -x

OPTSTRING=":i:k:p:s:d"
CUSTOMER_KEY_FILE_PEM=""
RPI_DEVICE_FAMILY=
RPI_DEVICE_STORAGE_TYPE=
GOLD_MASTER_OS_FILE=""
COPY_OS_COMBINED_FILE=""
DEBUG=
TARGET_DEVICE_SERIAL="$1"

. /etc/rpi-sb-provisioner/config
. /usr/local/bin/terminal-functions.sh

check_pidevice_storage_type() {
    case "${1}" in
        "sd")
            echo "mmcblk0"
            ;;
        "nvme")
            echo "nvme0n1"
            ;;
        "emmc")
            echo "mmcblk0"
            ;;
        ?)
            echo "Unexpected storage device type. Wanted sd, nvme or emmc, got $1" >&2
            exit 1
            ;;
    esac
}

# Lifted from pi-gen/scripts/common, unsure under what circumstances this would be necessary
ensure_next_loopdev() {
    local loopdev
    loopdev="$(losetup -f)"
    loopmaj="$(echo "$loopdev" | sed -E 's/.*[0-9]*?([0-9]+)$/\1/')"
    [[ -b "$loopdev" ]] || mknod "$loopdev" b 7 "$loopmaj"
}

# Lifted from pi-gen/scripts/common, unsure under what circumstances this would be necessary
ensure_loopdev_partitions() {
    local line
    local partition
    local majmin
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
        local LOCS
        LOCS=$(mount | grep "$DIR" | cut -f 3 -d ' ' | sort -r)
        for loc in $LOCS; do
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
    mkdir -p /var/log/rpi-sb-provisioner/${TARGET_DEVICE_SERIAL}/
    echo "1" > /var/log/rpi-sb-provisioner/${TARGET_DEVICE_SERIAL}/finished
    unmount_image "${COPY_OS_COMBINED_FILE}"
    if [ -d "${TMP_DIR}" ]; then
        rm -rf "${TMP_DIR}"
    fi

    if [ -f "${COPY_OS_COMBINED_FILE}" ]; then
        rm -rf "${COPY_OS_COMBINED_FILE}"
    fi
}

trap cleanup EXIT

while getopts ${OPTSTRING} opt; do
    case ${opt} in
        i)
            # Image path. Must be local, and a combined image.
            GOLD_MASTER_OS_FILE=$(check_file_is_expected_fatal "${OPTARG}" "img")
            ;;
        k)
            # Key file. Expected a PEM.
            CUSTOMER_KEY_FILE_PEM=$(check_file_is_expected_fatal "${OPTARG}" "pem")
            ;;
        p)
            RPI_DEVICE_FAMILY=$(check_pidevice_generation "${OPTARG}")
            ;;
        s)
            check_pidevice_storage_type "${OPTARG}"
            ;;
        v)
            DEBUG="2>&1 | tee debug.log"
            ;;
        :)
            echo "Option -${OPTARG} requires an argument"
            exit 1
            ;;
        ?)
            echo "Unexpected option -${OPTARG}"
            exit 1
            ;;
    esac
done

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
check_command_exists sfdisk

get_variable() {
    fastboot getvar "$1" 2>&1 | grep -oP "${1}"': \K.*'
}

RPI_DEVICE_FAMILY=$(check_pidevice_generation "${RPI_DEVICE_FAMILY}")

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

announce_start "Finding/generating fastboot image"

case ${RPI_DEVICE_FAMILY} in
    4)
        # Raspberry Pi 4-class devices do not use signed bootcode files, so just copy the file into the relevant place.
        cp /usr/share/rpiboot/mass-storage-gadget64/bootfiles.bin "${RPI_SB_WORKDIR}/bootfiles.bin"
        ;;
    5)
        FASTBOOT_SIGN_DIR=$(mktemp -d)
        pushd "${FASTBOOT_SIGN_DIR}"
        tar -vxf /usr/share/rpiboot/mass-storage-gadget64/bootfiles.bin
        rpi-sign-bootcode --debug -c 2712 -i 2712/bootcode5.bin -o 2712/bootcode5.bin.signed -k "${CUSTOMER_KEY_FILE_PEM}" -v 0 -n 16
        mv -f "2712/bootcode5.bin.signed" "2712/bootcode5.bin"
        tar -vcf "${RPI_SB_WORKDIR}/bootfiles.bin" -- *
        popd
        rm -rf "${FASTBOOT_SIGN_DIR}"
        ;;
esac

cp /usr/share/rpi-sb-provisioner/fastboot-gadget.img "${RPI_SB_WORKDIR}"/boot.img

cp /usr/share/rpi-sb-provisioner/boot_ramdisk_config.txt "${RPI_SB_WORKDIR}"/config.txt

#boot.sig generation
sha256sum "${RPI_SB_WORKDIR}"/boot.img | awk '{print $1}' > "${RPI_SB_WORKDIR}"/boot.sig
echo -n "rsa2048: " >> "${RPI_SB_WORKDIR}"/boot.sig
${OPENSSL} dgst -sign "${CUSTOMER_KEY_FILE_PEM}" -keyform PEM -sha256 "${RPI_SB_WORKDIR}"/boot.img | xxd -c 4096 -p >> "${RPI_SB_WORKDIR}"/boot.sig

announce_stop "Finding/generating fastboot image"

announce_start "Starting fastboot"
rpiboot -v -d "${RPI_SB_WORKDIR}" -i "${TARGET_DEVICE_SERIAL}"
announce_stop "Starting fastboot"

announce_start "Selecting and interrogating device"

announce_start "Getting target information"
#TARGET_STORAGE_LIST_RESULT="$(get_variable storage-types-list)"
#TARGET_PI_GENERATION="$(get_variable hw-generation)"
#TARGET_DUID="$(get_variable device-uuid)"
#TARGET_SERIAL="$(get_variable serialno)"
announce_stop "Getting target information"

announce_start "Storage device check"
#STORAGE_FOUND=0
#for device in ${TARGET_STORAGE_LIST_RESULT}
#do
#    if [ ${device} == ${RPI_DEVICE_STORAGE_TYPE} ]; then
#        STORAGE_FOUND=1
#    fi
#done

#if ! ${STORAGE_FOUND}; then
#    echo "Selected storage type is not available, wanted one of [${TARGET_STORAGE_LIST_RESULT}], got ${RPI_DEVICE_STORAGE_TYPE}"
#    exit 1
#fi

announce_stop "Storage device check"

#announce_start "Raspberry Pi Generation check"
#if ${RPI_DEVICE_FAMILY} != ${TARGET_PI_GENERATION}; then
#    echo "Raspberry Pi Generation mismatch. Expected a Raspberry Pi ${TARGET_PI_GENERATION} class device, you supplied ${RPI_DEVICE_FAMILY}"
#    exit 1
#fi
#announce_stop "Raspberry Pi Generation check"

# Fast path: If we've already generated the assets, just move to flashing.
if [[ -z $(check_file_is_expected "${RPI_SB_WORKDIR}"/bootfs-temporary.img "img") ||
      -z $(check_file_is_expected "${RPI_SB_WORKDIR}"/rootfs-temporary.simg "simg") ]]; then

    announce_start "OS Image Mounting"
    COPY_OS_COMBINED_FILE=$(mktemp "working-os-image.XXX" --tmpdir="/srv/")
    cp "${GOLD_MASTER_OS_FILE}" "${COPY_OS_COMBINED_FILE}"
    # Mount the 'complete' image as a series of partitions 
    cnt=0
    until ensure_next_loopdev && LOOP_DEV="$(losetup --show --find --partscan "${COPY_OS_COMBINED_FILE}")"; do
        if [ $cnt -lt 5 ]; then
            cnt=$((cnt + 1))
            echo "Error in losetup.  Retrying..."
            sleep 5
        else
            echo "ERROR: losetup failed; exiting"
            sleep 5
        fi
    done

    ensure_loopdev_partitions "$LOOP_DEV"
    DISK_IDENTIFIER="$(sfdisk --disk-id "${LOOP_DEV}")"
    BOOT_DEV="${LOOP_DEV}"p1
    ROOT_DEV="${LOOP_DEV}"p2

    mkdir -p "${TMP_DIR}"/rpi-boot-img-mount ${DEBUG}
    mkdir -p "${TMP_DIR}"/rpi-rootfs-img-mount ${DEBUG}

    # OS Images are, by convention, packed as a MBR whole-disk file,
    # containing two partitions: A FAT boot partition, which contains the kernel, command line,
    # and supporting boot infrastructure for the Raspberry Pi Device.
    # And in partition 2, the OS rootfs itself.
    # Note that this mechanism is _assuming_ Linux. We may revise that in the future, but
    # to do so would require a concrete support commitment from the vendor - and Raspberry Pi only
    # support Linux.
    mount -t vfat "${BOOT_DEV}" "${TMP_DIR}"/rpi-boot-img-mount ${DEBUG}
    mount -t ext4 "${ROOT_DEV}" "${TMP_DIR}"/rpi-rootfs-img-mount ${DEBUG}

    announce_stop "OS Image Mounting"

    # We supply a pre-baked Raspberry Pi Pre-boot-authentication initramfs, which we insert here.
    # This image is maintained by Raspberry Pi, with sources available on our GitHub pages.
    announce_start "Insert pre-boot authentication initramfs"
    cp /usr/share/rpi-sb-provisioner/cryptroot_initramfs "${TMP_DIR}"/rpi-boot-img-mount/initramfs8
    cp /usr/share/rpi-sb-provisioner/cryptroot_initramfs "${TMP_DIR}"/rpi-boot-img-mount/initramfs_2712
    announce_stop "Insert pre-boot authentication initramfs"

    announce_start "Initramfs modification"

    augment_initramfs() {
        local initramfs_compressed_file=$(check_file_is_expected "$1" "")
        mkdir -p "${TMP_DIR}"/initramfs ${DEBUG}
        zstd --rm -f -d "${initramfs_compressed_file}" -o "${TMP_DIR}"/initramfs.cpio ${DEBUG}
        local ROOTFS_MOUNT=$(realpath "${TMP_DIR}"/rpi-rootfs-img-mount)
        pushd "${TMP_DIR}"/initramfs 
        cpio -id < ../initramfs.cpio ${DEBUG}
        rm ../initramfs.cpio ${DEBUG}

        # Insert required kernel modules
        local INITRAMFS_DIR=$PWD/ # trailing '/' is meaningful
        pushd "${ROOTFS_MOUNT}"
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
            \) \
            -exec cp -r --parents "{}" "${INITRAMFS_DIR}" \;
        popd

        find . -print0 | cpio --null -ov --format=newc > ../initramfs.cpio
        popd
        rm -rf "${TMP_DIR}"/initramfs
        zstd --no-progress --rm -f -6 "${TMP_DIR}"/initramfs.cpio -o "${initramfs_compressed_file}"
    }

    if check_file_is_expected "${TMP_DIR}"/rpi-boot-img-mount/initramfs_2712 ""; then
        augment_initramfs "${TMP_DIR}"/rpi-boot-img-mount/initramfs_2712
    fi
    if check_file_is_expected "${TMP_DIR}"/rpi-boot-img-mount/initramfs8 ""; then
        augment_initramfs "${TMP_DIR}"/rpi-boot-img-mount/initramfs8
    fi
    announce_stop "Initramfs modification"

    announce_start "cmdline.txt modification"
    sed --in-place 's%\b\(root=\)\S*%\1/dev/ram0%' "${TMP_DIR}"/rpi-boot-img-mount/cmdline.txt
    sed --in-place 's%\binit=\S*%%' "${TMP_DIR}"/rpi-boot-img-mount/cmdline.txt
    sed --in-place 's%\brootfstype=\S*%%' "${TMP_DIR}"/rpi-boot-img-mount/cmdline.txt
    # Consider deleting quiet
    sed --in-place 's%\bquiet\b%%' "${TMP_DIR}"/rpi-boot-img-mount/cmdline.txt
    announce_stop "cmdline.txt modification"

    announce_start "config.txt modification"
    sed --in-place 's%^\(auto_initramfs=\S*\)%#\1%' "${TMP_DIR}"/rpi-boot-img-mount/config.txt

    case "${RPI_DEVICE_FAMILY}" in
        4)
            echo 'initramfs initramfs8' >> "${TMP_DIR}"/rpi-boot-img-mount/config.txt
            ;;
        # 5)
        #     echo 'initramfs initramfs_2712' >> "${TMP_DIR}"/rpi-boot-img-mount/config.txt
        #     ;;
    esac
    
    announce_stop "config.txt modification"

    announce_start "boot.img creation"
    cp /usr/share/rpi-sb-provisioner/boot_ramdisk_config.txt "${TMP_DIR}"/config.txt

    make-boot-image -b "pi${RPI_DEVICE_FAMILY}" -d "${TMP_DIR}"/rpi-boot-img-mount -o "${TMP_DIR}"/boot.img
    announce_stop "boot.img creation"

    announce_start "boot.img signing"
    # N.B. rpi-eeprom-digest could be used here but it includes a timestamp that is not required for this use-case
    sha256sum "${TMP_DIR}"/boot.img | awk '{print $1}' > "${TMP_DIR}"/boot.sig
    echo -n "rsa2048: " >> "${TMP_DIR}"/boot.sig
    ${OPENSSL} dgst -sign "${CUSTOMER_KEY_FILE_PEM}" -keyform PEM -sha256 "${TMP_DIR}"/boot.img | xxd -c 4096 -p >> "${TMP_DIR}"/boot.sig
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
    mv "${TMP_DIR}"/bootfs-temporary.img "${RPI_SB_WORKDIR}"/bootfs-temporary.img
    announce_stop "Boot Image partition extraction"
fi # Slow path

announce_start "Erase / Partition Device Storage"

# Arbitrary sleeps to handle lack of correct synchronisation in fastbootd.
[ -z "${DEMO_MODE_ONLY}" ] && fastboot erase "${RPI_DEVICE_STORAGE_TYPE}"
sleep 2
[ -z "${DEMO_MODE_ONLY}" ] && fastboot oem partinit "${RPI_DEVICE_STORAGE_TYPE}" DOS "${DISK_IDENTIFIER}"
sleep 2
[ -z "${DEMO_MODE_ONLY}" ] && fastboot oem partapp "${RPI_DEVICE_STORAGE_TYPE}" 0c "$(stat -c%s "${RPI_SB_WORKDIR}"/bootfs-temporary.img)"
sleep 2
[ -z "${DEMO_MODE_ONLY}" ] && fastboot oem partapp "${RPI_DEVICE_STORAGE_TYPE}" 83 # Grow to fill storage
sleep 2
[ -z "${DEMO_MODE_ONLY}" ] && fastboot oem cryptinit "${RPI_DEVICE_STORAGE_TYPE}"p2 root
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
if [ -f "${RPI_SB_WORKDIR}/rootfs-temporary.simg" ] && [ "$((TARGET_STORAGE_ROOT_EXTENT))" -eq "$(stat -c%s "${RPI_SB_WORKDIR}"/rootfs-temporary.simg)" ]; then
    announce_stop "Resizing OS images: Not required, already the correct size"
else
    mke2fs -t ext4 -b 4096 -d "${TMP_DIR}"/rpi-rootfs-img-mount "${RPI_SB_WORKDIR}"/rootfs-temporary.simg $((TARGET_STORAGE_ROOT_EXTENT / 4096))
    #TODO: Re-enable android_sparse
    #mke2fs -t ext4 -b 4096 -d ${TMP_DIR}/rpi-rootfs-img-mount -E android_sparse ${RPI_SB_WORKDIR}/rootfs-temporary.simg $((TARGET_STORAGE_ROOT_EXTENT / 4096))
    announce_stop "Resizing OS images: Resized to $((TARGET_STORAGE_ROOT_EXTENT))"
fi

announce_start "Writing OS images"
[ -z "${DEMO_MODE_ONLY}" ] && fastboot flash "${RPI_DEVICE_STORAGE_TYPE}"p1 "${RPI_SB_WORKDIR}"/bootfs-temporary.img
[ -z "${DEMO_MODE_ONLY}" ] && fastboot flash mapper/cryptroot "${RPI_SB_WORKDIR}"/rootfs-temporary.simg
announce_stop "Writing OS images"

announce_start "Cleaning up"
[ -d "${TMP_DIR}/rpi-boot-img-mount" ] && umount "${TMP_DIR}"/rpi-boot-img-mount
[ -d "${TMP_DIR}/rpi-rootfs-img-mount" ] && umount "${TMP_DIR}"/rpi-rootfs-img-mount
unmount_image "${COPY_OS_COMBINED_FILE}" ${DEBUG}
# We also delete the temporary directory - preserving the cached generated asset
rm -rf "${TMP_DIR}" ${DEBUG}
if [ -n "${DELETE_PRIVATE_TMPDIR}" ]; then
    announce_start "Deleting customised intermediates"
    rm -rf "${DELETE_PRIVATE_TMPDIR}" ${DEBUG}
    DELETE_PRIVATE_TMPDIR=
    announce_stop "Deleting customised intermediates"
fi
announce_stop "Cleaning up"

announce_start "Set LED status"
fastboot oem led PWR 0
announce_stop "Set LED status"

mkdir -p /var/log/rpi-sb-provisioner/${TARGET_DEVICE_SERIAL}/
echo "1" > /var/log/rpi-sb-provisioner/${TARGET_DEVICE_SERIAL}/success

echo "Provisioning completed. Remove the device from this machine."
