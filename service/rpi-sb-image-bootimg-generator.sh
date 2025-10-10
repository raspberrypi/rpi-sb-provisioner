#!/bin/sh

set -e
set -x

# This script generates a secure-boot style boot.img and boot.sig
# from a newly uploaded system image.
#
# Usage: rpi-sb-image-bootimg-generator.sh <image_filename>
#
# The script:
# 1. Checks if secure-boot is configured
# 2. Verifies key material is available
# 3. Extracts the boot partition from the uploaded image
# 4. Creates boot.img using rpi-make-boot-image
# 5. Signs boot.img with the customer key
# 6. Places boot.img and boot.sig alongside the source image

OPENSSL=${OPENSSL:-openssl}

# Source common helper functions
# shellcheck disable=SC1091
. "$(dirname "$0")/rpi-sb-common.sh"

IMAGE_FILENAME="${1}"
IMAGES_DIR="/srv/rpi-sb-provisioner/images"
IMAGE_PATH="${IMAGES_DIR}/${IMAGE_FILENAME}"
OUTPUT_DIR="${IMAGES_DIR}/bootimg-output"
LOG_DIR="/var/log/rpi-sb-provisioner/bootimg-generator"

log() {
    timestamp=$(date +"%Y-%m-%d %H:%M:%S.$(date +%N | cut -c1-3)")
    mkdir -p "${LOG_DIR}"
    echo "[${timestamp}] $*" | tee -a "${LOG_DIR}/bootimg-generator.log"
}

die() {
    log "ERROR: $*"
    exit 1
}

announce_start() {
    log "================================================================================"
    log "Starting $1"
    log "================================================================================"
}

announce_stop() {
    log "================================================================================"
    log "Stopping $1"
    log "================================================================================"
}

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

get_fastboot_config_file() {
    if [ -f /etc/rpi-sb-provisioner/boot_ramdisk_config.txt ]; then
        echo "/etc/rpi-sb-provisioner/boot_ramdisk_config.txt"
    else
        echo "/var/lib/rpi-sb-provisioner/boot_ramdisk_config.txt"
    fi
}

get_cryptroot() {
    if [ -f /etc/rpi-sb-provisioner/cryptroot_initramfs ]; then
        echo "/etc/rpi-sb-provisioner/cryptroot_initramfs"
    else
        echo "/var/lib/rpi-sb-provisioner/cryptroot_initramfs"
    fi
}

# Main script execution starts here
log "=========================================================================="
log "Boot Image Generator Started"
log "Image: ${IMAGE_FILENAME}"
log "=========================================================================="

# Validate parameters
if [ -z "${IMAGE_FILENAME}" ]; then
    die "No image filename provided"
fi

if [ ! -f "${IMAGE_PATH}" ]; then
    die "Image file does not exist: ${IMAGE_PATH}"
fi

# Read configuration
read_config

# Read package metadata configuration if it exists
if [ -f /etc/rpi-sb-provisioner/bootimg-package-config ]; then
    # shellcheck disable=SC1091
    . /etc/rpi-sb-provisioner/bootimg-package-config
fi

# Check if secure-boot is configured
if [ "${PROVISIONING_STYLE}" != "secure-boot" ]; then
    log "Provisioning style is '${PROVISIONING_STYLE}', not 'secure-boot'. Skipping boot.img generation."
    exit 0
fi

# Check if key material is available
if [ -z "${CUSTOMER_KEY_FILE_PEM}" ] && [ -z "${CUSTOMER_KEY_PKCS11_NAME}" ]; then
    log "No customer key material configured. Skipping boot.img generation."
    exit 0
fi

# Verify key file exists if PEM is used
if [ -n "${CUSTOMER_KEY_FILE_PEM}" ] && [ ! -f "${CUSTOMER_KEY_FILE_PEM}" ]; then
    die "Customer key file does not exist: ${CUSTOMER_KEY_FILE_PEM}"
fi

# Check if RPI_DEVICE_FAMILY is set
if [ -z "${RPI_DEVICE_FAMILY}" ]; then
    log "RPI_DEVICE_FAMILY not configured. Skipping boot.img generation."
    log "Please configure RPI_DEVICE_FAMILY (4 or 5) in /etc/rpi-sb-provisioner/config"
    exit 0
fi

log "Configuration validated:"
log "  - Provisioning style: ${PROVISIONING_STYLE}"
log "  - Device family: Pi ${RPI_DEVICE_FAMILY}"
log "  - Key material: $([ -n "${CUSTOMER_KEY_PKCS11_NAME}" ] && echo "PKCS11" || echo "PEM file")"

# Create temporary working directory
TMP_DIR=$(mktemp -d -p /srv/rpi-sb-provisioner)
trap 'rm -rf "${TMP_DIR}"' EXIT

announce_start "Image analysis"

# Use kpartx to map the partitions
LOOP_DEVICE=$(losetup -f --show -P "${IMAGE_PATH}")
log "Mapped image to loop device: ${LOOP_DEVICE}"

# Give the system a moment to create partition devices
sleep 1

# Find the boot partition (typically the first partition, type 0c FAT32)
BOOT_PARTITION="${LOOP_DEVICE}p1"

if [ ! -b "${BOOT_PARTITION}" ]; then
    losetup -d "${LOOP_DEVICE}"
    die "Boot partition not found: ${BOOT_PARTITION}"
fi

log "Found boot partition: ${BOOT_PARTITION}"
announce_stop "Image analysis"

announce_start "Boot partition extraction"

# Mount the boot partition
BOOT_MOUNT="${TMP_DIR}/boot-mount"
mkdir -p "${BOOT_MOUNT}"
mount -o ro "${BOOT_PARTITION}" "${BOOT_MOUNT}"

log "Mounted boot partition at: ${BOOT_MOUNT}"

# Create a working copy of the boot filesystem
BOOT_WORK="${TMP_DIR}/boot-work"
mkdir -p "${BOOT_WORK}"
cp -a "${BOOT_MOUNT}"/* "${BOOT_WORK}/" 2>/dev/null || true
cp -a "${BOOT_MOUNT}"/.[!.]* "${BOOT_WORK}/" 2>/dev/null || true

# Unmount the boot partition
umount "${BOOT_MOUNT}"

announce_stop "Boot partition extraction"

announce_start "Pre-boot authentication setup"

# Insert cryptroot initramfs
log "Copying cryptroot initramfs"
cp "$(get_cryptroot)" "${BOOT_WORK}/initramfs8"

# Modify cmdline.txt for secure boot
if [ -f "${BOOT_WORK}/cmdline.txt" ]; then
    log "Modifying cmdline.txt"
    sed --in-place 's%\b\(root=\)\S*%\1/dev/ram0%' "${BOOT_WORK}/cmdline.txt"
    sed --in-place 's%\binit=\S*%%' "${BOOT_WORK}/cmdline.txt"
    sed --in-place 's%\brootfstype=\S*%%' "${BOOT_WORK}/cmdline.txt"
    sed --in-place 's%\bquiet\b%%' "${BOOT_WORK}/cmdline.txt"
fi

# Modify config.txt for secure boot
if [ -f "${BOOT_WORK}/config.txt" ]; then
    log "Modifying config.txt"
    sed --in-place 's%^\(auto_initramfs=\S*\)%#\1%' "${BOOT_WORK}/config.txt"
    echo 'initramfs initramfs8' >> "${BOOT_WORK}/config.txt"
fi

announce_stop "Pre-boot authentication setup"

announce_start "boot.img creation"

# Copy the fastboot config.txt
cp "$(get_fastboot_config_file)" "${TMP_DIR}/config.txt"

# Create boot.img using rpi-make-boot-image
BOOT_IMG="${TMP_DIR}/boot.img"
rpi-make-boot-image -b "pi${RPI_DEVICE_FAMILY}" -a 64 -d "${BOOT_WORK}" -o "${BOOT_IMG}"

log "Created boot.img: ${BOOT_IMG}"
announce_stop "boot.img creation"

announce_start "boot.img signing"

# Sign boot.img
BOOT_SIG="${TMP_DIR}/boot.sig"
sha256sum "${BOOT_IMG}" | awk '{print $1}' > "${BOOT_SIG}"
printf 'rsa2048: ' >> "${BOOT_SIG}"
# shellcheck disable=SC2046
${OPENSSL} dgst -sign $(get_signing_directives) -sha256 "${BOOT_IMG}" | xxd -c 4096 -p >> "${BOOT_SIG}"

log "Created boot.sig: ${BOOT_SIG}"
announce_stop "boot.img signing"

announce_start "Output files"

# Create output directory
mkdir -p "${OUTPUT_DIR}"

# Generate output filename base (without extension)
IMAGE_BASE=$(basename "${IMAGE_FILENAME}" | sed 's/\.[^.]*$//')
OUTPUT_BASE="${OUTPUT_DIR}/${IMAGE_BASE}"

# Copy boot.img and boot.sig to output directory
cp "${BOOT_IMG}" "${OUTPUT_BASE}.boot.img"
cp "${BOOT_SIG}" "${OUTPUT_BASE}.boot.sig"
cp "${TMP_DIR}/config.txt" "${OUTPUT_BASE}.config.txt"

log "Output files created:"
log "  - ${OUTPUT_BASE}.boot.img"
log "  - ${OUTPUT_BASE}.boot.sig"
log "  - ${OUTPUT_BASE}.config.txt"

announce_stop "Output files"

announce_start "Debian package creation"

# Calculate SHA256 of the image file for versioning
log "Calculating SHA256 of image file..."
IMAGE_SHA256=$(sha256sum "${IMAGE_PATH}" | awk '{print $1}')
# Use first 12 characters as version, prefix with 0. to ensure valid Debian version
PACKAGE_VERSION="0.$(printf '%s' "${IMAGE_SHA256}" | cut -c1-12)"
log "Package version: ${PACKAGE_VERSION}"

# Package name
PACKAGE_NAME="rpi-sb-boot-update"
PACKAGE_ARCH="all"
PACKAGE_FULL_NAME="${PACKAGE_NAME}_${PACKAGE_VERSION}_${PACKAGE_ARCH}"

# Get package maintainer info from config, with fallbacks
if [ -z "${RPI_SB_PACKAGE_MAINTAINER_NAME}" ]; then
    PACKAGE_MAINTAINER_NAME="System Administrator"
else
    PACKAGE_MAINTAINER_NAME="${RPI_SB_PACKAGE_MAINTAINER_NAME}"
fi

if [ -z "${RPI_SB_PACKAGE_MAINTAINER_EMAIL}" ]; then
    # Try to get hostname, fallback to localhost
    HOSTNAME=$(hostname -f 2>/dev/null || echo "localhost")
    PACKAGE_MAINTAINER_EMAIL="root@${HOSTNAME}"
else
    PACKAGE_MAINTAINER_EMAIL="${RPI_SB_PACKAGE_MAINTAINER_EMAIL}"
fi

PACKAGE_MAINTAINER="${PACKAGE_MAINTAINER_NAME} <${PACKAGE_MAINTAINER_EMAIL}>"
log "Package maintainer: ${PACKAGE_MAINTAINER}"

# Create debian package directory structure
PKG_DIR="${TMP_DIR}/debian-package/${PACKAGE_FULL_NAME}"
mkdir -p "${PKG_DIR}/DEBIAN"
mkdir -p "${PKG_DIR}/boot/firmware"

# Copy boot.img and boot.sig into package
# Note: config.txt is already inside boot.img, no need to package it separately
cp "${BOOT_IMG}" "${PKG_DIR}/boot/firmware/boot.img"
cp "${BOOT_SIG}" "${PKG_DIR}/boot/firmware/boot.sig"

# Create control file
cat > "${PKG_DIR}/DEBIAN/control" << EOF
Package: ${PACKAGE_NAME}
Version: ${PACKAGE_VERSION}
Section: admin
Priority: optional
Architecture: ${PACKAGE_ARCH}
Maintainer: ${PACKAGE_MAINTAINER}
Description: Raspberry Pi Secure Boot Update
 This package contains a signed boot.img and boot.sig for secure boot
 enabled Raspberry Pi devices.
 .
 Source image: ${IMAGE_FILENAME}
 Image SHA256: ${IMAGE_SHA256}
 .
 This package will overwrite existing boot.img and boot.sig files in
 /boot/firmware to apply configuration changes or kernel updates while
 preserving the existing root filesystem.
 .
 Note: config.txt is embedded inside boot.img and does not need to be
 installed separately.
EOF

# No conffiles needed - boot.img and boot.sig are not configuration files
# that users should edit. config.txt is embedded inside boot.img.

# Create changelog
CHANGELOG_DIR="${PKG_DIR}/usr/share/doc/${PACKAGE_NAME}"
mkdir -p "${CHANGELOG_DIR}"
cat > "${CHANGELOG_DIR}/changelog.Debian" << EOF
${PACKAGE_NAME} (${PACKAGE_VERSION}) stable; urgency=medium

  * Secure boot image update generated from: ${IMAGE_FILENAME}
  * Source image SHA256: ${IMAGE_SHA256}
  * Generated on: $(date -R)
  * Device family: Pi ${RPI_DEVICE_FAMILY}

 -- ${PACKAGE_MAINTAINER}  $(date -R)
EOF

# Compress changelog
gzip -9n "${CHANGELOG_DIR}/changelog.Debian"

# Create copyright file
cat > "${CHANGELOG_DIR}/copyright" << EOF
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: rpi-sb-boot-update
Source: Generated by rpi-sb-provisioner

Files: *
Copyright: $(date +%Y) ${PACKAGE_MAINTAINER_NAME}
License: Custom
 This package contains boot images signed with a customer-specific key.
 Distribution and use should be controlled according to your organization's
 security policies.
 .
 Generated by rpi-sb-provisioner for internal use.
EOF

# Create postinst script to sync after installation
cat > "${PKG_DIR}/DEBIAN/postinst" << 'EOF'
#!/bin/sh
set -e

case "$1" in
    configure)
        # Sync to ensure files are written to disk
        sync
        echo "Secure boot files installed to /boot/firmware"
        echo "Reboot required for changes to take effect"
        ;;
esac

exit 0
EOF
chmod 755 "${PKG_DIR}/DEBIAN/postinst"

# Set proper permissions
find "${PKG_DIR}" -type d -exec chmod 755 {} \;
find "${PKG_DIR}/boot" -type f -exec chmod 644 {} \;

# Build the package
log "Building debian package: ${PACKAGE_FULL_NAME}.deb"
dpkg-deb --build --root-owner-group "${PKG_DIR}" "${OUTPUT_DIR}/${PACKAGE_FULL_NAME}.deb"

if [ $? -eq 0 ]; then
    log "Debian package created: ${OUTPUT_DIR}/${PACKAGE_FULL_NAME}.deb"
    
    # Generate package info file
    cat > "${OUTPUT_DIR}/${IMAGE_BASE}.package-info.txt" << EOF
Debian Package Information
==========================

Package: ${PACKAGE_NAME}
Version: ${PACKAGE_VERSION}
Architecture: ${PACKAGE_ARCH}
Filename: ${PACKAGE_FULL_NAME}.deb

Source Image: ${IMAGE_FILENAME}
Image SHA256: ${IMAGE_SHA256}

Installation:
  sudo dpkg -i ${PACKAGE_FULL_NAME}.deb

Removal:
  sudo dpkg -r ${PACKAGE_NAME}

Contents:
  /boot/firmware/boot.img (contains config.txt, kernel, initramfs, etc.)
  /boot/firmware/boot.sig (RSA signature)

Note: A reboot is required after installation for changes to take effect.
      The config.txt is embedded inside boot.img and will be used after reboot.
EOF
    
    log "Package info: ${OUTPUT_DIR}/${IMAGE_BASE}.package-info.txt"
else
    log "ERROR: Failed to create debian package"
fi

announce_stop "Debian package creation"

# Cleanup loop device
losetup -d "${LOOP_DEVICE}"

log "=========================================================================="
log "Boot Image Generator Completed Successfully"
log "=========================================================================="

exit 0

