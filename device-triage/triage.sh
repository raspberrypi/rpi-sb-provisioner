#!/bin/sh

set -e

. /usr/local/bin/terminal-functions.sh

read_config

TARGET_DEVICE_SERIAL="$(udevadm info --name="$1" --query=property --property=ID_SERIAL_SHORT --value)"
echo "Starting triage for $1, serial: $TARGET_DEVICE_SERIAL"

if [ -z "${DEVICE_SERIAL_STORE}" ]; then
    DEVICE_SERIAL_STORE=/usr/local/etc/rpi-sb-provisioner/seen
fi

if [ ! -d "${DEVICE_SERIAL_STORE}" ]; then
    mkdir -p "${DEVICE_SERIAL_STORE}"
fi

if [ -z "${RPI_DEVICE_BOOTLOADER_CONFIG_FILE}" ]; then
    RPI_DEVICE_BOOTLOADER_CONFIG_FILE=/var/lib/rpi-sb-provisioner/bootloader.default
fi

if [ -z "${CUSTOMER_KEY_FILE_PEM}" ] || [ -z "${CUSTOMER_KEY_PKCS11_NAME}" ]; then
    echo "You must provide a key in the environment via CUSTOMER_KEY_FILE_PEM, or a key name via CUSTOMER_KEY_PKCS11_NAME"
    exit 1
fi

if [ -z "${TARGET_DEVICE_SERIAL}" ]; then
    echo "You must provide a device serial as the argument to this program"
    exit 1
fi

if [ -e "${DEVICE_SERIAL_STORE}/${TARGET_DEVICE_SERIAL}" ]; then
    echo "Device already provisioned with the key, moving to write the image"
    echo "If this is in error, delete ${DEVICE_SERIAL_STORE}/${TARGET_DEVICE_SERIAL}"

    # Start the boot provisioner service
    mkdir -p /var/log/rpi-sb-provisioner/"${TARGET_DEVICE_SERIAL}"/
    touch "/var/log/rpi-sb-provisioner/${TARGET_DEVICE_SERIAL}/provisioner.log"
    systemctl start rpi-sb-provisioner@"${TARGET_DEVICE_SERIAL}"

    exit 0
else
    echo "Device is new to us, programing customer signature"
    echo "Using keyfile at ${CUSTOMER_KEY_FILE_PEM}"

    # Start the keywriter service
    mkdir -p /var/log/rpi-sb-provisioner/"${TARGET_DEVICE_SERIAL}"/
    touch "/var/log/rpi-sb-provisioner/${TARGET_DEVICE_SERIAL}/keywriter.log"
    systemctl start rpi-sb-keywriter@"${TARGET_DEVICE_SERIAL}"
    exit 0
fi
