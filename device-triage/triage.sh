#!/bin/sh

set -e

. /usr/local/bin/terminal-functions.sh

read_config

TARGET_DEVICE_SERIAL="$(udevadm info --name="$1" --query=property --property=ID_SERIAL_SHORT --value)"
echo "Starting triage for $1, serial: $TARGET_DEVICE_SERIAL"
mkdir -p /var/log/rpi-sb-provisioner/"${TARGET_DEVICE_SERIAL}"/


if [ -z "${RPI_DEVICE_SERIAL_STORE}" ]; then
    RPI_DEVICE_SERIAL_STORE=/usr/local/etc/rpi-sb-provisioner/seen
fi

if [ ! -d "${RPI_DEVICE_SERIAL_STORE}" ]; then
    mkdir -p "${RPI_DEVICE_SERIAL_STORE}"
fi

if [ -z "${RPI_DEVICE_BOOTLOADER_CONFIG_FILE}" ]; then
    RPI_DEVICE_BOOTLOADER_CONFIG_FILE=/var/lib/rpi-sb-provisioner/bootloader.default
fi

if [ -z "${CUSTOMER_KEY_FILE_PEM}" ] && [ -z "${CUSTOMER_KEY_PKCS11_NAME}" ]; then
    echo "You must provide a key in the environment via CUSTOMER_KEY_FILE_PEM, or a key name via CUSTOMER_KEY_PKCS11_NAME"
    exit 1
fi

if [ -z "${TARGET_DEVICE_SERIAL}" ]; then
    echo "You must provide a device serial as the argument to this program"
    exit 1
fi


if [ -e "/var/log/rpi-sb-provisioner/${TARGET_DEVICE_SERIAL}/progress" ]; then
    last_status=$(tail -n 1 "/var/log/rpi-sb-provisioner/${TARGET_DEVICE_SERIAL}/progress")
    echo "Observed provisioning state for ${TARGET_DEVICE_SERIAL}: ${last_status}"

    case "${last_status}" in
        "${KEYWRITER_STARTED}")
            echo "Taking no action - keywriter is already active"
            exit 0
            ;;
        "${KEYWRITER-FINISHED}")
            echo "Device already provisioned with the key, moving to write the image"
            echo "If this is in error, consult the README"

            # Start the boot provisioner service
            touch "/var/log/rpi-sb-provisioner/${TARGET_DEVICE_SERIAL}/provisioner.log"
            systemctl start rpi-sb-provisioner@"${TARGET_DEVICE_SERIAL}"
            exit 0
            ;;
        "${KEYWRITER-EXITED}")
            echo "Keywriter failed, inspect the logs and raise a bug report"
            exit 1
            ;;
        *)
            echo "Unexpected state, please raise a bug report"
            ;;
    esac

else
    echo "Device is completely new to us, starting keywriter"
    echo "Using keyfile at ${CUSTOMER_KEY_FILE_PEM}"

    # Start the keywriter service
    touch "/var/log/rpi-sb-provisioner/${TARGET_DEVICE_SERIAL}/keywriter.log"
    systemctl start rpi-sb-keywriter@"${TARGET_DEVICE_SERIAL}"
    exit 0
fi
