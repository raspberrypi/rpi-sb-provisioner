#!/bin/sh

set -e

TRIAGE_STARTED="TRIAGE-STARTED"
TRIAGE_HANDOFF="TRIAGE-HANDOFF"

. /usr/local/bin/terminal-functions.sh

read_config

TARGET_DEVICE_SERIAL="$(udevadm info --name="$1" --query=property --property=ID_SERIAL_SHORT --value)"
mkdir -p /var/log/rpi-sb-provisioner/"${TARGET_DEVICE_SERIAL}"/
touch /var/log/rpi-sb-provisioner/"${TARGET_DEVICE_SERIAL}"/triage.log
echo "Starting triage for $1, serial: $TARGET_DEVICE_SERIAL" >> /var/log/rpi-sb-provisioner/"${TARGET_DEVICE_SERIAL}"/triage.log
echo "${TRIAGE_STARTED}" >> /var/log/rpi-sb-provisioner/"${TARGET_DEVICE_SERIAL}"/progress

if [ -z "${RPI_DEVICE_BOOTLOADER_CONFIG_FILE}" ]; then
    RPI_DEVICE_BOOTLOADER_CONFIG_FILE=/var/lib/rpi-sb-provisioner/bootloader.default
fi

if [ -z "${CUSTOMER_KEY_FILE_PEM}" ] && [ -z "${CUSTOMER_KEY_PKCS11_NAME}" ]; then
    echo "You must provide a key in the environment via CUSTOMER_KEY_FILE_PEM, or a key name via CUSTOMER_KEY_PKCS11_NAME" >> /var/log/rpi-sb-provisioner/"${TARGET_DEVICE_SERIAL}"/triage.log
    exit 1
fi

if [ -z "${TARGET_DEVICE_SERIAL}" ]; then
    echo "You must provide a device serial as the argument to this program" >> /var/log/rpi-sb-provisioner/"${TARGET_DEVICE_SERIAL}"/triage.log
    exit 1
fi

if [ -e "/var/log/rpi-sb-provisioner/${TARGET_DEVICE_SERIAL}/progress" ]; then
    # Status messages are more for human consumption than anything else.
    last_status=$(tail -n 1 "/var/log/rpi-sb-provisioner/${TARGET_DEVICE_SERIAL}/progress")
    {
        echo "Observed provisioning state for ${TARGET_DEVICE_SERIAL}: ${last_status}"
        echo "Not starting additional services, device already undergoing provisioning"
    } >> /var/log/rpi-sb-provisioner/"${TARGET_DEVICE_SERIAL}"/triage.log
else
    { 
        echo "Device is completely new to us, starting keywriter"
        echo "Using keyfile at ${CUSTOMER_KEY_FILE_PEM}"
        echo "Using OS image at ${GOLD_MASTER_OS_FILE}"
    } >> /var/log/rpi-sb-provisioner/"${TARGET_DEVICE_SERIAL}"/triage.log

    # Start the keywriter service
    echo "${TRIAGE_HANDOFF}" >> /var/log/rpi-sb-provisioner/"${TARGET_DEVICE_SERIAL}"/progress
    touch "/var/log/rpi-sb-provisioner/${TARGET_DEVICE_SERIAL}/keywriter.log"
    touch "/var/log/rpi-sb-provisioner/${TARGET_DEVICE_SERIAL}/provisioner.log"
    systemctl start rpi-sb-provisioner@"${TARGET_DEVICE_SERIAL}"
    exit 0
fi
