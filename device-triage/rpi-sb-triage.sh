#!/bin/sh

set -e

TRIAGE_STARTED="TRIAGE-STARTED"
TRIAGE_HANDOFF="TRIAGE-HANDOFF"

TARGET_DEVICE_SERIAL="$(udevadm info --name="$1" --query=property --property=ID_SERIAL_SHORT --value)"

read_config() {
    if [ -f /etc/rpi-sb-provisioner/config ]; then
        . /etc/rpi-sb-provisioner/config
    else
        echo "Failed to load config. Please use configuration tool." >&2
        return 1
    fi
}

read_config

LOG_DIR=
case "${PROVISIONING_STYLE}" in
    secure-boot)
        LOG_DIR=/var/log/rpi-sb-provisioner/"${TARGET_DEVICE_SERIAL}"/

        if [ -z "${CUSTOMER_KEY_FILE_PEM}" ] && [ -z "${CUSTOMER_KEY_PKCS11_NAME}" ]; then
            echo "You must provide a key in the environment via CUSTOMER_KEY_FILE_PEM, or a key name via CUSTOMER_KEY_PKCS11_NAME" >> "${LOG_DIR}"/triage.log
            exit 1
        fi
        ;;
    fde-only)
        LOG_DIR=/var/log/rpi-fde-provisioner/"${TARGET_DEVICE_SERIAL}"/
        ;;
    naked)
        LOG_DIR=/var/log/rpi-naked-provisioner/"${TARGET_DEVICE_SERIAL}"/
        ;;
    *)
        echo "Unknown provisioning style: ${PROVISIONING_STYLE}" >&2
        exit 1
        ;;
esac

mkdir -p "${LOG_DIR}"
touch "${LOG_DIR}"/triage.log
echo "Starting triage for $1, serial: $TARGET_DEVICE_SERIAL" >> "${LOG_DIR}"/triage.log

if [ -e "${LOG_DIR}/progress" ]; then
    # Status messages are more for human consumption than anything else.
    last_status=$(tail -n 1 "${LOG_DIR}/progress")
    {
        echo "Observed provisioning state for ${TARGET_DEVICE_SERIAL}: ${last_status}"
        echo "Not starting additional services, device already undergoing provisioning"
    } >> "${LOG_DIR}"/triage.log
    echo "${TRIAGE_STARTED}" >> "${LOG_DIR}"/progress
else
    # A new device, start the appropriate provisioning process
    case "${PROVISIONER_STYLE}" in
        "secure-boot")
                { 
                    echo "Device is completely new to us, starting keywriter"
                    echo "Using OS image at ${GOLD_MASTER_OS_FILE}"
                } >> "${LOG_DIR}"/triage.log

                # Start the keywriter service
                echo "${TRIAGE_HANDOFF}" >> "${LOG_DIR}"/progress
                touch "${LOG_DIR}/keywriter.log"
                touch "${LOG_DIR}/provisioner.log"
                systemctl start rpi-sb-provisioner@"${TARGET_DEVICE_SERIAL}"
            ;;
        "fde-only")
                { 
                    echo "Device is completely new to us, starting fde-provisioner"
                    echo "Using OS image at ${GOLD_MASTER_OS_FILE}"
                } >> "${LOG_DIR}"/triage.log

                # Start the keywriter service
                echo "${TRIAGE_HANDOFF}" >> "${LOG_DIR}"/progress
                touch "${LOG_DIR}/provisioner.log"
                systemctl start rpi-fde-bootstrap@"${TARGET_DEVICE_SERIAL}"
            ;;
        "naked")
                { 
                    echo "Device is completely new to us, starting fde-provisioner"
                    echo "Using OS image at ${GOLD_MASTER_OS_FILE}"
                } >> "${LOG_DIR}"/triage.log

                # Start the keywriter service
                echo "${TRIAGE_HANDOFF}" >> "${LOG_DIR}"/progress
                touch "${LOG_DIR}/provisioner.log"
                systemctl start rpi-naked-provisioner@"${TARGET_DEVICE_SERIAL}"
            ;;
        *)
            echo "Unknown provisioner style: ${PROVISIONER_STYLE}" >&2
            exit 1
            ;;
    esac


    exit 0
fi
