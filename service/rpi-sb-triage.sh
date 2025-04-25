#!/bin/sh

set -e
set -x

OPENSSL=${OPENSSL:-openssl}

export TRIAGE_FINISHED="TRIAGE-FINISHED"
export TRIAGE_ABORTED="TRIAGE-ABORTED"
export TRIAGE_STARTED="TRIAGE-STARTED"

# Source common helper functions
# shellcheck disable=SC1091
. "$(dirname "$0")/rpi-sb-common.sh"
# shellcheck disable=SC1091
. /var/lib/rpi-sb-provisioner/state-recording

TARGET_DEVICE_SERIAL="${1}"
TARGET_DEVICE_SERIAL32=$(echo "${TARGET_DEVICE_SERIAL}" | cut -c $((${#TARGET_DEVICE_SERIAL}/2+1))-)
LOG_DIRECTORY="/var/log/rpi-sb-provisioner/${TARGET_DEVICE_SERIAL}"

log() {
    timestamp=$(date +"%Y-%m-%d %H:%M:%S.$(date +%N | cut -c1-3)")
    mkdir -p "${LOG_DIRECTORY}"
    echo "[${timestamp}] $*" >> "${LOG_DIRECTORY}"/triage.log
    printf "[%s] %s\n" "${timestamp}" "$*"
}

die() {
    # shellcheck disable=SC2086
    echo "$@" ${DEBUG}
    exit 1
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
            record_state "${TARGET_DEVICE_SERIAL}" "${TRIAGE_ABORTED}" "${TARGET_USB_PATH}"
            die "\"${command}\" FAILED: Timed out after 30 seconds (exit code 124)."
            ;;
        125)
            # Exit code 125 means the timeout command itself failed
            record_state "${TARGET_DEVICE_SERIAL}" "${TRIAGE_ABORTED}" "${TARGET_USB_PATH}"
            die "\"${command}\" FAILED: The timeout command itself failed (exit code 125)."
            ;;
        126)
            # Exit code 126 means the command was found but could not be executed
            record_state "${TARGET_DEVICE_SERIAL}" "${TRIAGE_ABORTED}" "${TARGET_USB_PATH}"
            die "\"${command}\" FAILED: Command found but could not be executed (exit code 126)."
            ;;
        127)
            # Exit code 127 means the command was not found
            record_state "${TARGET_DEVICE_SERIAL}" "${TRIAGE_ABORTED}" "${TARGET_USB_PATH}"
            die "\"${command}\" FAILED: Command not found (exit code 127)."
            ;;
        137)
            # Exit code 137 (128+9) means the command was killed by SIGKILL (kill -9)
            record_state "${TARGET_DEVICE_SERIAL}" "${TRIAGE_ABORTED}" "${TARGET_USB_PATH}"
            die "\"${command}\" FAILED: Command was killed by SIGKILL (exit code 137)."
            ;;
        *)
            # Any other non-zero exit code is a general failure
            record_state "${TARGET_DEVICE_SERIAL}" "${TRIAGE_ABORTED}" "${TARGET_USB_PATH}"
            die "\"${command}\" FAILED: Command returned exit code ${command_exit_status}."
            ;;
    esac
    set -e
}

TARGET_USB_PATH=$(get_usb_path_for_serial "${TARGET_DEVICE_SERIAL32}")

# Record state changes atomically
record_state "${TARGET_DEVICE_SERIAL}" "${TRIAGE_STARTED}" "${TARGET_USB_PATH}"

if [ -d "/var/log/rpi-sb-provisioner/${TARGET_DEVICE_SERIAL32}" ]; then
    cp -rf "/var/log/rpi-sb-provisioner/${TARGET_DEVICE_SERIAL32}/." "${LOG_DIRECTORY}/"
    rm -rf "/var/log/rpi-sb-provisioner/${TARGET_DEVICE_SERIAL32}"
fi

read_config
setup_fastboot_and_id_vars "${TARGET_DEVICE_SERIAL}"

KEYPAIR_DIR="${LOG_DIRECTORY}/${TARGET_DEVICE_SERIAL}"/keypair
if [ -d "${RPI_DEVICE_RETRIEVE_KEYPAIR}" ]; then
    KEYPAIR_DIR="${RPI_DEVICE_RETRIEVE_KEYPAIR}"
fi
mkdir -p "${KEYPAIR_DIR}"
log "Capturing device keypair to ${KEYPAIR_DIR}"
N_ALREADY_PROVISIONED=0
PRIVATE_KEY=$(get_variable private-key) || N_ALREADY_PROVISIONED=$?
if [ 0 -ne "$N_ALREADY_PROVISIONED" ]; then
    log "Warning: Unable to retrieve device private key; already provisioned"
else
    echo "${PRIVATE_KEY}" > "${KEYPAIR_DIR}/${TARGET_DEVICE_SERIAL}.der"
    PRIVATE_KEY=""
fi
get_variable public-key > "${KEYPAIR_DIR}/${TARGET_DEVICE_SERIAL}.pub"

# Based on the provisioning style, we can determine which systemd unit to trigger.
# All systemd must be parameterised with the device serial number.
echo "${TRIAGE_STARTED}" >> "${LOG_DIRECTORY}"/triage.log
case ${PROVISIONING_STYLE} in
    "secure-boot")
        log "Selecting Secure Boot Provisioner"
        systemctl start rpi-sb-provisioner@"${TARGET_DEVICE_SERIAL}".service
    ;;
    "fde-only")
        log "Selecting Full-Disk Encryption Provisioner"
        systemctl start rpi-fde-provisioner@"${TARGET_DEVICE_SERIAL}".service
    ;;
    "naked")
        log "Selecting Naked Provisioner"
        systemctl start rpi-naked-provisioner@"${TARGET_DEVICE_SERIAL}".service
    ;;
    *)
        log "Fatal: Unknown provisioning style: ${PROVISIONING_STYLE}"
        exit 1
    ;;
esac
log "${TRIAGE_FINISHED}" >> "${LOG_DIRECTORY}"/triage.log
record_state "${TARGET_DEVICE_SERIAL}" "${TRIAGE_FINISHED}" "${TARGET_USB_PATH}"
