#!/bin/sh

set -e
set -x

OPENSSL=${OPENSSL:-openssl}

# Stage prefix for record_progress(); see host-support/state-recording.
export STATE_PREFIX="TRIAGE"
export TRIAGE_FINISHED="${STATE_PREFIX}-FINISHED"
export TRIAGE_ABORTED="${STATE_PREFIX}-ABORTED"
export TRIAGE_STARTED="${STATE_PREFIX}-STARTED"

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

read_config
compute_image_summary

die() {
    # shellcheck disable=SC2086
    echo "$@" ${DEBUG}
    exit 1
}

CLEANUP_DONE=0

cleanup() {
    returnvalue=$?

    [ "$CLEANUP_DONE" -eq 1 ] && return
    CLEANUP_DONE=1

    set +e

    if [ "${returnvalue}" -ne 0 ]; then
        # Fastboot may appear briefly during bootstrap USB churn. A failed
        # early triage while bootstrap still holds its lock is not a user-
        # visible failure on programming rigs (keep the in-progress LED).
        if [ -z "${FASTBOOT_DEVICE_SPECIFIER:-}" ] && \
           [ -n "$(find /var/lock/rpi-sb-bootstrap -mindepth 1 -maxdepth 1 -type d -print -quit 2>/dev/null)" ]; then
            log "Skipping provision-failed: bootstrap in progress (expected USB re-enumeration)"
        else
            # Abort recorded under the same condition as the hook, and not in
            # the churn case above: a triage that lost a race with bootstrap is
            # expected, and writing ABORTED for it would put a failure on the
            # Devices page for a device that is provisioning normally.
            #
            # A `set -e` death never reaches die(), so without this a genuine
            # triage failure leaves the device recorded in its last
            # transitional state for ever.
            record_abort_once "${TARGET_DEVICE_SERIAL}" "${TARGET_USB_PATH}"

            PROVISIONER_NAME=$(get_configured_provisioner_name)
            if [ -n "${FASTBOOT_DEVICE_SPECIFIER:-}" ]; then
                run_provision_failed_hook "${PROVISIONER_NAME}" "provisioning"
            else
                run_provision_failed_hook "${PROVISIONER_NAME}" "bootstrap"
            fi
        fi
    fi

    exit ${returnvalue}
}
trap cleanup EXIT INT TERM

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

# Load config early so the image summary is populated before any
# record_state call -- otherwise the device-details page shows an empty
# image for the lifetime of triage and only fills in later, which looks
# inconsistent.
# Best-effort USB path purely for the initial TRIAGE-STARTED record;
# setup_fastboot_and_id_vars recomputes it authoritatively below. Query the
# full serial (the gadget's USB serial is the full value, not the lower half)
# and never let a miss abort triage: under `set -e`, a failed command
# substitution in an assignment exits the script -- which previously killed
# triage before it could even record TRIAGE-STARTED or write any log.
TARGET_USB_PATH=$(get_usb_path_for_serial "${TARGET_DEVICE_SERIAL}") || TARGET_USB_PATH=""

# Enforce the USB port restriction before recording TRIAGE-STARTED, so a
# device on an unwired jig port never appears to have entered provisioning.
# A device that reached fastboot through bootstrap has already passed this
# check, but one that boots straight to fastboot (an already-provisioned
# board being re-triaged) arrives here without having been filtered. The
# check is a no-op unless a rule file is installed -- see
# usb_port_permitted() in rpi-sb-common.sh.
if ! usb_port_permitted "${TARGET_USB_PATH}"; then
    record_usb_port_exclusion "triage" "${TARGET_USB_PATH}" "${TARGET_DEVICE_SERIAL}" || true
    exit 0
fi

# Record state changes atomically
record_state "${TARGET_DEVICE_SERIAL}" "${TRIAGE_STARTED}" "${TARGET_USB_PATH}"

# Establish that there is a usable OS image before engaging the device. This
# is a misconfiguration that no amount of retrying will resolve, so say so
# plainly here rather than letting a provisioner discover it much later --
# previously an unset GOLD_MASTER_OS_FILE got all the way to losetup, which
# retried for 25 seconds before failing with an error about loop devices.
if ! classify_gold_master_os; then
    mark_permanent_failure
    log "${GOLD_MASTER_OS_ERROR}"
    record_state "${TARGET_DEVICE_SERIAL}" "${TRIAGE_ABORTED}" "${TARGET_USB_PATH}"
    die "${GOLD_MASTER_OS_ERROR}"
fi
log "OS image: ${GOLD_MASTER_OS_FILE} (${GOLD_MASTER_OS_KIND})"

if [ -d "/var/log/rpi-sb-provisioner/${TARGET_DEVICE_SERIAL32}" ]; then
    cp -rf "/var/log/rpi-sb-provisioner/${TARGET_DEVICE_SERIAL32}/." "${LOG_DIRECTORY}/"
    rm -rf "/var/log/rpi-sb-provisioner/${TARGET_DEVICE_SERIAL32}"
fi

setup_fastboot_and_id_vars "${TARGET_DEVICE_SERIAL}"

# Ensure the device has a firmware crypto ECDSA key. Every provisioned
# device gets one regardless of style -- it is needed for HMAC-based LUKS
# key derivation and is useful for device identity.
#
# `oem fwcrypto init` is idempotent on the gadget side: OKAY whether the
# slot was empty (just generated) or already populated (no-op). Any
# non-zero exit here is a real firmware/transport failure, not "key
# already exists", so we can rely on the exit status alone.
record_progress "DEVICE-KEY-CHECKING"
log "Ensuring device firmware crypto key is provisioned"
timeout_fatal fastboot -s "${FASTBOOT_DEVICE_SPECIFIER}" oem fwcrypto init

KEYPAIR_DIR="${LOG_DIRECTORY}/${TARGET_DEVICE_SERIAL}"/keypair
if [ -d "${RPI_DEVICE_RETRIEVE_KEYPAIR}" ]; then
    KEYPAIR_DIR="${RPI_DEVICE_RETRIEVE_KEYPAIR}"
fi
mkdir -p "${KEYPAIR_DIR}"
record_progress "KEYPAIR-CAPTURING"
log "Capturing device keypair to ${KEYPAIR_DIR}"

# Both keys come back as multi-line PEM, so they must be read with
# get_variable_pem(): get_variable() stops at the first newline and would
# leave nothing but the "-----BEGIN ...-----" header on disk.
#
# The private key is only ever exportable while the OTP ECDSA key-slot is
# unprovisioned AND unlocked. rpi-fastbootd LOCKs the slot at startup and
# again immediately after `oem fwcrypto init` (run above), so on any device
# that has a device key -- which is now every device we triage -- getvar
# answers "refused" rather than a PEM. That is intended: the key is meant to
# stay in firmware. Treat the absence of a PEM as normal and keep going; the
# public key is what we retain for device identity.
if get_variable_pem private-key > "${KEYPAIR_DIR}/${TARGET_DEVICE_SERIAL}.der"; then
    log "Captured device private key"
else
    rm -f "${KEYPAIR_DIR}/${TARGET_DEVICE_SERIAL}.der"
    log "Device private key is not exportable (OTP key-slot locked); capturing public key only"
fi

if get_variable_pem public-key > "${KEYPAIR_DIR}/${TARGET_DEVICE_SERIAL}.pub"; then
    log "Captured device public key"
else
    rm -f "${KEYPAIR_DIR}/${TARGET_DEVICE_SERIAL}.pub"
    log "Warning: Unable to retrieve device public key"
fi

# Based on the image type and provisioning style, we can determine which
# systemd unit to trigger.  All units are parameterised with the device serial.
echo "${TRIAGE_STARTED}" >> "${LOG_DIRECTORY}"/triage.log

# Select the target unit first, but DON'T start it yet.  `systemctl start` is
# synchronous: it blocks until the provisioner unit is active, by which point
# the provisioner has already written PROVISIONER-STARTED.  If we recorded
# TRIAGE-FINISHED after the start, it would land in the same (second-resolution)
# timestamp as PROVISIONER-STARTED but sort after it -- the state race seen in
# the UI.  Triage's job is done once it has selected the provisioner, so record
# TRIAGE-FINISHED first and hand off last.
# Routing keys off the classification above rather than a bare `-d` test. The
# two are not equivalent: `-d` is also false for an IDP artefact whose
# directory is simply absent -- an unmounted share, a deleted export -- which
# silently routed such a device to the .img provisioner, where it failed later
# with an error naming loop devices rather than the missing artefact.
if [ "${GOLD_MASTER_OS_KIND}" = "idp" ]; then
    # Route to the IDP provisioner regardless of PROVISIONING_STYLE,
    # since the IDP provisioner handles the image format natively.
    # (Secure boot is handled by the bootstrap phase, not the provisioner.)
    log "GOLD_MASTER_OS_FILE is an IDP artefact directory; selecting IDP Provisioner"
    TARGET_PROVISIONER_UNIT="rpi-idp-provisioner@${TARGET_DEVICE_SERIAL}.service"
else
    # Traditional .img file -- use the PROVISIONING_STYLE switch as before
    case ${PROVISIONING_STYLE} in
        "secure-boot")
            log "Selecting Secure Boot Provisioner"
            TARGET_PROVISIONER_UNIT="rpi-sb-provisioner@${TARGET_DEVICE_SERIAL}.service"
        ;;
        "fde-only")
            log "Selecting Full-Disk Encryption Provisioner"
            TARGET_PROVISIONER_UNIT="rpi-fde-provisioner@${TARGET_DEVICE_SERIAL}.service"
        ;;
        "naked")
            log "Selecting Naked Provisioner"
            TARGET_PROVISIONER_UNIT="rpi-naked-provisioner@${TARGET_DEVICE_SERIAL}.service"
        ;;
        *)
            mark_permanent_failure
            log "Fatal: Unknown provisioning style: ${PROVISIONING_STYLE}"
            record_state "${TARGET_DEVICE_SERIAL}" "${TRIAGE_ABORTED}" "${TARGET_USB_PATH}"
            exit 1
        ;;
    esac
fi

# Mark triage finished before dispatching, so the state sequence reads
# TRIAGE-STARTED -> TRIAGE-FINISHED -> PROVISIONER-STARTED in causal order.
log "${TRIAGE_FINISHED}" >> "${LOG_DIRECTORY}"/triage.log
record_state "${TARGET_DEVICE_SERIAL}" "${TRIAGE_FINISHED}" "${TARGET_USB_PATH}"

# Hand off to the selected provisioner.
systemctl start "${TARGET_PROVISIONER_UNIT}"
