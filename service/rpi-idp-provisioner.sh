#!/bin/sh

set -e
set -x

# IDP (Image Description Provisioning) provisioner.
#
# Consumes a pre-built IDP artefact (JSON description + sparse images) from
# rpi-image-gen.  The device-side fastbootd handles partition creation,
# encryption setup, and partition enumeration from the JSON.  This script
# just orchestrates: stage JSON, idpinit, idpwrite, idpgetblk/flash loop,
# idpdone.

# shellcheck disable=SC1091
. /var/lib/rpi-sb-provisioner/manufacturing-data
# shellcheck disable=SC1091
. /var/lib/rpi-sb-provisioner/state-recording

DEBUG=

export PROVISIONER_FINISHED="IDP-PROVISIONER-FINISHED"
export PROVISIONER_ABORTED="IDP-PROVISIONER-ABORTED"
export PROVISIONER_STARTED="IDP-PROVISIONER-STARTED"

# Source common helper functions
# shellcheck disable=SC1091
. "$(dirname "$0")/rpi-sb-common.sh"

die() {
    record_state "${TARGET_DEVICE_SERIAL}" "${PROVISIONER_ABORTED}" "${TARGET_USB_PATH}"
    # shellcheck disable=SC2086
    echo "$@" ${DEBUG}
    exit 1
}

log() {
    timestamp=$(date +"%Y-%m-%d %H:%M:%S.$(date +%N | cut -c1-3)")
    echo "[${timestamp}] $*" >> /var/log/rpi-sb-provisioner/"${TARGET_DEVICE_SERIAL}"/provisioner.log
    printf "[%s] %s\n" "${timestamp}" "$*"
}

read_config

CLEANUP_DONE=0

check_command_exists() {
    command_to_test=$1
    if ! command -v "${command_to_test}" 1> /dev/null; then
        die "${command_to_test} could not be found"
    else
        echo "$command_to_test"
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

# timeout_fatal: 30-second default used by rpi-sb-common.sh helpers.
timeout_fatal() {
    timeout_fatal_secs 30 "$@"
}

# timeout_fatal with configurable timeout.
# Arguments: $1 = timeout in seconds, remaining = command to run
timeout_fatal_secs() {
    timeout_seconds="$1"
    shift
    command="$*"
    set +e
    log "Running command with ${timeout_seconds}s timeout: \"${command}\""
    # shellcheck disable=SC2086
    timeout "${timeout_seconds}" ${command}
    command_exit_status=$?

    case ${command_exit_status} in
        0)
            log "\"$command\" succeeded with exit code 0."
            ;;
        124)
            record_state "${TARGET_DEVICE_SERIAL}" "${PROVISIONER_ABORTED}" "${TARGET_USB_PATH}"
            die "\"${command}\" FAILED: Timed out after ${timeout_seconds} seconds (exit code 124)."
            ;;
        *)
            record_state "${TARGET_DEVICE_SERIAL}" "${PROVISIONER_ABORTED}" "${TARGET_USB_PATH}"
            die "\"${command}\" FAILED: Command returned exit code ${command_exit_status}."
            ;;
    esac
    set -e
}

cleanup() {
    # Guard against multiple invocations (signal + EXIT trap)
    [ "$CLEANUP_DONE" -eq 1 ] && return
    CLEANUP_DONE=1

    return_value=$?
    exit ${return_value}
}
trap cleanup EXIT INT TERM

### Pre-requisite checks

check_command_exists fastboot
check_command_exists jq
check_command_exists cut
check_command_exists sed
check_command_exists systemd-notify

setup_fastboot_and_id_vars "$1"

record_state "${TARGET_DEVICE_SERIAL}" "${PROVISIONER_STARTED}" "${TARGET_USB_PATH}"

systemd-notify --ready --status="Provisioning started"

# Run provision-started hook (e.g. LED control on programming rigs)
run_customisation_script "idp-provisioner" "provision-started" "${FASTBOOT_DEVICE_SPECIFIER}" "${TARGET_DEVICE_SERIAL}" "${RPI_DEVICE_STORAGE_TYPE}"

RPI_DEVICE_STORAGE_TYPE="$(check_pidevice_storage_type "${RPI_DEVICE_STORAGE_TYPE}")"

### Resolve the IDP artefact directory

if [ -d "${GOLD_MASTER_OS_FILE}" ]; then
    IDP_DIR="${GOLD_MASTER_OS_FILE}"
else
    die "GOLD_MASTER_OS_FILE is not a directory: ${GOLD_MASTER_OS_FILE}. IDP provisioner requires an IDP artefact directory."
fi

### Pre-flight validation
#
# Fail fast on the host before wasting device time.

announce_start "IDP pre-flight validation"

# Exactly one JSON file must be present
JSON_COUNT=$(find "${IDP_DIR}" -maxdepth 1 -name "*.json" -type f | wc -l)
if [ "${JSON_COUNT}" -eq 0 ]; then
    die "No JSON description file found in IDP artefact directory: ${IDP_DIR}"
elif [ "${JSON_COUNT}" -gt 1 ]; then
    die "Multiple JSON files found in IDP artefact directory: ${IDP_DIR}. Expected exactly one."
fi
IDP_JSON=$(find "${IDP_DIR}" -maxdepth 1 -name "*.json" -type f)

log "IDP artefact directory: ${IDP_DIR}"
log "IDP JSON description: ${IDP_JSON}"

# JSON must be syntactically valid
if ! jq empty < "${IDP_JSON}" 2>/dev/null; then
    die "IDP JSON description is not valid JSON: ${IDP_JSON}"
fi

# Extract and log metadata from the JSON
IDP_IMAGE_NAME=$(jq -r '.attributes."image-name" // "unknown"' < "${IDP_JSON}")
IDP_IMAGE_VERSION=$(jq -r '.IGmeta.IGconf_image_version // "unknown"' < "${IDP_JSON}")
IDP_DEVICE_CLASS=$(jq -r '.IGmeta.IGconf_device_class // "unknown"' < "${IDP_JSON}")
IDP_STORAGE_TYPE=$(jq -r '.IGmeta.IGconf_device_storage_type // "unknown"' < "${IDP_JSON}")
IDP_HAS_ENCRYPTION=$(jq -r 'if .layout.provisionmap[]? | .encrypted? then "yes" else "no" end' < "${IDP_JSON}" | head -1)

log "IDP image name: ${IDP_IMAGE_NAME}"
log "IDP image version: ${IDP_IMAGE_VERSION}"
log "IDP device class: ${IDP_DEVICE_CLASS}"
log "IDP storage type: ${IDP_STORAGE_TYPE}"
log "IDP encryption: ${IDP_HAS_ENCRYPTION}"

# Verify all referenced .simg files exist
MISSING_IMAGES=""
for SIMG_NAME in $(jq -r '.layout.partitionimages | to_entries[] | .value.simage // empty' < "${IDP_JSON}"); do
    if [ ! -f "${IDP_DIR}/${SIMG_NAME}" ]; then
        MISSING_IMAGES="${MISSING_IMAGES} ${SIMG_NAME}"
    fi
done
if [ -n "${MISSING_IMAGES}" ]; then
    die "IDP artefact is incomplete. Missing sparse images:${MISSING_IMAGES}"
fi

# Cross-check device class against host configuration
# Map IDP device class names to RPI_DEVICE_FAMILY convention
map_device_class_to_family() {
    case "$1" in
        pi5|cm5)   echo "5" ;;
        pi4|cm4)   echo "4" ;;
        pi2w)      echo "2W" ;;
        *)         echo "$1" ;;
    esac
}

EXPECTED_FAMILY=$(map_device_class_to_family "${IDP_DEVICE_CLASS}")
if [ -n "${RPI_DEVICE_FAMILY}" ] && [ "${EXPECTED_FAMILY}" != "${RPI_DEVICE_FAMILY}" ]; then
    die "IDP artefact is for device family '${EXPECTED_FAMILY}' (${IDP_DEVICE_CLASS}), but this station is configured for '${RPI_DEVICE_FAMILY}'."
fi

# Cross-check storage type against host configuration
if [ -n "${RPI_DEVICE_STORAGE_TYPE}" ]; then
    # RPI_DEVICE_STORAGE_TYPE has already been mapped to block device name (mmcblk0/nvme0n1)
    # Map IDP storage type to the same convention for comparison
    IDP_STORAGE_BLOCK=$(check_pidevice_storage_type "${IDP_STORAGE_TYPE}" 2>/dev/null || true)
    if [ -n "${IDP_STORAGE_BLOCK}" ] && [ "${IDP_STORAGE_BLOCK}" != "${RPI_DEVICE_STORAGE_TYPE}" ]; then
        die "IDP artefact is for storage type '${IDP_STORAGE_TYPE}', but this station is configured for storage device '${RPI_DEVICE_STORAGE_TYPE}'."
    fi
fi

log "Pre-flight validation passed"
announce_stop "IDP pre-flight validation"

### IDP Provisioning Protocol

announce_start "Erase Device Storage"
timeout_fatal_secs 30 fastboot -s "${FASTBOOT_DEVICE_SPECIFIER}" erase "${RPI_DEVICE_STORAGE_TYPE}"
sleep 3
announce_stop "Erase Device Storage"

# Re-check the fastboot device specifier, as it may take a while for a device to gain IP connectivity
setup_fastboot_and_id_vars "${FASTBOOT_DEVICE_SPECIFIER}"

announce_start "IDP Stage and Initialise"
timeout_fatal_secs 30 fastboot -s "${FASTBOOT_DEVICE_SPECIFIER}" stage "${IDP_JSON}"
timeout_fatal_secs 30 fastboot -s "${FASTBOOT_DEVICE_SPECIFIER}" oem idpinit
announce_stop "IDP Stage and Initialise"

announce_start "IDP Write Partitions"
timeout_fatal_secs 120 fastboot -s "${FASTBOOT_DEVICE_SPECIFIER}" oem idpwrite
announce_stop "IDP Write Partitions"

announce_start "IDP Flash Images"
PARTITION_INDEX=0
while true; do
    set +e
    RESPONSE=$(fastboot -s "${FASTBOOT_DEVICE_SPECIFIER}" oem idpgetblk 2>&1)
    FB_EXIT=$?
    set -e
    [ $FB_EXIT -ne 0 ] && die "idpgetblk failed (exit ${FB_EXIT}): ${RESPONSE}"

    # Extract the INFO line.
    # The host fastboot client outputs device INFO messages in various formats
    # depending on version: "(bootloader) msg" or "INFO msg".
    # We look for a line containing a colon-separated blockdev:simg pair.
    INFO_LINE=$(echo "${RESPONSE}" | sed -n 's/.*[Ii][Nn][Ff][Oo][[:space:]]*//p' | head -1)

    # If there was no info line, also try the (bootloader) format
    if [ -z "${INFO_LINE}" ]; then
        INFO_LINE=$(echo "${RESPONSE}" | sed -n 's/.*(bootloader)[[:space:]]*//p' | head -1)
    fi

    # No INFO line means we're done -- all partitions have been enumerated
    if [ -z "${INFO_LINE}" ]; then
        log "idpgetblk: no more partitions to flash"
        break
    fi

    # INFO line should be "blockdev:simg_filename"
    BLOCKDEV=$(echo "${INFO_LINE}" | cut -d: -f1)
    SIMG=$(echo "${INFO_LINE}" | cut -d: -f2)

    if [ -z "${BLOCKDEV}" ] || [ -z "${SIMG}" ]; then
        die "Malformed idpgetblk response: '${INFO_LINE}' (full response: ${RESPONSE})"
    fi

    if [ ! -f "${IDP_DIR}/${SIMG}" ]; then
        die "idpgetblk referenced image not found: ${IDP_DIR}/${SIMG}"
    fi

    PARTITION_INDEX=$((PARTITION_INDEX + 1))
    SIMG_SIZE=$(stat -c%s "${IDP_DIR}/${SIMG}" 2>/dev/null || echo "unknown")
    log "Flashing partition ${PARTITION_INDEX}: ${SIMG} (${SIMG_SIZE} bytes) -> ${BLOCKDEV}"

    FLASH_START=$(date +%s)
    timeout_fatal_secs 600 fastboot -s "${FASTBOOT_DEVICE_SPECIFIER}" flash "${BLOCKDEV}" "${IDP_DIR}/${SIMG}"
    FLASH_END=$(date +%s)
    FLASH_DURATION=$((FLASH_END - FLASH_START))
    log "Flashed ${SIMG} to ${BLOCKDEV} in ${FLASH_DURATION}s"
done
log "Flashed ${PARTITION_INDEX} partition(s) total"
announce_stop "IDP Flash Images"

announce_start "IDP Finalise"
timeout_fatal_secs 60 fastboot -s "${FASTBOOT_DEVICE_SPECIFIER}" oem idpdone
announce_stop "IDP Finalise"

announce_start "Set LED status"
fastboot -s "${FASTBOOT_DEVICE_SPECIFIER}" oem led PWR 0
announce_stop "Set LED status"

metadata_gather

# Run post-flash customisation script
run_customisation_script "idp-provisioner" "post-flash" "${FASTBOOT_DEVICE_SPECIFIER}" "${TARGET_DEVICE_SERIAL}" "${RPI_DEVICE_STORAGE_TYPE}"
log "Post-flash customisation script completed"

record_state "${TARGET_DEVICE_SERIAL}" "${PROVISIONER_FINISHED}" "${TARGET_USB_PATH}"

log "IDP provisioning completed. Remove the device from this machine."
log "Artefact: ${IDP_IMAGE_NAME} version ${IDP_IMAGE_VERSION}"

# Indicate successful completion to systemd
systemd-notify --status="Provisioning completed successfully" STOPPING=1

true
