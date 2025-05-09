#!/bin/sh

# Common helper functions for Raspberry Pi provisioning scripts
# This file should be sourced by all provisioning scripts

# Base directories for various operations
LOCK_BASE="/var/lock/rpi-sb-provisioner"
LOG_BASE="/var/log/rpi-sb-provisioner"
TEMP_BASE="/srv/rpi-sb-provisioner"

# Resource limits
MAX_TEMP_DIR_AGE_HOURS=24

# Creates a directory atomically, ensuring no race conditions
# Parameters:
#   $1 - Directory path to create
# Returns:
#   0 - Directory created successfully
#   1 - Directory already exists or creation failed
atomic_mkdir() {
    dir="$1"
    mkdir -p "$(dirname "$dir")"
    if mkdir "$dir" 2>/dev/null; then
        return 0
    fi
    return 1
}

# Executes a command with a file lock
# Parameters:
#   $1 - Lock file path
#   $2 - Timeout in seconds (default: 10)
#   $3 - Command to execute
# Returns:
#   0 - Command executed successfully
#   1 - Failed to acquire lock or command failed
with_lock() {
    lock_file="$1"
    timeout="${2:-10}"
    shift 2
    
    # Create lock file if it doesn't exist
    touch "$lock_file"
    
    # Use file descriptor 9 for locking
    # Redirecting within a subshell to ensure cleanup
    (
        # Try to acquire lock with timeout
        start_time=$(date +%s)
        end_time=$((start_time + timeout))
        
        while true; do
            if flock -n -x 9; then
                # Lock acquired, run the command
                "$@"
                ret=$?
                # Lock is released when fd 9 is closed upon subshell exit
                exit $ret
            fi
            
            # Check if timeout has been reached
            current_time=$(date +%s)
            if [ "$current_time" -ge "$end_time" ]; then
                # Timeout reached
                exit 1
            fi
            
            # Wait a bit before trying again
            sleep 0.1 2>/dev/null || sleep 1
        done
    ) 9>"$lock_file"
    
    # Return the exit status of the subshell
    return $?
}

# Cleans up orphaned resources
cleanup_orphans() {
    find "$TEMP_BASE" -maxdepth 0 -type d -mtime +"$MAX_TEMP_DIR_AGE_HOURS" -exec rm -rf {} +
    find "$LOG_BASE" -type d -empty -delete
    find "$LOCK_BASE" -type f -mtime +1 -delete
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

read_config() {
    if [ -f /etc/rpi-sb-provisioner/config ]; then
        # shellcheck disable=SC1091
        . /etc/rpi-sb-provisioner/config
    else
        printf "%s\n" "Failed to load config. Please use configuration tool." >&2
        return 1
    fi
}

# Initializes fastboot connection and device identification variables
# Takes a fastboot device specifier (USB serial or network address) and:
# 1. Verifies fastboot connectivity
# 2. Gets the device serial number
# 3. Tests both IPv4 and IPv6 connectivity, preferring IPv6 if available
# 4. Determines the USB path for the device
#
# Arguments:
#   $1 - Fastboot device specifier (required)
#
# Sets the following global variables:
#   FASTBOOT_DEVICE_SPECIFIER - Final fastboot connection string (USB/IPv4/IPv6)
#   TARGET_DEVICE_SERIAL - Device serial number
#   TARGET_USB_PATH - USB device path
#
# Exits with error if:
#   - Cannot establish fastboot connection
#   - Cannot determine USB path
setup_fastboot_and_id_vars() {
    FASTBOOT_DEVICE_SPECIFIER="$1"

    timeout_fatal fastboot -s "${FASTBOOT_DEVICE_SPECIFIER}" getvar version
    TARGET_DEVICE_SERIAL="$(get_variable serialno)"

    announce_start "Testing Fastboot IP connectivity"
    USE_IPV4=
    USE_IPV6=
    set +e
    IPV6_ADDRESS="$(fastboot -s "${FASTBOOT_DEVICE_SPECIFIER}" getvar ipv6-address 2>&1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}|::([0-9a-fA-F]{0,4}:){0,6}[0-9a-fA-F]{0,4}|[0-9a-fA-F]{0,4}::([0-9a-fA-F]{0,4}:){0,5}[0-9a-fA-F]{0,4}|([0-9a-fA-F]{0,4}:){1,2}:([0-9a-fA-F]{0,4}:){0,4}[0-9a-fA-F]{0,4}')"
    (timeout_nonfatal fastboot -s tcp:"${IPV6_ADDRESS}" getvar version)
    USE_IPV6=$?
    IPV4_ADDRESS="$(fastboot -s "${FASTBOOT_DEVICE_SPECIFIER}" getvar ipv4-address 2>&1 | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}')"
    (timeout_nonfatal fastboot -s tcp:"${IPV4_ADDRESS}" getvar version)
    USE_IPV4=$?
    set -e

    # Favour using IPv6 if available, and ethernet regardless to get 1024-byte chunks in Fastboot without USB3
    if [ "${USE_IPV6}" -eq 0 ]; then
    FASTBOOT_DEVICE_SPECIFIER="tcp:${IPV6_ADDRESS}"
    elif [ "${USE_IPV4}" -eq 0 ]; then
    FASTBOOT_DEVICE_SPECIFIER="tcp:${IPV4_ADDRESS}"
    else
    FASTBOOT_DEVICE_SPECIFIER="${TARGET_DEVICE_SERIAL}"
    fi

    # Set TARGET_USB_PATH based on TARGET_DEVICE_SERIAL
    if [ -n "${TARGET_DEVICE_SERIAL}" ]; then
        # Try to get the USB path for the device
        usb_path=$(get_usb_path_for_serial "${TARGET_DEVICE_SERIAL}")
        
        if [ -n "$usb_path" ]; then
            TARGET_USB_PATH="$usb_path"
            log "Found USB path ${TARGET_USB_PATH} for device ${TARGET_DEVICE_SERIAL}"
        else
            log "Warning: Could not find USB path for device ${TARGET_DEVICE_SERIAL}"

        fi
    fi

    # Ensure TARGET_USB_PATH is set
    if [ -z "${TARGET_USB_PATH}" ]; then
        log "Error: Could not determine USB path for device ${TARGET_DEVICE_SERIAL}"
        record_state "${TARGET_DEVICE_SERIAL}" "${PROVISIONER_ABORTED}" "unknown-usb-path"
        exit 1
    fi
}

run_customisation_script() {
    PROVISIONER_NAME="$1"
    STAGE_NAME="$2"
    
    SCRIPT_NAME="${PROVISIONER_NAME}-${STAGE_NAME}.sh"
    SCRIPT_PATH="/etc/rpi-sb-provisioner/scripts/${SCRIPT_NAME}"
    
    if [ -f "${SCRIPT_PATH}" ]; then
        announce_start "Running customisation script for ${PROVISIONER_NAME} at stage ${STAGE_NAME}"
        
        # Check if script is executable
        if [ ! -x "${SCRIPT_PATH}" ]; then
            log "Skipping disabled customisation script: ${SCRIPT_NAME}"
            return 0
        fi
        
        # Temporarily disable error exit to prevent script failures from aborting the provisioning process
        # Save current error exit setting and disable it
        ERROR_EXIT_WAS_SET=0
        if [ -o errexit ]; then
            ERROR_EXIT_WAS_SET=1
        fi
        set +e
        # Handle different stages with appropriate parameters
        if [ "${STAGE_NAME}" = "post-flash" ]; then
            # For post-flash stage, pass device info that can be used with fastboot
            "${SCRIPT_PATH}" "${FASTBOOT_DEVICE_SPECIFIER}" "${TARGET_DEVICE_SERIAL}" "${RPI_DEVICE_STORAGE_TYPE}"
        else
            # For filesystem mount stages, pass mount points
            BOOT_MOUNT="$3"
            ROOTFS_MOUNT="$4"
            "${SCRIPT_PATH}" "${BOOT_MOUNT}" "${ROOTFS_MOUNT}"
        fi
        if [ "${ERROR_EXIT_WAS_SET}" -eq 1 ]; then
            set -e
        fi
        SCRIPT_EXIT_CODE=$?
        
        if [ $SCRIPT_EXIT_CODE -eq 0 ]; then
            announce_stop "Customisation script ${SCRIPT_NAME} completed successfully"
        else
            announce_stop "Customisation script ${SCRIPT_NAME} failed with exit code ${SCRIPT_EXIT_CODE}"
            log "WARNING: Customisation script ${SCRIPT_NAME} failed with exit code ${SCRIPT_EXIT_CODE}"
        fi
    else
        log "No customisation script found for ${PROVISIONER_NAME} at stage ${STAGE_NAME}"
    fi
}

get_variable() {
    fastboot -s "${FASTBOOT_DEVICE_SPECIFIER}" getvar "$1" 2>&1 | grep -oP "${1}"': \K[^\r\n]*'
}
