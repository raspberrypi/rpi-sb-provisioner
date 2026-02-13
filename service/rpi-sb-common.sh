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

# Cleans up orphaned resources (temp dirs older than MAX_TEMP_DIR_AGE_HOURS)
cleanup_orphans() {
    # Clean up temp directories inside TEMP_BASE that are older than the threshold
    # Using -mindepth 1 to avoid removing TEMP_BASE itself
    find "$TEMP_BASE" -mindepth 1 -maxdepth 1 -type d -mtime +"$MAX_TEMP_DIR_AGE_HOURS" -exec rm -rf {} + 2>/dev/null || true
    find "$LOG_BASE" -type d -empty -delete 2>/dev/null || true
    find "$LOCK_BASE" -type f -mtime +1 -delete 2>/dev/null || true
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
    # Source package defaults first
    if [ -f /usr/share/rpi-sb-provisioner/defaults/config ]; then
        # shellcheck disable=SC1091
        . /usr/share/rpi-sb-provisioner/defaults/config
    else
        printf "%s\n" "Failed to load package defaults. Package may be corrupted." >&2
        return 1
    fi
    
    # Source user overrides (optional - user config takes precedence)
    if [ -f /etc/rpi-sb-provisioner/config ]; then
        # shellcheck disable=SC1091
        . /etc/rpi-sb-provisioner/config
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
    IPV6_ADDRESS="$(fastboot -s "${FASTBOOT_DEVICE_SPECIFIER}" getvar ipv6-address 2>&1 | awk '/^ipv6-address:/ {print $2}')"
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
        
        # Temporarily disable error exit so we can capture the script's exit code
        # Save current error exit setting and disable it
        ERROR_EXIT_WAS_SET=0
        case $- in
            *e*) ERROR_EXIT_WAS_SET=1 ;;
        esac
        set +e
        # Handle different stages with appropriate parameters
        if [ "${STAGE_NAME}" = "post-flash" ]; then
            # For post-flash stage, pass device info that can be used with fastboot
            "${SCRIPT_PATH}" "${FASTBOOT_DEVICE_SPECIFIER}" "${TARGET_DEVICE_SERIAL}" "${RPI_DEVICE_STORAGE_TYPE}"
        elif [ "${STAGE_NAME}" = "bootstrap" ]; then
            # For bootstrap stage, pass device detection info
            TARGET_DEVICE_SERIAL_ARG="$3"
            TARGET_DEVICE_FAMILY_ARG="$4"
            TARGET_USB_PATH_ARG="$5"
            TARGET_DEVICE_PATH_ARG="$6"
            "${SCRIPT_PATH}" "${TARGET_DEVICE_SERIAL_ARG}" "${TARGET_DEVICE_FAMILY_ARG}" "${TARGET_USB_PATH_ARG}" "${TARGET_DEVICE_PATH_ARG}"
        else
            # For filesystem mount stages, pass mount points
            BOOT_MOUNT="$3"
            ROOTFS_MOUNT="$4"
            "${SCRIPT_PATH}" "${BOOT_MOUNT}" "${ROOTFS_MOUNT}"
        fi
        # Capture exit code immediately, before restoring set -e
        SCRIPT_EXIT_CODE=$?
        if [ "${ERROR_EXIT_WAS_SET}" -eq 1 ]; then
            set -e
        fi
        
        if [ $SCRIPT_EXIT_CODE -eq 0 ]; then
            announce_stop "Customisation script ${SCRIPT_NAME} completed successfully"
        else
            announce_stop "Customisation script ${SCRIPT_NAME} failed with exit code ${SCRIPT_EXIT_CODE}"
            log "ERROR: Customisation script ${SCRIPT_NAME} failed with exit code ${SCRIPT_EXIT_CODE}"
            return $SCRIPT_EXIT_CODE
        fi
    else
        log "No customisation script found for ${PROVISIONER_NAME} at stage ${STAGE_NAME}"
    fi
}

get_variable() {
    fastboot -s "${FASTBOOT_DEVICE_SPECIFIER}" getvar "$1" 2>&1 | grep -oP "${1}"': \K[^\r\n]*'
}

# =============================================================================
# Loop Device and Mount Helpers
# =============================================================================
# These functions manage loop devices and mounts for OS image manipulation.
# Lifted from pi-gen/scripts/common.
# =============================================================================

ensure_next_loopdev() {
    set +e
    loopdev="$(losetup -f)"
    loopmaj="$(echo "$loopdev" | sed -E 's/.*[0-9]*?([0-9]+)$/\1/')"
    [ -b "$loopdev" ] || mknod "$loopdev" b 7 "$loopmaj"
    set -e
}

ensure_loopdev_partitions() {
    set +e
    lsblk -r -n -o "NAME,MAJ:MIN" "$1" | grep -v "^${1#/dev/}" | while read -r line; do
        partition="${line%% *}"
        majmin="${line#* }"
        if [ ! -b "/dev/$partition" ]; then
            mknod "/dev/$partition" b "${majmin%:*}" "${majmin#*:}"
        fi
    done
    set -e
}

unmount() {
    if [ -z "$1" ]; then
        DIR=$PWD
    else
        DIR=$1
    fi

    while mount | grep -q "$DIR"; do
        locs=$(mount | grep "$DIR" | cut -f 3 -d ' ' | sort -r)
        for loc in $locs; do
            umount "$loc"
        done
    done
}

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

# =============================================================================
# Signing Infrastructure
# =============================================================================
# These functions provide a unified interface for cryptographic signing
# operations, supporting both PEM files and PKCS#11 hardware security modules.
#
# Usage:
#   1. Call init_signing_context() early in your script (after read_config)
#   2. Use the get_*_sign_args() functions to get tool-specific arguments
#
# Supported signing modes:
#   - "pem"    : Traditional PEM file-based signing
#   - "pkcs11" : PKCS#11 HSM-based signing via wrapper script
#   - "none"   : No signing key configured
# =============================================================================

SIGNING_MODE=""
CUSTOMER_PUBLIC_KEY_FILE=""
PKCS11_WRAPPER_SCRIPT="/usr/bin/rpi-sb-pkcs11-sign.sh"

# Initialize the signing context
# Must be called after read_config() and before any signing operations
#
# This function:
#   - Validates that only one key source is configured (mutual exclusion)
#   - Derives and caches the public key (needed for rpi-sign-bootcode -p)
#   - Sets SIGNING_MODE for use by other functions
#
# Exits with error if:
#   - Both CUSTOMER_KEY_FILE_PEM and CUSTOMER_KEY_PKCS11_NAME are set
#   - PKCS#11 key is not accessible
#   - PEM key file doesn't exist
init_signing_context() {
    OPENSSL="${OPENSSL:-openssl}"
    
    # Mutual exclusion check
    if [ -n "${CUSTOMER_KEY_PKCS11_NAME}" ] && [ -n "${CUSTOMER_KEY_FILE_PEM}" ]; then
        log "ERROR: Both CUSTOMER_KEY_PKCS11_NAME and CUSTOMER_KEY_FILE_PEM are set."
        log "Please configure only one signing key source."
        return 1
    fi
    
    if [ -n "${CUSTOMER_KEY_PKCS11_NAME}" ]; then
        SIGNING_MODE="pkcs11"
        log "Signing mode: PKCS#11 (${CUSTOMER_KEY_PKCS11_NAME})"
        
        # Verify PKCS#11 key is accessible and derive public key
        CUSTOMER_PUBLIC_KEY_FILE="$(mktemp)"
        if ! "${OPENSSL}" rsa -engine pkcs11 -inform engine \
            -in "${CUSTOMER_KEY_PKCS11_NAME}" -pubout > "${CUSTOMER_PUBLIC_KEY_FILE}" 2>/dev/null; then
            rm -f "${CUSTOMER_PUBLIC_KEY_FILE}"
            CUSTOMER_PUBLIC_KEY_FILE=""
            log "ERROR: Cannot access PKCS#11 key: ${CUSTOMER_KEY_PKCS11_NAME}"
            log "Check that the token is present, PIN is correct, and URI is valid."
            return 1
        fi
        log "PKCS#11 key validated and public key derived"
        
    elif [ -n "${CUSTOMER_KEY_FILE_PEM}" ]; then
        SIGNING_MODE="pem"
        log "Signing mode: PEM file (${CUSTOMER_KEY_FILE_PEM})"
        
        if [ ! -f "${CUSTOMER_KEY_FILE_PEM}" ]; then
            log "ERROR: PEM key file not found: ${CUSTOMER_KEY_FILE_PEM}"
            return 1
        fi
        
        # Derive public key
        CUSTOMER_PUBLIC_KEY_FILE="$(mktemp)"
        if ! "${OPENSSL}" rsa -in "${CUSTOMER_KEY_FILE_PEM}" -pubout > "${CUSTOMER_PUBLIC_KEY_FILE}" 2>/dev/null; then
            rm -f "${CUSTOMER_PUBLIC_KEY_FILE}"
            CUSTOMER_PUBLIC_KEY_FILE=""
            log "ERROR: Failed to derive public key from: ${CUSTOMER_KEY_FILE_PEM}"
            return 1
        fi
        log "PEM key validated and public key derived"
        
    else
        SIGNING_MODE="none"
        log "Signing mode: none (no signing key configured)"
    fi
    
    export SIGNING_MODE CUSTOMER_PUBLIC_KEY_FILE
    return 0
}

# Check if signing is available
# Returns 0 if a signing key is configured, 1 otherwise
signing_available() {
    [ "${SIGNING_MODE}" = "pem" ] || [ "${SIGNING_MODE}" = "pkcs11" ]
}

# Get arguments for OpenSSL dgst -sign operations
# Usage: openssl dgst -sign $(get_openssl_sign_args) -sha256 <file>
#
# Returns the key specification and format arguments for OpenSSL
# Exits with error if no signing key is configured
get_openssl_sign_args() {
    case "${SIGNING_MODE}" in
        pkcs11)
            echo "${CUSTOMER_KEY_PKCS11_NAME} -engine pkcs11 -keyform engine"
            ;;
        pem)
            echo "${CUSTOMER_KEY_FILE_PEM} -keyform PEM"
            ;;
        *)
            log "ERROR: No signing key configured (get_openssl_sign_args)"
            return 1
            ;;
    esac
}

# Get arguments for rpi-eeprom-digest signing operations
# Usage: rpi-eeprom-digest $(get_eeprom_digest_sign_args) -i <input> -o <output>
#
# Returns -k or -H arguments depending on signing mode
# Returns empty string if no signing (unsigned mode)
get_eeprom_digest_sign_args() {
    case "${SIGNING_MODE}" in
        pkcs11)
            echo "-H ${PKCS11_WRAPPER_SCRIPT}"
            ;;
        pem)
            echo "-k ${CUSTOMER_KEY_FILE_PEM}"
            ;;
        *)
            # No signing - return empty for unsigned operation
            echo ""
            ;;
    esac
}

# Get arguments for rpi-sign-bootcode signing operations
# Usage: rpi-sign-bootcode $(get_sign_bootcode_key_args) -c <chip> -i <input> -o <output> ...
#
# Returns -k or -H/-p arguments depending on signing mode
# Exits with error if no signing key is configured (bootcode always requires signing)
get_sign_bootcode_key_args() {
    case "${SIGNING_MODE}" in
        pkcs11)
            # PKCS#11 mode requires HSM wrapper AND public key
            if [ -z "${CUSTOMER_PUBLIC_KEY_FILE}" ]; then
                log "ERROR: Public key not available for rpi-sign-bootcode"
                return 1
            fi
            echo "-H ${PKCS11_WRAPPER_SCRIPT} -p ${CUSTOMER_PUBLIC_KEY_FILE}"
            ;;
        pem)
            echo "-k ${CUSTOMER_KEY_FILE_PEM}"
            ;;
        *)
            log "ERROR: No signing key configured (bootcode signing requires a key)"
            return 1
            ;;
    esac
}

# Legacy compatibility wrapper - calls get_openssl_sign_args
# Deprecated: Use get_openssl_sign_args() directly
# This function exists for backward compatibility during migration
get_signing_directives() {
    if [ "${SIGNING_MODE}" = "" ]; then
        # Signing context not initialized - use legacy behavior
        if [ -n "${CUSTOMER_KEY_PKCS11_NAME}" ]; then
            echo "${CUSTOMER_KEY_PKCS11_NAME} -engine pkcs11 -keyform engine"
        elif [ -n "${CUSTOMER_KEY_FILE_PEM}" ]; then
            if [ -f "${CUSTOMER_KEY_FILE_PEM}" ]; then
                echo "${CUSTOMER_KEY_FILE_PEM} -keyform PEM"
            else
                log "ERROR: RSA private key \"${CUSTOMER_KEY_FILE_PEM}\" not a file."
                return 1
            fi
        else
            log "ERROR: Neither PKCS11 key name, or PEM key file specified."
            return 1
        fi
    else
        get_openssl_sign_args
    fi
}

# Get the kernel modules list file path
# Returns the path to the kernel modules list file, checking user config first
get_kernel_modules_list() {
    if [ -f /etc/rpi-sb-provisioner/kernel_modules.list ]; then
        echo "/etc/rpi-sb-provisioner/kernel_modules.list"
    else
        echo "/var/lib/rpi-sb-provisioner/kernel_modules.list"
    fi
}

# Find the kernel modules directory within a rootfs
# Checks both /lib/modules and /usr/lib/modules (older vs newer layouts)
#
# Arguments:
#   $1 - Root filesystem base directory
#
# Returns:
#   Prints the relative path to modules directory (e.g., "lib/modules" or "usr/lib/modules")
#   Returns 1 if no modules directory found
find_modules_dir() {
    _base="$1"
    
    # Check usr/lib/modules first (newer layout, e.g., Debian Bookworm+)
    if [ -d "${_base}/usr/lib/modules" ]; then
        echo "usr/lib/modules"
        return 0
    fi
    
    # Check lib/modules (older layout, e.g., Debian Bullseye and earlier)
    if [ -d "${_base}/lib/modules" ]; then
        echo "lib/modules"
        return 0
    fi
    
    return 1
}

# Find kernel version from a rootfs modules directory
# Checks both /lib/modules and /usr/lib/modules
#
# Arguments:
#   $1 - Root filesystem base directory
#
# Returns:
#   Prints the kernel version string (e.g., "6.6.31+rpt-rpi-v8")
#   Returns 1 if no kernel version found
find_kernel_version() {
    _base="$1"
    _modules_dir=$(find_modules_dir "${_base}") || return 1
    
    # Find the first kernel version directory
    _version=$(find "${_base}/${_modules_dir}" -mindepth 1 -maxdepth 1 -type d -exec basename {} \; 2>/dev/null | head -1)
    
    if [ -n "${_version}" ]; then
        echo "${_version}"
        return 0
    fi
    
    return 1
}

# Copy kernel modules with automatic dependency resolution
# This function uses rpi-modcopy to copy kernel modules and their dependencies
# into the destination directory (typically an initramfs).
#
# Arguments:
#   $1 - Source modules base directory (e.g., /path/to/rootfs containing lib/modules or usr/lib/modules)
#   $2 - Destination directory (e.g., /path/to/initramfs)
#   $3 - Kernel version string (e.g., "6.6.31+rpt-rpi-v8")
#   $4 - (Optional) Path to kernel modules list file. If not provided, uses default.
#
# The modules list file should contain one module name per line (without .ko extension).
# Lines starting with # are treated as comments.
#
# Returns:
#   0 - Success
#   1 - Failure (missing required files or commands)
copy_kernel_modules_with_deps() {
    _src_basedir="$1"
    _dst_basedir="$2"
    _kernel_version="$3"
    _modules_list="${4:-$(get_kernel_modules_list)}"

    # Validate inputs
    if [ -z "${_src_basedir}" ] || [ -z "${_dst_basedir}" ] || [ -z "${_kernel_version}" ]; then
        log "ERROR: copy_kernel_modules_with_deps requires source dir, dest dir, and kernel version"
        return 1
    fi

    # Find where modules are located (lib/modules or usr/lib/modules)
    _modules_rel_dir=$(find_modules_dir "${_src_basedir}")
    if [ -z "${_modules_rel_dir}" ]; then
        log "ERROR: No modules directory found in ${_src_basedir} (checked lib/modules and usr/lib/modules)"
        return 1
    fi

    if [ ! -d "${_src_basedir}/${_modules_rel_dir}/${_kernel_version}" ]; then
        log "ERROR: Kernel modules directory not found: ${_src_basedir}/${_modules_rel_dir}/${_kernel_version}"
        return 1
    fi

    if [ ! -f "${_modules_list}" ]; then
        log "ERROR: Kernel modules list file not found: ${_modules_list}"
        return 1
    fi

    log "Copying kernel modules using rpi-modcopy for ${_kernel_version}..."

    rpi-modcopy \
        --kernel-version="${_kernel_version}" \
        --module-file="${_modules_list}" \
        "${_src_basedir}" \
        "${_dst_basedir}"

    log "Kernel modules copied successfully"
    return 0
}
