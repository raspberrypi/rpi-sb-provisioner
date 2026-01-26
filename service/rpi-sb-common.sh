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
        
        # Temporarily disable error exit to prevent script failures from aborting the provisioning process
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
# This function uses modinfo to recursively find all module dependencies,
# ensuring that all required modules are included in the initramfs.
#
# Based on the approach from pi-gen-micro, adapted for POSIX shell.
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
    
    log "Found modules in ${_modules_rel_dir}/${_kernel_version}"
    
    if [ ! -f "${_modules_list}" ]; then
        log "ERROR: Kernel modules list file not found: ${_modules_list}"
        return 1
    fi
    
    # Create temporary files for tracking modules
    _tmp_dir=$(mktemp -d)
    _modules_to_process="${_tmp_dir}/modules_to_process"
    _modules_processed="${_tmp_dir}/modules_processed"
    _module_paths="${_tmp_dir}/module_paths"
    
    # Ensure cleanup on exit from this function
    trap 'rm -rf "${_tmp_dir}"' RETURN 2>/dev/null || true
    
    touch "${_modules_processed}"
    touch "${_module_paths}"
    
    # Read initial module list (strip comments and empty lines)
    sed '/^#/d; /^[[:space:]]*$/d' "${_modules_list}" | sort | uniq > "${_modules_to_process}"
    
    log "Resolving kernel module dependencies for ${_kernel_version}..."
    
    # Ensure the lib symlink exists for depmod/modinfo compatibility (they hard-code /lib path)
    if [ ! -e "${_src_basedir}/lib" ] && [ -d "${_src_basedir}/usr/lib" ]; then
        ln -sf usr/lib "${_src_basedir}/lib"
    fi
    
    # Run depmod first to ensure modules.dep exists
    depmod --basedir "${_src_basedir}" "${_kernel_version}" 2>/dev/null || true
    
    # Process modules iteratively until no new dependencies are found
    while [ -s "${_modules_to_process}" ]; do
        # Read modules that haven't been processed yet
        _new_modules=""
        while IFS= read -r _module; do
            # Skip if already processed
            if grep -qxF "${_module}" "${_modules_processed}" 2>/dev/null; then
                continue
            fi
            
            # Mark as processed
            echo "${_module}" >> "${_modules_processed}"
            
            # Get module info (filename and dependencies)
            # modinfo returns info for the module, we extract filename and depends
            _modinfo_output=$(modinfo --basedir "${_src_basedir}" -k "${_kernel_version}" "${_module}" 2>/dev/null) || true
            
            # Extract filename (skip if builtin)
            _filename=$(echo "${_modinfo_output}" | grep -E '^filename:' | sed 's/^filename:[[:space:]]*//' | head -1)
            
            if [ -n "${_filename}" ] && [ "${_filename}" != "(builtin)" ]; then
                # Convert absolute path to relative and store
                # The path from modinfo is relative to basedir
                _rel_path=$(echo "${_filename}" | sed "s|^${_src_basedir}/||; s|^/||")
                if [ -n "${_rel_path}" ]; then
                    echo "${_rel_path}" >> "${_module_paths}"
                fi
            fi
            
            # Extract dependencies and add them for processing
            _depends=$(echo "${_modinfo_output}" | grep -E '^depends:' | sed 's/^depends:[[:space:]]*//' | tr ',' '\n' | sed '/^$/d')
            
            for _dep in ${_depends}; do
                if [ -n "${_dep}" ] && ! grep -qxF "${_dep}" "${_modules_processed}" 2>/dev/null; then
                    _new_modules="${_new_modules}${_dep}
"
                fi
            done
        done < "${_modules_to_process}"
        
        # Set up next iteration with new dependencies
        if [ -n "${_new_modules}" ]; then
            echo "${_new_modules}" | sed '/^$/d' | sort | uniq > "${_modules_to_process}"
        else
            : > "${_modules_to_process}"
        fi
    done
    
    # Also include essential module metadata files (using detected modules path)
    {
        echo "${_modules_rel_dir}/${_kernel_version}/modules.order"
        echo "${_modules_rel_dir}/${_kernel_version}/modules.builtin"
        echo "${_modules_rel_dir}/${_kernel_version}/modules.builtin.modinfo"
    } >> "${_module_paths}"
    
    # Remove duplicates
    sort "${_module_paths}" | uniq > "${_module_paths}.dedup"
    mv "${_module_paths}.dedup" "${_module_paths}"
    
    # Count modules for logging
    _module_count=$(wc -l < "${_module_paths}" | tr -d ' ')
    log "Copying ${_module_count} kernel module files (including dependencies)..."
    
    # Create destination modules directory (always use usr/lib/modules for destination)
    mkdir -p "${_dst_basedir}/usr/lib/modules/${_kernel_version}"
    
    # Copy all module files preserving directory structure
    # Using rsync with --files-from for efficiency
    if command -v rsync >/dev/null 2>&1; then
        rsync \
            --archive \
            --files-from="${_module_paths}" \
            "${_src_basedir}/" \
            "${_dst_basedir}/" 2>/dev/null || {
            # Fallback to cpio if rsync fails
            log "rsync failed, falling back to cpio..."
            cd "${_src_basedir}"
            # shellcheck disable=SC2002
            cat "${_module_paths}" | cpio -pdm "${_dst_basedir}" 2>/dev/null
            cd - >/dev/null
        }
    else
        # Fallback if rsync not available
        cd "${_src_basedir}"
        while IFS= read -r _file; do
            if [ -f "${_file}" ]; then
                _dir=$(dirname "${_file}")
                mkdir -p "${_dst_basedir}/${_dir}"
                cp -a "${_file}" "${_dst_basedir}/${_file}"
            fi
        done < "${_module_paths}"
        cd - >/dev/null
    fi
    
    # If source was lib/modules but we want usr/lib/modules in destination,
    # create symlink for compatibility
    if [ "${_modules_rel_dir}" = "lib/modules" ] && [ ! -e "${_dst_basedir}/usr/lib/modules" ]; then
        mkdir -p "${_dst_basedir}/usr/lib"
        ln -sf ../../lib/modules "${_dst_basedir}/usr/lib/modules"
    fi
    
    # Ensure lib -> usr/lib symlink exists in destination for depmod
    if [ ! -e "${_dst_basedir}/lib" ] && [ -d "${_dst_basedir}/usr/lib" ]; then
        ln -sf usr/lib "${_dst_basedir}/lib"
    fi
    
    # Generate depmod information for the destination
    log "Generating module dependency information..."
    depmod --basedir "${_dst_basedir}" "${_kernel_version}"
    
    # Cleanup temporary files
    rm -rf "${_tmp_dir}"
    
    log "Kernel modules copied successfully"
    return 0
}
