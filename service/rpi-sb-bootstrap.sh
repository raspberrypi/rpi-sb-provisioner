#!/bin/sh

set -e
set -x

DEBUG=

OPENSSL=${OPENSSL:-openssl}

export BOOTSTRAP_FINISHED="BOOTSTRAP-FINISHED"
export BOOTSTRAP_ABORTED="BOOTSTRAP-ABORTED"
export BOOTSTRAP_STARTED="BOOTSTRAP-STARTED"


# Lock directories
LOCK_BASE="/var/lock/rpi-sb-bootstrap"
STATE_BASE="/var/run/rpi-sb-state"
LOG_BASE="/var/log/rpi-sb-provisioner"
TEMP_BASE="/srv/rpi-sb-bootstrap"

# Source common helper functions
# shellcheck disable=SC1091
. "$(dirname "$0")/rpi-sb-common.sh"
# shellcheck disable=SC1091
. /var/lib/rpi-sb-provisioner/manufacturing-data
# shellcheck disable=SC1091
. /var/lib/rpi-sb-provisioner/state-recording

HOLDING_LOCKFILE=0

log() {
    log_file="${EARLY_LOG_DIRECTORY}/bootstrap.log"
    timestamp=$(date +"%Y-%m-%d %H:%M:%S.$(date +%N | cut -c1-3)")
    message="$*"
    
    # Ensure log directory exists with proper permissions
    mkdir -p "$(dirname "$log_file")"
    touch "$log_file"
    chmod 644 "$log_file"
    
    # Write log message directly without locking
    echo "[${timestamp}] $message" >> "$log_file"
    printf "[%s] %s\n" "${timestamp}" "$message"
}

cleanup() {
    returnvalue=$?
    if [ ${HOLDING_LOCKFILE} -eq 1 ]; then
        rm -rf "$DEVICE_LOCK"
        
        announce_start "Deleting udev lock"
        rm -f "/etc/udev/rules.d/99-rpi-sb-bootstrap-${TARGET_DEVICE_SERIAL}.rules"
        udevadm control --reload-rules
        announce_stop "Deleting udev lock"
    fi

    if [ -n "${CUSTOMER_PUBLIC_KEY_FILE}" ]; then
        announce_start "Deleting public key"
        # shellcheck disable=SC2086
        rm -f "${CUSTOMER_PUBLIC_KEY_FILE}" ${DEBUG}
        CUSTOMER_PUBLIC_KEY_FILE=
        announce_stop "Deleting public key"
    fi

    if [ -n "${DELETE_PRIVATE_TMPDIR}" ]; then
        announce_start "Deleting customised intermediates"
        # shellcheck disable=SC2086
        rm -rf "${DELETE_PRIVATE_TMPDIR}" ${DEBUG}
        DELETE_PRIVATE_TMPDIR=
        announce_stop "Deleting customised intermediates"
    fi
    
    # Clean up orphaned resources
    cleanup_orphans

    if [ $returnvalue -eq 0 ]; then
        systemd-notify --status="Provisioning completed successfully" STOPPING=1
    else
        systemd-notify --status="Provisioning failed" STOPPING=1
    fi
    
    exit $returnvalue
}

trap cleanup INT TERM

# On pre-Pi4 devices, only TARGET_DEVICE_PATH is likely to be unique.
TARGET_DEVICE_PATH="$1"
# TARGET_USB_PATH is a udev device path in the format "X-Y[.Z]" where:
# - X is the USB bus number
# - Y is the port number on that bus  
# - Z is the optional port number for devices behind a hub
# Example: "1-1.2" means bus 1, hub port 1, hub downstream port 2
TARGET_USB_PATH="$(udevadm info "${TARGET_DEVICE_PATH}" | grep -oP '^M: \K.*')"
TARGET_DEVICE_FAMILY="$(udevadm info --name="$TARGET_DEVICE_PATH" --query=property --property=ID_MODEL_ID --value)"
# TARGET_DEVICE_SERIAL is best-effort, not all rpiboot devices have it set (some only show 32-bits)
TARGET_DEVICE_SERIAL="$(udevadm info --name="$TARGET_DEVICE_PATH" --query=property --property=ID_SERIAL_SHORT --value)"
# If TARGET_DEVICE_SERIAL is empty or equals "Broadcom", use TARGET_DEVICE_PATH instead
if [ -z "${TARGET_DEVICE_SERIAL}" ] || [ "${TARGET_DEVICE_SERIAL}" = "Broadcom" ]; then
    TARGET_DEVICE_SERIAL="${TARGET_DEVICE_PATH}"
    log "Using device path as serial: ${TARGET_DEVICE_SERIAL}"
fi


EARLY_LOG_DIRECTORY="/var/log/rpi-sb-provisioner/early/${TARGET_DEVICE_PATH}"
mkdir -p "${EARLY_LOG_DIRECTORY}"

die() {
    # shellcheck disable=SC2086
    echo "$@" ${DEBUG}
    false
    cleanup
}

read_config
systemd-notify --ready --status="Provisioning started"
# Create device-specific lock
DEVICE_LOCK="${LOCK_BASE}/${TARGET_DEVICE_SERIAL}"
if atomic_mkdir "$DEVICE_LOCK"; then
    HOLDING_LOCKFILE=1
else
    # Don't record state here, as this is an expected failure for devices
    # that produce multiple matching descriptors.
    die "Bootstrap already in progress for ${TARGET_DEVICE_SERIAL}"
fi

get_fastboot_gadget() {
    if [ -f /etc/rpi-sb-provisioner/fastboot-gadget.img ]; then
        echo "/etc/rpi-sb-provisioner/fastboot-gadget.img"
    else
        echo "/var/lib/rpi-sb-provisioner/fastboot-gadget.img"
    fi
}

get_fastboot_gadget_2710() {
    if [ -f /etc/rpi-sb-provisioner/fastboot-gadget.2710-bootfiles-bin ]; then
        echo "/etc/rpi-sb-provisioner/fastboot-gadget.2710-bootfiles-bin"
    else
        echo "/var/lib/rpi-sb-provisioner/fastboot-gadget.2710-bootfiles-bin"
    fi
}


get_fastboot_config_file() {
    if [ -f /etc/rpi-sb-provisioner/boot_ramdisk_config.txt ]; then
        echo "/etc/rpi-sb-provisioner/boot_ramdisk_config.txt"
    else
        echo "/var/lib/rpi-sb-provisioner/boot_ramdisk_config.txt"
    fi
}

check_command_exists() {
    command_to_test=$1
    if ! command -v "${command_to_test}" 1> /dev/null; then
        log "${command_to_test} could not be found"
        exit 1
    else
        echo "$command_to_test"
    fi
}

timeout_fatal() {
    command="$*"
    timeout_seconds=60
    set +e
    log "Running command with ${timeout_seconds}-second timeout: \"${command}\""
    # shellcheck disable=SC2086
    timeout ${timeout_seconds} ${command}
    command_exit_status=$?
    
    # Handle different exit codes from the timeout command
    case ${command_exit_status} in
        0)
            # Command completed successfully within the time limit
            log "\"$command\" succeeded with exit code 0."
            ;;
        124)
            # Exit code 124 means the command timed out (TERM signal sent but command didn't exit)
            record_state "${TARGET_DEVICE_SERIAL}" "${BOOTSTRAP_ABORTED}" "${TARGET_USB_PATH}"
            die "\"${command}\" FAILED: Timed out after ${timeout_seconds} seconds (exit code 124)."
            ;;
        125)
            # Exit code 125 means the timeout command itself failed
            record_state "${TARGET_DEVICE_SERIAL}" "${BOOTSTRAP_ABORTED}" "${TARGET_USB_PATH}"
            die "\"${command}\" FAILED: The timeout command itself failed (exit code 125)."
            ;;
        126)
            # Exit code 126 means the command was found but could not be executed
            record_state "${TARGET_DEVICE_SERIAL}" "${BOOTSTRAP_ABORTED}" "${TARGET_USB_PATH}"
            die "\"${command}\" FAILED: Command found but could not be executed (exit code 126)."
            ;;
        127)
            # Exit code 127 means the command was not found
            record_state "${TARGET_DEVICE_SERIAL}" "${BOOTSTRAP_ABORTED}" "${TARGET_USB_PATH}"
            die "\"${command}\" FAILED: Command not found (exit code 127)."
            ;;
        137)
            # Exit code 137 (128+9) means the command was killed by SIGKILL (kill -9)
            record_state "${TARGET_DEVICE_SERIAL}" "${BOOTSTRAP_ABORTED}" "${TARGET_USB_PATH}"
            die "\"${command}\" FAILED: Command was killed by SIGKILL (exit code 137)."
            ;;
        *)
            # Any other non-zero exit code is a general failure
            record_state "${TARGET_DEVICE_SERIAL}" "${BOOTSTRAP_ABORTED}" "${TARGET_USB_PATH}"
            die "\"${command}\" FAILED: Command returned exit code ${command_exit_status}."
            ;;
    esac
    set -e
}

get_signing_directives() {
    if [ -n "${CUSTOMER_KEY_PKCS11_NAME}" ]; then
        echo "${CUSTOMER_KEY_PKCS11_NAME} -engine pkcs11 -keyform engine"
    else
        if [ -n "${CUSTOMER_KEY_FILE_PEM}" ]; then
            if [ -f "${CUSTOMER_KEY_FILE_PEM}" ]; then
                echo "${CUSTOMER_KEY_FILE_PEM} -keyform PEM"
            else
                record_state "${TARGET_DEVICE_SERIAL}" "${BOOTSTRAP_ABORTED}" "${TARGET_USB_PATH}"
                die "RSA private key \"${CUSTOMER_KEY_FILE_PEM}\" not a file. Aborting."
            fi
        else
            record_state "${TARGET_DEVICE_SERIAL}" "${BOOTSTRAP_ABORTED}" "${TARGET_USB_PATH}"
            die "Neither PKCS11 key name, or PEM key file specified. Aborting."
        fi
    fi
}

CUSTOMER_PUBLIC_KEY_FILE=
derivePublicKey() {
    CUSTOMER_PUBLIC_KEY_FILE="$(mktemp)"
    "${OPENSSL}" rsa -in "${CUSTOMER_KEY_FILE_PEM}" -pubout > "${CUSTOMER_PUBLIC_KEY_FILE}"
}

writeSig() {
   SIG_TMP="$(mktemp)"
   IMAGE="$1"
   OUTPUT="$2"
   sha256sum "${IMAGE}" | awk '{print $1}' > "${OUTPUT}"

   # Include the update-timestamp
   echo "ts: $(date -u +%s)" >> "${OUTPUT}"

   if [ -n "$(get_signing_directives)" ]; then
      # shellcheck disable=SC2046
      "${OPENSSL}" dgst -sign $(get_signing_directives) -sha256 -out "${SIG_TMP}" "${IMAGE}"
      echo "rsa2048: $(xxd -c 4096 -p < "${SIG_TMP}")" >> "${OUTPUT}"
   fi
   rm "${SIG_TMP}"
}

enforceSecureBootloaderConfig() {
    if ! grep -Fxq "SIGNED_BOOT=1" "${RPI_DEVICE_BOOTLOADER_CONFIG_FILE}"; then
        echo "SIGNED_BOOT=1" >> "${RPI_DEVICE_BOOTLOADER_CONFIG_FILE}"
        sed -i -e "s/SIGNED_BOOT=0//g" "${RPI_DEVICE_BOOTLOADER_CONFIG_FILE}"
    fi

    # These directives are for the bootloader to load the ramdisk
    # Don't use the traditional boot flow, and instead look for boot.img/boot.sig
    echo "boot_ramdisk=1" >> "${RPI_SB_WORKDIR}/config.txt"
    # Log to the UART, so you can inspect the process
    echo "uart_2ndstage=1" >> "${RPI_SB_WORKDIR}/config.txt"
    #echo "eeprom_write_protect=1" >> "${RPI_SB_WORKDIR}/config.txt"
}

identifyBootloaderConfig() {
    # Possible to pass in RPI_DEVICE_BOOTLOADER_CONFIG_FILE... we should make sure the right thing happens with this.
    if [ ! -f "${RPI_DEVICE_BOOTLOADER_CONFIG_FILE}" ]; then
        RPI_DEVICE_BOOTLOADER_CONFIG_FILE="$(mktemp)"
    fi
}

# This function is adapted from the functions in the usbboot repo.
update_eeprom() {
    src_image="$1"
    dst_image="$2"
    pem_file="$3" 
    public_pem_file="$4"
    sign_args=""

    log "update_eeprom() src_image: \"${src_image}\""

    if [ -n "${pem_file}" ]; then
        if ! grep -q "SIGNED_BOOT=1" "${RPI_DEVICE_BOOTLOADER_CONFIG_FILE}"; then
            # If the OTP bit to require secure boot are set then then
            # SIGNED_BOOT=1 is implicitly set in the EEPROM config.
            # For debug in signed-boot mode it's normally useful to set this
            log "Warning: SIGNED_BOOT=1 not found in \"${RPI_DEVICE_BOOTLOADER_CONFIG_FILE}\""
        fi

        #update_version=$(strings "${src_image}" | grep BUILD_TIMESTAMP | sed 's/.*=//g')

        TMP_CONFIG_SIG="$(mktemp)"
        log "Signing bootloader config"
        writeSig "${RPI_DEVICE_BOOTLOADER_CONFIG_FILE}" "${TMP_CONFIG_SIG}"

        # shellcheck disable=SC2086
        cat "${TMP_CONFIG_SIG}" ${DEBUG}

        # rpi-eeprom-config extracts the public key args from the specified
        # PEM file.
        sign_args="-d ${TMP_CONFIG_SIG} -p ${public_pem_file}"

        case ${TARGET_DEVICE_FAMILY} in
            2712)
                customer_signed_bootcode_binary_workdir=$(mktemp -d)
                cd "${customer_signed_bootcode_binary_workdir}" || return
                rpi-eeprom-config -x "${src_image}"
                rpi-sign-bootcode --debug -c 2712 -i bootcode.bin -o bootcode.bin.signed -k "${pem_file}" -v 0 -n 16
                rpi-eeprom-config \
                    --out "${dst_image}.intermediate" --bootcode "${customer_signed_bootcode_binary_workdir}/bootcode.bin.signed" \
                    "${src_image}" || die "Failed to update signed bootcode in the EEPROM image"
                cd - > /dev/null || return
                rm -rf "${customer_signed_bootcode_binary_workdir}"
                ;;
            *)
                # 2711 and earlier do _not_ require a signed bootcode binary
                cp "${src_image}" "${dst_image}.intermediate"
                ;;
        esac
    fi

    rm -f "${dst_image}"
    set -x
    # shellcheck disable=SC2086
    if ! rpi-eeprom-config \
        --config "${RPI_DEVICE_BOOTLOADER_CONFIG_FILE}" \
        --out "${dst_image}" ${sign_args} \
        "${dst_image}.intermediate"; then
        record_state "${TARGET_DEVICE_SERIAL}" "${BOOTSTRAP_ABORTED}" "${TARGET_USB_PATH}"
        die "Failed to update EEPROM image"
    fi
    rm -f "${dst_image}.intermediate"
    rm -f "${TMP_CONFIG_SIG}"
    set +x

cat <<EOF
new-image: ${dst_image}
source-image: ${src_image}
config: ${RPI_DEVICE_BOOTLOADER_CONFIG_FILE}
EOF
}

FIRMWARE_ROOT="/lib/firmware/raspberrypi/bootloader"
FIRMWARE_RELEASE_STATUS="default"

# Taken from rpi-eeprom-update
BOOTLOADER_UPDATE_IMAGE=""
BOOTLOADER_UPDATE_VERSION=0
getBootloaderUpdateVersion() {
   BOOTLOADER_UPDATE_VERSION=0
   match=".*/pieeprom-[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9].bin"
   latest="$(find "${FIRMWARE_IMAGE_DIR}/" -maxdepth 1 -type f -follow -size "${EEPROM_SIZE}c" -regex "${match}" | sort -r | head -n1)"
   if [ -f "${latest}" ]; then
      BOOTLOADER_UPDATE_VERSION=$(strings "${latest}" | grep BUILD_TIMESTAMP | sed 's/.*=//g')
      BOOTLOADER_UPDATE_IMAGE="${latest}"
   fi
}

# These tools are used to modify the supplied images, and deal with mounting and unmounting the images.
check_command_exists losetup
check_command_exists mknod
check_command_exists lsblk
check_command_exists cut
check_command_exists findmnt
check_command_exists grep

DELETE_PRIVATE_TMPDIR=
announce_start "Finding the cache directory"
if [ -z "${RPI_SB_WORKDIR}" ]; then
    RPI_SB_WORKDIR=$(mktemp -d "rpi-sb-bootstrap.XXX" --tmpdir="$TEMP_BASE")
    announce_stop "Finding the cache directory: Created a new one as unspecified"
    DELETE_PRIVATE_TMPDIR="true"
elif [ ! -d "${RPI_SB_WORKDIR}" ]; then
    RPI_SB_WORKDIR=$(mktemp -d "rpi-sb-bootstrap.XXX" --tmpdir="$TEMP_BASE")
    announce_stop "Finding the cache directory: Created a new one in $TEMP_BASE, as supplied path isn't a directory"
    DELETE_PRIVATE_TMPDIR="true"
else
    # Deliberately do nothing
    announce_stop "Finding the cache directory: Using specified name"
fi

# Ensure work directory has proper permissions
chmod 700 "$RPI_SB_WORKDIR"

ALLOW_SIGNED_BOOT=0
case $TARGET_DEVICE_FAMILY in
    2712 | 2711)
        ALLOW_SIGNED_BOOT=1
        ;;
    2710 | 2764)
        ALLOW_SIGNED_BOOT=0
        ;;
    *)
        record_state "${TARGET_DEVICE_SERIAL}" "${BOOTSTRAP_ABORTED}" "${TARGET_USB_PATH}"
        die "Refusing to provision an unknown device family"
        ;;
esac

record_state "${TARGET_DEVICE_SERIAL}" "${BOOTSTRAP_STARTED}" "${TARGET_USB_PATH}"
# Determine if we're enforcing secure boot, and if so, prepare the environment & eeprom accordingly.
if [ "$ALLOW_SIGNED_BOOT" -eq 1 ]; then 
    if [ "${PROVISIONING_STYLE}" = "secure-boot" ]; then
        SECURE_BOOTLOADER_DIRECTORY="${RPI_SB_WORKDIR}/secure-bootloader/"
        mkdir -p "${SECURE_BOOTLOADER_DIRECTORY}"
        if [ -f "${SECURE_BOOTLOADER_DIRECTORY}/config.txt" ]; then
            case ${TARGET_DEVICE_FAMILY} in
                2712)
                    BOOTCODE_BINARY_IMAGE="${SECURE_BOOTLOADER_DIRECTORY}/bootcode5.bin"
                    BOOTCODE_FLASHING_NAME="${SECURE_BOOTLOADER_DIRECTORY}/bootcode5.bin"
                    ;;
                2711)
                    BOOTCODE_BINARY_IMAGE="${SECURE_BOOTLOADER_DIRECTORY}/bootcode4.bin"
                    BOOTCODE_FLASHING_NAME="${SECURE_BOOTLOADER_DIRECTORY}/bootcode4.bin"
                    ;;
            esac
            log "Secure bootloader directory already exists, skipping setup"
            if [ -f "/etc/rpi-sb-provisioner/special-reprovision-device/${TARGET_DEVICE_SERIAL}" ]; then
                # This only makes sense if you're re-provisioning a device that's already been provisioned.
                # It's a special case, and should not be used in normal operation.
                # Additionally, this only works on Raspberry Pi 5-family devices.
                if [ "${TARGET_DEVICE_FAMILY}" = "2712" ]; then
                    if [ ! -f "${CUSTOMER_KEY_FILE_PEM}" ]; then
                        record_state "${TARGET_DEVICE_SERIAL}" "${BOOTSTRAP_ABORTED}" "${TARGET_USB_PATH}"
                        die "No customer key file to use for re-provisioning. Aborting."
                    fi
                    log "Re-signing bootcode for special re-provisioning case"
                    rpi-sign-bootcode --debug -c 2712 -i "${BOOTCODE_BINARY_IMAGE}" -o "${BOOTCODE_FLASHING_NAME}" -k "${CUSTOMER_KEY_FILE_PEM}" -v 0 -n 16
                fi
            fi
            [ ! -f "/etc/rpi-sb-provisioner/special-skip-eeprom/${TARGET_DEVICE_SERIAL}" ] && timeout_fatal rpiboot -d "${SECURE_BOOTLOADER_DIRECTORY}" -p "${TARGET_USB_PATH}"
        else
            log "Creating secure bootloader for future reuse"
            touch "${SECURE_BOOTLOADER_DIRECTORY}/config.txt"

            announce_start "Setting up the environment for a signed-boot capable device"
            if [ -z "${RPI_DEVICE_BOOTLOADER_CONFIG_FILE}" ]; then
                RPI_DEVICE_BOOTLOADER_CONFIG_FILE=/var/lib/rpi-sb-provisioner/bootloader.default
            fi

            SOURCE_EEPROM_IMAGE=
            DESTINATION_EEPROM_IMAGE=
            DESTINATION_EEPROM_SIGNATURE=
            BOOTCODE_BINARY_IMAGE=
            BOOTCODE_FLASHING_NAME=
            case $TARGET_DEVICE_FAMILY in
                2711)
                    BCM_CHIP=2711
                    EEPROM_SIZE=524288
                    FIRMWARE_IMAGE_DIR="${FIRMWARE_ROOT}-${BCM_CHIP}/${FIRMWARE_RELEASE_STATUS}"
                    getBootloaderUpdateVersion
                    SOURCE_EEPROM_IMAGE="${BOOTLOADER_UPDATE_IMAGE}"
                    BOOTCODE_BINARY_IMAGE="${FIRMWARE_IMAGE_DIR}/recovery.bin"
                    BOOTCODE_FLASHING_NAME="${SECURE_BOOTLOADER_DIRECTORY}/bootcode4.bin"
                    ;;
                2712)
                    BCM_CHIP=2712
                    EEPROM_SIZE=2097152
                    FIRMWARE_IMAGE_DIR="${FIRMWARE_ROOT}-${BCM_CHIP}/${FIRMWARE_RELEASE_STATUS}"
                    getBootloaderUpdateVersion
                    SOURCE_EEPROM_IMAGE="${BOOTLOADER_UPDATE_IMAGE}"
                    BOOTCODE_BINARY_IMAGE="${FIRMWARE_IMAGE_DIR}/recovery.bin"
                    BOOTCODE_FLASHING_NAME="${SECURE_BOOTLOADER_DIRECTORY}/bootcode5.bin"
                    ;;
                *)
                    record_state "${TARGET_DEVICE_SERIAL}" "${BOOTSTRAP_ABORTED}" "${TARGET_USB_PATH}"
                    die "Unable to identify EEPROM parameters for non-Pi4, Pi5 device. Aborting."
            esac

            DESTINATION_EEPROM_IMAGE="${SECURE_BOOTLOADER_DIRECTORY}/pieeprom.bin"
            DESTINATION_EEPROM_SIGNATURE="${SECURE_BOOTLOADER_DIRECTORY}/pieeprom.sig"

            ### In the completely-unprovisioned state, where you have not yet written a customer OTP key, simply make the copy of the unsigned bootcode
            cp "${BOOTCODE_BINARY_IMAGE}" "${BOOTCODE_FLASHING_NAME}"
            ####

            if [ -n "${CUSTOMER_KEY_FILE_PEM}" ] || [ -n "${CUSTOMER_KEY_PKCS11_NAME}" ]; then
                derivePublicKey
                identifyBootloaderConfig
                enforceSecureBootloaderConfig

                if [ ! -e "${DESTINATION_EEPROM_SIGNATURE}" ]; then
                    if [ ! -e "${SOURCE_EEPROM_IMAGE}" ]; then
                        record_state "${TARGET_DEVICE_SERIAL}" "${BOOTSTRAP_ABORTED}" "${TARGET_USB_PATH}"
                        die "No Raspberry Pi EEPROM file to use as key vector"
                    else
                        update_eeprom "${SOURCE_EEPROM_IMAGE}" "${DESTINATION_EEPROM_IMAGE}" "${CUSTOMER_KEY_FILE_PEM}" "${CUSTOMER_PUBLIC_KEY_FILE}"
                        writeSig "${DESTINATION_EEPROM_IMAGE}" "${DESTINATION_EEPROM_SIGNATURE}"
                    fi
                fi

                # This directive informs the bootloader to write the public key into OTP
                echo "program_pubkey=1" > "${SECURE_BOOTLOADER_DIRECTORY}/config.txt"
                # This directive tells the bootloader to reboot once it's written the OTP
                echo "recovery_reboot=1" >> "${SECURE_BOOTLOADER_DIRECTORY}/config.txt"

                if [ -n "${RPI_DEVICE_LOCK_JTAG}" ]; then
                    echo "program_jtag_lock=1" >> "${SECURE_BOOTLOADER_DIRECTORY}/config.txt"
                fi

                if [ -n "${RPI_DEVICE_EEPROM_WP_SET}" ]; then
                    echo "eeprom_write_protect=1" >> "${SECURE_BOOTLOADER_DIRECTORY}/config.txt"
                fi

                log "Writing key and EEPROM configuration to the device"
                if [ -f "/etc/rpi-sb-provisioner/special-reprovision-device/${TARGET_DEVICE_SERIAL}" ]; then
                    if [ "${TARGET_DEVICE_FAMILY}" = "2712" ]; then
                        # This only makes sense if you're re-provisioning a device that's already been provisioned.
                        # It's a special case, and should not be used in normal operation.
                        # Additionally, this only works on Raspberry Pi 5-family devices.
                        log "Re-signing bootcode for special re-provisioning case"
                        rpi-sign-bootcode --debug -c 2712 -i "${BOOTCODE_BINARY_IMAGE}" -o "${BOOTCODE_FLASHING_NAME}" -k "${CUSTOMER_KEY_FILE_PEM}" -v 0 -n 16
                    fi
                fi
                [ ! -f "/etc/rpi-sb-provisioner/special-skip-eeprom/${TARGET_DEVICE_SERIAL}" ] && timeout_fatal rpiboot -d "${SECURE_BOOTLOADER_DIRECTORY}" -p "${TARGET_USB_PATH}"
            else
                log "No key specified, skipping eeprom update"
            fi
            log "Keywriting completed. Silently rebooting for next phase."

            case $TARGET_DEVICE_FAMILY in
                2712)
                    FASTBOOT_SIGN_DIR=$(mktemp -d)
                    cd "${FASTBOOT_SIGN_DIR}"
                    tar -vxf /usr/share/rpiboot/mass-storage-gadget64/bootfiles.bin
                    rpi-sign-bootcode --debug -c 2712 -i 2712/bootcode5.bin -o 2712/bootcode5.bin.signed -k "${CUSTOMER_KEY_FILE_PEM}" -v 0 -n 16
                    mv -f "2712/bootcode5.bin.signed" "2712/bootcode5.bin"
                    tar -vcf "${RPI_SB_WORKDIR}/bootfiles.bin" -- *
                    cd -
                    rm -rf "${FASTBOOT_SIGN_DIR}"

                    announce_start "Signing fastboot image"
                    cp "$(get_fastboot_gadget)" "${RPI_SB_WORKDIR}"/boot.img
                    sha256sum "${RPI_SB_WORKDIR}"/boot.img | awk '{print $1}' > "${RPI_SB_WORKDIR}"/boot.sig
                    printf 'rsa2048: ' >> "${RPI_SB_WORKDIR}"/boot.sig
                    # Prefer PKCS11 over PEM keyfiles, if both are specified.
                    # shellcheck disable=SC2046
                    ${OPENSSL} dgst -sign $(get_signing_directives) -sha256 "${RPI_SB_WORKDIR}"/boot.img | xxd -c 4096 -p >> "${RPI_SB_WORKDIR}"/boot.sig
                    cp "$(get_fastboot_config_file)" "${RPI_SB_WORKDIR}"/config.txt
                    announce_stop "Signing fastboot image"
                    ;;
                *)
                    # Raspberry Pi 4-class devices do not use signed bootcode files, so just copy the file into the relevant place.
                    cp /usr/share/rpiboot/mass-storage-gadget64/bootfiles.bin "${RPI_SB_WORKDIR}/bootfiles.bin"
                    ;;
            esac
        fi
    else # !PROVISIONING_STYLE=secure-boot
        NONSECURE_BOOTLOADER_DIRECTORY="${RPI_SB_WORKDIR}/non-secure-bootloader/"
        mkdir -p "${NONSECURE_BOOTLOADER_DIRECTORY}"
        if [ -f "${NONSECURE_BOOTLOADER_DIRECTORY}/config.txt" ]; then
            log "Nonsecure bootloader directory already exists, skipping setup"
        else
            log "Creating nonsecure bootloader for future reuse"
            touch "${NONSECURE_BOOTLOADER_DIRECTORY}/config.txt"
            touch "${NONSECURE_BOOTLOADER_DIRECTORY}/bootcode.bin"
            touch "${NONSECURE_BOOTLOADER_DIRECTORY}/pieeprom.bin"
            touch "${NONSECURE_BOOTLOADER_DIRECTORY}/pieeprom.sig"
            touch "${NONSECURE_BOOTLOADER_DIRECTORY}/bootcode4.bin"
            touch "${NONSECURE_BOOTLOADER_DIRECTORY}/bootcode5.bin"

            announce_start "Setting up the environment for a non-secure-boot capable device"
            if [ -z "${RPI_DEVICE_BOOTLOADER_CONFIG_FILE}" ]; then
                RPI_DEVICE_BOOTLOADER_CONFIG_FILE=/var/lib/rpi-sb-provisioner/bootloader.default
            fi

            SOURCE_EEPROM_IMAGE=
            DESTINATION_EEPROM_IMAGE=
            DESTINATION_EEPROM_SIGNATURE=
            BOOTCODE_BINARY_IMAGE=
            BOOTCODE_FLASHING_NAME=
            case $TARGET_DEVICE_FAMILY in
                2711)
                    BCM_CHIP=2711
                    EEPROM_SIZE=524288
                    FIRMWARE_IMAGE_DIR="${FIRMWARE_ROOT}-${BCM_CHIP}/${FIRMWARE_RELEASE_STATUS}"
                    getBootloaderUpdateVersion
                    SOURCE_EEPROM_IMAGE="${BOOTLOADER_UPDATE_IMAGE}"
                    BOOTCODE_BINARY_IMAGE="${FIRMWARE_IMAGE_DIR}/recovery.bin"
                    BOOTCODE_FLASHING_NAME="${NONSECURE_BOOTLOADER_DIRECTORY}/bootcode4.bin"
                    ;;
                2712)
                    BCM_CHIP=2712
                    EEPROM_SIZE=2097152
                    FIRMWARE_IMAGE_DIR="${FIRMWARE_ROOT}-${BCM_CHIP}/${FIRMWARE_RELEASE_STATUS}"
                    getBootloaderUpdateVersion
                    SOURCE_EEPROM_IMAGE="${BOOTLOADER_UPDATE_IMAGE}"
                    BOOTCODE_BINARY_IMAGE="${FIRMWARE_IMAGE_DIR}/recovery.bin"
                    BOOTCODE_FLASHING_NAME="${NONSECURE_BOOTLOADER_DIRECTORY}/bootcode5.bin"
                    ;;
                *)
                    record_state "${TARGET_DEVICE_SERIAL}" "${BOOTSTRAP_ABORTED}" "${TARGET_USB_PATH}"
                    die "Unable to identify EEPROM parameters for non-Pi4, Pi5 device. Aborting."
            esac

            DESTINATION_EEPROM_IMAGE="${NONSECURE_BOOTLOADER_DIRECTORY}/pieeprom.bin"

            ### In the completely-unprovisioned state, where you have not yet written a customer OTP key, simply make the copy of the unsigned bootcode
            cp "${BOOTCODE_BINARY_IMAGE}" "${BOOTCODE_FLASHING_NAME}"
            ####

            # This directive tells the bootloader to reboot once it's written the OTP
            echo "recovery_reboot=1" >> "${NONSECURE_BOOTLOADER_DIRECTORY}/config.txt"

            if [ -n "${RPI_DEVICE_LOCK_JTAG}" ]; then
                log "JTAG lock requested, but not supported on non-secure-boot devices"
            fi

            if [ -n "${RPI_DEVICE_EEPROM_WP_SET}" ]; then
                log "EEPROM write-protect requested, but not supported on non-secure-boot devices"
            fi

            log "Writing key and EEPROM configuration to the device"
            # shellcheck disable=SC2086
            if ! rpi-eeprom-config \
                --config "${RPI_DEVICE_BOOTLOADER_CONFIG_FILE}" \
                --out "${DESTINATION_EEPROM_IMAGE}" \
                "${SOURCE_EEPROM_IMAGE}"; then
                record_state "${TARGET_DEVICE_SERIAL}" "${BOOTSTRAP_ABORTED}" "${TARGET_USB_PATH}"
                die "Failed to update EEPROM image"
            fi
            [ ! -f "/etc/rpi-sb-provisioner/special-skip-eeprom/${TARGET_DEVICE_SERIAL}" ] && timeout_fatal rpiboot -d "${NONSECURE_BOOTLOADER_DIRECTORY}" -p "${TARGET_USB_PATH}"
        fi
        case ${TARGET_DEVICE_FAMILY} in
            2712|2711)
                cp /usr/share/rpiboot/mass-storage-gadget64/bootfiles.bin "${RPI_SB_WORKDIR}/bootfiles.bin"
                cp "$(get_fastboot_gadget)" "${RPI_SB_WORKDIR}"/boot.img
                cp "$(get_fastboot_config_file)" "${RPI_SB_WORKDIR}"/config.txt
                ;;
            *)
                cp "$(get_fastboot_gadget_2710)" "${RPI_SB_WORKDIR}/bootfiles.bin"
                ;;
        esac
    fi
else # !ALLOW_SIGNED_BOOT
    # No allowed signed boot? Must be pre-Pi4!
    cp "$(get_fastboot_gadget_2710)" "${RPI_SB_WORKDIR}/bootfiles.bin"
fi
record_state "${TARGET_DEVICE_SERIAL}" "bootstrap-firmware-updated" "${TARGET_USB_PATH}"

announce_start "fastboot initialisation"
record_state "${TARGET_DEVICE_SERIAL}" "bootstrap-fastboot-initialisation-started" "${TARGET_USB_PATH}"

timeout_fatal rpiboot -v -d "${RPI_SB_WORKDIR}" -p "${TARGET_USB_PATH}"
set +e

if [ -n "${TARGET_DEVICE_SERIAL}" ]; then
    target_log_dir="/var/log/rpi-sb-provisioner/${TARGET_DEVICE_SERIAL}"
    early_log_dir="${EARLY_LOG_DIRECTORY}"
    
    mkdir -p "${target_log_dir}"
    if [ -d "${early_log_dir}/metadata" ]; then
        mv "${early_log_dir}/metadata" "${target_log_dir}/metadata"
    fi
    mv "${early_log_dir}/bootstrap.log" "${target_log_dir}/bootstrap.log"
fi

announce_stop "fastboot initialisation"
record_state "${TARGET_DEVICE_SERIAL}" "${BOOTSTRAP_FINISHED}" "${TARGET_USB_PATH}"
set -e

# Exit with success code for systemd
true
cleanup
