#!/bin/sh

set -e
set -x

DEBUG=

OPENSSL=${OPENSSL:-openssl}

export BOOTSTRAP_FINISHED="BOOTSTRAP-FINISHED"
export BOOTSTRAP_ABORTED="BOOTSTRAP-ABORTED"
export BOOTSTRAP_STARTED="BOOTSTRAP-STARTED"

HOLDING_LOCKFILE=0

announce_start() {
    bootstrap_log "================================================================================"

    bootstrap_log "Starting $1"

    bootstrap_log "================================================================================"
}

announce_stop() {
    bootstrap_log "================================================================================"

    bootstrap_log "Stopping $1"

    bootstrap_log "================================================================================"
}

bootstrap_log() {
    echo "$@" >> "${EARLY_LOG_DIRECTORY}"/bootstrap.log
    printf "%s\n" "$@"
}

cleanup() {
    returnvalue=$?
    if [ ${HOLDING_LOCKFILE} -eq 1 ]; then
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

        announce_start "Deleting bootstrap lock"
        rm -f "/etc/udev/rules.d/99-rpi-sb-bootstrap-${TARGET_DEVICE_SERIAL}.rules"
        udevadm control --reload-rules
        announce_stop "Deleting bootstrap lock"
    fi
    exit $returnvalue
}
trap cleanup EXIT

# On pre-Pi4 devices, only TARGET_DEVICE_PATH is likely to be unique.
TARGET_DEVICE_PATH="$1"
TARGET_USB_PATH="$(udevadm info "${TARGET_DEVICE_PATH}" | grep -oP '^M: \K.*')"
TARGET_DEVICE_FAMILY="$(udevadm info --name="$TARGET_DEVICE_PATH" --query=property --property=ID_MODEL_ID --value)"
# TARGET_DEVICE_SERIAL is best-effort, not all rpiboot devices have it set (some only show 32-bits)
TARGET_DEVICE_SERIAL="$(udevadm info --name="$TARGET_DEVICE_PATH" --query=property --property=ID_SERIAL_SHORT --value)"

EARLY_LOG_DIRECTORY="/var/log/rpi-sb-provisioner/early/${TARGET_DEVICE_PATH}"
mkdir -p "${EARLY_LOG_DIRECTORY}"

die() {
    echo "${BOOTSTRAP_ABORTED}" >> "${EARLY_LOG_DIRECTORY}"/bootstrap.log
    # shellcheck disable=SC2086
    echo "$@" ${DEBUG}
    exit 1
}

read_config() {
    if [ -f /etc/rpi-sb-provisioner/config ]; then
        . /etc/rpi-sb-provisioner/config
    else
        die "%s\n" "Failed to load config. Please use configuration tool."
    fi
}

read_config

if [ ! -f "/etc/udev/rules.d/99-rpi-sb-bootstrap-${TARGET_DEVICE_SERIAL}.rules" ]; then
    echo "ACTION==\"*\", ATTRS{idSerial}==\"${TARGET_DEVICE_SERIAL}\", GOTO=\"end\"" > "/etc/udev/rules.d/99-rpi-sb-bootstrap-${TARGET_DEVICE_SERIAL}.rules"
    echo "LABEL=\"end\"" >> "/etc/udev/rules.d/99-rpi-sb-bootstrap-${TARGET_DEVICE_SERIAL}.rules"
    udevadm control --reload-rules
    HOLDING_LOCKFILE=1
else
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

# check_file_is_expected ${path_to_file} ${expected_file_extension}
# Checks if a file exists, is not a directory, is not zero and has the right extension.
# If any of those checks fail, exit the script entirely and print a debug message
# If all checks succeed, supply the filepath via stdout
check_file_is_expected() {
    filepath="$1"
    ext="$2"

    if [ ! -e "${filepath}" ]; then
        die "Specified file does not exist: ${filepath}"
    fi

    if [ -d "${filepath}" ]; then
        die "Expected a file, got a directory for ${filepath}"
    fi

    if [ -z "${filepath}" ]; then
        die "Provided file is empty: ${filepath}"
    fi

    if [ -z "${ext}" ] || echo "${filepath}" | grep -q "${ext}"; then
        echo "${filepath}"
        return 0
    else
        die "Provided file is of the wrong extension, wanted ${ext}, provided ${filepath}"
    fi
}

check_command_exists() {
    command_to_test=$1
    if ! command -v "${command_to_test}" 1> /dev/null; then
        bootstrap_log "${command_to_test} could not be found"
        exit 1
    else
        echo "$command_to_test"
    fi
}

# TODO: Refactor these two functions to use the same logic, but with different consequences for failure.
timeout_nonfatal() {
    command="$*"
    set +e
    timeout 10 ${command}
    command_exit_status=$?
    if [ ${command_exit_status} -eq 124 ]; then
        bootstrap_log "\"${command}\" failed, timed out."
    elif [ ${command_exit_status} -ne 0 ]; then
        bootstrap_log "\"${command}\" failed, exit status: ${command_exit_status}"
    else
        bootstrap_log "\"$command\" succeeded."
    fi
    set -e
    return ${command_exit_status}
}

timeout_fatal() {
    command="$*"
    set +e
    timeout 120 ${command}
    command_exit_status=$?
    if [ ${command_exit_status} -eq 124 ]; then
        echo "${PROVISIONER_ABORTED}" >> /var/log/rpi-sb-provisioner/"${TARGET_DEVICE_SERIAL}"/progress
        die "\"${command}\" failed, timed out."
    elif [ ${command_exit_status} -ne 0 ]; then
        echo "${PROVISIONER_ABORTED}" >> /var/log/rpi-sb-provisioner/"${TARGET_DEVICE_SERIAL}"/progress
        die "\"$command\" failed, exit status: ${command_exit_status}"
    else
        bootstrap_log "\"$command\" succeeded."
    fi
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
                die "RSA private key \"${CUSTOMER_KEY_FILE_PEM}\" not a file. Aborting."
            fi
        else
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

    bootstrap_log "update_eeprom() src_image: \"${src_image}\""

    if [ -n "${pem_file}" ]; then
        if ! grep -q "SIGNED_BOOT=1" "${RPI_DEVICE_BOOTLOADER_CONFIG_FILE}"; then
            # If the OTP bit to require secure boot are set then then
            # SIGNED_BOOT=1 is implicitly set in the EEPROM config.
            # For debug in signed-boot mode it's normally useful to set this
            bootstrap_log "Warning: SIGNED_BOOT=1 not found in \"${RPI_DEVICE_BOOTLOADER_CONFIG_FILE}\""
        fi

        #update_version=$(strings "${src_image}" | grep BUILD_TIMESTAMP | sed 's/.*=//g')

        TMP_CONFIG_SIG="$(mktemp)"
        bootstrap_log "Signing bootloader config"
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
    rpi-eeprom-config \
        --config "${RPI_DEVICE_BOOTLOADER_CONFIG_FILE}" \
        --out "${dst_image}" ${sign_args} \
        "${dst_image}.intermediate" || die "Failed to update EEPROM image"
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

get_variable() {
    fastboot getvar "$1" 2>&1 | grep -oP "${1}"': \K[^\r\n]*'
}

DELETE_PRIVATE_TMPDIR=
announce_start "Finding the cache directory"
if [ -z "${RPI_SB_WORKDIR}" ]; then
    RPI_SB_WORKDIR=$(mktemp -d "rpi-sb-bootstrap.XXX" --tmpdir="/srv/")
    announce_stop "Finding the cache directory: Created a new one as unspecified"
    DELETE_PRIVATE_TMPDIR="true"
elif [ ! -d "${RPI_SB_WORKDIR}" ]; then
    RPI_SB_WORKDIR=$(mktemp -d "rpi-sb-bootstrap.XXX" --tmpdir="/srv/")
    announce_stop "Finding the cache directory: Created a new one in /srv, as supplied path isn't a directory"
    DELETE_PRIVATE_TMPDIR="true"
else
    # Deliberately do nothing
    announce_stop "Finding the cache directory: Using specified name"
fi

ALLOW_SIGNED_BOOT=0
case $TARGET_DEVICE_FAMILY in
    2712 | 2711)
        ALLOW_SIGNED_BOOT=1
        ;;
    2710 | 2764)
        ALLOW_SIGNED_BOOT=0
        ;;
    *)
        die "Refusing to provision an unknown device family"
        ;;
esac


# Determine if we're enforcing secure boot, and if so, prepare the environment & eeprom accordingly.
if [ "$ALLOW_SIGNED_BOOT" -eq 1 ]; then 
    if [ "${PROVISIONING_STYLE}" = "secure-boot" ]; then
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
                BOOTCODE_FLASHING_NAME="${RPI_SB_WORKDIR}/bootcode4.bin"
                ;;
            2712)
                BCM_CHIP=2712
                EEPROM_SIZE=2097152
                FIRMWARE_IMAGE_DIR="${FIRMWARE_ROOT}-${BCM_CHIP}/${FIRMWARE_RELEASE_STATUS}"
                getBootloaderUpdateVersion
                SOURCE_EEPROM_IMAGE="${BOOTLOADER_UPDATE_IMAGE}"
                BOOTCODE_BINARY_IMAGE="${FIRMWARE_IMAGE_DIR}/recovery.bin"
                BOOTCODE_FLASHING_NAME="${RPI_SB_WORKDIR}/bootcode5.bin"
                ;;
            *)
                die "Unable to identify EEPROM parameters for non-Pi4, Pi5 device. Aborting."
        esac

        DESTINATION_EEPROM_IMAGE="${RPI_SB_WORKDIR}/pieeprom.bin"
        DESTINATION_EEPROM_SIGNATURE="${RPI_SB_WORKDIR}/pieeprom.sig"

        ### In the completely-unprovisioned state, where you have not yet written a customer OTP key, simply make the copy of the unsigned bootcode
        cp "${BOOTCODE_BINARY_IMAGE}" "${BOOTCODE_FLASHING_NAME}"
        ####

        if [ -n "${CUSTOMER_KEY_FILE_PEM}" ] || [ -n "${CUSTOMER_KEY_PKCS11_NAME}" ]; then
            derivePublicKey
            identifyBootloaderConfig
            enforceSecureBootloaderConfig

            if [ ! -e "${DESTINATION_EEPROM_SIGNATURE}" ]; then
                if [ ! -e "${SOURCE_EEPROM_IMAGE}" ]; then
                    die "No Raspberry Pi EEPROM file to use as key vector"
                else
                    update_eeprom "${SOURCE_EEPROM_IMAGE}" "${DESTINATION_EEPROM_IMAGE}" "${CUSTOMER_KEY_FILE_PEM}" "${CUSTOMER_PUBLIC_KEY_FILE}"
                    writeSig "${DESTINATION_EEPROM_IMAGE}" "${DESTINATION_EEPROM_SIGNATURE}"
                fi
            fi

            # This directive informs the bootloader to write the public key into OTP
            echo "program_pubkey=1" > "${RPI_SB_WORKDIR}/config.txt"
            # This directive tells the bootloader to reboot once it's written the OTP
            echo "recovery_reboot=1" >> "${RPI_SB_WORKDIR}/config.txt"

            if [ -n "${RPI_DEVICE_FETCH_METADATA}" ]; then
                echo "recovery_metadata=1" >> "${RPI_SB_WORKDIR}/config.txt"
            fi

            if [ -n "${RPI_DEVICE_JTAG_LOCK}" ]; then
                echo "program_jtag_lock=1" >> "${RPI_SB_WORKDIR}/config.txt"
            fi

            if [ -n "${RPI_DEVICE_EEPROM_WP_SET}" ]; then
                echo "eeprom_write_protect=1" >> "${RPI_SB_WORKDIR}/config.txt"
            fi

            bootstrap_log "Writing key and EEPROM configuration to the device"
            [ ! -f "/var/log/rpi-sb-provisioner/${TARGET_DEVICE_SERIAL}/special-skip-keywriter" ] && timeout_fatal rpiboot -d "${RPI_SB_WORKDIR}" -p "${TARGET_USB_PATH}" -j "${EARLY_LOG_DIRECTORY}/metadata/"
        else
            bootstrap_log "No key specified, skipping eeprom update"
        fi
        bootstrap_log "Keywriting completed. Rebooting for next phase."
        # Clear signing intermediates
        rm -rf "${RPI_SB_WORKDIR:?}/*"

        case "${TARGET_DEVICE_FAMILY}" in
            2712)
                FASTBOOT_SIGN_DIR=$(mktemp -d)
                cd "${FASTBOOT_SIGN_DIR}"
                tar -vxf /usr/share/rpiboot/mass-storage-gadget64/bootfiles.bin
                rpi-sign-bootcode --debug -c 2712 -i 2712/bootcode5.bin -o 2712/bootcode5.bin.signed -k "${CUSTOMER_KEY_FILE_PEM}" -v 0 -n 16
                mv -f "2712/bootcode5.bin.signed" "2712/bootcode5.bin"
                tar -vcf "${RPI_SB_WORKDIR}/bootfiles.bin" -- *
                cd -
                rm -rf "${FASTBOOT_SIGN_DIR}"
                ;;
            *)
                # Raspberry Pi 4-class devices do not use signed bootcode files, so just copy the file into the relevant place.
                cp /usr/share/rpiboot/mass-storage-gadget64/bootfiles.bin "${RPI_SB_WORKDIR}/bootfiles.bin"
                ;;
        esac
    else # !PROVISIONING_STYLE=secure-boot
        case ${TARGET_DEVICE_FAMILY} in
            2712|2711)
                cp /usr/share/rpiboot/mass-storage-gadget64/bootfiles.bin "${RPI_SB_WORKDIR}/bootfiles.bin"
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

announce_start "Staging fastboot image"

if [ "$ALLOW_SIGNED_BOOT" -eq 1 ] && [ "${PROVISIONING_STYLE}" = "secure-boot" ]; then
    announce_start "Signing fastboot image"
    cp "$(get_fastboot_gadget)" "${RPI_SB_WORKDIR}"/boot.img
    sha256sum "${RPI_SB_WORKDIR}"/boot.img | awk '{print $1}' > "${RPI_SB_WORKDIR}"/boot.sig
    printf 'rsa2048: ' >> "${RPI_SB_WORKDIR}"/boot.sig
    # Prefer PKCS11 over PEM keyfiles, if both are specified.
    # shellcheck disable=SC2046
    ${OPENSSL} dgst -sign $(get_signing_directives) -sha256 "${RPI_SB_WORKDIR}"/boot.img | xxd -c 4096 -p >> "${RPI_SB_WORKDIR}"/boot.sig
    cp "$(get_fastboot_config_file)" "${RPI_SB_WORKDIR}"/config.txt
    announce_stop "Signing fastboot image"
else # !secure-boot
    set -x
    case ${TARGET_DEVICE_FAMILY} in
        2712|2711)
            cp "$(get_fastboot_gadget)" "${RPI_SB_WORKDIR}"/boot.img
            cp "$(get_fastboot_config_file)" "${RPI_SB_WORKDIR}"/config.txt
            ;;
        *)
            cp "$(get_fastboot_gadget_2710)" "${RPI_SB_WORKDIR}/bootfiles.bin"
            ;;
    esac
    set +x
fi
announce_stop "Staging fastboot image"

announce_start "fastboot initialisation"

timeout_fatal rpiboot -v -d "${RPI_SB_WORKDIR}" -p "${TARGET_USB_PATH}"
set +e
if [ -n "${TARGET_DEVICE_SERIAL}" ]; then
    mkdir -p "/var/log/rpi-sb-provisioner/${TARGET_DEVICE_SERIAL}"
    [ -d "${EARLY_LOG_DIRECTORY}/metadata" ] && mv "${EARLY_LOG_DIRECTORY}/metadata" "/var/log/rpi-sb-provisioner/${TARGET_DEVICE_SERIAL}/metadata"
    mv "${EARLY_LOG_DIRECTORY}/bootstrap.log" "/var/log/rpi-sb-provisioner/${TARGET_DEVICE_SERIAL}/bootstrap.log"
fi
announce_stop "fastboot initialisation"
set -e