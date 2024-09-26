#!/bin/sh

set -x

. /usr/local/bin/terminal-functions.sh

TARGET_DEVICE_SERIAL="$1"

echo "${KEYWRITER_STARTED}" >> /var/log/rpi-sb-provisioner/"${TARGET_DEVICE_SERIAL}"/progress

read_config

die() {
   # shellcheck disable=SC2086
   echo "$@" ${DEBUG}
   exit 1
}

TMP_DIR=""
cleanup() {
    mkdir -p /var/log/rpi-sb-provisioner/"${TARGET_DEVICE_SERIAL}"/
    echo "${KEYWRITER_EXITED}" >> /var/log/rpi-sb-provisioner/"${TARGET_DEVICE_SERIAL}"/progress
   if [ -d "${TMP_DIR}" ]; then
      rm -rf "${TMP_DIR}"
   fi
   rm "${CUSTOMER_PUBLIC_KEY_FILE}"
}
trap cleanup EXIT

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
    echo "boot_ramdisk=1" >> "${FLASHING_DIR}/config.txt"
    # Log to the UART, so you can inspect the process
    echo "uart_2ndstage=1" >> "${FLASHING_DIR}/config.txt"
    #echo "eeprom_write_protect=1" >> "${FLASHING_DIR}/config.txt"
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

    if [ -n "${pem_file}" ]; then
        if ! grep -q "SIGNED_BOOT=1" "${RPI_DEVICE_BOOTLOADER_CONFIG_FILE}"; then
            # If the OTP bit to require secure boot are set then then
            # SIGNED_BOOT=1 is implicitly set in the EEPROM config.
            # For debug in signed-boot mode it's normally useful to set this
            echo "Warning: SIGNED_BOOT=1 not found in \"${RPI_DEVICE_BOOTLOADER_CONFIG_FILE}\""
        fi

        #update_version=$(strings "${src_image}" | grep BUILD_TIMESTAMP | sed 's/.*=//g')

        TMP_CONFIG_SIG="$(mktemp)"
        echo "Signing bootloader config"
        writeSig "${RPI_DEVICE_BOOTLOADER_CONFIG_FILE}" "${TMP_CONFIG_SIG}"

        # shellcheck disable=SC2086
        cat "${TMP_CONFIG_SIG}" ${DEBUG}

        # rpi-eeprom-config extracts the public key args from the specified
        # PEM file.
        sign_args="-d ${TMP_CONFIG_SIG} -p ${public_pem_file}"

        case ${RPI_DEVICE_FAMILY} in
            4)
                # 2711 does _not_ require a signed bootcode binary
                cp "${src_image}" "${dst_image}.intermediate"
                ;;
            5)
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
    set +x

cat <<EOF
new-image: ${dst_image}
source-image: ${src_image}
config: ${RPI_DEVICE_BOOTLOADER_CONFIG_FILE}
EOF
}

OPTSTRING="c:vh:"
while getopts ${OPTSTRING} opt; do
    case ${opt} in
        c)
            # Override config path
            . "$(check_file_is_expected_fatal "${OPTARG}" "")"
            ;;
        v)
            DEBUG="2>&1 | tee /var/log/rpi-sb-provisioner/${OPTARG}.log"
            ;;
        h)
            RPI_DEVICE_FAMILY=$(check_pidevice_generation "${OPTARG}")
            ;;
        :)
            die "Option -${OPTARG} requires an argument"
            ;;
        ?)
            die "Unexpected option -${OPTARG}"
            ;;
    esac
done

FLASHING_DIR=$(mktemp -d)
derivePublicKey
identifyBootloaderConfig
enforceSecureBootloaderConfig

SOURCE_EEPROM_IMAGE=
DESTINATION_EEPROM_IMAGE=
DESTINATION_EEPROM_SIGNATURE=
BOOTCODE_BINARY_IMAGE=
BOOTCODE_FLASHING_NAME=
case ${RPI_DEVICE_FAMILY} in
    4)
        SOURCE_EEPROM_IMAGE="/lib/firmware/raspberrypi/bootloader-2711/latest/pieeprom-2024-09-05.bin"
        BOOTCODE_BINARY_IMAGE="/lib/firmware/raspberrypi/bootloader-2711/latest/recovery.bin"
        BOOTCODE_FLASHING_NAME="${FLASHING_DIR}/bootcode4.bin"
        ;;
    5)
        SOURCE_EEPROM_IMAGE="/lib/firmware/raspberrypi/bootloader-2712/latest/pieeprom-2024-09-23.bin"
        BOOTCODE_BINARY_IMAGE="/lib/firmware/raspberrypi/bootloader-2712/latest/recovery.bin"
        BOOTCODE_FLASHING_NAME="${FLASHING_DIR}/bootcode5.bin"
        ;;
    *)
        die "Unable to identify Raspberry Pi HW Family. Aborting key writing."
esac

DESTINATION_EEPROM_IMAGE="${FLASHING_DIR}/pieeprom.bin"
DESTINATION_EEPROM_SIGNATURE="${FLASHING_DIR}/pieeprom.sig"

if [ ! -e "${DESTINATION_EEPROM_SIGNATURE}" ]; then
    if [ ! -e "${SOURCE_EEPROM_IMAGE}" ]; then
        die "No Raspberry Pi EEPROM file to use as key vector"
    else
        update_eeprom "${SOURCE_EEPROM_IMAGE}" "${DESTINATION_EEPROM_IMAGE}" "${CUSTOMER_KEY_FILE_PEM}" "${CUSTOMER_PUBLIC_KEY_FILE}"
        writeSig "${DESTINATION_EEPROM_IMAGE}" "${DESTINATION_EEPROM_SIGNATURE}"
    fi
fi

### NOTE: Use this in only case of a partial signing situation, where you have provisioned the key, but need to re-write the eeprom.
# case ${RPI_DEVICE_FAMILY} in
#     4)
#         cp "${BOOTCODE_BINARY_IMAGE}" "${BOOTCODE_FLASHING_NAME}"
#         ;;
#     5)
#         rpi-sign-bootcode --debug -c 2712 -i "${BOOTCODE_BINARY_IMAGE}" -o "${BOOTCODE_FLASHING_NAME}" -k "${CUSTOMER_KEY_FILE_PEM}" -v 0 -n 16
#         ;;
# esac
### In the completely-unprovisioned state, where you have not yet written a customer OTP key, simply make the copy of the unsigned bootcode
cp "${BOOTCODE_BINARY_IMAGE}" "${BOOTCODE_FLASHING_NAME}"
####

# This directive informs the bootloader to write the public key into OTP
echo "program_pubkey=1" > "${FLASHING_DIR}/config.txt"
# This directive tells the bootloader to reboot once it's written the OTP
echo "recovery_reboot=1" >> "${FLASHING_DIR}/config.txt"

if [ -n "${RPI_DEVICE_FETCH_METADATA}" ]; then
echo "recovery_metadata=1" >> "${FLASHING_DIR}/config.txt"
fi

if [ -n "${RPI_DEVICE_JTAG_LOCK}" ]; then
echo "program_jtag_lock=1" >> "${FLASHING_DIR}/config.txt"
fi

if [ -n "${RPI_DEVICE_EEPROM_WP_SET}" ]; then
echo "eeprom_write_protect=1" >> "${FLASHING_DIR}/config.txt"
fi

# With the EEPROMs configured and signed, RPIBoot them.
mkdir -p "/var/log/rpi-sb-provisioner/${TARGET_DEVICE_SERIAL}/metadata/"
[ -z "${DEMO_MODE_ONLY}" ] && rpiboot -d "${FLASHING_DIR}" -i "${TARGET_DEVICE_SERIAL}" -j "/var/log/rpi-sb-provisioner/${TARGET_DEVICE_SERIAL}/metadata/"

touch "${RPI_DEVICE_SERIAL_STORE}/${TARGET_DEVICE_SERIAL}"

if [ -z "${DEMO_MODE_ONLY}" ] && [ -n "${RPI_DEVICE_FETCH_METADATA}" ]; then
    USER_BOARDREV="0x$(jq -r '.USER_BOARDREV' < /var/log/rpi-sb-provisioner/"${TARGET_DEVICE_SERIAL}"/metadata/"${TARGET_DEVICE_SERIAL}".json)"
    MAC_ADDRESS=$(jq -r '.MAC_ADDR' < /var/log/rpi-sb-provisioner/"${TARGET_DEVICE_SERIAL}"/metadata/"${TARGET_DEVICE_SERIAL}".json)

    TYPE=$(printf "0x%X\n" $(((USER_BOARDREV & 0xFF0) >> 4)))
    PROCESSOR=$(printf "0x%X\n" $(((USER_BOARDREV & 0xF000) >> 12)))
    MEMORY=$(printf "0x%X\n" $(((USER_BOARDREV & 0x700000) >> 20)))
    MANUFACTURER=$(printf "0x%X\n" $(((USER_BOARDREV & 0xF0000) >> 16)))
    REVISION=$((USER_BOARDREV & 0xF))

    case ${TYPE} in
        "0x11") BOARD_STR="CM4" ;;
        "0x12") BOARD_STR="Zero 2 W" ;;
        "0x13") BOARD_STR="400" ;;
        "0x14") BOARD_STR="CM4" ;;
        "0x15") BOARD_STR="CM4S" ;;
        "0x17") BOARD_STR="5" ;;
        *)
            BOARD_STR="Unsupported Board"
    esac

    case ${PROCESSOR} in
        "0x0") PROCESSOR_STR="BCM2835" ;;
        "0x1") PROCESSOR_STR="BCM2836" ;;
        "0x2") PROCESSOR_STR="BCM2837" ;;
        "0x3") PROCESSOR_STR="BCM2711" ;;
        "0x4") PROCESSOR_STR="BCM2712" ;;
        *)
            PROCESSOR_STR="Unknown"
    esac

    case ${MEMORY} in
        "0x0") MEMORY_STR="256MB" ;;
        "0x1") MEMORY_STR="512MB" ;;
        "0x2") MEMORY_STR="1GB" ;;
        "0x3") MEMORY_STR="2GB" ;;
        "0x4") MEMORY_STR="4GB" ;;
        "0x5") MEMORY_STR="8GB" ;;
        *)
            MEMORY_STR="Unknown"
    esac

    case ${MANUFACTURER} in
        "0x0") MANUFACTURER_STR="Sony UK" ;;
        "0x1") MANUFACTURER_STR="Egoman" ;;
        "0x2") MANUFACTURER_STR="Embest" ;;
        "0x3") MANUFACTURER_STR="Sony Japan" ;;
        "0x4") MANUFACTURER_STR="Embest" ;;
        "0x5") MANUFACTURER_STR="Stadium" ;;
        *)
            MANUFACTURER_STR="Unknown"
    esac

    echo "Board is: ${BOARD_STR}, with revision number ${REVISION}. Has Processor ${PROCESSOR_STR} with Memory ${MEMORY_STR}. Was manufactured by ${MANUFACTURER_STR}"
fi
echo "Keywriting completed. Rebooting for next phase."

mkdir -p /var/log/rpi-sb-provisioner/"${TARGET_DEVICE_SERIAL}"/
echo "${KEYWRITER_FINISHED}" >> /var/log/rpi-sb-provisioner/"${TARGET_DEVICE_SERIAL}"/progress
