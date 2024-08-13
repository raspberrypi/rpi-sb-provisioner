#!/bin/sh

set -x

. /usr/local/bin/terminal-functions.sh

read_config

TARGET_DEVICE_SERIAL="$1"

die() {
   echo "$@" ${DEBUG}
   exit 1
}

TMP_DIR=""
cleanup() {
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

   if [ -n "${CUSTOMER_KEY_FILE_PEM}" ]; then
      [ -f "${CUSTOMER_KEY_FILE_PEM}" ] || die "RSA private key \"${CUSTOMER_KEY_FILE_PEM}\" not found"
      "${OPENSSL}" dgst -sign "${CUSTOMER_KEY_FILE_PEM}" -keyform PEM -sha256 -out "${SIG_TMP}" "${IMAGE}"
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
        echo "Signing bootloader config" ${DEBUG}
        writeSig "${RPI_DEVICE_BOOTLOADER_CONFIG_FILE}" "${TMP_CONFIG_SIG}"

        cat "${TMP_CONFIG_SIG}" ${DEBUG}

        # rpi-eeprom-config extracts the public key args from the specified
        # PEM file.
        sign_args="-d ${TMP_CONFIG_SIG} -p ${public_pem_file}"

        case ${RPI_DEVICE_FAMILY} in
            4)
                # 2711 does _not_ require a signed bootcode binary
                cp "${src_image}" "${dst_image}.intermediate"
                ;;
            # 5)
            #     customer_signed_bootcode_binary_workdir=$(mktemp -d)
            #     cd "${customer_signed_bootcode_binary_workdir}" || return
            #     rpi-eeprom-config -x "${src_image}"
            #     rpi-sign-bootcode --debug -c 2712 -i bootcode.bin -o bootcode.bin.signed -k "${pem_file}" -v 0 -n 16
            #     rpi-eeprom-config \
            #         --out "${dst_image}.intermediate" --bootcode "${customer_signed_bootcode_binary_workdir}/bootcode.bin.signed" \
            #         "${src_image}" || die "Failed to update signed bootcode in the EEPROM image"
            #     cd - || return
            #     rm -rf "${customer_signed_bootcode_binary_workdir}"
            #     ;;
        esac
    fi

    rm -f "${dst_image}"
    set -x
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
        SOURCE_EEPROM_IMAGE="/lib/firmware/raspberrypi/bootloader-2711/latest/pieeprom-2024-05-17.bin"
        BOOTCODE_BINARY_IMAGE="/lib/firmware/raspberrypi/bootloader-2711/latest/recovery.bin"
        BOOTCODE_FLASHING_NAME="${FLASHING_DIR}/bootcode4.bin"
        ;;
    # 5)
    #     SOURCE_EEPROM_IMAGE="/lib/firmware/raspberrypi/bootloader-2712/latest/pieeprom-2024-05-17.bin"
    #     BOOTCODE_BINARY_IMAGE="/lib/firmware/raspberrypi/bootloader-2712/latest/recovery.bin"
    #     BOOTCODE_FLASHING_NAME="${FLASHING_DIR}/bootcode5.bin"
    #     ;;
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

if [ -n "${RPI_DEVICE_JTAG_LOCK}" ]; then
echo "program_jtag_lock=1" >> "${FLASHING_DIR}/config.txt"
fi

if [ -n "${RPI_DEVICE_EEPROM_WP_SET}" ]; then
echo "eeprom_write_protect=1" >> "${FLASHING_DIR}/config.txt"
fi

# With the EEPROMs configured and signed, RPIBoot them.
[ -z "${DEMO_MODE_ONLY}" ] && rpiboot -d "${FLASHING_DIR}" -i "${TARGET_DEVICE_SERIAL}"

touch "${DEVICE_SERIAL_STORE}/${TARGET_DEVICE_SERIAL}"

echo "Keywriting completed. Rebooting for next phase."
