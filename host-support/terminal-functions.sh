#!/bin/sh

OPENSSL=${OPENSSL:-openssl}

CUSTOMER_PUBLIC_KEY_FILE=
derivePublicKey() {
    CUSTOMER_PUBLIC_KEY_FILE="$(mktemp)"
    "${OPENSSL}" rsa -in "${CUSTOMER_KEY_FILE_PEM}" -pubout > "${CUSTOMER_PUBLIC_KEY_FILE}"
}

ring_bell() {
    tput bel
}

announce_start() {
    echo "================================================================================"

    printf '\n\t%s\n' "Starting $1"

    echo "================================================================================"
}

announce_stop() {
    echo "================================================================================"

    printf '\n\t%s\n' "Stopping $1"

    echo "================================================================================"
}

# check_file_is_expected ${path_to_file} ${expected_file_extension}
# Checks if a file exists, is not a directory, is not zero and has the right extension.
# If any of those checks fail, exit the script entirely and print a debug message
# If all checks succeed, supply the filepath via stdout
check_file_is_expected() {
    filepath="$1"
    ext="$2"

    if [ ! -e "${filepath}" ]; then
        echo "Specified file does not exist: ${filepath}" >&2
        return 1
    fi

    if [ -d "${filepath}" ]; then
        echo "Expected a file, got a directory for ${filepath}" >&2
        return 1
    fi

    if [ -z "${filepath}" ]; then
        echo "Provided file is empty: ${filepath}" >&2
        return 1
    fi

    ## RHS of == is a shell pattern, believe this is a bashism
    if [ -z "${ext}" ] || [[ ${filepath} == *.${ext} ]]; then
        echo "${filepath}"
        return 0
    else
        echo "Provided file is of the wrong extension, wanted ${ext}, provided ${filepath}" >&2
        return 1
    fi
}

check_file_is_expected_fatal() {
    if ! check_file_is_expected "$1" "$2"; then
        exit 1
    fi
}

check_command_exists() {
    command_to_test=$1
    if ! command -v "${command_to_test}" 1> /dev/null; then
        echo "${command_to_test} could not be found" >&2
        exit 1
    else
        echo "$command_to_test"
    fi
}

check_python_module_exists() {
    module_name=$1
    if ! python -c "import ${module_name}" 1> /dev/null; then
        echo "Failed to load Python module '${module_name}'" >&2
        exit 1
    else
        echo "${module_name}"
    fi
}

check_pidevice_generation() {
    case "$1" in
        4)
            echo "$1"
            ;;
        ?)
            echo "Unexpected Raspberry Pi Generation. Wanted 4, got $1" >&2
            exit 1
            ;;
    esac
}

read_config() {
    if [ -f /etc/rpi-sb-provisioner/config ]; then
        . /etc/rpi-sb-provisioner/config
    else
        echo "Failed to load config. Please use configuration tool." >&2
        exit 1
    fi
}

get_cryptroot() {
    if [ -f /etc/rpi-sb-provisioner/cryptroot_initramfs ]; then
        echo "/etc/rpi-sb-provisioner/cryptroot_initramfs"
    else
        echo "/var/lib/rpi-sb-provisioner/cryptroot_initramfs"
    fi
}

get_fastboot_gadget() {
    if [ -f /etc/rpi-sb-provisioner/fastboot-gadget.img ]; then
        echo "/etc/rpi-sb-provisioner/fastboot-gadget.img"
    else
        echo "/var/lib/rpi-sb-provisioner/fastboot-gadget.img"
    fi
}

get_fastboot_config_file() {
    if [ -f /etc/rpi-sb-provisioner/boot_ramdisk_config.txt ]; then
        echo "/etc/rpi-sb-provisioner/boot_ramdisk_config.txt"
    else
        echo "/var/lib/rpi-sb-provisioner/boot_ramdisk_config.txt"
    fi
}

get_internal_config_file() {
    if [ -f /etc/rpi-sb-provisioner/ramdisk_internal_config.txt ]; then
        echo "/etc/rpi-sb-provisioner/ramdisk_internal_config.txt"
    else
        echo "/var/lib/rpi-sb-provisioner/ramdisk_internal_config.txt"
    fi
}

get_ramdisk_cmdline_file() {
    if [ -f /etc/rpi-sb-provisioner/ramdisk_cmdline.txt ]; then
        echo "/etc/rpi-sb-provisioner/ramdisk_cmdline.txt"
    else
        echo "/var/lib/rpi-sb-provisioner/ramdisk_cmdline.txt"
    fi
}

get_signing_directives() {
    if [ -n "${CUSTOMER_KEY_PKCS11_NAME}" ]; then
        echo "${CUSTOMER_KEY_PKCS11_NAME} -engine pkcs11 -keyform engine"
    else
        if [ -n "${CUSTOMER_KEY_FILE_PEM}" ]; then
            if [ -f "${CUSTOMER_KEY_FILE_PEM}" ]; then
                echo "${CUSTOMER_KEY_FILE_PEM} -keyform PEM"
            else
                echo "RSA private key \"${CUSTOMER_KEY_FILE_PEM}\" not a file. Aborting." >&2
                exit 1
            fi
        else
            echo "Neither PKCS11 key name, or PEM key file specified. Aborting." >&2
            exit 1
        fi
    fi
}

get_bootimg_preinst_file() {
    if [ -f /etc/rpi-sb-provisioner/bootimg_preinst ]; then
        echo "/etc/rpi-sb-provisioner/bootimg_preinst"
    else
        echo "/var/lib/rpi-sb-provisioner/bootimg_preinst"
    fi
}
