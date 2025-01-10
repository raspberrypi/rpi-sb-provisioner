## Format of return will be [Happy: bool, error: str]
import os
import subprocess

def validate_PROVISIONING_STYLE(text) -> tuple[bool, str]:
    if text in ["secure-boot", "fde-only", "naked"]:
        return (True, "")
    else:
        return (False, "Unexpected provisioning style: `" + text + "` is not one of secure-boot, fde-only, naked")

def validate_CUSTOMER_KEY_FILE_PEM(text) -> tuple[bool, str]:
    if not os.path.exists(text):
        return (False, "Could not find file " + text)
    output = subprocess.run(
        ["openssl", "rsa", "-in", text, "-check", "-noout"],
        capture_output=True,
        text=True,
    )
    if "RSA key ok" not in output.stdout:
        return (False, "openssl error: " + output.stdout + output.stderr)
    # "openssl rsa -in " + text + "  -check -noout"
    return (True, "")


def validate_CUSTOMER_KEY_PKCS11_NAME(text) -> tuple[bool, str]:
    output = subprocess.run(
        ["openssl", "rsa", text, "-engine", "pkcs11", "-keyform", "engine", "-check", "-noout"],
        capture_output=True,
        text=True,
    )
    if "RSA key ok" not in output.stdout:
        return (False, "openssl error: " + output.stdout + output.stderr)
    # "openssl rsa -in " + text + "  -check -noout"
    return (True, "")


def validate_GOLD_MASTER_OS_FILE(text) -> tuple[bool, str]:
    if not os.path.exists(text):
        return (False, "Could not find file " + text)

    return (True, "")


def validate_RPI_DEVICE_STORAGE_TYPE(text) -> tuple[bool, str]:
    if text in "sd nvme emmc":
        return (True, "")
    else:
        return (False, "type `" + text + "` was not any of sd, nvme or emmc")


def validate_RPI_DEVICE_STORAGE_CIPHER(text) -> tuple[bool, str]:
    if text in "aes-xts-plain64 xchacha12,aes-adiantum-plain64":
        return (True, "")
    else:
        return (False, "cipher `" + text + "` was not any of aes-xts-plain64, xchacha12,aes-adiantum-plain64")


def validate_RPI_DEVICE_FAMILY(text) -> tuple[bool, str]:
    if text in ["4", "5", "2W"]:
        return (True, "")
    else:
        return (False, "type `" + text + "` was not any of 4, 5, or 2W")


def validate_RPI_DEVICE_BOOTLOADER_CONFIG_FILE(text) -> tuple[bool, str]:
    if not os.path.exists(text):
        return (False, "Could not find file " + text)

    return (True, "")

def validate_RPI_DEVICE_LOCK_JTAG(text) -> tuple[bool, str]:
    return (True, "")

def validate_RPI_DEVICE_EEPROM_WP_SET(text) -> tuple[bool, str]:
    return (True, "")

def validate_RPI_DEVICE_RETRIEVE_KEYPAIR(text) -> tuple[bool, str]:
    return (True, "")

def validate_RPI_DEVICE_FETCH_METADATA(text) -> tuple[bool, str]:
    return (True, "")

def validate_RPI_SB_WORKDIR(text) -> tuple[bool, str]:
    if text and text[0] != "/":
        return (False, "Please specify absolute path, beginning with /")
    return (True, "")

def validate_RPI_SB_PROVISONER_MANUFACTURING_DB(text) -> tuple[bool, str]:
    if not os.path.exists(text):
            return (False, "Failed to check file. You must create the file ahead of use, using 'touch " + text + "'")
    return (True, "")