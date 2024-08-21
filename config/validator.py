## Format of return will be [Happy: bool, error: str]
from os import path
from email.utils import parseaddr, formataddr
import subprocess

def validate_CUSTOMER_KEY_FILE_PEM(text) -> tuple[bool, str]:
    if path.exists(text):
        pass
    else:
        return (False, "Could not find file " + text)
    output = subprocess.run(["openssl", "rsa", "-in", text, "-check", "-noout"], capture_output=True)
    if "RSA key ok" in output.stdout.decode():
        pass
    else:
        return (False, "openssl error: " + output.stdout.decode() + output.stderr.decode())
    # "openssl rsa -in " + text + "  -check -noout"
    return (True, "")
    

def validate_GOLD_MASTER_OS_FILE(text) -> tuple[bool, str]:
    if path.exists(text):
        pass
    else:
        return (False, "Could not find file " + text)

    return (True, "")

def validate_RPI_DEVICE_STORAGE_TYPE(text) -> tuple[bool, str]:
    if text in "sd nvme emmc":
        return (True, "")
    else:
        return (False, "type `" + text + "` was not any of sd, nvme or emmc")

def validate_RPI_DEVICE_FAMILY(text) -> tuple[bool, str]:
    if text in "45":
        return (True, "")
    else:
        return (False, "type `" + text + "` was not any of 4 or 5")

def validate_RPI_DEVICE_BOOTLOADER_CONFIG_FILE(text) -> tuple[bool, str]:
    if path.exists(text):
        pass
    else:
        return (False, "Could not find file " + text)

    return (True, "")

def validate_RPI_DEVICE_LOCK_JTAG(text) -> tuple[bool, str]:
    return (True, "")

def validate_RPI_DEVICE_EEPROM_WP_SET(text) -> tuple[bool, str]:
    return (True, "")

def validate_DEVICE_SERIAL_STORE(text) -> tuple[bool, str]:
    if text[0] == "/":
        pass
    else:
        return (False, "Please specify absolute path, beginning with /")

    return (True, "")


def validate_DEMO_MODE_ONLY(text) -> tuple[bool, str]:
    return (True, "")

def validate_RPI_SB_WORKDIR(text) -> tuple[bool, str]:
    if len(text) > 0:
        if text[0] == "/":
            pass
        else:
            return (False, "Please specify absolute path, beginning with /")
    return (True, "")

def validate_BOOT_IMAGE_VENDOR(text) -> tuple[bool, str]:
    if len(text) > 0:
        if text.isalpha() and text.islower():
            return (True, "")
        else:
            return (False, "BOOT_IMAGE_VENDOR must contain only lowercase letters")
    else:
        return (False, "Please specify a boot image vendor, e.g. \"acme\"")

def validate_BOOT_IMAGE_MAINTAINER(text) -> tuple[bool, str]:
    # TODO: parseaddr/formataddr is now a legacy API.
    # Switch to python3-email-validator once v2.2.0 is available in Debian.
    #
    # parseaddr supports many formats but formataddr always uses RFC 5322
    # mailbox.
    # Ensure that both display name and addr-spec address enclosed in angle
    # brackets are present.
    maint_addr = parseaddr(text)
    if all(maint_addr) and formataddr(maint_addr) == text:
        return (True, "")
    else:
        return (False, "BOOT_IMAGE_MAINTAINER must be an RFC 5322 mailbox, e.g. \"Able Maintainer <a.maintainer@example.com>\"")
