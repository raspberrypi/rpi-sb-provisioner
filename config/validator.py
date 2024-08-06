## Format of return will be [Happy: bool, error: str]
from os import path
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
