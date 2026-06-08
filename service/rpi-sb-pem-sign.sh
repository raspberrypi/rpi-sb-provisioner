#!/bin/sh
# PEM signing wrapper for Raspberry Pi signing tools (device-wrapped key).
#
# This is the PEM-key counterpart of rpi-sb-pkcs11-sign.sh. The customer
# private key (CUSTOMER_KEY_FILE_PEM) is stored device-wrapped at rest; this
# wrapper hands the file to rpi-sb-keyhelper, which unwraps the key in its own
# process memory, signs, and prints the signature. The plaintext key never
# reaches this shell or the filesystem.
#
# Interface (per Raspberry Pi tooling requirements):
#   Input:  Single argument = path to file containing data to sign
#   Output: PKCS#1 v1.5 RSA SHA-256 signature in hex on stdout
#   Exit:   0 = success, non-zero = failure

set -e

# Validate argument
if [ -z "$1" ]; then
    echo "Error: No input file specified" >&2
    echo "Usage: $0 <file-to-sign>" >&2
    exit 1
fi

INPUT_FILE="$1"

if [ ! -f "${INPUT_FILE}" ]; then
    echo "Error: Input file does not exist: ${INPUT_FILE}" >&2
    exit 1
fi

# Read configuration (defaults first, then user overrides)
DEFAULTS_FILE="/usr/share/rpi-sb-provisioner/defaults/config"
USER_CONFIG_FILE="/etc/rpi-sb-provisioner/config"

if [ ! -f "${DEFAULTS_FILE}" ]; then
    echo "Error: Package defaults not found: ${DEFAULTS_FILE}" >&2
    exit 1
fi

# Source defaults first
# shellcheck disable=SC1090
. "${DEFAULTS_FILE}"

# Source user overrides if present
if [ -f "${USER_CONFIG_FILE}" ]; then
    # shellcheck disable=SC1090
    . "${USER_CONFIG_FILE}"
fi

if [ -z "${CUSTOMER_KEY_FILE_PEM}" ]; then
    echo "Error: CUSTOMER_KEY_FILE_PEM not set in ${USER_CONFIG_FILE}" >&2
    exit 1
fi

# Unwrap-and-sign happens entirely inside rpi-sb-keyhelper; it emits the hex
# signature on stdout, matching the PKCS#11 wrapper's output contract.
exec rpi-sb-keyhelper sign --key "${CUSTOMER_KEY_FILE_PEM}" --in "${INPUT_FILE}"
