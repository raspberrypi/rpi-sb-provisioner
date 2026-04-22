#!/bin/sh
# PKCS#11 HSM wrapper script for Raspberry Pi signing tools
#
# This script provides a consistent interface for rpi-sign-bootcode and
# rpi-eeprom-digest when using PKCS#11 hardware security modules.
#
# Interface (per Raspberry Pi tooling requirements):
#   Input:  Single argument = path to file containing data to sign
#   Output: PKCS#1 v1.5 RSA-2048 SHA-256 signature in hex format (stdout)
#   Exit:   0 = success, non-zero = failure
#
# The PKCS#11 key URI is read from configuration
# (CUSTOMER_KEY_PKCS11_NAME variable from /etc/rpi-sb-provisioner/config)

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

if [ -z "${CUSTOMER_KEY_PKCS11_NAME}" ]; then
    echo "Error: CUSTOMER_KEY_PKCS11_NAME not set in ${CONFIG_FILE}" >&2
    exit 1
fi

# Sign using OpenSSL PKCS#11 engine
# Output format: hex-encoded signature with no line breaks
OPENSSL="${OPENSSL:-openssl}"

if ! "${OPENSSL}" dgst -sha256 \
    -sign "${CUSTOMER_KEY_PKCS11_NAME}" \
    -engine pkcs11 \
    -keyform engine \
    "${INPUT_FILE}" | xxd -p -c 256; then
    echo "Error: Signing failed" >&2
    exit 1
fi

exit 0
