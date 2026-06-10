#!/bin/sh
# PKCS#11 HSM wrapper script for Raspberry Pi signing tools
#
# This script provides a consistent interface for rpi-sign-bootcode and
# rpi-eeprom-digest when using PKCS#11 hardware security modules.
#
# Interface (per Raspberry Pi tooling requirements):
#   Input:  [-a rsa2048-sha256] <file-to-sign>
#   Output: PKCS#1 v1.5 RSA-2048 SHA-256 signature in hex format (stdout)
#   Exit:   0 = success, non-zero = failure
#
# The PKCS#11 key URI is read from configuration
# (CUSTOMER_KEY_PKCS11_NAME variable from /etc/rpi-sb-provisioner/config)

set -e

WRAPPER_NAME="$0"
# shellcheck disable=SC1091
. "$(dirname "$0")/rpi-sb-hsm-wrapper-parse.sh" "$@"

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
    echo "Error: CUSTOMER_KEY_PKCS11_NAME not set in ${USER_CONFIG_FILE}" >&2
    exit 1
fi

# Sign using the OpenSSL PKCS#11 provider (pkcs11-provider).
# The ENGINE API (-engine pkcs11 -keyform engine) is deprecated in OpenSSL 3.x;
# the provider resolves the pkcs11: URI passed to -sign via OSSL_STORE. The PIN
# is taken from the URI (pin-value=/pin-source=), exactly as with the engine.
# Output format: hex-encoded signature with no line breaks
OPENSSL="${OPENSSL:-openssl}"

if ! "${OPENSSL}" dgst -sha256 \
    -provider pkcs11 -provider default \
    -sign "${CUSTOMER_KEY_PKCS11_NAME}" \
    "${INPUT_FILE}" | xxd -p -c 256; then
    echo "Error: Signing failed" >&2
    exit 1
fi

exit 0
