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

# Signing happens entirely inside rpi-sb-keyhelper: it reads the device-wrapped
# token PIN stored by the WebUI (/etc/rpi-sb-provisioner/keys/pkcs11.pin),
# unwraps it in its own process memory, supplies it to the pkcs11-provider via
# OpenSSL's passphrase callback so the token's C_Login succeeds, signs on the
# token, and prints the hex signature on stdout. The PIN never reaches this
# shell, a command line, or a pin-source= file. Deployments that manage PIN
# material outside the provisioner can still carry pin-value=/pin-source= in the
# URI - with no stored PIN the callback is a no-op and the provider uses those.
# Output format: hex-encoded signature with no line breaks (keyhelper contract).
exec rpi-sb-keyhelper sign --pkcs11-uri "${CUSTOMER_KEY_PKCS11_NAME}" --in "${INPUT_FILE}"
