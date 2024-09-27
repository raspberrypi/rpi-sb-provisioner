#!/bin/sh

OPENSSL=${OPENSSL:-openssl}

export KEYWRITER_FINISHED="KEYWRITER-FINISHED"
export KEYWRITER_ABORTED="KEYWRITER-ABORTED"
export KEYWRITER_STARTED="KEYWRITER-STARTED"
export PROVISIONER_FINISHED="PROVISIONER-FINISHED"
export PROVISIONER_ABORTED="PROVISIONER-ABORTED"
export PROVISIONER_STARTED="PROVISIONER-STARTED"


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

read_config() {
    if [ -f /etc/rpi-sb-provisioner/config ]; then
        . /etc/rpi-sb-provisioner/config
    else
        echo "Failed to load config. Please use configuration tool." >&2
        return 1
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