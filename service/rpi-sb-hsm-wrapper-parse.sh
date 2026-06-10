#!/bin/sh
# Shared argument parsing for rpi-sb HSM signing wrappers.
#
# rpi-eeprom-digest and rpi-sign-bootcode invoke wrappers as:
#   wrapper -a rsa2048-sha256 <file>
# Internal callers may also use the legacy form:
#   wrapper <file>

INPUT_FILE=""

while [ $# -gt 0 ]; do
    case "$1" in
        -a)
            if [ $# -lt 2 ]; then
                echo "Error: -a requires an algorithm argument" >&2
                exit 1
            fi
            shift 2
            ;;
        *)
            if [ -n "${INPUT_FILE}" ]; then
                echo "Error: multiple input files specified" >&2
                exit 1
            fi
            INPUT_FILE="$1"
            shift
            ;;
    esac
done

if [ -z "${INPUT_FILE}" ]; then
    echo "Error: No input file specified" >&2
    echo "Usage: ${WRAPPER_NAME:-$0} [-a rsa2048-sha256] <file-to-sign>" >&2
    exit 1
fi

if [ ! -f "${INPUT_FILE}" ]; then
    echo "Error: Input file does not exist: ${INPUT_FILE}" >&2
    exit 1
fi
