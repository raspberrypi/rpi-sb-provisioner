#!/bin/sh

set -e
set -x

# IDP (Image Description Provisioning) provisioner.
#
# Consumes a pre-built IDP artefact (JSON description + sparse images) from
# rpi-image-gen.  The device-side fastbootd handles partition creation,
# encryption setup, and partition enumeration from the JSON.  This script
# just orchestrates: stage JSON, idpinit, idpwrite, idpgetblk/flash loop,
# idpdone.

# shellcheck disable=SC1091
. /var/lib/rpi-sb-provisioner/manufacturing-data
# shellcheck disable=SC1091
. /var/lib/rpi-sb-provisioner/state-recording

DEBUG=

# Stage prefix for record_progress(); see host-support/state-recording.
export STATE_PREFIX="IDP-PROVISIONER"
export PROVISIONER_FINISHED="${STATE_PREFIX}-FINISHED"
export PROVISIONER_ABORTED="${STATE_PREFIX}-ABORTED"
export PROVISIONER_STARTED="${STATE_PREFIX}-STARTED"

# Source common helper functions
# shellcheck disable=SC1091
. "$(dirname "$0")/rpi-sb-common.sh"

die() {
    record_abort_once "${TARGET_DEVICE_SERIAL}" "${TARGET_USB_PATH}"
    # shellcheck disable=SC2086
    echo "$@" ${DEBUG}
    exit 1
}

log() {
    timestamp=$(date +"%Y-%m-%d %H:%M:%S.$(date +%N | cut -c1-3)")
    echo "[${timestamp}] $*" >> /var/log/rpi-sb-provisioner/"${TARGET_DEVICE_SERIAL}"/provisioner.log
    printf "[%s] %s\n" "${timestamp}" "$*"
}

read_config
compute_image_summary

CLEANUP_DONE=0
DELETE_PRIVATE_TMPDIR=

check_command_exists() {
    command_to_test=$1
    if ! command -v "${command_to_test}" 1> /dev/null; then
        die "${command_to_test} could not be found"
    else
        echo "$command_to_test"
    fi
}

check_pidevice_storage_type() {
    case "${1}" in
        "sd")
            echo "mmcblk0"
            ;;
        "emmc")
            echo "mmcblk0"
            ;;
        "nvme")
            echo "nvme0n1"
            ;;
        *)
            die "Unexpected storage device type. Wanted sd, nvme or emmc, got '$1'"
            ;;
    esac
}

cleanup() {
    # Capture the exit status that triggered the trap BEFORE any other
    # command runs, otherwise $? is clobbered by the guard/assignment below
    # and a genuine failure is reported as success.
    return_value=$?

    # Guard against multiple invocations (signal + EXIT trap)
    [ "$CLEANUP_DONE" -eq 1 ] && return
    CLEANUP_DONE=1

    set +e

    # Only remove the workdir if we created it ourselves; a station-configured
    # RPI_SB_WORKDIR is a deliberate cross-run cache and must survive.
    if [ -n "${DELETE_PRIVATE_TMPDIR}" ]; then
        announce_start "Deleting customised intermediates"
        # shellcheck disable=SC2086
        rm -rf "${RPI_SB_WORKDIR}" ${DEBUG}
        sync
        DELETE_PRIVATE_TMPDIR=
        announce_stop "Deleting customised intermediates"
    fi

    if [ "${return_value}" -ne 0 ]; then
        # A `set -e` death never reaches die(), so without this the device
        # stays recorded in its last transitional state for ever. Recorded
        # before the hook, so operator code that reads the state sees the
        # abort rather than the stage it died in.
        record_abort_once "${TARGET_DEVICE_SERIAL}" "${TARGET_USB_PATH}"
        run_provision_failed_hook "idp-provisioner" "provisioning"
    fi

    exit ${return_value}
}
# Signals exit with their own status so cleanup sees a failure. Trapped
# directly, cleanup read the last command's status, often 0, and recorded a
# killed run as a success.
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

### Pre-requisite checks

check_command_exists fastboot
check_command_exists jq
check_command_exists cut
check_command_exists sed
check_command_exists systemd-notify

# Tools required when we have to re-sign boot slots for secure-boot.
# Always present in the package's runtime deps; check up-front so we
# fail before touching the device rather than mid-flight.
if [ "${PROVISIONING_STYLE}" = "secure-boot" ]; then
    check_command_exists simg2img
    check_command_exists img2simg
    check_command_exists mkfs.fat
    check_command_exists mount
    check_command_exists umount
    check_command_exists truncate
    check_command_exists rpi-make-boot-image
    check_command_exists xxd
    check_command_exists openssl
    check_command_exists sha256sum

    if ! init_signing_context; then
        die "Failed to initialise signing context for secure-boot IDP run"
    fi
    if ! signing_available; then
        die "PROVISIONING_STYLE=secure-boot but no customer signing key configured"
    fi
fi

# The staged descriptor, partition cursor and write pipeline live in one
# fastbootd session, and only USB keeps a session across fastboot calls: over
# TCP each is a new one. A daemon not in split mode would be driven over TCP
# and lose the descriptor between stage and idpinit, so it stays on USB.
keep_idp_on_one_session() {
    if [ "${TCP_DATA_PLANE_ONLY}" != "yes" ] && [ "${FASTBOOT_DEVICE_SPECIFIER}" != "${TARGET_DEVICE_SERIAL}" ]; then
        log "Not split mode: IDP stays on USB ${TARGET_DEVICE_SERIAL}, not ${FASTBOOT_DEVICE_SPECIFIER}, to keep one session"
        FASTBOOT_DEVICE_SPECIFIER="${TARGET_DEVICE_SERIAL}"
    fi
}

setup_fastboot_and_id_vars "$1"
keep_idp_on_one_session

record_state "${TARGET_DEVICE_SERIAL}" "${PROVISIONER_STARTED}" "${TARGET_USB_PATH}"

systemd-notify --ready --status="Provisioning started"

# Re-check the OS image here as well as in triage: these units can be started
# directly, and the configuration can change between triage selecting a
# provisioner and that provisioner running.
if ! classify_gold_master_os; then
    mark_permanent_failure
    die "${GOLD_MASTER_OS_ERROR}"
fi

### Resolve the IDP artefact directory

if [ -d "${GOLD_MASTER_OS_FILE}" ]; then
    IDP_DIR="${GOLD_MASTER_OS_FILE}"
else
    die "GOLD_MASTER_OS_FILE is not a directory: ${GOLD_MASTER_OS_FILE}. IDP provisioner requires an IDP artefact directory."
fi

### Pre-flight validation
#
# Fail fast on the host before wasting device time.

record_progress "IMAGE-PREPARING"
announce_start "IDP pre-flight validation"

# Exactly one JSON file must be present
JSON_COUNT=$(find "${IDP_DIR}" -maxdepth 1 -name "*.json" -type f | wc -l)
if [ "${JSON_COUNT}" -eq 0 ]; then
    die "No JSON description file found in IDP artefact directory: ${IDP_DIR}"
elif [ "${JSON_COUNT}" -gt 1 ]; then
    die "Multiple JSON files found in IDP artefact directory: ${IDP_DIR}. Expected exactly one."
fi
IDP_JSON=$(find "${IDP_DIR}" -maxdepth 1 -name "*.json" -type f)

log "IDP artefact directory: ${IDP_DIR}"
log "IDP JSON description: ${IDP_JSON}"

# JSON must be syntactically valid
if ! jq empty < "${IDP_JSON}" 2>/dev/null; then
    die "IDP JSON description is not valid JSON: ${IDP_JSON}"
fi

# Extract and log metadata from the JSON
IDP_IMAGE_NAME=$(jq -r '.attributes."image-name" // "unknown"' < "${IDP_JSON}")
IDP_IMAGE_VERSION=$(jq -r '.IGmeta.IGconf_image_version // "unknown"' < "${IDP_JSON}")
IDP_DEVICE_CLASS=$(jq -r '.IGmeta.IGconf_device_class // "unknown"' < "${IDP_JSON}")
IDP_STORAGE_TYPE=$(jq -r '.IGmeta.IGconf_device_storage_type // "unknown"' < "${IDP_JSON}")
IDP_HAS_ENCRYPTION=$(jq -r 'any(.. | objects; has("encrypted")) | if . then "yes" else "no" end' < "${IDP_JSON}")

log "IDP image name: ${IDP_IMAGE_NAME}"
log "IDP image version: ${IDP_IMAGE_VERSION}"
log "IDP device class: ${IDP_DEVICE_CLASS}"
log "IDP storage type: ${IDP_STORAGE_TYPE}"
log "IDP encryption: ${IDP_HAS_ENCRYPTION}"

# A sparse image is named by the artefact and, later, by the device. Either
# could name a host file instead, which the flash loop would then send to the
# device, so only a plain name inside the artefact is accepted.
idp_plain_name() {
    case "$1" in
        ""|.*|*/*|*..*) return 1 ;;
    esac
    printf '%s' "$1" | grep -Eqx '[A-Za-z0-9._+-]+'
}

# Verify all referenced .simg files exist
MISSING_IMAGES=""
ARTEFACT_SIMGS=""
for SIMG_NAME in $(jq -r '.layout.partitionimages | to_entries[] | .value.simage // empty' < "${IDP_JSON}"); do
    if ! idp_plain_name "${SIMG_NAME}"; then
        die "IDP artefact names an image outside itself: ${SIMG_NAME}"
    fi
    ARTEFACT_SIMGS="${ARTEFACT_SIMGS}${SIMG_NAME}
"
    if [ ! -f "${IDP_DIR}/${SIMG_NAME}" ]; then
        MISSING_IMAGES="${MISSING_IMAGES} ${SIMG_NAME}"
    fi
done
if [ -n "${MISSING_IMAGES}" ]; then
    die "IDP artefact is incomplete. Missing sparse images:${MISSING_IMAGES}"
fi

# Cross-check device class against host configuration
# Map IDP device class names to RPI_DEVICE_FAMILY convention
map_device_class_to_family() {
    case "$1" in
        pi5|cm5)   echo "5" ;;
        pi4|cm4)   echo "4" ;;
        zero2w)    echo "2W" ;;
        *)         echo "$1" ;;
    esac
}

EXPECTED_FAMILY=$(map_device_class_to_family "${IDP_DEVICE_CLASS}")
if [ -n "${RPI_DEVICE_FAMILY}" ] && [ "${EXPECTED_FAMILY}" != "${RPI_DEVICE_FAMILY}" ]; then
    die "IDP artefact is for device family '${EXPECTED_FAMILY}' (${IDP_DEVICE_CLASS}), but this station is configured for '${RPI_DEVICE_FAMILY}'."
fi

# Cross-check storage type against host configuration, or adopt it from the
# JSON if the host didn't set one. The JSON's IGconf_device_storage_type is
# authoritative for IDP artefacts; RPI_DEVICE_STORAGE_TYPE is kept as an
# optional assertion so a misconfigured station still fails loudly.
if [ -n "${RPI_DEVICE_STORAGE_TYPE}" ]; then
    if [ "${RPI_DEVICE_STORAGE_TYPE}" != "${IDP_STORAGE_TYPE}" ]; then
        die "IDP artefact is for storage type '${IDP_STORAGE_TYPE}', but this station is configured with RPI_DEVICE_STORAGE_TYPE='${RPI_DEVICE_STORAGE_TYPE}'."
    fi
else
    log "RPI_DEVICE_STORAGE_TYPE is not set; adopting '${IDP_STORAGE_TYPE}' from IDP artefact."
    RPI_DEVICE_STORAGE_TYPE="${IDP_STORAGE_TYPE}"
fi

# Resolve the raw storage type to its block device name for fastboot.
RPI_DEVICE_STORAGE_TYPE="$(check_pidevice_storage_type "${RPI_DEVICE_STORAGE_TYPE}")"

log "Pre-flight validation passed"
announce_stop "IDP pre-flight validation"

# Run provision-started hook (e.g. LED control on programming rigs).
# Deferred until after pre-flight so the hook receives the resolved block
# device name rather than the raw IDP value.
run_customisation_script "idp-provisioner" "provision-started" "${FASTBOOT_DEVICE_SPECIFIER}" "${TARGET_DEVICE_SERIAL}" "${RPI_DEVICE_STORAGE_TYPE}"

### Working directory
#
# RPI_SB_WORKDIR is where we keep anything worth reusing between provisioning
# runs. It is optional -- when a station doesn't configure one we create an
# ephemeral directory and remove it on exit, exactly as the other provisioners
# do. Because an IDP artefact ships its partitions pre-built, the only thing
# the IDP path currently caches is the signed boot slot.
announce_start "Finding the cache directory"
if [ -z "${RPI_SB_WORKDIR}" ]; then
    RPI_SB_WORKDIR=$(make_temp_dir "rpi-sb-provisioner.XXX")
    DELETE_PRIVATE_TMPDIR="true"
    announce_stop "Finding the cache directory: Created ${RPI_SB_WORKDIR} (none configured)"
elif [ ! -d "${RPI_SB_WORKDIR}" ]; then
    RPI_SB_WORKDIR=$(make_temp_dir "rpi-sb-provisioner.XXX")
    DELETE_PRIVATE_TMPDIR="true"
    announce_stop "Finding the cache directory: Created ${RPI_SB_WORKDIR} (configured path isn't a directory)"
elif ! workdir_is_private "${RPI_SB_WORKDIR}"; then
    RPI_SB_WORKDIR=$(make_temp_dir "rpi-sb-provisioner.XXX")
    DELETE_PRIVATE_TMPDIR="true"
    announce_stop "Finding the cache directory: Created ${RPI_SB_WORKDIR} (configured path is not root's alone)"
else
    announce_stop "Finding the cache directory: Using specified name"
fi

### Boot slot signing for secure-boot
#
# A signed-boot Pi 5 EEPROM rejects raw firmware/kernel files in the slot
# VFAT and only loads {boot.img, boot.sig}. The IDP artefact ships unsigned
# slot VFATs, so when running secure-boot we transform each boot-role slot
# into a signed sparse and substitute it during the flash loop.
#
# Discovery rule: any partition under layout.partitionimages whose pmap entry
# carries .static.role == "boot". The bootconfig partition is intentionally
# left unmodified -- autoboot.txt is read by the early bootloader stage and
# does not require signing; tryboot redirection still works as expected.

# SIGNED_BOOT_SUBST is a newline-separated list of "<source-simg>=<replacement-path>"
# entries. Empty when not in secure-boot mode.
SIGNED_BOOT_SUBST=""

if [ "${PROVISIONING_STYLE}" = "secure-boot" ]; then
    record_progress "IMAGE-SIGNING"
    announce_start "Sign boot slots for secure-boot"

    if [ -z "${RPI_DEVICE_FAMILY}" ]; then
        die "RPI_DEVICE_FAMILY not set; required for rpi-make-boot-image"
    fi

    SIGNED_CACHE_DIR="${RPI_SB_WORKDIR}/idp-signed-boot"
    mkdir -p "${SIGNED_CACHE_DIR}"

    # Cache key per (source-simg-content, public-key-content). Same artefact
    # + same key signs identically on every run, so we can flash many devices
    # from one transform.
    PUBKEY_HASH=$(sha256sum "${CUSTOMER_PUBLIC_KEY_FILE}" | awk '{print $1}')

    # Collect the source simg filename of every boot-role partition.
    #
    # Discovery is by provisionmap .static.role == "boot" (walked recursively,
    # so top-level partitions, slots and encrypted groups are all covered).
    # partitionimages.bootable is NOT a usable discriminator on its own:
    # rpi-image-gen legitimately flags bootconfig as bootable="true" because
    # the EEPROM reads autoboot.txt out of it, so a bootable-based predicate
    # sweeps bootconfig into the signing set. That both breaks A/B slot
    # selection (autoboot.txt would end up bundled inside boot.img instead of
    # sitting in the filesystem where the bootloader looks for it) and, in
    # practice, aborts the run outright -- bootconfig's ~64 bytes of content
    # size the inner FAT below mkfs.fat's viable floor.
    #
    # Flat (non-slotted) layouts carry no roles at all, so fall back to the
    # bootable flag there; those images have no bootconfig to confuse us.
    #
    # A/B images legitimately list the same simage twice (boot_a and boot_b
    # both point at boot.sparse), so we dedupe.
    UNIQUE_SOURCE_SIMGS=$(jq -r '
        [ .layout.provisionmap? // [] | .. | objects
          | select(has("image") and (.static?.role? == "boot"))
          | .image ] as $bootrole
        | ( [ .layout.partitionimages | to_entries[]
              | select(.key as $k | $bootrole | index($k))
              | .value.simage // empty ] | unique ) as $byrole
        | ( [ .layout.partitionimages | to_entries[]
              | select(.value.bootable == "true")
              | .value.simage // empty ] | unique ) as $byflag
        | ( if ($bootrole | length) > 0 then $byrole else $byflag end ) | .[]
    ' < "${IDP_JSON}")

    if [ -z "${UNIQUE_SOURCE_SIMGS}" ]; then
        die "secure-boot configured but no boot-role partitions in ${IDP_JSON}"
    fi

    for src_simg in ${UNIQUE_SOURCE_SIMGS}; do
        SRC_PATH="${IDP_DIR}/${src_simg}"
        if [ ! -f "${SRC_PATH}" ]; then
            die "boot slot source missing: ${SRC_PATH}"
        fi

        SRC_HASH=$(sha256sum "${SRC_PATH}" | awk '{print $1}')
        # v2: VFAT now also contains config.txt with boot_ramdisk=1 so the
        # EEPROM actually chainloads boot.img.
        # v3: a slot that already holds a boot.img is signed as it stands rather
        # than bundled into a second one.
        # Bump on any future on-disk format change so stale cache entries don't
        # get reused.
        CACHE_NAME="${src_simg%.sparse}-v3-${SRC_HASH}-${PUBKEY_HASH}.sparse"
        CACHE_PATH="${SIGNED_CACHE_DIR}/${CACHE_NAME}"

        log "Signing boot slot source ${src_simg} -> ${CACHE_PATH}"
        if ! with_lock "${LOCK_BASE}/idp-signed-boot.lock" 600 \
                prepare_signed_boot_simg "${SRC_PATH}" "${CACHE_PATH}"; then
            die "Failed to produce signed boot sparse for ${src_simg}"
        fi

        SIGNED_BOOT_SUBST="${SIGNED_BOOT_SUBST}
${src_simg}=${CACHE_PATH}"
    done

    announce_stop "Sign boot slots for secure-boot"
fi

# Resolve a source simg name to the path that should actually be flashed.
# Returns the substituted path on stdout if the simg is in the boot-slot
# substitution table; otherwise echoes ${IDP_DIR}/${simg} unchanged.
resolve_flash_source() {
    _simg="$1"
    if [ -n "${SIGNED_BOOT_SUBST}" ]; then
        _hit=$(printf '%s\n' "${SIGNED_BOOT_SUBST}" \
            | awk -F= -v k="${_simg}" '$1 == k { print $2; exit }')
        if [ -n "${_hit}" ]; then
            printf '%s\n' "${_hit}"
            return 0
        fi
    fi
    printf '%s/%s\n' "${IDP_DIR}" "${_simg}"
}

### IDP Provisioning Protocol

record_progress "STORAGE-ERASING"
announce_start "Erase Device Storage"
timeout_fatal_secs "${FASTBOOT_ERASE_TIMEOUT}" fastboot -s "${FASTBOOT_DEVICE_SPECIFIER}" erase "${RPI_DEVICE_STORAGE_TYPE}"
sleep 3
announce_stop "Erase Device Storage"

# Re-check the fastboot device specifier, as it may take a while for a device to gain IP connectivity
setup_fastboot_and_id_vars "${FASTBOOT_DEVICE_SPECIFIER}"
keep_idp_on_one_session

announce_start "IDP Stage and Initialise"
timeout_fatal_secs "${FASTBOOT_CONTROL_TIMEOUT}" fastboot -s "${FASTBOOT_DEVICE_SPECIFIER}" stage "${IDP_JSON}"
timeout_fatal_secs "${FASTBOOT_CONTROL_TIMEOUT}" fastboot -s "${FASTBOOT_DEVICE_SPECIFIER}" oem idpinit
announce_stop "IDP Stage and Initialise"

record_progress "STORAGE-PARTITIONING"
announce_start "IDP Write Partitions"
timeout_fatal_secs "${FASTBOOT_STORAGE_TIMEOUT}" fastboot -s "${FASTBOOT_DEVICE_SPECIFIER}" oem idpwrite
announce_stop "IDP Write Partitions"

# Prefer the TCP data-plane specifier when the daemon advertises split
# mode (-i usb+tcp); fall back to whatever the control plane is using.
FLASH_SPECIFIER="${FASTBOOT_TCP_FLASH_SPECIFIER:-${FASTBOOT_DEVICE_SPECIFIER}}"
probe_flash_pipeline "${FLASH_SPECIFIER}"

record_progress "WRITING-OS"
announce_start "IDP Flash Images"
PARTITION_INDEX=0
while true; do
    set +e
    RESPONSE=$(timeout -k 5 "${FASTBOOT_CONTROL_TIMEOUT}" fastboot -s "${FASTBOOT_DEVICE_SPECIFIER}" oem idpgetblk 2>&1)
    FB_EXIT=$?
    set -e
    case ${FB_EXIT} in
        0) ;;
        124|137) die "idpgetblk: no answer within ${FASTBOOT_CONTROL_TIMEOUT} seconds" ;;
        *) die "idpgetblk failed (exit ${FB_EXIT}): ${RESPONSE}" ;;
    esac

    # Extract the INFO line.
    # The host fastboot client outputs device INFO messages in various formats
    # depending on version: "(bootloader) msg" or "INFO msg".
    # We look for a line containing a colon-separated blockdev:simg pair.
    INFO_LINE=$(echo "${RESPONSE}" | sed -n 's/.*[Ii][Nn][Ff][Oo][[:space:]]*//p' | head -1)

    # If there was no info line, also try the (bootloader) format
    if [ -z "${INFO_LINE}" ]; then
        INFO_LINE=$(echo "${RESPONSE}" | sed -n 's/.*(bootloader)[[:space:]]*//p' | head -1)
    fi

    # No INFO line means we're done -- all partitions have been enumerated
    if [ -z "${INFO_LINE}" ]; then
        log "idpgetblk: no more partitions to flash"
        break
    fi

    # INFO line should be "blockdev:simg_filename"
    BLOCKDEV=$(echo "${INFO_LINE}" | cut -d: -f1)
    SIMG=$(echo "${INFO_LINE}" | cut -d: -f2)

    if [ -z "${BLOCKDEV}" ] || [ -z "${SIMG}" ]; then
        die "Malformed idpgetblk response: '${INFO_LINE}' (full response: ${RESPONSE})"
    fi
    # The device chose both. The image must be one the artefact lists, and the
    # block device must not be mistaken for an option by fastboot.
    if ! idp_plain_name "${SIMG}" || ! printf '%s' "${ARTEFACT_SIMGS}" | grep -Fqx -- "${SIMG}"; then
        die "Device asked for an image the artefact does not contain: '${SIMG}'"
    fi
    if ! printf '%s' "${BLOCKDEV}" | grep -Eqx '[A-Za-z0-9][A-Za-z0-9/_-]*'; then
        die "Device named an invalid block device: '${BLOCKDEV}'"
    fi

    FLASH_SOURCE=$(resolve_flash_source "${SIMG}")
    if [ ! -f "${FLASH_SOURCE}" ]; then
        die "idpgetblk referenced image not found: ${FLASH_SOURCE}"
    fi

    PARTITION_INDEX=$((PARTITION_INDEX + 1))
    SIMG_SIZE=$(stat -c%s "${FLASH_SOURCE}" 2>/dev/null || echo "unknown")
    if [ "${FLASH_SOURCE}" != "${IDP_DIR}/${SIMG}" ]; then
        log "Flashing partition ${PARTITION_INDEX}: ${SIMG} (signed: ${FLASH_SOURCE}, ${SIMG_SIZE} bytes) -> ${BLOCKDEV}"
    else
        log "Flashing partition ${PARTITION_INDEX}: ${SIMG} (${SIMG_SIZE} bytes) -> ${BLOCKDEV}"
    fi

    FLASH_START=$(date +%s)
    # Report each partition as its own state: an IDP artefact can carry many,
    # each taking minutes, so a single "writing" state for the whole loop
    # leaves the tile view looking stalled for the duration. The block device
    # is folded to the record_progress character set (see
    # host-support/state-recording) -- "mapper/cryptroot" becomes
    # "MAPPER-CRYPTROOT".
    BLOCKDEV_STATE=$(printf '%s' "${BLOCKDEV}" | tr -c 'A-Za-z0-9' '-' | tr 'a-z' 'A-Z')
    record_progress "WRITING-${BLOCKDEV_STATE}"
    fastboot_flash "${FLASH_SPECIFIER}" "${BLOCKDEV}" "${FLASH_SOURCE}"
    FLASH_END=$(date +%s)
    FLASH_DURATION=$((FLASH_END - FLASH_START))
    log "Flashed ${SIMG} to ${BLOCKDEV} in ${FLASH_DURATION}s"
done
log "Flashed ${PARTITION_INDEX} partition(s) total"

announce_stop "IDP Flash Images"

record_progress "FINALISING"
announce_start "IDP Finalise"
timeout_fatal_secs 60 fastboot -s "${FASTBOOT_DEVICE_SPECIFIER}" oem idpdone
announce_stop "IDP Finalise"

announce_start "Set LED status"
timeout_nonfatal_secs "${FASTBOOT_CONTROL_TIMEOUT}" fastboot -s "${FASTBOOT_DEVICE_SPECIFIER}" oem led PWR 0 || true
announce_stop "Set LED status"

metadata_gather

# Run post-flash customisation script
run_customisation_script "idp-provisioner" "post-flash" "${FASTBOOT_DEVICE_SPECIFIER}" "${TARGET_DEVICE_SERIAL}" "${RPI_DEVICE_STORAGE_TYPE}"
log "Post-flash customisation script completed"

record_state "${TARGET_DEVICE_SERIAL}" "${PROVISIONER_FINISHED}" "${TARGET_USB_PATH}"

log "IDP provisioning completed. Remove the device from this machine."
log "Artefact: ${IDP_IMAGE_NAME} version ${IDP_IMAGE_VERSION}"

# Indicate successful completion to systemd
systemd-notify --status="Provisioning completed successfully" STOPPING=1

true
