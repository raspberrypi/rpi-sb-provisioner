The Configuration API provides endpoints for managing system configuration options, firmware selection, the bootloader configuration, signing keys and working directory management.

Every `POST` endpoint here needs the CSRF token from a browser session, or a bearer token (see [authentication.md](authentication.md)).

# /options/get

**HTTP Method:** GET

**Description:** Retrieves all current configuration values: the package defaults in `/usr/share/rpi-sb-provisioner/defaults/config` overlaid with `/etc/rpi-sb-provisioner/config`. With `Accept: text/html` the Options page is returned instead.

**Parameters:** None

**Response Format:**

``` json
{
  "GOLD_MASTER_OS_FILE": "/srv/rpi-sb-provisioner/images/raspios-2025-04-01.img",
  "RPI_SB_WORKDIR": "/srv/rpi-sb-provisioner/work",
  "RPI_SB_PROVISIONER_MANUFACTURING_DB": "/srv/rpi-sb-provisioner/manufacturing.db",
  "RPI_DEVICE_FAMILY": "5",
  "RPI_DEVICE_FIRMWARE_FILE": "/lib/firmware/raspberrypi/bootloader-2712/default/pieeprom-2025-01-17.bin"
}
```

**Notes:**

- Every value is a string. `RPI_CONNECT_API_KEY` is write-only and never returned, so a client that writes these settings back leaves the saved token alone

- The response body is JSON but is not labelled `application/json`

# /options/set

**HTTP Method:** POST

**Description:** Updates one or more configuration values. Values not named are kept.

**Request Format:**

``` json
{
  "GOLD_MASTER_OS_FILE": "/srv/rpi-sb-provisioner/images/new-image.img",
  "RPI_DEVICE_FAMILY": "5"
}
```

**Response Format:**

HTTP 200 OK with no body on success.

**Error Responses:**

| Status | `error_code`           | Cause                                                                 |
|--------|------------------------|-----------------------------------------------------------------------|
| 400    | `INVALID_JSON`         | The body is not a JSON object                                         |
| 400    | `INVALID_CONFIG_ENTRY` | A value is not a string or holds a line break, or a name is not a provisioner setting (it must match `(RPI\|GOLD_MASTER\|PROVISIONING\|CUSTOMER\|PKCS11)_[A-Z0-9_]+`) |
| 500    | `CONFIG_WRITE_ERROR`   | The file could not be written                                         |
| 500    | `DB_CREATE_ERROR`, `DB_PERMISSION_ERROR` | The manufacturing database file could not be created  |

Nothing is written if any entry is refused.

**Notes:**

- Every successful save empties `RPI_SB_WORKDIR`, whatever changed, so the next device re-signs. A workdir that holds the provisioner's images, database, keys or logs, a home directory or a system directory is never emptied

- Creates the manufacturing database file, mode 0600, if its path is set and the file does not exist

# /options/validate

**HTTP Method:** POST

**Description:** Validates a single configuration field value before saving. Performs field-specific validation including file path checks on disk.

**Request Format:**

``` json
{
  "field": "GOLD_MASTER_OS_FILE",
  "value": "/srv/rpi-sb-provisioner/images/raspios-2025-04-01.img"
}
```

**Response Format (Success):**

``` json
{
  "valid": true,
  "field": "GOLD_MASTER_OS_FILE"
}
```

**Response Format (Success with Info):**

``` json
{
  "valid": true,
  "field": "RPI_SB_PROVISIONER_MANUFACTURING_DB",
  "message": "File will be created on save"
}
```

**Response Format (Validation Failure):**

``` json
{
  "valid": false,
  "field": "GOLD_MASTER_OS_FILE",
  "error": "Image file does not exist at specified path"
}
```

**Validation Rules:**

File Path Fields (must exist and be readable):

- `CUSTOMER_KEY_FILE_PEM` - RSA private key file

- `GOLD_MASTER_OS_FILE` - Must be a traditional `.img` file or an IDP artefact directory containing exactly one valid JSON image descriptor and its referenced sparse images

- `RPI_DEVICE_BOOTLOADER_CONFIG_FILE` - Bootloader configuration file

Directory Path Fields (must exist or be creatable):

- `RPI_SB_WORKDIR` - Working directory for cached assets

- `RPI_DEVICE_RETRIEVE_KEYPAIR` - Directory for storing device keypairs

Database Path Fields:

- `RPI_SB_PROVISIONER_MANUFACTURING_DB` - SQLite database path (mandatory, parent directory must exist)

Enumerated Values:

- `PROVISIONING_STYLE` - Must be `secure-boot`, `fde-only`, or `naked`

- `RPI_DEVICE_FAMILY` - Must be `4`, `5`, or `2W`

- `RPI_DEVICE_STORAGE_TYPE` - Must be `sd`, `emmc`, or `nvme`

- `RPI_DEVICE_STORAGE_CIPHER` - Must be `aes-xts-plain64` or `xchacha12,aes-adiantum-plain64`

- `RPI_DEVICE_RPIBOOT_GPIO` - For Raspberry Pi 4 family secure-boot provisioning, must be one of `2`, `4`, `5`, `6`, `7`, or `8`

Format-Specific:

- `CUSTOMER_KEY_PKCS11_NAME` - Must start with `pkcs11:` and include `object=` and `type=private` parameters

- `RPI_CONNECT_API_KEY` - Must not contain whitespace

- `RPI_SB_PROVISIONER_PUBLIC_DASHBOARD` - `1` (on) or empty (off)

Boolean Toggles:

- `RPI_DEVICE_BOOT_ORDER_MATCH_STORAGE` - Enabled by default; rewrites `BOOT_ORDER` so the selected storage device boots first. Stored as `1` (on) or empty (off); the WebUI exposes this as a switch

**Security Measures:**

- **Dynamic Field Whitelist:** Only validates fields that exist in the configuration; any other is refused with `400 UNKNOWN_FIELD`

- **Path Canonicalization:** File paths are canonicalized to prevent path traversal attacks (../)

- **Path Validation:** Rejects paths with suspicious patterns after normalization

- **Audit Logging:** All validation requests are logged with client IP addresses

- **Input Validation:** JSON body is validated before processing

- **No Execution:** Endpoint only reads from filesystem, never writes or executes

**Notes:**

- Used by the web UI for real-time field validation

- Returns HTTP 200 with `valid` for every known field; `400` (`INVALID_JSON`, `MISSING_FIELD_NAME`, `UNKNOWN_FIELD`) only for a malformed request

- File system checks verify actual file/directory existence and permissions

- Does not modify configuration - use `/options/set` to save values

- Failed validation attempts for unknown fields are logged as security warnings

# Key And Secret Management

## /options/upload-key

**HTTP Method:** POST

**Description:** Uploads a PEM signing key, adds it to the saved keys and, by default, makes it the active signing key.

**Request Format:**

`multipart/form-data` with the PEM key as its first file, at most 64 KiB, named `*.pem`, `*.key` or with no extension. It is stored under `/etc/rpi-sb-provisioner/keys/` by its file name.

An optional `activate` form field set to `if-none` makes the key active only when no key is active yet. The web interface sends it, so a new key replaces the one in use only when an operator chooses it; without it the uploaded key becomes active, as older scripts expect. The response's `activated` says which happened.

``` bash
curl -X POST -H "Authorization: Bearer $RPI_SB_TOKEN" \
  -F "keyfile=@customer-key.pem" -F "activate=if-none" \
  http://localhost:3142/options/upload-key
```

**Response Format:**

``` json
{
  "success": true,
  "path": "/etc/rpi-sb-provisioner/keys/customer-key.pem",
  "filename": "customer-key.pem",
  "keyId": "a1b2c3d4e5f6",
  "activated": true,
  "keyInfo": {
    "algorithm": "RSA",
    "keySize": 2048,
    "isPrivateKey": true,
    "fingerprint": "sha256:...",
    "isFitForPurpose": true,
    "statusMessage": "Key is suitable for Raspberry Pi secure boot signing",
    "statusLevel": "success",
    "valid": true
  }
}
```

**Error Responses:** `400` with `PARSE_ERROR`, `NO_FILE`, `FILE_TOO_LARGE`, `INVALID_FILE_TYPE` or `INVALID_KEY_FORMAT`; `409` with `DEVICE_KEY_BLANK` or `DEVICE_KEY_UNAVAILABLE` when this host cannot encrypt the key at rest; `500` with `STORAGE_ERROR`, `SAVE_ERROR`, `WRAP_ERROR` or `REGISTRY_ERROR`.

**Notes:**

- Uploaded PEM keys are device-wrapped at rest before the handler returns. If device wrapping fails, the upload is rejected and the plaintext file is removed.

- Activating a PEM key, by upload or later, sets `CUSTOMER_KEY_FILE_PEM` and clears `CUSTOMER_KEY_PKCS11_NAME`, and empties the workdir cache

- Uploaded keys are added to the saved-key registry. Use `/options/keys/activate`
  to make a saved key the active provisioning key.

## Signing Key Registry

The Options page and the endpoints below manage a saved-key registry at
`/etc/rpi-sb-provisioner/keys/registry.json`. One key is active at a time;
activating a key updates `CUSTOMER_KEY_FILE_PEM` or `CUSTOMER_KEY_PKCS11_NAME`
in the main config. Legacy single-key config entries are migrated into the
registry automatically on first access.

## /options/keys

**HTTP Method:** GET

**Description:** Lists saved PEM and PKCS#11 signing keys and reports which key
is active.

**Response Format:**

``` json
{
  "activeKeyId": "a1b2c3d4e5f6",
  "keys": [
    {
      "id": "a1b2c3d4e5f6",
      "type": "pem",
      "label": "production-2026",
      "path": "/etc/rpi-sb-provisioner/keys/production-2026.pem",
      "fingerprint": "sha256:...",
      "algorithm": "RSA",
      "keySize": 2048,
      "isFitForPurpose": true,
      "statusMessage": "Key is suitable for Raspberry Pi secure boot signing",
      "statusLevel": "success",
      "wrapped": true,
      "addedAt": "2026-06-30T10:15:00Z"
    }
  ]
}
```

A PKCS#11 key has `uri` in place of `path`.

## /options/keys/activate

**HTTP Method:** POST

**Description:** Makes a saved registry key the active provisioning key.

**Request Format:**

``` json
{
  "id": "a1b2c3d4e5f6"
}
```

**Response Format:**

``` json
{
  "success": true,
  "activeKeyId": "a1b2c3d4e5f6"
}
```

**Notes:**

- Activating a key with a different fingerprint invalidates cached signed
  artefacts in the workdir.

- Errors: `400 MISSING_KEY_ID`, `400 KEY_ACTIVATE_FAILED` (with the reason in `error`).

## /options/keys/remove

**HTTP Method:** POST

**Description:** Removes a saved key from the registry. The active key cannot
be removed until another key is activated.

**Request Format:**

``` json
{
  "id": "a1b2c3d4e5f6"
}
```

**Response Format:** `{"success": true}`. Errors: `400 MISSING_KEY_ID`, `400 KEY_REMOVE_FAILED`.

## /options/keys/register-pkcs11

**HTTP Method:** POST

**Description:** Adds a PKCS#11 key to the saved-key registry.

**Request Format:**

``` json
{
  "uri": "pkcs11:object=my-signing-key;type=private",
  "label": "HSM production key",
  "pin": "optional-pin",
  "activate": true
}
```

Only `uri` is required. `label` defaults to the URI and `activate` to `true`. The PIN is used to check the key and is not stored; store one with `/options/set-pkcs11-pin`.

**Response Format:**

``` json
{
  "success": true,
  "keyId": "a1b2c3d4e5f6",
  "keyInfo": {
    "algorithm": "RSA",
    "keySize": 2048,
    "fingerprint": "sha256:...",
    "isFitForPurpose": true,
    "statusMessage": "Key is suitable for Raspberry Pi secure boot signing",
    "statusLevel": "success",
    "valid": true
  }
}
```

**Error Responses:** `400 MISSING_PKCS11_URI`, `400 INVALID_PKCS11_KEY`, `500 REGISTRY_ERROR`.

## /options/keys/wrap

**HTTP Method:** POST

**Description:** Device-wraps a saved PEM key at rest in place.

**Request Format:**

``` json
{
  "id": "a1b2c3d4e5f6"
}
```

**Notes:**

- Requires a usable device key on the provisioning host. Where there is none the
  request is refused with `409` and `DEVICE_KEY_BLANK` (the slot can be
  programmed) or `DEVICE_KEY_UNAVAILABLE`, carrying the reason and, where one
  exists, the remedy in `details`.

- Returns `{"success": true}`, also when the key was already wrapped. `404 KEY_NOT_FOUND` if `id` names no PEM key; HTTP 500 with `{"success": false, "error": ...}` if wrapping fails.

## /options/validate-key

**HTTP Method:** POST

**Description:** Validates either a PEM key file or a PKCS#11 URI and returns key metadata.

**Request Format:**

For a PEM key:

``` json
{
  "path": "/etc/rpi-sb-provisioner/keys/customer-key.pem"
}
```

For a PKCS#11 key:

``` json
{
  "uri": "pkcs11:object=my-signing-key;type=private",
  "pin": "optional-pin"
}
```

**Response Format:**

``` json
{
  "keyType": "pkcs11",
  "keyInfo": {
    "algorithm": "RSA",
    "keySize": 2048,
    "isPrivateKey": true,
    "fingerprint": "sha256:...",
    "isFitForPurpose": true,
    "statusMessage": "Key is suitable for Raspberry Pi secure boot signing",
    "statusLevel": "success",
    "valid": true
  }
}
```

`keyType` is `pem` or `pkcs11`; an invalid key still returns HTTP 200, with `valid` false and an `errorMessage`. A request with neither `uri` nor `path` gets `400 MISSING_KEY_IDENTIFIER`; an unsafe path gets `400 INVALID_KEY_PATH`.

## /options/signing-status

**HTTP Method:** GET

**Description:** Reports whether the provisioning scripts would find a usable signing key. Never returns key material.

**Response Format:**

``` json
{
  "available": false,
  "mode": "none",
  "reason": "No signing key is configured."
}
```

`mode` is `pem`, `pem-wrapped`, `pkcs11`, `none` or `conflict` (both a PEM and a PKCS#11 key are configured). `reason` is present when there is a problem.

## /options/pkcs11-status

**HTTP Method:** GET

**Description:** Reports whether the OpenSSL `pkcs11-provider` is installed and loadable. This does not touch a token and does not require a PIN.

**Response Format:**

``` json
{
  "providerAvailable": true
}
```

## /options/pkcs11-discover

**HTTP Method:** POST

**Description:** Enumerates key objects visible to `pkcs11-provider` through p11-kit so the WebUI can offer a key picker.

**Request Format:**

``` json
{
  "pin": "optional-pin"
}
```

The request body is optional. If no PIN is supplied, the service uses the stored PIN if one is configured.

**Response Format:**

``` json
{
  "providerAvailable": true,
  "objects": [
    {
      "uri": "pkcs11:token=token-label;object=my-signing-key;type=private",
      "label": "my-signing-key",
      "token": "token-label",
      "type": "private"
    }
  ]
}
```

If discovery fails, the response may include `errorMessage`.

## /options/pkcs11-pin-status

**HTTP Method:** GET

**Description:** Reports whether an HSM PIN is stored. The PIN value is never returned.

**Response Format:**

``` json
{
  "configured": true
}
```

## /options/set-pkcs11-pin

**HTTP Method:** POST

**Description:** Stores or removes the HSM PIN used for PKCS#11 signing.

**Request Format:**

``` json
{
  "pin": "123456"
}
```

An empty `pin` removes the stored PIN. A PIN may be up to 256 characters.

**Response Format:**

``` json
{
  "success": true,
  "configured": true
}
```

Removing the PIN returns `"configured": false` and `"message": "PIN removed"`. Errors: `400 INVALID_JSON`, `400 MISSING_PIN`, `400 PIN_TOO_LONG`, `500 PIN_REMOVE_ERROR`.

**Notes:**

- Stored PINs are device-wrapped at rest. Wrapping is not optional: on a host
  with no usable device key the PIN is refused with `409` and
  `DEVICE_KEY_BLANK` or `DEVICE_KEY_UNAVAILABLE` rather than stored in
  plaintext, with the remedy in `details` where there is one.

- The PIN is never returned by the API

## /options/device-key-status

**HTTP Method:** GET

**Description:** Reports whether this host has a usable firmware crypto device
key, and so whether it can store signing keys and HSM PINs at all. Without one
those operations are refused rather than falling back to plaintext.

`state` is one of `ok`, `blank`, `locked`, `no_slot` or `no_service`.
`can_provision` is true only for `blank` — the one state an operator can fix,
by generating a key.

**Response Format:**

``` json
{
  "available": false,
  "state": "blank",
  "can_provision": true,
  "device_unique": true,
  "key_id": 1,
  "reason": "This host's OTP key slot has never been programmed, so there is no device key to protect stored secrets with.",
  "remedy": "Generate a device key for this host. This writes to OTP and cannot be undone."
}
```

## /options/provision-device-key

**HTTP Method:** POST

**Description:** Generates this host's device key in OTP.

**This writes to OTP permanently and cannot be undone.** On BCM2712 there is a
single key slot and it is the device-unique slot, so there is no spare to use
instead. The request must carry the confirmation token; a bare POST is rejected
with `CONFIRMATION_REQUIRED`. Refused unless `/options/device-key-status`
reports `can_provision`.

**Request Format:**

``` json
{
  "confirm": "BURN OTP"
}
```

**Response Format:**

``` json
{
  "provisioned": true,
  "available": true,
  "state": "ok",
  "key_id": 1,
  "message": "Device key generated. Secrets are now encrypted at rest."
}
```

A host that already has a key returns `provisioned: false` with
`available: true` — idempotent success, with no OTP write attempted.

## /options/encryption-status

**HTTP Method:** GET

**Description:** Reports whether configured local secrets are present and device-wrapped at rest.

**Response Format:**

``` json
{
  "pin": {
    "configured": true,
    "wrapped": true
  },
  "key": {
    "configured": true,
    "wrapped": true
  },
  "anyUnwrapped": false
}
```

## /options/migrate-secrets

**HTTP Method:** POST

**Description:** Device-wraps previously plaintext stored secrets in place.

**Request Format:**

``` json
{
  "target": "all"
}
```

`target` may be `pin`, `key`, or `all`. If omitted, `all` is used.

**Response Format:**

``` json
{
  "success": true,
  "pin": {
    "migrated": true
  },
  "key": {
    "migrated": true
  }
}
```

**Notes:**

- If any secret could not be wrapped the response is HTTP 500 with `success` false and an `error`.

- Every migration here shares one precondition. Where the host has no usable
  device key the request is refused up front with `409` and `DEVICE_KEY_BLANK`
  or `DEVICE_KEY_UNAVAILABLE`, rather than reporting a per-secret failure whose
  shared cause is not named.

# /options/clear-workdir

**HTTP Method:** POST

**Description:** Empties the working directory named by `RPI_SB_WORKDIR`.

**Parameters:** None

**Response Format:**

HTTP 200 OK with no body on success.

**Notes:**

- Useful when switching OS images or resetting provisioning state

- Does not delete the working directory itself, only its contents

- Returns 200 when `RPI_SB_WORKDIR` is unset or does not exist

- Refused with `409 WORKDIR_UNSAFE` when the workdir holds the provisioner's images, database, keys or logs, a home directory or a system directory

# Firmware Management

## /options/firmware/list

**HTTP Method:** GET

**Description:** Lists the bootloader firmware available for the configured device family, and the one selected.

**Response Format:**

``` json
{
  "deviceFamily": "5",
  "chipNumber": "2712",
  "selectedFirmwareFile": "/usr/lib/firmware/raspberrypi/bootloader-2712/default/pieeprom-2025-01-17.bin",
  "firmwareList": [
    {
      "version": "2025-01-17",
      "filename": "pieeprom-2025-01-17.bin",
      "filepath": "/usr/lib/firmware/raspberrypi/bootloader-2712/default/pieeprom-2025-01-17.bin",
      "releaseChannel": "default",
      "size": "2097152"
    }
  ]
}
```

**Notes:**

- Scans `/lib/firmware/raspberrypi/bootloader-<chip>/` and its release channels (`default`, `latest`, `beta`, `stable`, `critical`)

- `size` is a string, in bytes

- `selectedFirmwareFile` is empty when the package default is used

- The Options page's firmware browser is part of the Options page itself; there is no separate firmware page

## /options/firmware/set

**HTTP Method:** POST

**Description:** Sets `RPI_DEVICE_FIRMWARE_FILE`. An empty `firmware_path` returns to the package default. The path must be a regular file under `/lib/firmware/raspberrypi/bootloader-*`, and is stored in canonical form. The workdir cache is emptied so the next device gets the new firmware.

**Request Format:**

``` json
{
  "firmware_path": "/lib/firmware/raspberrypi/bootloader-2712/default/pieeprom-2025-01-17.bin"
}
```

**Response Format:**

HTTP 200 OK with no body on success.

**Error Responses:**

``` json
{
  "error": "Selected firmware file does not exist",
  "error_code": "FIRMWARE_NOT_FOUND"
}
```

Other errors: `400 INVALID_JSON`, `400 INVALID_FIRMWARE_PATH`, `400 NOT_A_FILE`, `400 INVALID_PATH`, `500 CONFIG_WRITE_ERROR`.

## /options/firmware/notes/{version}

**HTTP Method:** GET

**Description:** Retrieves the release notes for one firmware version, from `release-notes.md` for the configured family's chip (BCM2711 for family `4`, otherwise BCM2712).

**Path Parameters:**

| Parameter | Type   | Required | Description                           |
|-----------|--------|----------|---------------------------------------|
| version   | String | Yes      | Firmware version in YYYY-MM-DD format |

**Response Format:**

``` json
{
  "version": "2025-01-17",
  "notes": "## 2025-01-17: Description\n\n* Feature 1\n* Bug fix 2\n"
}
```

**Error Responses:**

HTTP 404:

``` json
{
  "error": "No release notes found for version 2025-01-17"
}
```

# Bootloader Configuration

Devices get either the package default bootloader configuration for the provisioning style (`/var/lib/rpi-sb-provisioner/bootloader.secure` for `secure-boot`, `bootloader.naked` otherwise) or a custom one kept in `/etc/rpi-sb-provisioner/bootloader.conf`. The choice is `RPI_DEVICE_BOOTLOADER_CONFIG_FILE`: empty for the default, or that file's path for the custom one. The next device to bootstrap gets the change.

## /options/bootloader-config

**HTTP Method:** GET

**Description:** The bootloader configuration editor (HTML). There is no JSON form; read the setting from `/options/get`.

## /options/bootloader-config/help

**HTTP Method:** GET

**Description:** The Raspberry Pi documentation for each bootloader setting, as shipped in the package.

**Response Format:**

``` json
{
  "source": "...",
  "commit": "...",
  "licence": "...",
  "attribution": "...",
  "settings": {
    "BOOT_ORDER": "<p>...</p>"
  }
}
```

Each setting's text is HTML. If the file is missing, HTTP 404 with `{"settings": {}}`.

## /options/bootloader-config/check

**HTTP Method:** POST

**Description:** Checks a configuration without saving it.

**Request Format:**

``` json
{ "content": "[all]\nBOOT_UART=1\nBOOT_ORDER=0xf461\n" }
```

**Response Format:**

``` json
{
  "errors": [],
  "warnings": [
    { "line": 2, "message": "BOOT_UARTX is not a setting the Raspberry Pi documentation describes" }
  ],
  "bytes": 47,
  "max_bytes": 4076
}
```

Errors are lines that are not plain ASCII, not a `NAME=value` setting, `[filter]` or `# comment`, an unclosed filter, or a `BOOT_ORDER` that is not a hexadecimal number of up to eight digits. `bytes` is the size on the device: with a final newline and, for `secure-boot`, the `SIGNED_BOOT=1` bootstrap adds when it is missing. More than `max_bytes`, the EEPROM's limit, is an error on line 0. Unknown setting names are only warnings.

A body without a string `content` gets `400 INVALID_REQUEST`; content over 64 KiB gets `413 TOO_LARGE`.

## /options/bootloader-config/save

**HTTP Method:** POST

**Description:** Checks, then saves the custom configuration and puts it in use.

**Request Format:** as `/check`.

**Response Format:**

The `/check` result with `"saved": true` and `"in_use": "custom"`. If the check finds errors, HTTP 400 with the same result and `"saved": false`; nothing is written. A write failure gets `500 WRITE_ERROR`.

The save is recorded in the audit log as `BOOTLOADER_CONFIG_SAVE`, with the operator.

## /options/bootloader-config/use

**HTTP Method:** POST

**Description:** Chooses which configuration devices get. The custom file is kept either way, so the choice can be reversed.

**Request Format:**

``` json
{ "choice": "default" }
```

`choice` is `default` or `custom`.

**Response Format:**

``` json
{ "in_use": "default" }
```

**Error Responses:** `400 INVALID_REQUEST` for any other choice; `409 NO_CUSTOM` when choosing `custom` before one has been saved; `500 WRITE_ERROR`. Recorded in the audit log as `BOOTLOADER_CONFIG_USE`.
