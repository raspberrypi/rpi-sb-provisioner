The Configuration API provides endpoints for managing system configuration options, firmware selection, and working directory management.

# /options/get

**HTTP Method:** GET

**Description:** Retrieves all current configuration values.

**Parameters:** None

**Response Format:**

``` json
{
  "GOLD_MASTER_OS_FILE": "/srv/rpi-sb-provisioner/images/raspios-2025-04-01.img",
  "RPI_SB_WORKDIR": "/srv/rpi-sb-provisioner/work",
  "RPI_SB_PROVISIONER_MANUFACTURING_DB": "/srv/rpi-sb-provisioner/manufacturing.db",
  "RPI_DEVICE_FAMILY": "5",
  "RPI_DEVICE_FIRMWARE_FILE": "/lib/firmware/raspberrypi/bootloader-2712/default/pieeprom-2025-01-17.bin",
  "RPI_CONNECT_API_KEY": ""
}
```

**Notes:**

- Returns all configuration key-value pairs from `/etc/rpi-sb-provisioner/config`

- Configuration values control provisioning behavior

# /options/set

**HTTP Method:** POST

**Description:** Updates one or more configuration values.

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

``` json
{
  "error": {
    "status": 500,
    "title": "Config Error",
    "code": "CONFIG_WRITE_ERROR",
    "detail": "Failed to write configuration file"
  }
}
```

**Notes:**

- Merges provided values with existing configuration

- Automatically creates manufacturing database file if path is set and file doesn’t exist

- Clears working directory contents if `RPI_SB_WORKDIR`, selected firmware, or signing-key settings are modified

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

**Security Measures:**

- **HTTP Method Restriction:** Only accepts POST requests; returns 405 Method Not Allowed for other methods

- **Dynamic Field Whitelist:** Only validates fields that exist in the configuration file; rejects unknown fields

- **Path Canonicalization:** File paths are canonicalized to prevent path traversal attacks (../)

- **Path Validation:** Rejects paths with suspicious patterns after normalization

- **Audit Logging:** All validation requests are logged with client IP addresses

- **Input Validation:** JSON body is validated before processing

- **No Execution:** Endpoint only reads from filesystem, never writes or executes

**Notes:**

- Used by the web UI for real-time field validation

- Always returns HTTP 200 with JSON indicating validation success/failure

- File system checks verify actual file/directory existence and permissions

- Does not modify configuration - use `/options/set` to save values

- Failed validation attempts for unknown fields are logged as security warnings

# Key And Secret Management

## /options/upload-key

**HTTP Method:** POST

**Description:** Uploads a PEM signing key and updates `CUSTOMER_KEY_FILE_PEM`.

**Request Format:**

Multipart form data containing the PEM key file.

**Response Format:**

``` json
{
  "success": true,
  "path": "/etc/rpi-sb-provisioner/keys/customer-key.pem",
  "filename": "customer-key.pem",
  "keyInfo": {
    "algorithm": "RSA",
    "keySize": 2048,
    "isPrivateKey": true,
    "fingerprint": "sha256:...",
    "isFitForPurpose": true
  }
}
```

**Notes:**

- Uploaded PEM keys are device-wrapped at rest before the handler returns. If device wrapping fails, the upload is rejected and the plaintext file is removed.

- Uploading a PEM key clears `CUSTOMER_KEY_PKCS11_NAME`

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

- Requires firmware-crypto support on the provisioning host.

- Returns an error if the key is already wrapped or wrapping fails.

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

An empty `pin` removes the stored PIN.

**Response Format:**

``` json
{
  "success": true,
  "configured": true
}
```

**Notes:**

- Stored PINs are device-wrapped at rest when firmware crypto support is available

- The PIN is never returned by the API

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

# /options/clear-workdir

**HTTP Method:** POST

**Description:** Clears all contents of the working directory specified in `RPI_SB_WORKDIR` configuration.

**Parameters:** None

**Response Format:**

HTTP 200 OK with no body on success.

**Notes:**

- Useful when switching OS images or resetting provisioning state

- Does not delete the working directory itself, only its contents

- Safe to call even if directory doesn’t exist

# Firmware Management

## /options/firmware

**HTTP Method:** GET

**Description:** Lists available firmware versions for the configured device family.

**Parameters:** None

**Response Format:**

Returns HTML view with firmware list, release notes, and selection interface.

**Notes:**

- Scans `/lib/firmware/raspberrypi/bootloader-{chip}/` for available firmware

- Automatically groups firmware by version across release channels

- Shows firmware from default, latest, beta, stable, and critical channels

## /options/firmware/set

**HTTP Method:** POST

**Description:** Sets the selected firmware file for device provisioning.

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
  "error": {
    "status": 400,
    "title": "Invalid Request",
    "code": "FIRMWARE_NOT_FOUND",
    "detail": "Selected firmware file does not exist"
  }
}
```

## /options/firmware/notes/{version}

**HTTP Method:** GET

**Description:** Retrieves release notes for a specific firmware version.

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

``` json
{
  "error": "No release notes found for version 2025-01-17"
}
```
