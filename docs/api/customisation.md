The Customisation API provides full CRUD (Create, Read, Update, Delete) operations for managing customisation scripts. These scripts allow you to customize the provisioning process at various stages.

# /customisation/list-scripts

**HTTP Method:** GET

**Description:** Lists all available customisation scripts and hook points in the system.

**Parameters:** None

**Response Format:**

The endpoint returns a JSON object containing script information:

``` json
{
  "scripts": [
    {
      "filename": "secure-boot-post-flash.sh",
      "exists": true,
      "enabled": true,
      "provisioner": "secure-boot",
      "stage": "post-flash",
      "description": "Runs after images have been flashed to the device"
    },
    ...
  ]
}
```

# /customisation/get-script

**HTTP Method:** GET

**Description:** Retrieves the content and metadata of a specific customisation script.

**Parameters:**

| Parameter | Type   | Required | Description                         |
|-----------|--------|----------|-------------------------------------|
| script    | String | Yes      | Name of the script file to retrieve |

**Response Format:**

The endpoint returns a JSON object with script details:

``` json
{
  "exists": true,
  "filename": "secure-boot-post-flash.sh",
  "content": "#!/bin/sh\n\n# Script content here...",
  "enabled": true
}
```

**Error Responses:**

If the script name is missing:

``` json
{
  "error": {
    "status": 400,
    "title": "Missing Parameter",
    "code": "MISSING_SCRIPT_NAME",
    "detail": "Script name is required"
  }
}
```

If the script is not found:

``` json
{
  "error": {
    "status": 400,
    "title": "Script Not Found",
    "code": "SCRIPT_NOT_FOUND",
    "detail": "The requested script file could not be found"
  }
}
```

**Notes:**

- For known hook points that don’t exist yet, the API will return a template with default content.

- The `enabled` flag indicates if the script has executable permissions.

# /customisation/delete-script

**HTTP Method:** POST

**Description:** Deletes a customisation script from the system.

**Parameters:**

| Parameter | Type   | Required | Description                                          |
|-----------|--------|----------|------------------------------------------------------|
| script    | String | Yes      | Name of the script to delete (without .sh extension) |

**Response Format:**

Plain text success message: "Script deleted successfully"

**Error Responses:**

``` json
{
  "error": {
    "status": 500,
    "title": "Deletion Error",
    "code": "SCRIPT_DELETE_ERROR",
    "detail": "Failed to delete script file"
  }
}
```

# /customisation/disable-script

**HTTP Method:** POST

**Description:** Disables a script by removing its executable permissions (sets permissions to 0644).

**Parameters:**

| Parameter | Type   | Required | Description                                           |
|-----------|--------|----------|-------------------------------------------------------|
| script    | String | Yes      | Name of the script to disable (without .sh extension) |

**Response Format:**

Plain text success message: "Script disabled successfully"

# /customisation/enable-script

**HTTP Method:** POST

**Description:** Enables a script by adding executable permissions (sets permissions to 0755).

**Parameters:**

| Parameter | Type   | Required | Description                                          |
|-----------|--------|----------|------------------------------------------------------|
| script    | String | Yes      | Name of the script to enable (without .sh extension) |

**Response Format:**

Plain text success message: "Script enabled successfully"

# /customisation/save-script

**HTTP Method:** POST

**Description:** Saves or updates a customisation script with new content.

**Request Format:**

``` json
{
  "filename": "sb-provisioner-post-flash",
  "content": "#!/bin/sh\n\necho \"Custom script content\"\nexit 0\n"
}
```

**Response Format:**

Returns JSON with updated script metadata including SHA256 hash:

``` json
{
  "filename": "sb-provisioner-post-flash.sh",
  "executable": true,
  "enabled": true,
  "sha256": "abc123...",
  "provisioner": "sb-provisioner",
  "stage": "post-flash",
  "description": "Runs after images have been flashed to the device"
}
```

**Error Responses:**

``` json
{
  "error": {
    "status": 400,
    "title": "Missing Fields",
    "code": "MISSING_REQUIRED_FIELDS",
    "detail": "Filename and content are required fields"
  }
}
```

**Notes:**

- New scripts are created with non-executable permissions (0644)

- Existing scripts preserve their original permissions when updated

- The .sh extension is automatically added if not present

# /customisation/upload-script

**HTTP Method:** POST

**Description:** Uploads a script file via multipart/form-data.

**Request Format:**

Multipart form data with a field named "script" containing the file.

**Response Format:**

Plain text success message: "Script file uploaded successfully"

**Error Responses:**

``` json
{
  "error": {
    "status": 400,
    "title": "Missing File",
    "code": "MISSING_SCRIPT_FILE",
    "detail": "Script file is required in the form data with field name 'script'"
  }
}
```

**Notes:**

- Uploaded scripts are automatically set to executable (0755)

- The .sh extension is automatically added if not present

# /customisation/list-hooks

**HTTP Method:** GET

**Description:** Lists all available hook points for customisation scripts, including provisioners, stages, and their descriptions.

**Parameters:** None

**Response Format:**

``` json
{
  "provisioners": ["sb-provisioner", "fde-provisioner", "naked-provisioner", "idp-provisioner"],
  "stages": [
    {
      "name": "bootstrap",
      "description": "Executed when a device is detected, before provisioning begins"
    },
    {
      "name": "provision-started",
      "description": "Executed at the start of provisioning, before image preparation"
    },
    {
      "name": "bootfs-mounted",
      "description": "Executed after boot image is mounted, before modifications"
    }
  ],
  "hooks": [
    {
      "filename": "sb-provisioner-bootstrap.sh",
      "provisioner": "sb-provisioner",
      "stage": "bootstrap",
      "exists": true,
      "enabled": true
    }
  ]
}
```

**Notes:**

- This endpoint provides a comprehensive list of all possible customisation points

- `sb-provisioner`, `fde-provisioner`, and `naked-provisioner` support `bootstrap`, `provision-started`, `bootfs-mounted`, `rootfs-mounted`, `post-flash`, and `provision-failed`

- `idp-provisioner` supports `provision-started`, `post-flash`, and `provision-failed`; IDP provisioning does not expose host-side `bootfs-mounted` or `rootfs-mounted` stages because partition creation and encryption are handled by fastbootd on the device

- The `exists` field indicates whether a script file currently exists for that hook

- The `enabled` field indicates whether the script has executable permissions

# Hook Arguments And Environment

Customisation scripts receive stage-specific positional arguments. The WebUI
script templates document the exact argument order for each hook.

All hooks also receive device-identity environment variables:

| Variable | Description |
| --- | --- |
| `TARGET_USB_PATH` | USB topology path (for example `1-1.2`) |
| `TARGET_DEVICE_PATH` | USB device node (for example `/dev/bus/usb/001/004`) |
| `TARGET_DEVICE_SERIAL` | Device serial number |
| `TARGET_DEVICE_FAMILY` | USB model ID / SoC family (`bootstrap` only) |
| `FASTBOOT_DEVICE_SPECIFIER` | Active fastboot route on provisioning hooks |
| `RPI_DEVICE_STORAGE_TYPE` | Storage block device (for example `mmcblk0`) |

`post-flash` hooks additionally receive manufacturing metadata as environment
variables after `metadata_gather`. Names mirror the manufacturing database
columns in uppercase — for example `BOARDNAME`, `ETH_MAC`, `OS_IMAGE_SHA256`,
`CUSTOMER_KEY_FINGERPRINT`, and `CUSTOMER_KEY_LABEL`. Integer fields that
would be SQL `NULL` are exported as empty strings.

## provision-failed

The `provision-failed` hook runs when bootstrap, triage, or provisioning exits
with an error. Typical uses include driving programming-rig status LEDs or
buzzers.

| Context | Positional arguments |
| --- | --- |
| Bootstrap failure (`sb-`, `fde-`, `naked-provisioner` only) | serial, device family, USB path, device path |
| Provisioning failure | fastboot specifier, serial, storage type |

`PROVISION_FAILED_CONTEXT` is set to `bootstrap` or `provisioning` for the
duration of the hook. Manufacturing metadata is not available on failure.

The hook is not invoked for duplicate `bootstrap@` lock contention or for triage
failure while bootstrap is still in progress (expected USB re-enumeration during
DUT reboot).

# /customisation/create-script

**HTTP Method:** GET

**Description:** Returns a default template for creating a new customisation script.

**Parameters:**

| Parameter | Type   | Required | Description                                           |
|-----------|--------|----------|-------------------------------------------------------|
| script    | String | Yes      | Name of the script (e.g., "sb-provisioner-bootstrap") |

**Response Format:**

``` json
{
  "exists": false,
  "filename": "sb-provisioner-bootstrap",
  "content": "#!/bin/sh\n\n# Script template content...",
  "enabled": false
}
```

**Error Responses:**

``` json
{
  "error": {
    "status": 400,
    "title": "Invalid Script Name",
    "code": "INVALID_SCRIPT_NAME",
    "detail": "The script name is not a valid hook point"
  }
}
```
