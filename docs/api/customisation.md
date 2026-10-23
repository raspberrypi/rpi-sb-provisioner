The Customisation API manages the hook scripts the provisioners run at fixed points in each device's run. Scripts live in `/etc/rpi-sb-provisioner/scripts/` as `<provisioner>-<stage>.sh`.

| Provisioner         | Stages                                                                                             |
|---------------------|----------------------------------------------------------------------------------------------------|
| `sb-provisioner`    | `bootstrap`, `provision-started`, `bootfs-mounted`, `rootfs-mounted`, `post-flash`, `provision-failed` |
| `fde-provisioner`   | as `sb-provisioner`                                                                                |
| `naked-provisioner` | as `sb-provisioner`                                                                                |
| `idp-provisioner`   | `provision-started`, `post-flash`, `provision-failed`                                               |

IDP provisioning has no host-side `bootfs-mounted` or `rootfs-mounted` stage, because fastbootd creates and encrypts the partitions on the device, and no `bootstrap` stage of its own.

The endpoints that save, upload, enable, disable or delete a script act only on these hook names; any other name is refused with `400 INVALID_SCRIPT_NAME`. Every such change is recorded in the [audit log](audit.md) with the operator, the script's SHA-256 and its mode.

Where an endpoint takes a `script` parameter, send it in the query string or as a form field (`application/x-www-form-urlencoded`), not in a JSON body. The `.sh` suffix is optional.

# /customisation/list-scripts

**HTTP Method:** GET

**Description:** Lists every file in the scripts directory, followed by a placeholder for each hook point that has no script. With `Accept: text/html` the customisation page is returned instead.

**Response Format:**

``` json
{
  "scripts": [
    {
      "filename": "sb-provisioner-post-flash.sh",
      "exists": true,
      "executable": true,
      "enabled": true,
      "sha256": "3f1c...e9",
      "provisioner": "sb-provisioner",
      "stage": "post-flash",
      "description": "Executed after bootfs and rootfs have been flashed to the device"
    },
    {
      "filename": "sb-provisioner-bootstrap.sh",
      "exists": false,
      "executable": false,
      "enabled": false,
      "provisioner": "sb-provisioner",
      "stage": "bootstrap",
      "description": "Executed when a device is detected, before provisioning begins"
    }
  ]
}
```

`enabled` and `executable` are the same: whether the owner may execute the file. `sha256` is present only for files that exist.

# /customisation/get-script

**HTTP Method:** GET

**Description:** Returns a script's content. For a hook point with no script yet, returns the default template with `exists: false`. With `Accept: text/html` the script editor is returned instead.

**Parameters:**

| Parameter | Type   | Required | Description                               |
|-----------|--------|----------|-------------------------------------------|
| script    | String | Yes      | Script name, such as `sb-provisioner-post-flash` |

**Response Format:**

``` json
{
  "exists": true,
  "filename": "sb-provisioner-post-flash",
  "content": "#!/bin/sh\n\n# Script content here...",
  "enabled": true
}
```

`filename` is returned without `.sh`.

**Error Responses:**

| Status | `error_code`          | Cause                                                                 |
|--------|-----------------------|-----------------------------------------------------------------------|
| 400    | `MISSING_SCRIPT_NAME` | No `script` parameter                                                 |
| 400    | `INVALID_SCRIPT_NAME` | No such file and not a hook point; `details` lists the valid names    |
| 400    | `SCRIPT_NOT_FOUND`    | The file exists but could not be opened                               |

# /customisation/delete-script

**HTTP Method:** POST

**Description:** Deletes a hook script.

**Parameters:**

| Parameter | Type   | Required | Description         |
|-----------|--------|----------|---------------------|
| script    | String | Yes      | Hook name to delete |

**Response Format:**

Plain text: `Script deleted successfully`

**Error Responses:**

| Status | `error_code`          | Cause                          |
|--------|-----------------------|--------------------------------|
| 400    | `MISSING_SCRIPT_NAME` | No `script` parameter          |
| 400    | `INVALID_SCRIPT_NAME` | Not a hook point               |
| 404    | `SCRIPT_NOT_FOUND`    | There is no script to delete   |
| 500    | `SCRIPT_DELETE_ERROR` | The file could not be removed  |

``` bash
curl -X POST -H "Authorization: Bearer $RPI_SB_TOKEN" \
  "http://localhost:3142/customisation/delete-script?script=sb-provisioner-post-flash"
```

# /customisation/disable-script

**HTTP Method:** POST

**Description:** Disables a hook script by setting its mode to 0644. A disabled script is skipped.

**Parameters:**

| Parameter | Type   | Required | Description          |
|-----------|--------|----------|----------------------|
| script    | String | Yes      | Hook name to disable |

**Response Format:**

Plain text: `Script disabled successfully`

**Error Responses:** `400 MISSING_SCRIPT_NAME`, `400 INVALID_SCRIPT_NAME`, `400 SCRIPT_NOT_FOUND` (no such script), `500 SCRIPT_PERMISSION_ERROR`.

# /customisation/enable-script

**HTTP Method:** POST

**Description:** Enables a hook script by setting its mode to 0755, so the provisioner runs it.

**Parameters:**

| Parameter | Type   | Required | Description         |
|-----------|--------|----------|---------------------|
| script    | String | Yes      | Hook name to enable |

**Response Format:**

Plain text: `Script enabled successfully`

**Error Responses:** as for disable-script.

# /customisation/save-script

**HTTP Method:** POST

**Description:** Creates or replaces a hook script. The file is replaced in one step, so a provisioner starting the hook during a save runs the old script or the new, never a truncated one.

**Request Format:**

``` json
{
  "filename": "sb-provisioner-post-flash",
  "content": "#!/bin/sh\n\necho \"Custom script content\"\nexit 0\n"
}
```

**Response Format:**

The script's metadata after saving:

``` json
{
  "filename": "sb-provisioner-post-flash.sh",
  "executable": false,
  "enabled": false,
  "sha256": "abc123...",
  "provisioner": "sb-provisioner",
  "stage": "post-flash",
  "description": "Executed after bootfs and rootfs have been flashed to the device"
}
```

**Error Responses:**

| Status | `error_code`              | Cause                                         |
|--------|---------------------------|-----------------------------------------------|
| 400    | `INVALID_JSON`            | The body is not JSON                          |
| 400    | `MISSING_REQUIRED_FIELDS` | `filename` or `content` is missing            |
| 400    | `INVALID_SCRIPT_NAME`     | Not a hook point                              |
| 411    | —                         | A chunked body (`Transfer-Encoding`)          |
| 413    | `SCRIPT_TOO_LARGE`        | The script is over 1 MiB, or the body over 4 MiB |
| 500    | `FILE_WRITE_ERROR`, `DIR_CREATE_ERROR` | The script could not be written  |

**Notes:**

- A new script is created disabled (0644). Enable it with enable-script.

- Replacing a script keeps its mode, so saving never enables or disables it.

# /customisation/upload-script

**HTTP Method:** POST

**Description:** Uploads a hook script as `multipart/form-data`. The uploaded file's own name, such as `sb-provisioner-post-flash.sh`, chooses the hook.

**Request Format:**

A form field named `script` holding the file.

``` bash
curl -X POST -H "Authorization: Bearer $RPI_SB_TOKEN" \
  -F "script=@sb-provisioner-post-flash.sh" \
  http://localhost:3142/customisation/upload-script
```

**Response Format:**

Plain text: `Script file uploaded successfully`, or an HTML page for `Accept: text/html`.

**Error Responses:**

| Status | `error_code`           | Cause                                               |
|--------|------------------------|-----------------------------------------------------|
| 400    | `INVALID_CONTENT_TYPE` | Not `multipart/form-data`                           |
| 400    | `FORM_PARSE_ERROR`     | The form could not be parsed, or holds no file      |
| 400    | `MISSING_SCRIPT_FILE`  | No file in a field named `script`                   |
| 400    | `INVALID_SCRIPT_NAME`  | The file's name is not a hook point                 |
| 411, 413 | as save-script       | Chunked or oversized body                           |
| 500    | `FILE_WRITE_ERROR`, `DIR_CREATE_ERROR` | The script could not be written     |

**Notes:**

- A new script is created disabled (0644), as with save-script.

- Uploading over an existing script keeps its mode.

# /customisation/list-hooks

**HTTP Method:** GET

**Description:** Lists the provisioners, the stages and every hook point, with whether a script exists for each.

**Response Format:**

``` json
{
  "provisioners": ["fde-provisioner", "idp-provisioner", "naked-provisioner", "sb-provisioner"],
  "stages": [
    {
      "name": "bootfs-mounted",
      "description": "Executed after boot image is mounted, before modifications"
    },
    {
      "name": "bootstrap",
      "description": "Executed when a device is detected, before provisioning begins"
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

Provisioners and stages are listed in alphabetical order.

# Hook Arguments And Environment

The script editor's **Help** describes the same contract.

| Stage | When it runs | Arguments |
| --- | --- | --- |
| `bootstrap` | A device in RPIBOOT mode is found, before its EEPROM is updated. No fastboot yet. Not for IDP. | `$1` serial, `$2` device family (USB product ID, e.g. `2712`), `$3` USB path, `$4` USB device node |
| `provision-started` | The device is in fastboot and provisioning begins. | `$1` fastboot specifier, `$2` serial, `$3` storage device (e.g. `mmcblk0`) |
| `bootfs-mounted` | While the image is prepared, on this server. Once per image, not per device; clear the workdir cache to run it again. Not for IDP. | `$1` boot partition mount point, `$2` root partition mount point |
| `rootfs-mounted` | Straight after `bootfs-mounted`, on the same mounts, with the same once-per-image rule. Not for IDP. | as `bootfs-mounted` |
| `post-flash` | The device is written and its details recorded. | `$1` fastboot specifier, `$2` serial, `$3` storage device |
| `provision-failed` | Bootstrap, triage or provisioning stopped with an error. | see [provision-failed](#provision-failed) |

All hooks also receive device-identity environment variables:

| Variable | Description |
| --- | --- |
| `TARGET_USB_PATH` | USB topology path (for example `1-1.2`) |
| `TARGET_DEVICE_PATH` | USB device node (for example `/dev/bus/usb/001/004`) |
| `TARGET_DEVICE_SERIAL` | Device serial number |
| `TARGET_DEVICE_FAMILY` | USB product ID of the SoC family (`bootstrap` only) |
| `FASTBOOT_DEVICE_SPECIFIER` | What to pass to `fastboot -s`, once the device is in fastboot |
| `RPI_DEVICE_STORAGE_TYPE` | Storage block device (for example `mmcblk0`) |

`post-flash` hooks also receive the device's manufacturing record. Names are the manufacturing database columns in upper case: `BOARDNAME`, `SERIAL`, `ETH_MAC`, `WIFI_MAC`, `BT_MAC`, `MMC_SIZE`, `MMC_CID`, `RPI_DUID`, `BOARD_REVISION`, `PROCESSOR`, `MEMORY`, `MANUFACTURER`, `SECURE`, `JTAG_LOCKED`, `EEPROM_WRITE_PROTECTED`, `PUBKEY_PROGRAMMED`, `DEVKEY_REVOKED`, `SIGNED_BOOT_ENABLED`, `OS_IMAGE_FILENAME`, `OS_IMAGE_SHA256`, `CONNECT_REGISTERED`, `CONNECT_DEVICE_ID`, `EEPROM_SIZE`, `EEPROM_JEDEC`, `EEPROM_UNIQUE_ID`, `BOOTLOADER_BUILD_TIMESTAMP`, `CUSTOMER_KEY_FINGERPRINT` and `CUSTOMER_KEY_LABEL`. A value not recorded is empty.

A hook runs only while enabled, and exiting non-zero fails the device's run. Its output goes to the provisioner's log for the device. Always name the device to fastboot (`fastboot -s "$1" ...`) and give each call its own limit (`timeout 30 fastboot ...`), because fastboot waits for ever for a device that has gone.

## Time limit

Every hook must finish within `RPI_SB_HOOK_TIMEOUT` seconds, 1800 by default.
A hook still running at that point is sent `SIGTERM`, then `SIGKILL` ten seconds
later, and is reported as failed with exit code 124. Raise the limit in the
config file if a hook legitimately needs longer. See
[config_vars.md](../config_vars.md#rpi_sb_hook_timeout).

## provision-failed

The `provision-failed` hook runs when bootstrap, triage or provisioning exits
with an error. Typical uses include driving programming-rig status LEDs or
buzzers.

| Context | Positional arguments |
| --- | --- |
| Bootstrap failure (`sb-`, `fde-`, `naked-provisioner` only) | as `bootstrap`: serial, device family, USB path, device path |
| Provisioning failure | as `provision-started`: fastboot specifier, serial, storage type |

These variables are set for the duration of the hook:

| Variable | Value |
| --- | --- |
| `PROVISION_FAILED_CONTEXT` | `bootstrap` or `provisioning` |
| `PROVISION_FAILED_PERMANENT` | `1` if the device will not be retried, so a rig should show its error rather than its in-progress lights; otherwise `0` |
| `PROVISION_FAILED_REASON` | Why the run failed, when a time-limited command failed; see below |

Manufacturing metadata is not available on failure.

| `PROVISION_FAILED_REASON` | Meaning |
| --- | --- |
| `bootcode-refused` | The board refused its bootcode. It may already hold a customer key in OTP and need the reprovision flag, or the USB cable or connection may be faulty. The failure is marked permanent. |
| `board-absent` | The board did not answer before a long fastboot command. |
| `board-lost` | The board went away part-way through a long fastboot command. |
| `device-refused` | fastbootd answered `FAILED`. |
| `timed-out` | The command ran out of time. |
| `command-failed` | The command failed some other way. |

It is empty when the failure had no recorded cause.

The hook is not invoked for duplicate `bootstrap@` lock contention or for triage
failure while bootstrap is still in progress (expected USB re-enumeration during
DUT reboot).

# /customisation/create-script

**HTTP Method:** POST

**Description:** Returns the default template for a hook point, without writing anything. Use save-script to store it. With `Accept: text/html` the script editor is returned instead.

**Parameters:**

| Parameter | Type   | Required | Description                                           |
|-----------|--------|----------|-------------------------------------------------------|
| script    | String | Yes      | Hook name, such as `sb-provisioner-bootstrap`          |

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

| Status | `error_code`          | Cause                                                       |
|--------|-----------------------|-------------------------------------------------------------|
| 400    | `MISSING_SCRIPT_NAME` | No `script` parameter                                       |
| 400    | `INVALID_SCRIPT_NAME` | Not a hook point; `details` lists the valid names           |
