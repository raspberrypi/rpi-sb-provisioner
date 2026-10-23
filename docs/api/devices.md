The Devices API provides access to information about devices being provisioned, their logs, and associated cryptographic keys.

Device identifiers in these paths are a serial number or, for a device that has not reported one yet, its USB path (such as `1-1.4`). An identifier may contain only letters, digits, `.`, `-` and `:`, up to 64 characters; anything else is answered with `400 DEVICE_NOT_FOUND`.

`/devices` and `/devices/{serialno}` can be read without signing in while the public dashboard is on (see [authentication.md](authentication.md)). The log, key and flag endpoints always need an operator.

# /devices

**HTTP Method:** GET

**Description:** Returns the provisioning state history recorded in `/srv/rpi-sb-provisioner/state.db`. There is one entry per state change, newest first, so a device appears once for every state it has passed through. With `Accept: text/html` the devices page is returned instead.

**Parameters:** None

**Response Format:**

``` json
{
  "devices": [
    {
      "serial": "c561b701",
      "port": "1-1.4",
      "ip_address": "",
      "state": "SB-PROVISIONER-FINISHED",
      "image": "raspios-trixie.img"
    },
    ...
  ]
}
```

**Field Descriptions:**

| Field      | Description                                                                           |
|------------|---------------------------------------------------------------------------------------|
| serial     | Device serial number                                                                  |
| port       | USB path of the port the device is on                                                 |
| ip_address | Address the device reported for flashing over the network, or empty                  |
| state      | State recorded at that point, such as `BOOTSTRAP-STARTED`, `TRIAGE-FINISHED`, `SB-PROVISIONER-STARTED`, `FDE-PROVISIONER-ABORTED` or `PORT-EXCLUDED`. Provisioners prefix their states with `SB-PROVISIONER`, `FDE-PROVISIONER`, `NAKED-PROVISIONER` or `IDP-PROVISIONER`. |
| image      | OS image summary recorded with the state, or empty                                    |

# /devices/{serialno}

**HTTP Method:** GET

**Description:** Returns the latest state of one device, looked up by serial number and then, if that finds nothing, by USB path. With `Accept: text/html` the device's page is returned; it includes logs and per-device flags only for a signed-in operator.

**Path Parameters:**

| Parameter | Type   | Required | Description                          |
|-----------|--------|----------|--------------------------------------|
| serialno  | String | Yes      | Serial number or USB path of the device |

**Response Format:**

``` json
{
  "serial": "c561b701",
  "port": "1-1.4",
  "state": "SB-PROVISIONER-FINISHED"
}
```

**Error Responses:**

If the device is not found, HTTP 400:

``` json
{
  "error": "Device not found in database",
  "error_code": "DEVICE_NOT_FOUND",
  "details": "Requested identifier: c561b701"
}
```

# Device Log Endpoints

## /devices/{serialno}/log/provisioner

**HTTP Method:** GET

**Description:** Returns the provisioner log file for a specific device.

**Path Parameters:**

| Parameter | Type   | Required | Description                 |
|-----------|--------|----------|-----------------------------|
| serialno  | String | Yes      | Serial number of the device |

**Response Format:**

Plain text log file content.

**Error Responses:**

If the log file is not found:

HTTP 400:

``` json
{
  "error": "Log file not found",
  "error_code": "LOG_NOT_FOUND",
  "details": "Attempted path: /var/log/rpi-sb-provisioner/{serialno}/provisioner.log"
}
```

The bootstrap and triage log endpoints answer the same way.

## /devices/{serialno}/log/bootstrap

**HTTP Method:** GET

**Description:** Returns the bootstrap log file for a specific device.

**Path Parameters:**

| Parameter | Type   | Required | Description                 |
|-----------|--------|----------|-----------------------------|
| serialno  | String | Yes      | Serial number of the device |

**Response Format:**

Plain text log file content.

## /devices/{serialno}/log/triage

**HTTP Method:** GET

**Description:** Returns the triage log file for a specific device.

**Path Parameters:**

| Parameter | Type   | Required | Description                 |
|-----------|--------|----------|-----------------------------|
| serialno  | String | Yes      | Serial number of the device |

**Response Format:**

Plain text log file content.

# Per-device flags

Flags change what the next run does to one device. Each is a file in `/etc/rpi-sb-provisioner/special-<flag>/<serial>` holding `once` or `persistent`.

| Flag                 | Effect                                                                                       |
|----------------------|----------------------------------------------------------------------------------------------|
| `skip-eeprom`        | Skip writing the EEPROM and bootloader during bootstrap                                      |
| `reprovision-device` | Provision a device that has been provisioned before, re-signing the bootcode from the original `recovery.bin`. Raspberry Pi 5 family (BCM2712) only. |

## /devices/{serialno}/flags

**HTTP Method:** GET

**Description:** Reports every flag and whether it is set for the device. A USB path is resolved to the device's serial first.

**Response Format:**

``` json
{
  "serial": "c561b701",
  "flags": [
    {
      "id": "reprovision-device",
      "label": "Re-provision Device",
      "description": "Provisions a device that has already been provisioned, ...",
      "constraint": "Raspberry Pi 5 family only (BCM2712)",
      "active": true,
      "mode": "once"
    }
  ]
}
```

`constraint` is present only for flags that apply to some devices. `mode` is `off`, `once` or `persistent`.

## /devices/{serialno}/flags

**HTTP Method:** POST

**Description:** Sets or clears one flag.

**Request Body:**

``` json
{ "flag": "skip-eeprom", "mode": "once" }
```

| Field | Description                                   |
|-------|-----------------------------------------------|
| flag  | A flag id from the table above                |
| mode  | `once`, `persistent`, or `off` to clear it    |

**Response Format:**

``` json
{ "success": true, "flag": "skip-eeprom", "mode": "once", "serial": "c561b701" }
```

**Error Responses:**

| Status | `error_code`                                   | Cause                                              |
|--------|------------------------------------------------|----------------------------------------------------|
| 400    | `INVALID_JSON`, `MISSING_FLAG`, `INVALID_MODE`, `UNKNOWN_FLAG` | Bad request body                        |
| 409    | `SERIAL_NOT_RESOLVED`                          | The device has not reported a serial yet; retry later |
| 500    | `FLAG_DIR_ERROR`, `FLAG_WRITE_ERROR`, `FLAG_REMOVE_ERROR` | The flag file could not be written or removed |

``` bash
curl -X POST -H "Authorization: Bearer $RPI_SB_TOKEN" -H "Content-Type: application/json" \
  -d '{"flag":"reprovision-device","mode":"once"}' \
  http://localhost:3142/devices/c561b701/flags
```

# Device Key Endpoints

## /devices/{serialno}/key/public

**HTTP Method:** GET

**Description:** Downloads the public key file for a specific device.

**Path Parameters:**

| Parameter | Type   | Required | Description                 |
|-----------|--------|----------|-----------------------------|
| serialno  | String | Yes      | Serial number of the device |

**Response Format:**

Binary file (Content-Type: application/octet-stream) containing the device’s public key.

**Error Responses:**

If the key file is not found:

HTTP 400:

``` json
{
  "error": "Public key file not found",
  "error_code": "KEY_NOT_FOUND",
  "details": "Attempted path: /var/log/rpi-sb-provisioner/{serialno}/keypair/{serialno}.pub"
}
```

## /devices/{serialno}/key/private

> **Caution**
>
> **SECURITY-CRITICAL ENDPOINT - DISABLED BY DEFAULT**
>
> This endpoint exposes device private keys via HTTP and is **DISABLED by default** for security reasons. Private keys are cryptographic secrets that should never be transmitted over insecure channels.

**HTTP Method:** GET

**Description:** Downloads the private key file for a specific device in DER format.

**Security Configuration:**

This endpoint is **disabled by default** and requires explicit configuration to enable:

1.  Edit `/etc/rpi-sb-provisioner/config`

2.  Add the following line:

    ``` bash
    RPI_SB_PROVISIONER_ENABLE_PRIVATE_KEY_API=true
    ```

3.  Nothing needs restarting: the setting is read on every request.

4.  **WARNING:** Only enable in secure, isolated networks

**Path Parameters:**

| Parameter | Type   | Required | Description                 |
|-----------|--------|----------|-----------------------------|
| serialno  | String | Yes      | Serial number of the device |

**Response Format:**

Binary file (Content-Type: application/octet-stream) containing the device’s private key in DER format.

**Error Responses:**

If the endpoint is disabled (default), HTTP 403:

``` json
{
  "error": "Private key download API is disabled for security reasons. This endpoint must be explicitly enabled in configuration: Set RPI_SB_PROVISIONER_ENABLE_PRIVATE_KEY_API=true in /etc/rpi-sb-provisioner/config. WARNING: Enabling this endpoint exposes device private keys via HTTP and should only be done in secure, isolated networks.",
  "error_code": "PRIVATE_KEY_API_DISABLED",
  "details": "This is a security feature. Private keys are cryptographic secrets that should not be transmitted over HTTP."
}
```

If the key file is not found:

HTTP 400:

``` json
{
  "error": "Private key file not found",
  "error_code": "KEY_NOT_FOUND",
  "details": "Attempted path: /var/log/rpi-sb-provisioner/{serialno}/keypair/{serialno}.der"
}
```

**Security Notes:**

> **Important**
>
> **This endpoint presents significant security risks:**
>
> - Private keys are cryptographic secrets that provide complete control over device identity
>
> - Transmitting private keys over HTTP is inherently insecure, even on "private" networks
>
> - All access attempts (successful and failed) are logged to the audit log
>
> - Each private key download generates WARNING level logs
>
> - Consider using physical media (USB drive) or secure file transfer methods instead
>
> **Only enable this endpoint if:**
>
> - You are in a completely isolated test/development environment
>
> - You have no other means of retrieving the keys
>
> - You understand and accept the security implications
>
> - You can monitor the audit logs for unauthorized access

**Audit Logging:**

All activity on this endpoint is heavily audited:

- Denied access attempts are logged with client IP address

- Successful downloads are logged as CRITICAL security events

- Logs include client IP, User-Agent, and serial number

- All events appear in `/srv/rpi-sb-provisioner/audit.db`

**Alternatives to Consider:**

Instead of using this endpoint, consider:

1.  **Physical retrieval:** Access keys directly from `/var/log/rpi-sb-provisioner/{serialno}/keypair/` on the server

2.  **Secure file transfer:** Use `scp` or `sftp` over SSH

3.  **Out-of-band delivery:** Deliver keys via secure USB drive

4.  **Key management system:** Integrate with a proper secrets management solution
