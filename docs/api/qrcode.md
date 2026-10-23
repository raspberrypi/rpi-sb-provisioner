The QR Code Verification API provides endpoints for validating QR codes against the manufacturing database.

# /api/v2/verify-qrcode

**HTTP Method:** GET, or POST

**Description:** Verifies if a QR code value exists in the manufacturing database, typically used for device validation during scanning.

**Request Format:**

``` bash
curl 'http://localhost:3142/api/v2/verify-qrcode?code=10000000abcdef'
```

`GET` needs no sign-in unless `RPI_SB_PROVISIONER_PUBLIC_DASHBOARD` is turned off. `POST` with a JSON body is kept for existing scripts. It needs an operator and, from a browser session, the CSRF token, as other writes do:

``` json
{
  "qrcode": "10000000abcdef"
}
```

The code must be 1 to 256 printable characters and not only spaces.

**Response Format:**

The endpoint returns a JSON object with verification results:

``` json
{
  "success": true,
  "exists": true,
  "qrcode": "10000000abcdef"
}
```

**Field Descriptions:**

| Field   | Description                                                            |
|---------|------------------------------------------------------------------------|
| success | Indicates if the verification check was performed successfully         |
| exists  | Indicates if the QR code value was found in the manufacturing database |
| qrcode  | The QR code value that was checked                                     |

**Error Responses:**

If the code is missing, blank, not printable or longer than 256 characters, HTTP 400:

``` json
{
  "error": "Missing or invalid code",
  "error_code": "INVALID_PARAMETER"
}
```

If the manufacturing database cannot be read, HTTP 500 with `error_code` `DB_ERROR`.

**Notes:**

- This endpoint is particularly useful for integration with barcode scanners or mobile applications.

- The QR code value is checked against the `rpi_duid` field in the manufacturing database.
