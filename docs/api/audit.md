The Audit Log API reads the security audit log, which records API access, file operations, sign-ins and API token changes.

# /auditlog

**HTTP Method:** GET

**Description:** Returns audit log entries, newest first. With `Accept: text/html` the audit log page is returned instead.

**Parameters:**

| Parameter  | Type    | Required | Default | Description                                                                                         |
|------------|---------|----------|---------|-----------------------------------------------------------------------------------------------------|
| event_type | String  | No       | All     | `HANDLER_ACCESS`, `FILE_ACCESS`, `SYSTEMD_LOG_ACCESS` or `AUTHENTICATION`                           |
| start_date | String  | No       | None    | Entries at or after this local time: `YYYY-MM-DD HH:MM[:SS]` or `YYYY-MM-DDTHH:MM[:SS]`. Anything else is ignored |
| end_date   | String  | No       | None    | Entries at or before this local time, in the same forms. Seconds default to `:00`                     |
| limit      | Integer | No       | 100     | Maximum number of entries, clamped to 1–1000                                                         |

**Response Format:**

``` json
{
  "audit_entries": [
    {
      "id": "125",
      "timestamp": "2026-10-07 09:12:03",
      "event_type": "AUTHENTICATION",
      "client_ip": "192.168.1.100",
      "user_agent": "Mozilla/5.0...",
      "operation": "LOGIN",
      "success": "No",
      "username": "operator",
      "additional_info": "Authentication failure"
    },
    {
      "id": "124",
      "timestamp": "2026-10-07 09:11:58",
      "event_type": "FILE_ACCESS",
      "operation": "HOOK_SAVE",
      "target_path": "/etc/rpi-sb-provisioner/scripts/sb-provisioner-post-flash",
      "success": "Yes",
      "username": "operator",
      "additional_info": "sha256 none -> 3f1c...e9, mode 0644"
    },
    {
      "id": "123",
      "timestamp": "2026-10-07 09:11:40",
      "event_type": "HANDLER_ACCESS",
      "client_ip": "192.168.1.100",
      "user_agent": "curl/8.14.1",
      "handler_path": "/api/v2/manufacturing",
      "username": "operator"
    }
  ],
  "count": 3
}
```

Every value is a string. A field is left out when the entry has no value for it.

**Fields:**

| Field           | Description                                                                                    |
|-----------------|------------------------------------------------------------------------------------------------|
| id              | Entry number                                                                                   |
| timestamp       | Local time, to the second                                                                      |
| event_type      | See below                                                                                      |
| client_ip       | Client address. `X-Forwarded-For` is believed only from a reverse proxy on this machine        |
| user_agent      | The client's `User-Agent`                                                                      |
| handler_path    | Path of the endpoint called (`HANDLER_ACCESS`)                                                 |
| operation       | What was done, such as `DELETE`, `UPLOAD`, `HOOK_SAVE` or `LOGIN`                               |
| target_path     | File or unit acted on                                                                          |
| success         | `Yes` or `No`                                                                                  |
| username        | Who made the entry: the signed-in operator or the token's owner, or for a sign-in the name tried. Recorded for endpoint access, sign-ins, token changes, hook changes and bootloader configuration changes; empty for most other file operations and for service log reads |
| additional_info | Further detail, such as why a sign-in failed or a hook's SHA-256 before and after              |

**Event Types:**

| Event Type         | Description                                                                                       |
|--------------------|---------------------------------------------------------------------------------------------------|
| HANDLER_ACCESS     | An endpoint was called                                                                            |
| FILE_ACCESS        | A file operation: read, write, delete, upload, hook change, key change and so on                  |
| SYSTEMD_LOG_ACCESS | A service log was read                                                                            |
| AUTHENTICATION     | A sign-in, sign-out, or API token creation or revocation: `operation` is `LOGIN`, `LOGOUT`, `TOKEN_CREATE` or `TOKEN_REVOKE` |

Every sign-in attempt is recorded, including those refused for plain HTTP (`refused: not over HTTPS`) or for too many attempts in progress (`refused: too many attempts in progress`).

Hook changes are `FILE_ACCESS` entries with `operation` `HOOK_SAVE`, `HOOK_UPLOAD`, `HOOK_ENABLE`, `HOOK_DISABLE` or `HOOK_DELETE`; `additional_info` holds the script's SHA-256 (before and after, for a save or upload) and its mode.

**Example:**

``` bash
curl -H "Authorization: Bearer $RPI_SB_TOKEN" \
  "http://localhost:3142/auditlog?event_type=AUTHENTICATION&start_date=2026-10-07T00:00&limit=50"
```

**Notes:**

- The log is a SQLite database at `/srv/rpi-sb-provisioner/audit.db`, mode 0640.

- On a database error the endpoint returns HTTP 500 with `error_code` `DB_OPEN_ERROR` or `QUERY_ERROR`.
