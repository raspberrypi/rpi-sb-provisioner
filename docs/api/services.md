The Services API provides access to information about provisioning services running on the system. These endpoints allow monitoring of service states and retrieving service logs.

# /api/v2/services

**HTTP Method:** GET

**Description:** Returns information about all provisioning services discovered on the system. This includes both currently active services and previously run services found in the systemd journal.

**Parameters:** None

**Response Format:**

The endpoint returns a JSON object containing an array of services:

``` json
{
  "services": [
    {
      "name": "rpi-sb-provisioner@",
      "status": "completed",
      "active": "inactive",
      "instance": "c561b701",
      "base_name": "rpi-sb-provisioner",
      "full_name": "rpi-sb-provisioner@c561b701.service",
      "timestamp": 1760000000000000
    },
    {
      "name": "rpi-sb-bootstrap@",
      "status": "running",
      "active": "active",
      "instance": "1-1.4",
      "base_name": "rpi-sb-bootstrap",
      "full_name": "rpi-sb-bootstrap@1-1.4.service",
      "timestamp": 1760000100000000
    }
  ]
}
```

**Field Descriptions:**

| Field     | Description                                                                |
|-----------|----------------------------------------------------------------------------|
| name      | Unit name, ending in `@` for template instances; without `.service`        |
| status    | systemd sub-state (`running`, `exited`, `failed`, ...), or `completed` if the unit is no longer loaded |
| active    | systemd active state (`active`, `inactive`, `failed`, ...); `inactive` if no longer loaded |
| instance  | Instance parameter for template units, otherwise empty                     |
| base_name | Unit name without `@`, instance or `.service`                              |
| full_name | Complete unit name including `.service`; pass this to `/api/v2/service-log/{name}` |
| timestamp | Time of the unit's latest journal entry, in microseconds since the Unix epoch |

**Notes:**

- Services are discovered from the systemd journal, so units that have finished are included as well as running ones.

- Services are sorted by `timestamp`, most recent first.

- A unit is included if its name contains `rpi-sb-`, or contains both `rpi-` and `provisioner`, and ends in `.service`. `rpi-provisioner-ui` is excluded.

# /api/v2/service-log/{name}

**HTTP Method:** GET

**Description:** Returns log entries for a specific provisioning service with support for pagination and ordering. This endpoint provides detailed logging information for monitoring service execution.

**Path Parameters:**

| Parameter | Type   | Required | Description                                                                                 |
|-----------|--------|----------|---------------------------------------------------------------------------------------------|
| name      | String | Yes      | Full unit name, including `.service`, as given by `full_name` above. Must start with `rpi-sb-`, `rpi-naked-`, `rpi-fde-` or `rpi-idp-` |

**Query Parameters:**

| Parameter | Type    | Required | Default | Description                                                         |
|-----------|---------|----------|---------|---------------------------------------------------------------------|
| page      | Integer | No       | 1       | Page number. Values below 1 become 1; values past the last page return the last page |
| page_size | Integer | No       | 50      | Entries per page, at most 500. Values below 1 become 50              |
| order     | String  | No       | desc    | `desc` pages back from the newest entry, `asc` forward from the oldest |

**Response Format:**

The endpoint returns a JSON object with log entries and pagination metadata:

``` json
{
  "logs": [
    "2025-01-25T14:30:45.120Z Foo",
    "2025-01-25T14:30:46.004Z Bar",
    "2025-01-25T14:30:47.518Z Baz"
  ],
  "service_name": "rpi-sb-provisioner@c561b701.service",
  "page": 1,
  "page_size": 50,
  "total_entries": 150,
  "total_pages": 3,
  "order": "desc"
}
```

**Field Descriptions:**

| Field         | Description                                                     |
|---------------|-----------------------------------------------------------------|
| logs          | Log lines, each an ISO 8601 UTC timestamp with milliseconds, a space and the message. Within a page, lines are in chronological order whichever `order` is used |
| service_name  | Name of the service the logs belong to                          |
| page          | Current page number                                             |
| page_size     | Number of entries per page                                      |
| total_entries | Total number of log entries available                           |
| total_pages   | Total number of pages available                                 |
| order         | The `order` used                                                |

**Example Usage:**

To retrieve the first page with default settings (50 newest entries):

``` bash
curl -H "Authorization: Bearer $RPI_SB_TOKEN" http://localhost:3142/api/v2/service-log/rpi-sb-provisioner@c561b701.service
```

To retrieve page 2 with 100 entries per page, oldest first:

``` bash
curl -H "Authorization: Bearer $RPI_SB_TOKEN" "http://localhost:3142/api/v2/service-log/rpi-sb-provisioner@c561b701.service?page=2&page_size=100&order=asc"
```

**Error Responses:**

For a name without an allowed prefix, HTTP 403:

``` json
{
  "error": "Access denied: Only logs for rpi-sb, rpi-naked, rpi-fde, and rpi-idp services are available",
  "error_code": "SERVICE_UNAUTHORIZED",
  "details": "Requested service: invalid-service-name"
}
```

If the journal cannot be read, HTTP 500 with `JOURNAL_OPEN_ERROR` or `JOURNAL_FILTER_ERROR`.

**Notes:**

- A name with no journal entries returns an empty `logs` array, not an error.

- `/service-log/{name}` is the HTML page for the same log; it returns the same JSON when the request's `Accept` header contains `application/json`.
