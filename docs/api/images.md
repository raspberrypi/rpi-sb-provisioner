The Images API provides complete management of OS images used for device provisioning, including upload, download, metadata retrieval, and SHA256 hash calculation.

The API supports both traditional `.img` files and IDP (Image Description Provisioning) artefact directories. IDP artefacts are directories containing a JSON image descriptor and one or more sparse images (`.simg` files), typically produced by `rpi-image-gen`.

Images live in `/srv/rpi-sb-provisioner/images`. Every `name` parameter must be a plain name: no `/` or `\`, no `..`, and no leading `.`. Any other name is refused with `400 INVALID_IMAGE_NAME`.

# /images/list

**HTTP Method:** GET

**Description:** Lists all available OS images in the system.

**Parameters:** None

**Response Format:**

The response is a JSON object with a single `images` key containing the array of image entries:

``` json
{
  "images": [
    {
      "name": "raspios-2025-04-01.img",
      "path": "/srv/rpi-sb-provisioner/images/raspios-2025-04-01.img",
      "sha256": "abc123...",
      "size_mb": 4096.0,
      "is_gold_master": false,
      "is_idp": false,
      "type": "traditional"
    },
    {
      "name": "deb13-arm64-min-ab-luks2-2026-04-13",
      "path": "/srv/rpi-sb-provisioner/images/deb13-arm64-min-ab-luks2-2026-04-13",
      "sha256": "def456...",
      "size_mb": 822.7,
      "is_gold_master": true,
      "is_idp": true,
      "type": "idp"
    }
  ]
}
```

**Field Descriptions:**

| Field          | Description                                                                                                                                               |
|----------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------|
| name           | Filename of the image or name of the IDP artefact directory                                                                                               |
| path           | Full filesystem path                                                                                                                                      |
| sha256         | SHA256 hash, or `Calculating...` or `Error`. For IDP artefacts, the hash of the original uploaded archive from its `.sha256` sidecar file, or `IDP Artefact` if there is none |
| size_mb        | Size in MiB (1 048 576 bytes). For IDP artefacts, the sum of all files in the directory                                                                   |
| is_gold_master | Whether `GOLD_MASTER_OS_FILE` contains this name                                                                                                          |
| is_idp         | Whether this entry is an IDP artefact directory (as opposed to a traditional `.img` file)                                                                 |
| type           | Image type: `"idp"` for IDP artefact directories or `"traditional"` for `.img` files                                                                       |

**Notes:**

- SHA256 hashes for traditional images are calculated in the background, for every image when the service starts and for each new one as it appears

- IDP artefact SHA256 is read from a sidecar file created at upload time; there is no background calculation

- `.sha256` sidecar files, hidden directories (prefixed with `.`) and directories that are not IDP artefacts are not listed

# /get-image-metadata

**HTTP Method:** GET

**Description:** Retrieves detailed metadata for a specific image.

**Parameters:**

| Parameter | Type   | Required | Description           |
|-----------|--------|----------|-----------------------|
| name      | String | Yes      | Filename of the image |

**Response Format:**

``` json
{
  "name": "raspios-2025-04-01.img",
  "size_bytes": 4294967296,
  "size_mb": 4096.0,
  "size_formatted": "4.00 GB",
  "last_modified": "2025-04-01 10:30:45",
  "estimated_process_minutes": 103
}
```

**Field Descriptions:**

| Field                     | Description                                            |
|---------------------------|--------------------------------------------------------|
| name                      | Filename of the image                                  |
| size_bytes                | File size in bytes                                     |
| size_mb                   | Size in MiB                                            |
| size_formatted            | Human-readable size, in binary units (KB, MB and GB of 1024) |
| last_modified             | Last modification time, local time                     |
| estimated_process_minutes | Estimated time to process this image, at 40 MiB/s, rounded up |

**Error Responses:** `400 MISSING_IMAGE_NAME`, `400 INVALID_IMAGE_NAME`, `400 IMAGE_NOT_FOUND`, `500 METADATA_ERROR`.

# /get-image-sha256

**HTTP Method:** GET

**Description:** Reports an image's SHA256 hash, or the progress of its calculation.

**Parameters:**

| Parameter | Type   | Required | Description           |
|-----------|--------|----------|-----------------------|
| name      | String | Yes      | Filename of the image |

**Response Format:**

When calculation is complete:

``` json
{
  "sha256": "abc123def456...",
  "status": "complete"
}
```

If the calculation failed, `status` is `error` and `sha256` holds the error message.

For an IDP artefact the archive's hash is returned at once, with `name` added; without a sidecar file `sha256` is `IDP Artefact` and a `message` says so.

When calculation is in progress:

``` json
{
  "sha256": "Calculating...",
  "status": "pending",
  "message": "SHA256 calculation is in progress.",
  "progress": 0.45,
  "progress_percent": 45
}
```

`progress` and `progress_percent` appear once some progress has been made.

**Notes:**

- Calculation starts on its own when the service starts and when an image is added; this endpoint only reports it

- Use the WebSocket endpoint `/ws/sha256` for live progress

- Results are cached and stored in `.sha256` sidecar files

- **Error Responses:** `400 MISSING_IMAGE_NAME`, `400 INVALID_IMAGE_NAME`, `400 IMAGE_NOT_FOUND`

# /upload-image

**HTTP Method:** POST

**Description:** Uploads an OS image or IDP artefact archive. The upload is streamed to disk, so multi-GB files are fine.

**Request Format:**

`multipart/form-data` with one file part; the file's own name decides how it is handled. Accepted names end in `.img`, `.img.xz`, `.img.zst`, `.tar.xz` or `.tar.zst`.

Send an `X-Upload-Id` header with a value of your choosing to follow the upload's progress on the `/ws/progress` WebSocket (see [websockets.md](websockets.md)).

``` bash
curl -X POST -H "Authorization: Bearer $RPI_SB_TOKEN" \
  -F "file=@raspios-2025-04-01.img.xz" http://localhost:3142/upload-image
```

**Response Format:**

``` json
{
  "success": true,
  "message": "File uploaded successfully",
  "filename": "raspios-2025-04-01.img",
  "is_idp": false,
  "renamed": false,
  "sha256": "Calculating..."
}
```

A compressed image is decompressed as it arrives; `filename` is then the `.img` name, `message` is `Compressed image uploaded and decompressed successfully`, and `sha256` is usually the hash of the decompressed image.

An IDP archive is extracted into a directory named after the archive without its extension:

``` json
{
  "success": true,
  "message": "IDP artefact uploaded and extracted successfully",
  "filename": "deb13-arm64-min-ab-luks2-2026-04-13",
  "is_idp": true,
  "renamed": false,
  "sha256": "def456...",
  "analysis": { "type": "idp", "schema_valid": true, "...": "as /analyze-image" }
}
```

If an image file with the same name exists, the upload is renamed:

``` json
{
  "success": true,
  "message": "File uploaded successfully (renamed to avoid conflict)",
  "original_filename": "raspios.img",
  "filename": "raspios_1.img",
  "is_idp": false,
  "renamed": true,
  "sha256": "Calculating..."
}
```

**Error Responses:**

| Status | `error_code`                | Cause                                                                    |
|--------|-----------------------------|--------------------------------------------------------------------------|
| 400    | `UPLOAD_WRITE_ERROR`        | The file name is not plain, or not an accepted type (`error` says which) |
| 400    | `ARCHIVE_PATH_TRAVERSAL`    | The archive holds an unsafe path                                         |
| 400    | `IDP_SPARSE_INVALID`        | A sparse image named by the IDP descriptor is truncated or malformed     |
| 400    | `STREAM_ERROR`              | The upload stream failed                                                 |
| 500    | `UPLOAD_WRITE_ERROR`        | Writing the file failed                                                  |
| 500    | `ARCHIVE_EXTRACT_ERROR`, `ARCHIVE_VALIDATE_ERROR`, `DECOMPRESS_ERROR` | Extraction or decompression failed |
| 507    | `INSUFFICIENT_DISK_SPACE`   | Less free space than five times the request's `Content-Length`, or too little for the decompressed image |

**Notes:**

- An image file whose name is taken is renamed with a numeric suffix. An IDP archive replaces an existing artefact of the same name.

- SHA256 calculation, and for the `secure-boot` style boot package generation, begin automatically after upload.

- IDP archives are extracted with the archive's SHA256 stored in a `.sha256` sidecar file. Every entry must stay inside the archive: absolute paths, `..`, links pointing outside it, device nodes and FIFOs are refused.

# /delete-image

**HTTP Method:** POST

**Description:** Deletes an OS image file from the system.

**Parameters:**

| Parameter | Type   | Required | Description                     |
|-----------|--------|----------|---------------------------------|
| name      | String | Yes      | Filename of the image to delete |

Send `name` in the query string or as a form field.

**Response Format:**

HTTP 200 OK with no body on success.

**Error Responses:**

``` json
{
  "error": "The requested image file was not found",
  "error_code": "IMAGE_NOT_FOUND",
  "details": "Requested image: raspios-2025-04-01.img"
}
```

HTTP 400 for `IMAGE_NOT_FOUND`, `MISSING_IMAGE_NAME` and `INVALID_IMAGE_NAME`; 500 for `IMAGE_DELETE_ERROR`.

**Notes:**

- Deleting an image will cancel any ongoing SHA256 calculation

- If the image was the selected `GOLD_MASTER_OS_FILE`, that setting is cleared

- Both the image file (or IDP artefact directory) and its `.sha256` sidecar file are removed

# /analyze-image

**HTTP Method:** GET

**Description:** Analyses an image and returns detailed metadata. For IDP artefact directories, this parses the JSON image descriptor and returns device class, storage type, encryption settings, and partition information.

**Parameters:**

| Parameter | Type   | Required | Description                                 |
|-----------|--------|----------|---------------------------------------------|
| name      | String | Yes      | Name of the image or IDP artefact directory |

**Response Format (IDP artefact):**

``` json
{
  "type": "idp",
  "name": "deb13-arm64-min-ab-luks2-2026-04-13",
  "path": "/srv/rpi-sb-provisioner/images/deb13-arm64-min-ab-luks2-2026-04-13",
  "schema_valid": true,
  "device_class_raw": "pi5",
  "device_class": "5",
  "storage_type_raw": "sd",
  "storage_type": "sd",
  "image_version": "2026-04-13",
  "image_name": "deb13-arm64-min-ab-luks2",
  "partition_count": 6,
  "encryption": true,
  "cipher": "aes-xts-plain64",
  "simg_file_count": 6
}
```

**Response Format (traditional image):**

``` json
{
  "type": "traditional",
  "name": "raspios-2025-04-01.img",
  "path": "/srv/rpi-sb-provisioner/images/raspios-2025-04-01.img",
  "size_bytes": 4294967296
}
```

**IDP Field Descriptions:**

| Field            | Description                                                                         |
|------------------|-------------------------------------------------------------------------------------|
| type             | `idp` for IDP artefact directories, `traditional` for `.img` files                  |
| schema_valid     | Whether the IDP JSON passes schema validation                                       |
| schema_errors    | The validation errors, present only when `schema_valid` is false                    |
| device_class_raw | Raw device class from the JSON (e.g. `pi5`, `cm4`, `zero2w`)                        |
| device_class     | Mapped device family matching `RPI_DEVICE_FAMILY` convention (`5`, `4`, `2W`)       |
| storage_type_raw | Storage type as written in the JSON                                                 |
| storage_type     | Storage type (`sd`, `emmc`, `nvme`); currently the same value                       |
| image_version    | Image version string from JSON metadata                                             |
| image_name       | Human-readable image name from JSON attributes                                      |
| partition_count  | Number of partitions defined in the image layout                                    |
| encryption       | Whether any partition uses encryption                                               |
| cipher           | Encryption cipher (e.g. `aes-xts-plain64`), present only when encryption is enabled |
| simg_file_count  | Number of distinct sparse images named by the descriptor that exist in the directory |

**Notes:**

- This endpoint is used by the WebUI to auto-populate device family, storage type, and cipher fields when an IDP artefact is selected

- For IDP artefacts, the response is parsed from the JSON image descriptor without modifying the artefact

- Returns an `error` field, still with HTTP 200, if analysis fails (e.g. missing JSON file, parse error). A directory that is not an IDP artefact is reported with `type` `unknown_directory`

- Errors: `400 MISSING_IMAGE_NAME`, `400 INVALID_IMAGE_NAME`, `404 IMAGE_NOT_FOUND`

# /get-boot-package-info

**HTTP Method:** GET

**Description:** Reports whether a signed boot package (a Debian package, `rpi-sb-boot-update_*_all.deb`) has been generated for a given image. Boot packages are only produced in the `secure-boot` provisioning style.

**Parameters:**

| Parameter | Type   | Required | Description           |
|-----------|--------|----------|-----------------------|
| name      | String | Yes      | Filename of the image |

**Response Format:**

When a boot package is available:

``` json
{
  "exists": true,
  "image_name": "raspios-2025-04-01.img",
  "status": "available",
  "package_name": "rpi-sb-boot-update_1.0_all.deb",
  "package_path": "/srv/rpi-sb-provisioner/images/bootimg-output/rpi-sb-boot-update_1.0_all.deb"
}
```

When no boot package has been generated for the image:

``` json
{
  "exists": false,
  "image_name": "raspios-2025-04-01.img",
  "status": "not_found"
}
```

When no signing key is configured:

``` json
{
  "exists": false,
  "image_name": "raspios-2025-04-01.img",
  "status": "no_signing_key",
  "reason": "No signing key is configured."
}
```

When the current provisioning style does not support boot packages:

``` json
{
  "exists": false,
  "image_name": "raspios-2025-04-01.img",
  "status": "unsupported"
}
```

**Error Responses:**

``` json
{
  "error": "Missing required parameter: name",
  "error_code": "MISSING_PARAMETER"
}
```

**Notes:**

- `status` is one of `available`, `not_found`, `no_signing_key` or `unsupported`

- Generated boot packages are stored in `/srv/rpi-sb-provisioner/images/bootimg-output`

- Used by the WebUI to poll for completion after triggering `/generate-boot-package`

# /generate-boot-package

**HTTP Method:** POST

**Description:** Triggers asynchronous generation of a signed boot package (`boot.img`) for the specified image. Only supported in the `secure-boot` provisioning style.

**Parameters:**

| Parameter | Type   | Required | Description           |
|-----------|--------|----------|-----------------------|
| name      | String | Yes      | Filename of the image |

**Response Format:**

``` json
{
  "success": true,
  "message": "Boot package generation started for raspios-2025-04-01.img",
  "image_name": "raspios-2025-04-01.img"
}
```

**Error Responses:**

``` json
{
  "error": "Boot package generation only supported in secure-boot mode (current: naked)",
  "error_code": "UNSUPPORTED_PROVISIONING_STYLE"
}
```

| Status | `error_code`                      | Cause                                     |
|--------|-----------------------------------|-------------------------------------------|
| 400    | `UNSUPPORTED_PROVISIONING_STYLE`  | `PROVISIONING_STYLE` is not `secure-boot` |
| 409    | `NO_SIGNING_KEY`                  | No signing key is configured              |
| 400    | `MISSING_PARAMETER`, `INVALID_IMAGE_NAME` | Bad `name`                        |
| 404    | `IMAGE_NOT_FOUND`                 | No such image                             |

**Notes:**

- Generation runs in the background; the response only confirms the request was accepted

- Poll `/get-boot-package-info` to determine when the package becomes `available`

- Once generated, retrieve the package with `/download-boot-package`

# /download-boot-package

**HTTP Method:** GET

**Description:** Downloads the generated boot package (`.deb`) for the specified image.

**Parameters:**

| Parameter | Type   | Required | Description           |
|-----------|--------|----------|-----------------------|
| name      | String | Yes      | Filename of the image |

**Response Format:**

On success, the response is the raw Debian package file with:

- `Content-Type: application/octet-stream`

- `Content-Disposition: attachment; filename="rpi-sb-boot-update_1.0_all.deb"`

**Error Responses:**

``` json
{
  "error": "Boot package not found for this image",
  "error_code": "BOOT_PACKAGE_NOT_FOUND"
}
```

**Notes:**

- Generate the package with `/generate-boot-package` before downloading

- Returns `404` with code `BOOT_PACKAGE_NOT_FOUND` if no matching package exists in the output directory
