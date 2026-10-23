WebSocket endpoints provide real-time updates for long-running operations and dynamic data.

A handshake from another origin is refused with `403 CROSS_ORIGIN`. `/ws/devices` may be opened without signing in while the public dashboard is on, up to 32 such connections at once; the others need an operator, by session cookie or bearer token (see [authentication.md](authentication.md)).

# /ws/devices

**Protocol:** WebSocket

**Description:** Provides real-time updates on device topology, including USB connections, provisioning status, and device states.

**Message Format:**

Server sends JSON messages with current topology:

``` json
{
  "type": "topology",
  "timestamp": 1706191845000,
  "nodes": [
    {
      "id": "1-1.4",
      "parentId": "1-1",
      "portPermitted": true,
      "isHub": false,
      "vendor": "0a5c",
      "product": "2712",
      "productName": "BCM2712 Boot",
      "serial": "c561b701c85be8ea",
      "state": "SB-PROVISIONER-WRITING-ROOTFS",
      "image": "raspios-2025-04-01.img",
      "model": "CM5",
      "ip": "192.168.1.100",
      "ethMac": "d8:3a:dd:12:34:56",
      "modelGen": 5,
      "boardType": "CM5",
      "speed": 480,
      "history": [
        { "state": "SB-PROVISIONER-WRITING-ROOTFS", "ts": "2026-08-26 09:41:12" },
        { "state": "SB-PROVISIONER-WRITING-BOOTFS", "ts": "2026-08-26 09:40:58" },
        { "state": "SB-PROVISIONER-STORAGE-ERASING", "ts": "2026-08-26 09:40:31" }
      ]
    }
  ],
  "usbPortRules": [],
  "usbPortRestrictionActive": false,
  "removed": ["1-1.3"]
}
```

**Notes:**

- Automatically sends topology snapshot on connection

- Broadcasts updates when devices connect/disconnect or state changes

- Includes placeholder nodes for empty hub ports, marked `"placeholder": true`

- A node's optional fields (`vendor`, `product`, `productName`, `serial`, `state`, `image`, `model`, `ip`, `speed`, `modelGen`, `boardType`, `ethMac`, `history`) are left out when unknown. The root node is `server`, with `parentId` `null`

- `portPermitted` says whether the USB port allowlist lets the provisioner act on a device at that port; `usbPortRules` lists the allowlist's patterns and `usbPortRestrictionActive` whether there are any

- `companionPairs`, when present, pairs each USB 2 bus with its USB 3 companion (`hsBus`, `ssBus`, `ssPortCount`)

- Client messages are ignored

- The `removed` array lists device IDs that were disconnected

- `state` is the device's most recent row in `state.db`. Every state carries
  the name of the stage that wrote it (`BOOTSTRAP`, `TRIAGE`, or
  `<STYLE>-PROVISIONER`) followed by a step name, so a consumer can place a
  step it has not seen before in the right stage

- `history` holds that device's most recent state transitions, newest first,
  each with the `state.db` timestamp (UTC, second resolution). Rows are keyed
  by USB path, so the list stops at the end of the previous device's run on
  that port. Only rows written since the service started are reported, so a
  device connected across a service restart has no history until it next
  changes state

- `ethMac` is the wired MAC, read from `manufacturing.db`. It is only present
  once the provisioner has gathered metadata from the device, which happens
  towards the end of a run

# /ws/sha256

**Protocol:** WebSocket

**Description:** Provides real-time progress updates for SHA256 hash calculations of image files.

**Client Messages:**

Request SHA256 calculation:

``` json
{
  "action": "get_sha256",
  "image_name": "raspios-2025-04-01.img"
}
```

**Server Messages:**

Progress update:

``` json
{
  "image_name": "raspios-2025-04-01.img",
  "status": "pending",
  "progress": 0.45,
  "progress_percent": 45
}
```

Complete:

``` json
{
  "image_name": "raspios-2025-04-01.img",
  "status": "complete",
  "sha256": "abc123def456..."
}
```

Error:

``` json
{
  "image_name": "raspios-2025-04-01.img",
  "status": "error",
  "error": "Failed to read file"
}
```

**Notes:**

- Multiple clients can subscribe to the same image calculation

- If the image has no cached result, the request starts a calculation and the server replies `{"image_name": ..., "status": "pending"}`

- `progress` and `progress_percent` appear once some progress has been made

- A pending calculation is cancelled when the last client listening for it disconnects

- An image name that is not plain, or one ending `.sha256`, is answered with `status` `error`

# /ws/boot-package

**Protocol:** WebSocket

**Description:** Reports whether a signed boot package exists for an image, and follows its generation.

**Client Messages:**

``` json
{
  "action": "check_boot_package",
  "image_name": "raspios-2025-04-01.img"
}
```

**Server Messages:**

``` json
{
  "image_name": "raspios-2025-04-01.img",
  "exists": true,
  "package_name": "rpi-sb-boot-update_1.0_all.deb",
  "status": "available"
}
```

`status` is `available`, `not_found`, `generating`, `unsupported` (the provisioning style has no boot packages) or `no_signing_key`. Updates are sent to every client that has asked about the image.

# /ws/progress

**Protocol:** WebSocket

**Description:** Streams the progress of an image upload. Choose an ID, send it as the `X-Upload-Id` header on `POST /upload-image`, and subscribe to `upload:<id>` here.

**Client Messages:**

``` json
{ "subscribe": "upload:3f9c2b" }
```

``` json
{ "unsubscribe": "upload:3f9c2b" }
```

**Server Messages:**

``` json
{ "phase": "decompressing", "bytes_written": 1073741824, "total_bytes": 4294967296 }
```

``` json
{ "phase": "extracting", "bytes_written": 524288000, "current_entry": "rootfs.simg" }
```

The last message has `phase` `complete`, or `error` with a `message`; the topic is then closed. A plain `.img` upload sends only `error` messages, never `complete`: wait for the HTTP response instead.
