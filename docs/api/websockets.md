WebSocket endpoints provide real-time updates for long-running operations and dynamic data.

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
      "parentId": "server",
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
      "history": [
        { "state": "SB-PROVISIONER-WRITING-ROOTFS", "ts": "2026-08-26 09:41:12" },
        { "state": "SB-PROVISIONER-WRITING-BOOTFS", "ts": "2026-08-26 09:40:58" },
        { "state": "SB-PROVISIONER-STORAGE-ERASING", "ts": "2026-08-26 09:40:31" }
      ]
    }
  ],
  "removed": ["1-1.3"]
}
```

**Notes:**

- Automatically sends topology snapshot on connection

- Broadcasts updates when devices connect/disconnect or state changes

- Includes placeholder nodes for empty hub ports

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

- Progress updates are sent approximately every 5% of completion

- Calculations are automatically cancelled when no clients are listening

- SHA256 sidecar files (.sha256) are not hashable and will return an error
