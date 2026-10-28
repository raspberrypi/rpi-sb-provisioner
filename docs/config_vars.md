This document describes the configuration variables used in `/etc/rpi-sb-provisioner/config`. Package defaults are in `/usr/share/rpi-sb-provisioner/defaults/config`; the provisioning scripts read the defaults first and then `/etc/rpi-sb-provisioner/config`, so a value there wins.

Most variables are set from the web interface's Options page, and each section below names the control. You may also set them by hand, for example from a change management system. The Options page saves only names beginning `RPI_`, `GOLD_MASTER_`, `PROVISIONING_`, `CUSTOMER_` or `PKCS11_`; the few others below can only be set by hand.

The file is readable by root only, because it can hold `RPI_CONNECT_API_KEY`.

# Variables

## PROVISIONING_STYLE

**Mandatory, with a default**

Select the provisioning style you wish to use. Supported values are `secure-boot`, `fde-only` and `naked`. For details on what each provisioning style does, see the [user guide](user-guide.md#provisioning-styles).

If `PROVISIONING_STYLE` is not specified, it defaults to `secure-boot`.

Set from Options, **Security Configuration**, as the **Secure Boot**, **FDE Only** or **Naked** tile. A Raspberry Pi Zero 2 W cannot use `secure-boot`.

## CUSTOMER_KEY_FILE_PEM

**For `secure-boot`, set this or CUSTOMER_KEY_PKCS11_NAME, never both**

The fully qualified path to your signing key, encoded in PEM format. This file is expected to contain an RSA 2048-bit private key. If both this and `CUSTOMER_KEY_PKCS11_NAME` are set, provisioning refuses to sign.

Under Options, **Bootloader Signing Key**, the **PEM Key File** tab lists the **Saved PEM keys**. **Add a PEM key** takes a file by drag and drop, by keyboard or with **Choose a file…**. A new key joins the saved keys and signs nothing until you choose **Use for provisioning** on it; only the first key saved is used straight away. The saved PEM and PKCS#11 keys are recorded in `/etc/rpi-sb-provisioner/keys/registry.json`, and the one in use is written to `CUSTOMER_KEY_FILE_PEM` or `CUSTOMER_KEY_PKCS11_NAME`, emptying the other.

> **Warning**
>
> This file should be considered key material. When uploaded through the WebUI it is stored device-wrapped at rest, using a key derived from the provisioning Raspberry Pi firmware crypto device key, and an upload that cannot be wrapped is refused. A plaintext key named by hand still works. A saved key held unencrypted is marked *Stored unencrypted at rest*, with an **Encrypt** button. The plaintext key is still present in process memory while signing, so protect the provisioner host according to your threat model.

## CUSTOMER_KEY_PKCS11_NAME

**For `secure-boot`, set this or CUSTOMER_KEY_FILE_PEM, never both**

The keypair alias or URI for a PKCS#11 keypair, typically stored on a Hardware Security Module (HSM). This acts in place of the RSA 2048-bit private key specified with `CUSTOMER_KEY_FILE_PEM`, and is used as the signing device for all future pre-boot authentication images.

The value should take the format:

    'pkcs11:object=<keypair-alias>;type=private'

> **Warning**
>
> When editing by hand, enclose the value in single quotes and URI encode it. The Options page quotes the value itself.

Set from Options, **Bootloader Signing Key**, on the **PKCS#11 / HSM** tab: **Detect keys on HSM** and then **Save & use**, or type a **Key Label** to build `pkcs11:object=<label>;type=private`. Either puts the key in use at once.

> **Warning**
>
> The PKCS#11 provider, its associated HSM, and any PIN used to unlock it should be considered key material and protected according to your threat model.

### Making your HSM available

> For the full picture — supported tokens, requirements, PIN handling, a
> SoftHSM2 smoke test, and troubleshooting — see the [PKCS#11 / HSM Support
> guide](hsm-support.md). The essentials are below.

No OpenSSL configuration is required. `rpi-sb-provisioner` activates the OpenSSL `pkcs11-provider` automatically, and the provider discovers tokens through [p11-kit](https://p11-glue.github.io/p11-glue/). To make your HSM visible, register its PKCS#11 module with p11-kit by dropping a one-line module file into `/usr/share/p11-kit/modules/` (for example `myhsm.module`):

    module: /usr/lib/aarch64-linux-gnu/libmyhsm-pkcs11.so

Replace the path with your vendor's PKCS#11 driver library. That is the only system configuration step — the provisioner needs no changes to `openssl.cnf`.

To confirm the token is discoverable, and to find the object alias for the `CUSTOMER_KEY_PKCS11_NAME` URI above, use `p11tool` (provided by the `gnutls-bin` dependency):

    # List the tokens p11-kit can see
    p11tool --list-tokens

    # List the keys on your token (use a token URI from the command above)
    p11tool --login --list-all 'pkcs11:token=<your-token-label>'

> **Note**
>
> If the token requires a PIN, store it through the WebUI (**HSM PIN**, then **Validate & Save PIN**). Stored PINs are device-wrapped at rest using the provisioning Raspberry Pi firmware crypto device key, and are supplied to the token automatically for both key validation and provisioning-time signing. The PIN is unwrapped in-process and handed to the `pkcs11-provider` via OpenSSL's passphrase callback (inside `rpi-sb-keyhelper`), so it never appears on a command line or in a `pin-source=` file. You do not need to add any PIN attribute to `CUSTOMER_KEY_PKCS11_NAME` when the WebUI holds the PIN.
>
> For deployments that manage PIN material outside the provisioner, you may instead append a `pin-value=<PIN>` or `pin-source=<file>` attribute to `CUSTOMER_KEY_PKCS11_NAME`; a PIN carried in the URI takes precedence, and with no stored PIN the callback is a no-op.

## GOLD_MASTER_OS_FILE

**Mandatory**

> **Warning**
>
> Provisioning erases the device’s storage before writing the OS image. If this variable is not set, or names a missing or empty file, or a directory without exactly one JSON descriptor, triage stops before the device is changed and the run fails with the reason.

This should be your 'gold master' OS image. This can be either:

- A **traditional `.img` file** — an uncompressed disk image, typically created using `pi-gen`. No customisation should be present in this image that you would not expect to be deployed to your entire fleet. Using a non-`pi-gen` image may produce undefined behaviour.

- An **IDP artefact directory** — a directory containing a JSON image descriptor and one or more sparse image (`.simg`) files, produced by `rpi-image-gen`. When a directory is specified, the provisioning system automatically uses the IDP protocol regardless of the `PROVISIONING_STYLE` setting. The artefact’s JSON descriptor defines the partition layout, encryption, storage type, and device family, so these fields are auto-populated by the WebUI.

> **Warning**
>
> Traditional `.img` files **must** be uncompressed. A compressed image uploaded through the WebUI is decompressed on upload.

Set from Options, **OS Image**, with **Use This Image** in the image browser.

> **Note**
>
> When selecting an IDP artefact through the WebUI, image metadata is used to pre-fill the device family, storage type, and cipher fields. Fields defined by the artefact are treated as the image defaults; the WebUI may still allow supported overrides such as storage type when the artefact and device support them.

## RPI_DEVICE_STORAGE_TYPE

**Mandatory**

Specify the kind of storage your target will use. Supported values are `sd`, `emmc`, `nvme`.

Set from Options, **Device & Firmware**, as the **SD Card**, **eMMC** or **NVMe** tile. NVMe is not offered for a Zero 2 W. For an IDP artefact that declares a storage type, that type is used when this is not set.

## RPI_DEVICE_BOOT_ORDER_MATCH_STORAGE

**Optional, enabled by default**

When enabled, the bootloader `BOOT_ORDER` flashed to the device is rewritten so the selected storage device is the **first** boot option, with the shipped fallbacks (and restart) kept behind it. For example, when provisioning `nvme`, the default `0xf2461` becomes `0xf2416`. `sd` and `emmc` are already first in the default order, so no change is made for those.

This feature is **on by default**. To disable it and use the shipped `BOOT_ORDER` unchanged, set the value to empty or a falsey token (`0`, `false`, `no`, `off`), or turn off **Boot selected storage first** under Options, **Bootloader Configuration**. The switch stores `1` or empty.

The storage type is taken from `RPI_DEVICE_STORAGE_TYPE` when set. For IDP artefacts that do not set it, the storage type declared in the artefact's JSON (`IGconf_device_storage_type`) is used instead, so IDP runs are covered.

> **Note**
>
> The reorder is applied to bootstrap's copy of the bootloader configuration, before it is signed and flashed; the file itself is never changed. A configuration that does not have exactly one `BOOT_ORDER` line (for example, one with section-scoped filters) is used as it is.

## RPI_DEVICE_STORAGE_CIPHER

**Optional**

Specify the full-disk-encryption cipher for the `secure-boot` and `fde-only` styles. Supported values are `aes-xts-plain64`, `xchacha12,aes-adiantum-plain64`.

If `RPI_DEVICE_STORAGE_CIPHER` is not specified, it defaults to `aes-xts-plain64`. Set from Options, **Encryption Cipher**, as the **AES-XTS** or **Adiantum** tile.

`aes-xts-plain64` is recommended for Raspberry Pi 5 family devices (including Compute Module 5); all other Raspberry Pi devices are recommended to use `xchacha12,aes-adiantum-plain64` for improved performance.

## RPI_DEVICE_FAMILY

**Mandatory**

Specify the family of Raspberry Pi device you are provisioning. Supported values are `4, 5, 2W`. For example:

- A Raspberry Pi Compute Module 4 would be family `4`

- A Raspberry Pi 5 would be family `5`

- A Raspberry Pi Compute Module 5 would be family `5`

- A Raspberry Pi Zero 2 W would be family `2W`

Set from Options, **Device & Firmware**, as a **Device Family** tile. Bootstrap refuses a connected device of another family.

## RPI_DEVICE_BOOTLOADER_CONFIG_FILE

**Optional**

> **Warning**
>
> `rpi-sb-provisioner` will ignore the Raspberry Pi Bootloader configuration built by `pi-gen`, and use its own.

The EEPROM bootloader configuration Raspberry Pi 4 and 5 family devices get, when this is empty, is the package default: `/var/lib/rpi-sb-provisioner/bootloader.secure` for `secure-boot`, `bootloader.naked` otherwise. Options, **Bootloader Configuration**, offers it and a custom one as the **Default** and **Custom** tiles, each showing the boot order devices will get. **Create** or **Edit** on the Custom tile opens an editor; saving checks the file, including the EEPROM's size limit, writes `/etc/rpi-sb-provisioner/bootloader.conf` and sets this variable to it. Choosing Default empties the variable and keeps the custom file.

Any other path names a file managed outside the provisioner, entered under **Use a file managed outside the provisioner…**; it must already exist. The provisioner reads the configuration in use and never changes it; it changes only its own copy, applying `RPI_DEVICE_BOOT_ORDER_MATCH_STORAGE` and removing any `SIGNED_BOOT`. A customer key in OTP turns signed boot on, and without one `SIGNED_BOOT=1` would stop an unsigned OS booting. A change to the configuration in use rebuilds the cached bootloader for the next device.

The settings are described in the Raspberry Pi Documentation, at <https://www.raspberrypi.com/documentation/computers/raspberry-pi.html#raspberry-pi-bootloader-configuration>, and the editor shows that description for the setting under the cursor.

## RPI_DEVICE_FIRMWARE_FILE

**Optional**

Specify an explicit path to a specific pieeprom firmware file to use during provisioning.

When set, the provisioning system will use the exact firmware file specified, and refuses a device whose chip does not match the file's `bootloader-<chip>` directory. If not set, the system automatically selects the newest firmware in the `latest` release channel, `/lib/firmware/raspberrypi/bootloader-<chip>/latest`.

Example: `RPI_DEVICE_FIRMWARE_FILE=/lib/firmware/raspberrypi/bootloader-2712/default/pieeprom-2025-05-08.bin`

Set from Options, **Device Firmware**: **Browse Available Firmware**, then **Use This Firmware**, or **Use Default Firmware** to empty it. The page accepts only files under `/lib/firmware/raspberrypi/bootloader-*`.

> **Warning**
>
> Ensure the specified firmware file exists and is compatible with your target device family before provisioning.

## RPI_DEVICE_LOCK_JTAG

**Optional**

Raspberry Pi devices have a mechanism to restrict JTAG access to the device. The lock is written into OTP of each device provisioned, permanently; it changes nothing on the provisioning server.

Note that using this function will prevent Raspberry Pi engineers from being able to assist in debugging your device, should you request assistance.

Set to any value to enable the JTAG restrictions. It is applied only by `secure-boot` provisioning of Raspberry Pi 4 and 5 family devices. Set from Options, **Hardware Security**, **Lock JTAG access on provisioned devices**, which stores `1` or empty.

## RPI_DEVICE_EEPROM_WP_SET

**Optional**

Raspberry Pi devices that use an EEPROM as part of their boot flow can configure that EEPROM to enable write protection - preventing modification, including bootloader security updates. It applies to the devices provisioned, permanently, never to the provisioning server.

Set to any value to enable EEPROM write protection. Like `RPI_DEVICE_LOCK_JTAG`, it is applied only by `secure-boot` provisioning of Raspberry Pi 4 and 5 family devices. Set from Options, **Hardware Security**, **Write-protect the EEPROM on provisioned devices**.

## RPI_DEVICE_RPIBOOT_GPIO

**Required for Raspberry Pi 4 family secure-boot provisioning**

Specifies the GPIO pin number to program into OTP for RPIBOOT mode on Raspberry Pi 4 family devices (including Compute Module 4).

When secure-boot provisioning a Raspberry Pi 4 family device, the bootloader must program both the secure boot public key AND the RPIBOOT GPIO configuration into OTP. Without this setting, provisioning will fail with the error:

    Failed to set RPIBOOT OTP gpio0 c800 -> 0
    BOOT ERROR: code 34

**Valid values:** `2`, `4`, `5`, `6`, `7`, `8`

**Recommended value:** `8` (GPIO 8 is the standard RPIBOOT pin)

These GPIO pins are valid because they are high by default, allowing them to enable RPIBOOT mode when pulled low.

**Example:**

    RPI_DEVICE_RPIBOOT_GPIO=8

Set from Options, **RPIBOOT GPIO Pin**, shown for the Raspberry Pi 4 family with Secure Boot. The list shows GPIO 8 while the variable is still empty; choose a pin to save it.

> **Note**
>
> This setting is only required for Raspberry Pi 4 family devices. Raspberry Pi 5 family devices do not require this setting as they have a built-in power button for RPIBOOT mode entry.

> **Warning**
>
> This value is programmed into OTP (one-time programmable memory) and cannot be changed once set. Ensure you use the same GPIO pin that you will physically connect to ground when entering RPIBOOT mode.

See the [Raspberry Pi 4 Connection Guide](device-guidance/pi4.md) for more information about GPIO configuration.

## RPI_SB_PROVISIONER_MANUFACTURING_DB

**Optional, with a default**

Store manufacturing data in a sqlite3 database. Defaults to `/srv/rpi-sb-provisioner/manufacturing.db`, which the package creates; set it empty to stop recording. Each record holds the board name, serial number, revision, processor, memory and manufacturer; the Ethernet, Wi-Fi and Bluetooth MAC addresses; the eMMC size and CID and the device's DUID; the EEPROM size, JEDEC ID, unique ID and bootloader build time; whether the device was secured, its public key programmed, its development key revoked and signed boot enabled; the JTAG lock and EEPROM write protection requested; the fingerprint and label of the customer signing key; the OS image filename and SHA256; and the Raspberry Pi Connect registration.

Set from Options, **Storage & Output**, **Manufacturing Database**.

You must not specify the path of a database stored on a network drive or similar storage, as this mechanism is only safe to use on a single provisioning system. For merging the output with multiple provisioning systems, consider [The manufacturing database](user-guide.md#the-manufacturing-database) in the user guide.

Set to the path of a file to contain a SQLite database stored on local storage. The WebUI will create this file if it does not exist.

> **Warning**
>
> Nothing is recorded when the file does not exist. If you are not using the WebUI, create it before execution, for example using `touch`:

    $ touch ${RPI_SB_PROVISIONER_MANUFACTURING_DB}

## RPI_CONNECT_API_KEY

**Optional**

Raspberry Pi Connect management API access token. When configured, provisioned devices are registered with Raspberry Pi Connect during provisioning.

Registration uses hardware-backed firmware crypto signing. The signing material remains hardware-held on the device, and Connect registration failures are logged as warnings rather than aborting provisioning.

A device provisioned again keeps its key, so Connect refuses a second identity for it. The provisioner then finds the identity that holds the key and updates its description, name and tags. If the device has already signed in to Connect, the identity takes only the description, so the name and tags go to the device record, found by its serial number. The search reads at most 50 pages of 100 identities; set `CONNECT_LIST_MAX_PAGES` by hand for a larger organisation.

The token must not contain whitespace. Set from Options, **Cloud Services**, **Connect Management API Access Token**, which is write-only: the page shows only that a token is saved, an empty field leaves it alone, and **Remove token** clears it. It is stored in `/etc/rpi-sb-provisioner/config`, which only root can read, and is kept out of the journal and the process list. The Connect server's certificate is verified; a development server with its own CA can be named with `CURL_CA_BUNDLE`, and a different server with `CONNECT_BASE_URL`, both set by hand.

## RPI_CONNECT_DESCRIPTION

**Optional**

Description prefix used when registering devices with Raspberry Pi Connect. The provisioner appends the board type and serial number. Set from Options, **Cloud Services**, **Description Prefix**.

## RPI_CONNECT_DEVICE_NAME

**Optional**

The name each device registered with Raspberry Pi Connect is given; without one, Connect would name it after its hostname, which a whole batch shares. `{board}` becomes the board in hostname form (`pi5`, `pi500`, `pi4b`, `pizero2w`, `cm5`, `cm5lite`) and `{serial}` the device's serial number, which the template must include. Defaults to `{board}-{serial}`, for example `cm5-8399ccde61e0280b`. Set from Options, **Cloud Services**, **Device Name**.

## RPI_CONNECT_TAGS

**Optional**

Comma-separated [tags](https://www.raspberrypi.com/documentation/services/connect-for-organisations.html#device-identities) applied to each device registered with Raspberry Pi Connect, for example `production, line2`. Connect allows up to 10, each up to 30 lowercase letters, digits, hyphens or underscores; the provisioner leaves out, with a warning in the log, any that break these rules rather than lose the registration. Set from Options, **Cloud Services**, **Tags**.

## RPI_DEVICE_RETRIEVE_KEYPAIR

**Optional**

Specify a directory to copy the device unique keypair to. The keys will be named \<serial\>.der and \<serial\>.pub, and are written in PEM format, readable by root only.

Set to a directory whose parent exists; triage creates the directory itself, root-only, if it is missing. If it is empty, or cannot be created, keys are stored in `/var/log/rpi-sb-provisioner/<serial>/keypair`. Set from Options, **Storage & Output**, **Keypair Storage Directory**.

> **Note**
>
> In practice only \<serial\>.pub is produced. Triage provisions the device's firmware crypto key (`oem fwcrypto init`), which locks the OTP ECDSA key-slot immediately, and the fastboot gadget also locks any already-provisioned slot at startup. Once locked, the device refuses to export its raw private key and \<serial\>.der is omitted. This is deliberate: the private key is meant to stay inside the firmware, reachable only through the on-device signing API.

> **Note**
>
> These keys are sensitive key material, and you must ensure they are handled appropriately.

## RPI_SB_PROVISIONER_ENABLE_PRIVATE_KEY_API

**Optional - SECURITY CRITICAL**

> **Caution**
>
> **DANGER: This setting controls a highly dangerous feature that should NEVER be enabled in production environments.**

Controls whether the HTTP API endpoint `/devices/{serialno}/key/private` is enabled. This endpoint allows downloading device private keys over HTTP. It is not on the Options page; set it by hand. Since a device's private key is normally not exportable (see `RPI_DEVICE_RETRIEVE_KEYPAIR`), there is usually nothing for it to return.

**Default:** `false` (endpoint is disabled)

**Values:**

- Not set or any value except `true`: Endpoint is **disabled** (secure default)

- `true`: Endpoint is **enabled** (DANGEROUS - private keys can be downloaded via HTTP)

**Security Implications:**

When enabled, this setting allows device private keys to be retrieved via HTTP API calls. This presents severe security risks:

- Private keys provide complete control over device cryptographic identity

- Keys transmitted over HTTP (even on "private" networks) can be intercepted

- Compromised keys allow impersonation and signature forgery

- Keys cannot be revoked once compromised

**Only enable this setting if:**

- You are in a completely isolated development/test environment

- The provisioning server is air-gapped from production networks

- You have no alternative method to retrieve keys

- You fully understand and accept the security implications

- You can actively monitor audit logs for unauthorized access

**Audit Logging:**

When this endpoint is enabled and used:

- All access attempts (successful and denied) are logged to the audit database

- Each access generates WARNING level logs

- Successful key downloads are logged as CRITICAL security events

- Logs include client IP address, User-Agent, and serial numbers

**Alternatives:**

Instead of enabling this endpoint, consider:

- Accessing keys directly from the filesystem: `/var/log/rpi-sb-provisioner/{serial}/keypair/`

- Using secure file transfer over SSH (`scp` or `sftp`)

- Delivering keys via physical media (USB drive)

- Implementing a proper secrets management solution

**Example Configuration:**

To enable this endpoint (NOT RECOMMENDED):

    # WARNING: Only enable in isolated test environments
    # This exposes device private keys via HTTP API
    RPI_SB_PROVISIONER_ENABLE_PRIVATE_KEY_API=true

> **Warning**
>
> Raspberry Pi does not recommend enabling this setting under any circumstances in production environments. If you must retrieve keys programmatically, carefully consider the security implications.

## RPI_SB_WORKDIR

**Optional**

> **Warning**
>
> If you do not set this variable, your modified OS intermediates will not be stored, and will be unavailable for inspection.

Set to a location to cache OS assets between provisioning sessions. Recommended for use in production. Set from Options, **Storage & Output**, **Work Directory**. For example:

    /srv/rpi-sb-provisioner/workdir

The workdir contains signed boot images, signed bootfiles, EEPROM staging assets and other expensive intermediate artefacts. Its contents are cleared whenever settings are saved from the Options page, when the selected firmware or signing key changes, and on package upgrades; the directory itself is kept. A change to the bootloader configuration rebuilds the cached bootloader on its own.

Persistent data such as uploaded images, manufacturing databases, state databases, logs and configuration are not stored in the workdir and are not removed by workdir cache invalidation.

Give the workdir a directory of its own. Its contents are deleted when the cache is invalidated, so a workdir that is, or holds, the images directory, the manufacturing database, signing keys, logs, a home directory or a system directory is never cleared.

The workdir must be owned by root and writable only by root, for example `install -d -m 0755 -o root -g root /srv/rpi-sb-provisioner/workdir`. Its contents are flashed to devices, so anything else that could write there could replace them. A workdir that others can write to is not used, and each run works in a fresh temporary directory instead. Upgrading to 2.4.0 fixes a dedicated workdir's ownership and empties it; it reports a symlinked workdir with the real path to use instead.

## RPI_SB_PROVISIONER_PUBLIC_DASHBOARD

**Optional**

Whether the devices page, a device's own page and the code scanner can be viewed without signing in. Defaults to `1` (on); set it empty to require signing in for everything. Set from Options, **Web Interface**, **Show devices and the code scanner without signing in**.

Viewers who have not signed in see serial numbers, USB ports, addresses, states and image names. They never see a device's logs or per-device overrides, settings, customisation scripts, images, the manufacturing database or the audit log, and they cannot change anything. With the default loopback binding, that means other accounts on this computer; behind a reverse proxy, anyone who can reach it.

## RPI_SB_HOOK_TIMEOUT

**Optional**

The longest a customisation hook may run, in seconds. Defaults to `1800`. A hook still running at the limit is stopped and treated as failed. Set this higher if a hook legitimately takes longer, for example one that flashes further images. Zero, or anything that is not a whole number of seconds, is ignored with a log message and the default used, because every step of provisioning must have a limit. Set it by hand; the Options page does not show it.

The provisioning services also have their own overall limits: six hours for a provisioner, one hour for bootstrap and ten minutes for triage. A higher hook limit may also need a systemd drop-in raising `RuntimeMaxSec` for the service that runs the hook.

## FASTBOOT_CONTROL_TIMEOUT, FASTBOOT_STORAGE_TIMEOUT, FASTBOOT_ERASE_TIMEOUT, FASTBOOT_PRESENCE_TIMEOUT

**Optional, set by hand**

Time limits, in seconds, on the fastboot commands the provisioner sends:

| Variable | Default | Applies to |
| --- | --- | --- |
| `FASTBOOT_CONTROL_TIMEOUT` | `30` | Short commands: `getvar`, LEDs, staging |
| `FASTBOOT_STORAGE_TIMEOUT` | `120` | Partitioning, and LUKS format and open |
| `FASTBOOT_ERASE_TIMEOUT` | `900` | Erasing the whole device |
| `FASTBOOT_PRESENCE_TIMEOUT` | `10` | How long a board has to answer before, and if it goes away during, a long command |

A flash is allowed time in proportion to its size. When a limit is reached the command is stopped, which fails the run for all but a few optional queries, and the reason reaches the device's log. The Options page cannot set these; a save from it keeps them.

# Format of the config file

The config file is a simple text file, with one variable per line. It is read as shell by root, and a value may not span lines. Variables are specified in the format:

    VARIABLE_NAME=value

For example:

    RPI_SB_PROVISIONER_MANUFACTURING_DB=/var/lib/rpi-sb-provisioner/manufacturing.db

Comments can be added to the file by starting a line with a `#` character.

    # This is a comment
    RPI_SB_PROVISIONER_MANUFACTURING_DB=/var/lib/rpi-sb-provisioner/manufacturing.db

Saving from the Options page rewrites the whole file: it writes every setting, the package defaults included, single-quotes values that need it, and drops comments.

# Boot Image Package Configuration

The boot image generator creates Debian packages for deploying boot updates to provisioned devices. Package metadata is configured in a separate file, `/etc/rpi-sb-provisioner/bootimg-package-config`, read after the package defaults in `/usr/share/rpi-sb-provisioner/defaults/bootimg-package-config`. It is set by hand; the web interface does not edit it.

## RPI_SB_PACKAGE_MAINTAINER_NAME

**Optional**

The maintainer name to use in generated Debian packages.

**Default:** `System Administrator` (if not set)

**Example:**

    RPI_SB_PACKAGE_MAINTAINER_NAME="Acme Corporation"

This value appears in the `Maintainer` field of the Debian package control file and changelog.

## RPI_SB_PACKAGE_MAINTAINER_EMAIL

**Optional**

The maintainer email address to use in generated Debian packages.

**Default:** `root@<hostname>`, from `hostname -f` on the provisioning server

**Example:**

    RPI_SB_PACKAGE_MAINTAINER_EMAIL="ops@acme.com"

This value is combined with `RPI_SB_PACKAGE_MAINTAINER_NAME` to form the full maintainer field in Debian packages.

**Complete Example Configuration:**

File: `/etc/rpi-sb-provisioner/bootimg-package-config`

    # Debian package metadata for boot image updates
    RPI_SB_PACKAGE_MAINTAINER_NAME="Acme Corporation"
    RPI_SB_PACKAGE_MAINTAINER_EMAIL="ops@acme.com"

This will generate packages with:

    Maintainer: Acme Corporation <ops@acme.com>

See [Boot Image Generator Documentation](boot-img-generator.md) for more information about the automatic boot image generation feature.

# Settings that are not configuration variables

## Restricting provisioning to specific USB ports

Which USB ports the provisioner will pick devices up from is **not** controlled
by a variable in `/etc/rpi-sb-provisioner/config`. It is controlled by drop-in
rule files, so that a package describing a particular programming jig can ship
the topology for that hardware without touching this configuration file:

    /usr/share/rpi-sb-provisioner/usb-ports.d/    package-supplied rules
    /etc/rpi-sb-provisioner/usb-ports.d/          local administrator rules

With no `*.conf` file in either directory — the state of a fresh install — the
restriction is inactive and devices on every port are provisioned.

See the [USB Port Restriction Guide](usb-port-restriction.md) for the file
format, merge and masking rules, and how a skipped device is reported.
