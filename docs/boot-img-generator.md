*Automatic generation of boot.img and boot.sig when system images are uploaded*

# Overview

When a new system image is uploaded to the provisioner, and secure-boot mode is configured with appropriate key material, the system automatically generates a signed `boot.img` file that can be used to update devices in the field without re-provisioning.

This feature addresses the use case described in [Issue \#191](https://github.com/raspberrypi/rpi-sb-provisioner/issues/191), where users need to modify configuration files (like `config.txt`) on already-provisioned devices.

# How It Works

## Workflow

1.  **Image Upload:** User uploads a new system image via the web interface. A compressed image is decompressed first. IDP artefacts are not packaged.

2.  **Automatic Trigger:** The provisioner service starts the generator once the upload is complete. It can also be started from the image's details in the image browser with **Generate Boot Package**, offered only while a signing key is configured; the **Boot Package** row there shows whether a package exists.

3.  **Configuration Check:** System verifies, in this order:

    - `PROVISIONING_STYLE` is set to `secure-boot`

    - Customer key material is available (`CUSTOMER_KEY_FILE_PEM` or `CUSTOMER_KEY_PKCS11_NAME`), and can be used

    - `RPI_DEVICE_FAMILY` is configured

4.  **Boot Image Generation:** If checks pass, the system:

    - Extracts the boot partition, the image's first partition, which must be FAT

    - Inserts the pre-boot authentication initramfs

    - Modifies `cmdline.txt` and `config.txt` for secure boot

    - Creates `boot.img` using `rpi-make-boot-image`

    - Signs `boot.img` with the customer key to create `boot.sig`

5.  **Output:** Generated files are placed in `/srv/rpi-sb-provisioner/images/bootimg-output/`

## Generated Files

For each uploaded image (e.g., `2024-10-06-raspios-bookworm-arm64.img`), the following files are created:

- `<image-basename>.boot.img` - The signed boot image

- `<image-basename>.boot.sig` - The RSA signature for the boot image

- `<image-basename>.config.txt` - The fastboot configuration file

- `rpi-sb-boot-update_<version>_all.deb` - **Debian package** containing boot files

- `<image-basename>.package-info.txt` - Package information and installation instructions

The Debian package version is `0.` followed by the first 12 characters of the source image’s SHA256 hash, so each package has a unique, traceable version.

Example:

    /srv/rpi-sb-provisioner/images/bootimg-output/
    ├── 2024-10-06-raspios-bookworm-arm64.boot.img
    ├── 2024-10-06-raspios-bookworm-arm64.boot.sig
    ├── 2024-10-06-raspios-bookworm-arm64.config.txt
    ├── rpi-sb-boot-update_0.a3f5e8c9b2d1_all.deb
    └── 2024-10-06-raspios-bookworm-arm64.package-info.txt

# Using Generated Boot Images

## Method 1: Debian Package Installation (Recommended)

The easiest way to update provisioned devices is using the generated Debian package:

``` bash
# On the provisioned device
sudo dpkg -i rpi-sb-boot-update_0.a3f5e8c9b2d1_all.deb
sudo reboot
```

The package will:

- Install boot.img and boot.sig to `/boot/firmware/`, replacing the ones written at provisioning

- Display a message indicating a reboot is required

**Note:** `config.txt` is embedded inside `boot.img` and does not need to be installed separately. The bootloader mounts `boot.img` as a filesystem and reads `config.txt` from within it.

**Advantages of using the Debian package:**

- Standard package management integration

- Version tracking with `dpkg -l rpi-sb-boot-update`

- Automatic handling of file permissions

- Traceable versions (SHA256-based version numbers)

## Method 2: Manual File Replacement

If you need to manually update files on a device:

1.  Modify your base OS image with the desired changes

2.  Upload the modified image to the provisioner

3.  Retrieve the generated `boot.img` and `boot.sig` from the output directory

4.  Copy to the device:

    ``` bash
    # On the provisioner
    scp /srv/rpi-sb-provisioner/images/bootimg-output/*.boot.img device:/tmp/
    scp /srv/rpi-sb-provisioner/images/bootimg-output/*.boot.sig device:/tmp/

    # On the device
    sudo cp /tmp/*.boot.img /boot/firmware/boot.img
    sudo cp /tmp/*.boot.sig /boot/firmware/boot.sig
    sudo sync
    sudo reboot
    ```

## Updating Config on Provisioned Devices

If you need to update `config.txt` on devices already provisioned with secure boot:

1.  Modify your base OS image with the desired `config.txt` changes

2.  Upload the modified image to the provisioner

3.  Deploy the generated Debian package to your devices

4.  Reboot the devices

**Important:** This approach updates only the boot configuration and kernel. The rootfs remains unchanged, preserving any device-specific configuration.

## Deployment at Scale

For deploying updates to many devices, consider setting up an APT repository:

### Creating a Simple APT Repository

``` bash
# On your update server
mkdir -p /var/www/html/apt/pool/main
mkdir -p /var/www/html/apt/dists/stable/main/binary-all

# Copy the generated package
cp rpi-sb-boot-update_*.deb /var/www/html/apt/pool/main/

# Generate Packages file
cd /var/www/html/apt
dpkg-scanpackages pool/ /dev/null | gzip -9c > dists/stable/main/binary-all/Packages.gz

# Create Release file
cat > dists/stable/Release << EOF
Origin: RPI-SB-Provisioner
Label: Secure Boot Updates
Suite: stable
Codename: stable
Architectures: all
Components: main
Description: Raspberry Pi Secure Boot Updates
EOF
```

### Configuring Devices to Use the Repository

On each provisioned device:

``` bash
# Add repository
echo "deb [trusted=yes] http://your-server/apt stable main" | \
  sudo tee /etc/apt/sources.list.d/rpi-sb-updates.list

# Update and install
sudo apt update
sudo apt install rpi-sb-boot-update
sudo reboot
```

**Note:** The `[trusted=yes]` flag is used because the packages are not signed with a GPG key. For production deployments, consider signing your repository with GPG.

### Package Versioning and Updates

Since package versions are based on the source image SHA256:

- Each unique source image produces a unique package version

- The versions do not increase with time. Debian compares the hash's letters and digits in turn, so a newer image's version may sort below an older one's, and `apt upgrade` will then not offer it. Install the version you want explicitly, for example `sudo apt install rpi-sb-boot-update=0.b7c2a1f5e3d8 --allow-downgrades`, or with `dpkg -i`

- You can have multiple versions in your repository

- Devices can be pinned to specific versions if needed

Example versions from three images:

    rpi-sb-boot-update_0.a3f5e8c9b2d1_all.deb  # Initial image
    rpi-sb-boot-update_0.b7c2a1f5e3d8_all.deb  # After config.txt change
    rpi-sb-boot-update_0.c8d3b2e6f4a9_all.deb  # After kernel update

## Security Considerations

- The generated boot images are signed with your customer key

- Only devices provisioned with the matching public key can use these boot images

- The signing key must be the same one used during initial provisioning

- PEM signing keys uploaded through the WebUI may be stored device-wrapped at rest. The generator uses the provisioner's signing helpers, so wrapped PEM keys and PKCS#11 keys are both supported without manually decrypting key material.

- Generated files and packages should be handled as sensitive material

- Debian packages contain the source image filename and SHA256 in the changelog for traceability

- Consider using HTTPS and GPG signing for production APT repositories

# Configuration Requirements

## Required Settings

In `/etc/rpi-sb-provisioner/config`:

``` bash
# Must be set to secure-boot
PROVISIONING_STYLE=secure-boot

# Device family (4 for Pi 4/CM4, 5 for Pi 5/CM5)
RPI_DEVICE_FAMILY=4

# Key material (choose one)
CUSTOMER_KEY_FILE_PEM=/path/to/customer-key.pem
# OR
CUSTOMER_KEY_PKCS11_NAME='pkcs11:object=<keypair-alias>;type=private'
```

`CUSTOMER_KEY_FILE_PEM` may point at a device-wrapped key uploaded through the WebUI. `CUSTOMER_KEY_PKCS11_NAME` is resolved through OpenSSL `pkcs11-provider`; register the HSM module with p11-kit as described in the [Configuration Reference](config_vars.md#making-your-hsm-available).

## Package Metadata Configuration

In `/etc/rpi-sb-provisioner/bootimg-package-config`, which is set by hand (package defaults are in `/usr/share/rpi-sb-provisioner/defaults/bootimg-package-config`):

``` bash
# Maintainer name for generated Debian packages
RPI_SB_PACKAGE_MAINTAINER_NAME="Your Organization"

# Maintainer email for generated Debian packages
RPI_SB_PACKAGE_MAINTAINER_EMAIL="ops@example.com"
```

**Defaults if not configured:**

- Name: `System Administrator`

- Email: `root@<hostname>`, from `hostname -f` on the provisioner server

This separate configuration file allows you to customize the package metadata without modifying the main provisioner configuration.

## Optional Settings

If these are not set, the boot image generation will be skipped:

- If `PROVISIONING_STYLE` is not `secure-boot`, generation is skipped, and the web interface does not offer **Generate Boot Package**

- If no key material is configured, generation is skipped

- If `RPI_DEVICE_FAMILY` is not set, generation is skipped

A key that is configured but cannot be used, such as a missing PEM file or an unreachable HSM, fails the run instead.

# Monitoring and Logs

## Service Status

Check the status of boot image generation for a specific image:

``` bash
systemctl status rpi-sb-image-bootimg-generator@<image-filename>.service
```

## Logs

Logs are written to:

- **Journal:** `journalctl -u rpi-sb-image-bootimg-generator@<image-filename>.service`

- **File:** `/var/log/rpi-sb-provisioner/bootimg-generator/bootimg-generator.log`

## Log Inspection

``` bash
# View recent boot image generation activity
tail -f /var/log/rpi-sb-provisioner/bootimg-generator/bootimg-generator.log

# View service status for all boot image generation jobs
systemctl list-units 'rpi-sb-image-bootimg-generator@*'
```

# Implementation Details

## Components

| Component                                 | Purpose                                                                           |
|-------------------------------------------|-----------------------------------------------------------------------------------|
| `rpi-sb-image-bootimg-generator.sh`       | POSIX shell script that extracts boot partition and generates signed boot.img     |
| `rpi-sb-image-bootimg-generator@.service` | systemd template service that runs the generation script                          |
| `images.cpp::triggerBootImgGeneration()`  | C++ function in web service that starts the systemd service via D-Bus, on upload or from **Generate Boot Package** |

## Process Flow

1.  Web service detects image upload (via multipart form upload)

2.  File is saved to `/srv/rpi-sb-provisioner/images/`

3.  `triggerBootImgGeneration()` is called with the filename

4.  Function makes a D-Bus call to systemd’s Manager interface using `sd_bus_call_method()` to start the service

5.  systemd starts the service, which runs the shell script

6.  Shell script:

    - Reads the package defaults, then `/etc/rpi-sb-provisioner/config`, then the package metadata configuration

    - Validates prerequisites (secure-boot mode, key material, device family)

    - Mounts the image using loop device

    - Copies the boot partition, refusing one that holds links or special files, and modifies the copy

    - Creates and signs `boot.img`

    - Places output files in `/srv/rpi-sb-provisioner/images/bootimg-output/`

# Troubleshooting

## Boot Image Not Generated

**Check configuration:**

``` bash
grep -E '(PROVISIONING_STYLE|RPI_DEVICE_FAMILY|CUSTOMER_KEY)' /etc/rpi-sb-provisioner/config
```

**Check service status:**

``` bash
systemctl status rpi-sb-image-bootimg-generator@<image-filename>.service
```

**Check logs:**

``` bash
journalctl -u rpi-sb-image-bootimg-generator@<image-filename>.service -n 100
```

## Common Issues

**Issue:** Service starts but immediately exits

|          |                                                                       |
|----------|-----------------------------------------------------------------------|
| Cause    | Configuration is not set to `secure-boot`, or key material is missing |
| Solution | Verify configuration settings in `/etc/rpi-sb-provisioner/config`     |

**Issue:** "Boot partition not found" error

|          |                                                                                           |
|----------|-------------------------------------------------------------------------------------------|
| Cause    | Uploaded file is not a valid Raspberry Pi OS image                                        |
| Solution | Ensure the uploaded image is a standard Raspberry Pi OS image with a FAT32 boot partition |

**Issue:** "Boot partition contains links or special files" error, or the boot partition will not mount

|          |                                                                                           |
|----------|-------------------------------------------------------------------------------------------|
| Cause    | The image's first partition is not a FAT boot partition                                   |
| Solution | Use a standard Raspberry Pi OS image; a boot partition of any other type is refused       |

**Issue:** "PEM key file not found" error, followed by "Failed to initialize signing context"

|          |                                                          |
|----------|----------------------------------------------------------|
| Cause    | `CUSTOMER_KEY_FILE_PEM` points to a non-existent file    |
| Solution | Verify the key file path, or choose the key again under Options |

# Package Management

## Viewing Installed Package Information

``` bash
# Check if the package is installed
dpkg -l rpi-sb-boot-update

# View package details including changelog
dpkg -s rpi-sb-boot-update

# View package contents
dpkg -L rpi-sb-boot-update

# View changelog (includes source image filename)
zcat /usr/share/doc/rpi-sb-boot-update/changelog.Debian.gz
```

## Reverting

To revert to a previous boot configuration, install the package version built from the earlier image:

``` bash
sudo apt install rpi-sb-boot-update=<version> --allow-downgrades
# or
sudo dpkg -i rpi-sb-boot-update_<version>_all.deb
```

> **Warning**
>
> Do not remove or purge the package on a device. `/boot/firmware/boot.img` and `boot.sig` are its files, so `dpkg -r` deletes them, and a secure boot device will not boot until they are restored.

## Querying Package Version

``` bash
# Get installed version
dpkg-query -W -f='${Version}\n' rpi-sb-boot-update

# Check package info file for source image details
cat /srv/rpi-sb-provisioner/images/bootimg-output/*.package-info.txt
```

# Future Enhancements

Potential improvements for this feature:

- A download button in the web UI (the API serves a package at `/download-boot-package?name=<image>`)

- Automatic cleanup of old packages

- GPG signing of APT repository

- Support for FDE-only mode (without secure boot signing)

- Notification when package generation completes

- Batch generation for multiple images

- Automatic APT repository generation and hosting

# References

- [GitHub Issue \#191](https://github.com/raspberrypi/rpi-sb-provisioner/issues/191)

- [System Architecture](architecture.md)

- [Configuration Variables](config_vars.md)
