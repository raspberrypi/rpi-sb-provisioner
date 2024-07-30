# rpi-sb-provisioner
A minimal-input automatic secure boot provisioning system for Raspberry Pi devices.

## Required hardware for the provisioning system

* A Raspberry Pi 5 (or other 64-bit Raspberry Pi device)
* An official Raspberry Pi 5 Power Supply
* An installation of Raspberry Pi OS Bookworm, or later
* At least 32GB of storage, for temporary working files
* For provisioning Raspberry Pi 5:
    * A USB-A to USB-C cable
* For provisoning Raspberry Pi Compute Module 4:
    * A USB-A to microUSB-B cable
    * A Raspberry Pi Compute Module 4 IO Board
    * A single Jumper Wire

## Hardware configuration

Connect your Raspberry Pi 5 to your Raspberry Pi Compute Module 4 IO Board as illustrated. Grey cables supply power, Red supplies data.

**TODO**: Include diagram

## Software configuration

`rpi-sb-provisioner` is provided from the Raspberry Pi OS APT repositories, and can be installed in the usual manner.

First, ensure you are running an up-to-date version of Raspberry Pi OS on your provisioning server:

```
sudo apt update && sudo apt full-upgrade -y
```

Now install a .deb release from this repository.

```
sudo dpkg -I ${release_filename}.deb
```

Copy the example configuration file into the expected location:

```
cp /etc/default/rpi-sb-provisioner /etc/rpi-sb-provisioner/config
```

Edit this configuration file with your editor of choice. For example:

```
sudo nano /etc/rpi-sb-provisioner/config
```

### Configuration fields

Configure `rpi-sb-provisioner` by using the following fields in `/etc/rpi-sb-provisioner/config`

#### CUSTOMER_KEY_FILE_PEM
*Mandatory*

The fully qualified path to your signing key, encoded in PEM format. This file is expected to contain an RSA 2048-bit Private Key.

**WARNING**: This file should be considered key material, and should be protected while at rest and in use according to your threat model.

#### GOLD_MASTER_OS_FILE
*Mandatory*

This should be your 'gold master' OS image. No customisation should be present in this image that you would not expect to be deployed to your entire fleet. `rpi-sb-provisioner` assumes this image has been created using `pi-gen`, and using a non-`pi-gen` image may produce undefined behaviour.

#### RPI_DEVICE_STORAGE_TYPE
*Mandatory*

Specify the kind of storage your target will use. Supported values are `sd`, `emmc`, `nvme`.

#### RPI_DEVICE_FAMILY
*Mandatory*

Specify the family of Raspberry Pi device you are provisioning. Supported values are `4` or `5`. For example,

A Raspberry Pi Compute Module 4 would be family `4`

A Raspberry Pi 5 would be family `5`

#### RPI_DEVICE_BOOTLOADER_CONFIG_FILE
*Mandatory, with a default*

**WARNING**: `rpi-sb-provisioner` will ignore the Raspberry Pi Bootloader configuration built by `pi-gen`, and use the one provided in this variable.

Specify the Raspberry Pi Bootloader configuration you want your provisioned devices to use. A default is provided.

Further information on the format of this configuration file can be found in [the Raspberry Pi Documentation](https://www.raspberrypi.com/documentation/computers/config_txt.html)

#### RPI_DEVICE_SERIAL_STORE
*Optional, with a default*

Specify a location for the seen-devices storage directory. This directory will contain a zero-length file named with the serial number of each device seen, with the created files being used inside the state machine of `rpi-sb-provisioner`

#### RPI_SB_WORKDIR
*Optional*

**WARNING**: If you do not set this variable, your modified OS intermediates will not be stored, and will be unavailable for inspection.

Set to a location to cache OS assets between provisioning sessions. Recommended for use in production. For example:

```
RPI_SB_WORKDIR=/srv/rpi-sb-provisioner/
```

#### DEMO_MODE_ONLY
*Optional*

Set to `1` to allow the service to run without actually writing keys or OS images. You may, for example, use `DEMO_MODE_ONLY` in combination with `RPI_SB_WORKDIR` to inspect the modifications `rpi-sb-provisioner` would make to your OS ahead of deployment.

**WARNING**: Setting `DEMO_MODE_ONLY` will cause your seen-devices storage location to change to a subdirectory of the one specified by `RPI_DEVICE_SERIAL_STORE`, `demo/`

## Observing active provisioning operations

As `rpi-sb-provisioner` is implemented using `systemd` services, you can use the typical `systemctl` commands to observe the services as they provision your device.

To see active provisioning operations, and the serial numbers of the devices involved, type into a Terminal window:

```
systemctl list-units rpi-sb-*
```

## Observing logs

Logs are stored on a per-device, per-stage basis, where logs for a given device are stored at `/var/log/rpi-sb-provisioner/<serial>`. The logs for the **triage** stage, which is the state machine controlling `rpi-sb-provisioner`, are accessible via the systemd journal:

To observe the triage of an individual device, use `systemctl`

```
sudo systemctl status rpi-sb-triage@<serial>.service
```

For the **keywriter** and **provisioner** stages, logs are named per their stage in the log directory. For example, to observe the progress of an individual device through a stage, you could use `tail`:

```
tail -f -n 100 /var/log/rpi-sb-provisioner/<serial>/keywriter.log
tail -f -n 100 /var/log/rpi-sb-provisioner/<serial>/provisioner.log
```

## Identifying secured devices

A 'secured device' is one where your customer signing key has been written - regardless of the state of your OS or other software. Such devices can only load Linux images signed by your customer signing key.

Obtain this by enumerating the files from the *Device Serial Store* directory:

```
ls <RPI_DEVICE_SERIAL_STORE>
```

**WARNING**: If you have set `DEMO_MODE_ONLY`, your demo mode seen files will be located at `<RPI_DEVICE_SERIAL_STORE>/demo`

## Inspecting the OS to be flashed

When run with `DEMO_MODE_ONLY=1`, `rpi-sb-provisioner` will only prepare images to be provisioned - allowing you to inspect the OS images prior to mass deployment.

**WARNING**: You must set `RPI_SB_WORKDIR` in the configuration file to observe the modified image. If you do not set `RPI_SB_WORKDIR`, the intermediates will be deleted at the completion of the run.

With both variables set, connect a device to be demo-provisioned per the provisoning instructions above.

The images will be located in the directory pointed to by `RPI_SB_WORKDIR`.

**WARNING**: Remember to unset `DEMO_MODE_ONLY` before moving to mass deployment.

## Debugging unexpected results

The first stage of debugging unexpected results is to delete the contents of the directory pointed to by `RPI_SB_WORKDIR`, which will force any intermediate OS images to be deleted.

```
sudo rm ${RPI_SB_WORKDIR}/*
```

The second stage is to delete the corresponding `seen` file, matching the serial number of the device you are debugging, in the directory pointed to by `RPI_DEVICE_SERIAL_STORE`

```
sudo rm ${RPI_DEVICE_SERIAL_STORE}/<serial>
```