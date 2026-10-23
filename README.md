*Automated provisioning of secure boot and encryption for Raspberry Pi devices*

# rpi-sb-provisioner

rpi-sb-provisioner turns a Raspberry Pi into a provisioning station. Connect a device over USB and it programs secure boot, encrypts the device's storage with a device-unique key, writes your operating system and records the device in a manufacturing database, without anyone typing a command. Operators configure and watch it through a web interface.

It is meant for businesses building products on Raspberry Pi, for manufacturers working at volume, and for anyone preparing more than a handful of devices. Operating it needs no knowledge of the boot chain or of cryptography.

Three provisioning styles are offered: **secure-boot** (secure boot, encrypted storage and a device-unique key), **fde-only** (encryption without secure boot) and **naked** (the operating system alone). Disk images and IDP artefacts built with `rpi-image-gen` are both supported.

# Supported devices

- Raspberry Pi 5 and Compute Module 5
- Raspberry Pi 4 and Compute Module 4
- Raspberry Pi Zero 2 W (fde-only or naked; it has no secure boot)

The provisioning station itself is a Raspberry Pi running 64-bit Raspberry Pi OS.

# Installation

    sudo apt update && sudo apt full-upgrade -y
    sudo apt install -y rpi-sb-provisioner
    xdg-open http://localhost:3142

Sign in with an account in the `rpi-sb-provisioner` group; installing adds the first user. Then configure the station under **Options**. Upgrading from 2.3 changes how the station is accessed: read [Upgrading from 2.3](docs/user-guide.md#upgrading-from-23) first.

# Documentation

- [User guide](docs/user-guide.md): setting up a station, preparing devices, monitoring, troubleshooting, the manufacturing database and customisation.
- [Configuration reference](docs/config_vars.md): every setting in `/etc/rpi-sb-provisioner/config`.
- Device connection guides: [Raspberry Pi 5](docs/device-guidance/pi5.md), [Raspberry Pi 4](docs/device-guidance/pi4.md), [Raspberry Pi Zero 2 W](docs/device-guidance/zero2.md).
- [HSM support](docs/hsm-support.md): signing with a PKCS#11 token.
- [USB port restriction](docs/usb-port-restriction.md): provisioning only on a jig's wired ports.
- [Scaling](docs/mass-provisioning-guidance/scaling.md): high-volume production.
- [HTTP API](docs/api/README.md): automation and integration.
- [Architecture](docs/architecture.md): how the services fit together.
- [Boot image generator](docs/boot-img-generator.md) and [Debian package example](docs/debian-package-example.md).
- [Reverse proxy example](nginx-example/README.md): serving the web interface over HTTPS with nginx.

# Reporting problems

Report issues at <https://github.com/raspberrypi/rpi-sb-provisioner/issues>, with the device type, the error and the logs.
