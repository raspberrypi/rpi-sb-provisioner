*How to prepare Raspberry Pi 5 devices for provisioning*

# Overview

Raspberry Pi 5 has a built-in power button. Unlike Raspberry Pi 4, no GPIO configuration is required.

The connection process requires holding the power button while you plug in the cable.

# What You Need

- One USB A to USB C cable (high quality)

- Your Raspberry Pi 5 device

# The Connection Process

Raspberry Pi 5 requires a **single** connection. The device handles the
reboot between provisioning phases by itself.

## Connect the device

1.  **Hold down the power button** on the Raspberry Pi 5

2.  **While holding the button**, plug the USB C cable from your provisioning computer into the Raspberry Pi 5

3.  **Keep holding the power button** until the provisioning system recognizes the device

    You will see this in the web interface or system logs.

4.  **Release the button**

The device will start the bootstrap phase and then continue through the
remaining provisioning phases automatically. After the bootloader/EEPROM
update it reboots straight back into RPIBOOT mode on its own, so **you do
not need to unplug, reconnect, or touch the power button again** — just
leave it connected.

> Earlier releases required a manual unplug-and-reconnect at the
> `bootstrap-fastboot-initialisation-started` stage. This is no longer
> needed: rpi-sb-provisioner now writes `set_reboot_order=0x3` into the
> recovery config so the device returns to RPIBOOT mode by itself.

## When Is Provisioning Complete?

The Devices page in the web interface shows when the device has finished. The provisioner also turns off the power LED at the end:

- **Power LED off** = Provisioning is complete

- You can now disconnect the device

- The device is ready to use

# Bootloader Configuration

Bootstrap writes a new EEPROM to every Raspberry Pi 5 family device, built from the newest bootloader in `/lib/firmware/raspberrypi/bootloader-2712/latest/` unless the Options page names a firmware. Its configuration is the one chosen on the Options page: **Default**, the package's configuration for the provisioning style, or **Custom**, edited at `/options/bootloader-config`. With **Boot selected storage first** on (`RPI_DEVICE_BOOT_ORDER_MATCH_STORAGE`, the default), the selected storage type is moved to the front of `BOOT_ORDER`; both tiles show the boot order devices will get.

# Important Points To Remember

| Point                             | Explanation                                                                     |
|-----------------------------------|---------------------------------------------------------------------------------|
| **Single connection**             | Connect once and leave the device plugged in; it reboots itself between phases. |
| **Hold button before cable**      | Always hold the power button BEFORE plugging in the cable.                      |
| **Good cables matter**            | Use a high-quality USB A to USB C cable. Poor cables cause connection problems. |
| **Monitor in web interface**      | The Devices page at <http://localhost:3142/devices> shows provisioning progress. |

# Troubleshooting Raspberry Pi 5

## Problem: Device Not Entering RPIBOOT Mode

**Symptoms:** You hold the power button and connect the cable, but nothing happens.

**Solutions:**

- **Hold button first:** Make sure you hold the power button BEFORE connecting the USB cable

- **Try a better cable:** Use a shorter, high-quality USB A to USB C cable

- **Try a different USB port:** Some USB ports work better than others

- **Check power:** Make sure your provisioning computer has enough power

- **Keep holding:** Hold the button until you see the device is recognized

## Problem: Device Stalls Partway Through Provisioning

**Symptoms:** Provisioning starts but does not progress past the bootstrap or fastboot phase.

**Solutions:**

- **Leave it connected:** The device reboots itself between phases — do not unplug it while provisioning is in progress.

- **Check the logs:** Look at the web interface or logs for error messages.

- **Check your firmware:** This automatic-reboot flow requires a recent
  `rpi-eeprom`. If the device does not return on its own, update the host
  packages and try again.

- **Start over:** Try the complete process again from the start.

# Summary

**Connection process:**

1.  Hold power button → Plug in cable → Release button

2.  Leave the device connected

3.  Wait for the power LED to turn off

4.  Provisioning complete

**Remember:**

- Always hold button before connecting cable

- Connect once and leave it plugged in

- Use good quality cables

- Power LED off = provisioning complete
