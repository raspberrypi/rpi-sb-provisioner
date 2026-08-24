# Restricting provisioning to specific USB ports

By default `rpi-sb-provisioner` programs any Raspberry Pi device that appears on
any USB port of the provisioning host. The udev rules that ship with the package
match on vendor and product ID alone, so a board plugged in anywhere on the host
is picked up and provisioned.

On a fixed programming jig that is rarely what you want. A single-headed jig has
exactly one port wired to its head, and a board attached to any other port — a
developer's board on a bench cable, a device left connected for debugging, a
downstream hub used for something else — must be left alone. Restricting
provisioning to a known set of ports makes the jig's behaviour deterministic:
if it is not in the head, it does not get programmed.

## How rules are expressed

The restriction is expressed as drop-in rule files, not as a variable in
`/etc/rpi-sb-provisioner/config`. This lets a package that describes a
particular piece of programming hardware ship the topology for that hardware
without touching the provisioner's own configuration, and without colliding
with the local administrator's settings.

Two directories are consulted, in ascending order of precedence:

| Directory | Intended owner |
| --- | --- |
| `/usr/share/rpi-sb-provisioner/usb-ports.d/` | Packages — a jig-specific package ships its topology here |
| `/etc/rpi-sb-provisioner/usb-ports.d/` | The local administrator |

Only files named `*.conf` are read. Both directories are empty of `*.conf`
files on a fresh install, so the restriction is inactive and every port is
accepted — the historical behaviour is unchanged until you opt in.

### Merging and masking

Files are merged by basename, with the `/etc` copy winning. This is the same
convention systemd uses for its own drop-ins:

- **Different names are additive.** The permitted set is the union of every
  pattern in every effective file, so a local `60-bench.conf` adds ports
  alongside a package's `50-jig.conf`.
- **The same name masks.** An empty `/etc/rpi-sb-provisioner/usb-ports.d/50-jig.conf`
  suppresses the package's `50-jig.conf` entirely, letting you disable a
  package-supplied rule set without removing the package.

## File format

One USB topology path per line, in the form the kernel uses for a device
directory under `/sys/bus/usb/devices`:

    <bus>-<port>[.<port>...]

Shell glob metacharacters are permitted. Blank lines are ignored, as is
anything from a `#` to the end of a line.

    # /etc/rpi-sb-provisioner/usb-ports.d/50-jig.conf

    # Jig head A
    1-1.2

    # Jig head B
    1-1.3

    # Every downstream port of the hub on bus 3, port 4
    3-4.*

A copyable template is installed at
`/usr/share/rpi-sb-provisioner/usb-ports.d/example.conf.sample`, alongside a
`README` covering the same ground as this page.

## Finding the path for a port

The topology path is a property of the physical port, not of the device
attached to it. It stays the same as boards are swapped through a jig head,
and it stays the same across the USB re-enumeration a device performs between
the bootstrap and fastboot phases — so a port permitted for bootstrap is
automatically permitted for triage.

To find the path for a port, plug a device into it and list what the kernel
sees:

    ls /sys/bus/usb/devices/

Or read it back from a known device node:

    udevadm info --name=/dev/bus/usb/<bus>/<dev> | grep -oE '[0-9]+-[0-9]+(\.[0-9]+)*$'

The USB path of any device the provisioner has handled is also shown on its
device details page in the web UI, and in the `USB path` field of the device
tiles.

## What happens to a device on a non-permitted port

The device is skipped, not failed:

- The reason is written to the provisioning log for that device.
- A `PORT-EXCLUDED` state is recorded against it, so the skip is visible in the
  web UI. The device tile is muted rather than flagged red, and reads
  `Skipped: USB port not permitted`; the device details page explains which
  directory the rules came from.
- No lock, no udev rule and no `rpiboot` invocation is created for it, and the
  provision-failed hook does not run.

Both entry points enforce the restriction: `rpi-sb-bootstrap.sh`, which handles
devices in rpiboot mode, and `rpi-sb-triage.sh`, which handles devices that
present as fastboot. Triage checks independently of bootstrap because an
already-provisioned board can boot straight to fastboot without passing through
bootstrap at all.

> **Note**
>
> While a restriction is in force, a device whose USB path cannot be determined
> at all is also skipped. An allowlist cannot be honoured for a device whose
> port is unknown, and on a jig the safe reading of "I cannot tell where this is
> plugged in" is "do not program it". If you see this in the log, check that the
> device is enumerating properly before adding ports to the rules.

## Verifying a rule set

After adding or editing a rule file, plug a board into a port that should be
ignored and confirm the skip is recorded:

    journalctl -u 'rpi-sb-bootstrap@*' -n 50

You should see the port that was rejected and the list of ports that are
permitted. No service restart or `udevadm` reload is needed — the rule files
are read afresh each time a device appears.
