# rpi-package-download
A oneshot service to download the latest version of a Raspberry Pi OS package
(using a previously fetched package list). The latest package information is
also available in dctrl format.

## Usage
To download the latest version of the alsa-utils package:
```
systemctl start rpi-package-download@$(systemd-escape alsa-utils).service
```

The service makes use of systemd's CacheDirectory during execution.  The latest
package can be found by following symlinks in the CacheDirectory which would
typically be as follows for the above example:
```
/var/cache/rpi-package-download@alsa\x2dutils.service/latest/package.deb
```
