# make-boot-image
A oneshot service to download the specified Raspberry Pi linux-image- and
create a replacement boot-image- package.  This replacement package contains a
signed boot.img with a cryptroot-enabled initramfs. The kernel modules are
retained in the replacement package. Necessary firmware file are inserted into
the signed boot.img where appropriate (via raspi-firmware package).

> [!CAUTION]
> Support only exists for v8 kernels at this time.

## Configuration
- VENDOR
- OPENSSL
- CUSTOMER\_KEY\_FILE\_PEM

## Usage
To create a replacement boot-image- package for linux-image-6.6.31+rpt-rpi-v8
```
systemctl start make-boot-image@$(systemd-escape 6.6.31+rpt-rpi-v8).service
```

To determine the latest v8 linux image (in order to run the service as
suggested above)
```
META_PKG=linux-image-rpi-v8
SRV=rpi-package-download@$(systemd-escape $META_PKG).service
systemctl start --wait $SRV \
	&& grep-dctrl -F Package -X $META_PKG -n -s Depends /var/cache/$SRV/latest/Packages \
		| grep -o '^[[:graph:]]*'
```

The service makes use of systemd's CacheDirectory during execution.  The boot-image- package created by the example given above would typically be found at:
```
/var/cache/make-boot-image@6.6.31\x2brpt\x2drpi\x2dv8.service/boot-image-<vendor>-6.6.31+rpt-rpi-v8_6.6.31-1+rpt1_arm64.deb
```
