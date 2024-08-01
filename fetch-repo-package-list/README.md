# fetch-repo-package-list

## Usage
### Oneshot
To fetch the latest Raspberry Pi OS package list:
```
systemctl start fetch-repo-package-list@$(systemd-escape https://archive.raspberrypi.org/debian).service
```

The service makes use of systemd's CacheDirectory, and RuntimeDirectory during
execution.  The updated package list is outputted to the RuntimeDirectory,
which would typically as follows for the above example:
```
/var/run/fetch-repo-package-list@https\:--archive.raspberrypi.org-debian.service/Packages
```

### Regularly via timer
To fetch package lists every day at a random, but consistent, time between midnight and 6a.m. (local time):
```
systemctl enable --now fetch-repo-package-list@$(systemd-escape https://archive.raspberrypi.org/debian).timer
```
