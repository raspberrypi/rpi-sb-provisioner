#!/bin/bash

if [ ! $(getent group rpi-sb-provisioner) ]; then
  groupadd rpi-sb-provisioner
else
    echo "Group rpi-sb-provisioner already exists"
fi

if id -nGz "pi" | grep -qzxF "rpi-sb-provisioner"
then
    echo User \`pi\' already belongs to group \`rpi-sb-provisioner\'
else
    usermod --append --groups rpi-sb-provisioner pi
fi

if id -nGz "root" | grep -qzxF "rpi-sb-provisioner"
then
    echo User \`root\' already belongs to group \`rpi-sb-provisioner\'
else
    usermod --append --groups rpi-sb-provisioner root
fi

if ! [ -f /etc/rpi-sb-provisioner/config ]; then
  touch /etc/rpi-sb-provisioner/config
else
    echo "Config file already exists"
fi

chown :rpi-sb-provisioner /etc/rpi-sb-provisioner/config
chmod g+w /etc/rpi-sb-provisioner/config