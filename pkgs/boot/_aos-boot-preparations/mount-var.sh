#!@bash@/bin/bash
set -euo pipefail

if ! mountpoint -q /sysroot/var; then
  mkdir -p /sysroot/var
  if [ "$AOS_ZFS_STATE" = true ]; then
    mount -t zfs -o zfsutil,nosuid,nodev "$AOS_ZFS_POOL/var" /sysroot/var
    mkdir -p /sysroot/var/log /sysroot/var/lib
    mount -t zfs -o zfsutil,nosuid,nodev "$AOS_ZFS_POOL/var/log" /sysroot/var/log
    mount -t zfs -o zfsutil,nosuid,nodev "$AOS_ZFS_POOL/var/lib" /sysroot/var/lib
  elif [ -e /dev/mapper/var ]; then
    mount -o nosuid,nodev /dev/mapper/var /sysroot/var
  else
    mount -o nosuid,nodev /dev/disk/by-partlabel/var /sysroot/var
  fi
fi

mkdir -p /sysroot/var/{log,lib,tmp}
mkdir -p /sysroot/var/etc
ln -sfn /run /sysroot/var/run
