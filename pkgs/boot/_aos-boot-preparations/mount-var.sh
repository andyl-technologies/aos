#!@bash@/bin/bash
set -euo pipefail

if ! mountpoint -q /sysroot/var; then
  mkdir -p /sysroot/var
  if [ "$AOS_ZFS_STATE" = true ]; then
    mount -t zfs -o zfsutil,nosuid,nodev "$AOS_ZFS_POOL/var" /sysroot/var
    mkdir -p /sysroot/var/log /sysroot/var/lib
    mount -t zfs -o zfsutil,nosuid,nodev "$AOS_ZFS_POOL/var/log" /sysroot/var/log
    mount -t zfs -o zfsutil,nosuid,nodev "$AOS_ZFS_POOL/var/lib" /sysroot/var/lib
  else
    # An unlocked mapper wins over an assembled array and its member
    # partition. Wait for udev to publish the selected system-state device.
    var_dev=""
    i=0
    while [ -z "$var_dev" ] && [ "$i" -lt 60 ]; do
      for candidate in /dev/mapper/var /dev/md/var /dev/disk/by-partlabel/var; do
        if [ -e "$candidate" ]; then
          var_dev="$candidate"
          break
        fi
      done
      [ -n "$var_dev" ] || { i=$((i + 1)); sleep 0.5; }
    done
    if [ -z "$var_dev" ]; then
      echo "mount-var: no device carries the system-state volume" >&2
      exit 1
    fi
    fs_type=$(@util_linux@/sbin/blkid -p -s TYPE -o value "$var_dev" 2>/dev/null || true)
    if [ "$fs_type" != ext4 ]; then
      echo "mount-var: refusing $var_dev with filesystem type ${fs_type:-none}; expected ext4" >&2
      exit 1
    fi
    mount -o nosuid,nodev "$var_dev" /sysroot/var
  fi
fi

mkdir -p /sysroot/var/{log,lib,tmp}
mkdir -p /sysroot/var/etc /sysroot/var/srv /sysroot/var/home
chmod 0755 /sysroot/var/home
mkdir -p /sysroot/var/roothome
chmod 0700 /sysroot/var/roothome
ln -sfn /run /sysroot/var/run
