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
    mount_options=nosuid,nodev
    if [ "$AOS_PROTECTED_VAR" = true ]; then
      # A raw inode read cannot see committed metadata still in the journal
      # after power loss. Replay it before checking the durable label, without
      # mounting or creating a label on an unqualified volume.
      recovery_status=0
      "$AOS_E2FSCK" -p -E journal_only "$var_dev" || recovery_status=$?
      if [ "$recovery_status" -gt 1 ]; then
        echo "mount-var: protected /var journal recovery failed ($recovery_status)" >&2
        exit 1
      fi
      # The mount option cannot replace a durable label from the format owner.
      var_label=$("$AOS_DEBUGFS" -R 'ea_get / security.selinux' "$var_dev" 2>/dev/null) || {
        echo "mount-var: cannot read protected /var root label" >&2
        exit 1
      }
      expected_label="security.selinux (${#AOS_VAR_ROOT_CONTEXT}) = \"$AOS_VAR_ROOT_CONTEXT\""
      if [ "$var_label" != "$expected_label" ]; then
        echo "mount-var: protected /var lacks its durable exact root label" >&2
        printf 'mount-var: observed root label: %.512q\n' "$var_label" >&2
        exit 1
      fi
      mount_options="$mount_options,rootcontext=$AOS_VAR_ROOT_CONTEXT"
    fi
    mount -o "$mount_options" "$var_dev" /sysroot/var
  fi
fi

if [ "$AOS_PROTECTED_VAR" = true ]; then
  # The authenticated handoff establishes /var/lib before generic state paths.
  /sysroot/usr/lib/systemd/aos-selinux-root-handoff \
    --launch-runtime-roots "$AOS_RUNTIME_ROOTS_EXECUTABLE" \
    --root /sysroot --prepare-var-base
  if [ "$AOS_PROTECTED_SANDBOX_OWNER_ROOTS" = true ]; then
    /sysroot/usr/lib/systemd/aos-selinux-root-handoff \
      --launch-runtime-roots "$AOS_RUNTIME_ROOTS_EXECUTABLE" \
      --root /sysroot --prepare-sandbox-owner-roots
  fi
  mkdir -p /sysroot/var/{log,tmp,srv}
else
  mkdir -p /sysroot/var/{log,lib,tmp,srv}
fi
mkdir -p /sysroot/var/etc /sysroot/var/home
chmod 0755 /sysroot/var/home
mkdir -p /sysroot/var/roothome
chmod 0700 /sysroot/var/roothome
ln -sfn /run /sysroot/var/run
