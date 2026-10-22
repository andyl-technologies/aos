#!@bash@/bin/bash
set -euo pipefail

. /run/aos-profile-gen.env

toplevel=$(readlink /sysroot/usr/lib/aos/toplevel)
gen=$AOS_PROFILE_GEN
sys=/run/etc/system-$gen
config_lower=/run/etc/config-$gen
upper_root=/run/etc/upper-$gen

mkdir -p "$sys/metadata" "$sys/content" \
  "$upper_root/dir" "$upper_root/work"

basedir=$(readlink "/sysroot$toplevel/etc-basedir")
metadata=$(readlink "/sysroot$toplevel/etc-metadata.erofs")

if [ "$AOS_CONFIGURATION_SELINUX_LABELS" = true ]; then
  # Persistent configuration is the highest-priority /etc lower. Its labels
  # must use the runtime /etc namespace before it can shadow labeled images
  # or be copied into the tmpfs upper. Never relabel the other /var owners.
  "$AOS_SETFILES" -F -E -r /sysroot/var \
    /sysroot/usr/lib/aos/selinux-file-contexts /sysroot/var/etc
fi

mount --bind "/sysroot$basedir" "$sys/content"
mount -t erofs -o ro,nodev,nosuid "/sysroot$metadata" "$sys/metadata"
mount -t overlay overlay -o \
  nodev,nosuid,metacopy=on,redirect_dir=on,lowerdir+=/sysroot/var/etc,lowerdir+=$config_lower/etc,lowerdir+=$sys/metadata,datadir+=$sys/content,upperdir=$upper_root/dir,workdir=$upper_root/work \
  /sysroot/etc

ln -sfn system-$gen /run/etc/system
ln -sfn config-$gen /run/etc/config
ln -sfn upper-$gen /run/etc/upper
rm -f /run/aos-profile-gen.env
