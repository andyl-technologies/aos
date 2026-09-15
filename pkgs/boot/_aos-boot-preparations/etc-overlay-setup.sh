#!@bash@/bin/bash
set -euo pipefail

. /run/aos-profile-gen.env

toplevel=$(readlink /sysroot/aos-toplevel)
gen=$AOS_PROFILE_GEN
sys=/run/etc/system-$gen
config_lower=/run/etc/config-$gen
upper_root=/run/etc/upper-$gen

mkdir -p "$sys/metadata" "$sys/content" \
  "$upper_root/dir" "$upper_root/work"

basedir=$(readlink "/sysroot$toplevel/etc-basedir")
metadata=$(readlink "/sysroot$toplevel/etc-metadata.erofs")
mount --bind "/sysroot$basedir" "$sys/content"
mount -t erofs -o ro,nodev,nosuid "/sysroot$metadata" "$sys/metadata"
mount -t overlay overlay -o \
  nodev,nosuid,metacopy=on,redirect_dir=on,lowerdir+=/sysroot/var/etc,lowerdir+=$config_lower/etc,lowerdir+=$sys/metadata,datadir+=$sys/content,upperdir=$upper_root/dir,workdir=$upper_root/work \
  /sysroot/etc

ln -sfn system-$gen /run/etc/system
ln -sfn config-$gen /run/etc/config
ln -sfn upper-$gen /run/etc/upper
rm -f /run/aos-profile-gen.env
