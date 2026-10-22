# Observes kernel contracts independently of the unimplemented exposure worker.
{
  pkgs,
  lib,
}: let
  testing = import ../../lib/testing {inherit pkgs lib;};
  probe = pkgs.writeTextFile {
    name = "terrane-fuse-kernel-probe";
    destination = "/share/fuse_kernel_vm.py";
    text = builtins.readFile ./fuse_kernel_vm.py;
  };
in
  testing.mkVMTest {
    name = "terrane-fuse-kernel-contract-ext4";
    memory = 512;
    rootfsDeps = [probe pkgs.coreutils pkgs.util-linux pkgs.e2fsprogs pkgs.python3];
    testScript = ''
      set -euo pipefail
      umask 077
      mount -o remount,rw /
      fixture_root=$(mktemp -d /var/terrane-fuse-kernel.XXXXXXXX)
      mkdir "$fixture_root/ext4"
      truncate -s 128M "$fixture_root/disk.img"
      mkfs.ext4 -F -b 4096 -O verity "$fixture_root/disk.img"
      mount -t ext4 -o loop "$fixture_root/disk.img" "$fixture_root/ext4"
      trap 'umount "$fixture_root/ext4"; rm -rf -- "$fixture_root"' EXIT
      mkdir -p /sys/fs/fuse/connections
      mount -t fusectl fusectl /sys/fs/fuse/connections
      if [ ! -e /dev/fuse ]; then
        mknod /dev/fuse c 10 229
      fi
      timeout --signal=TERM --kill-after=5 30 \
        ${pkgs.python3}/bin/python3 ${probe}/share/fuse_kernel_vm.py \
        "$fixture_root/ext4" ${pkgs.coreutils}/bin/true
      umount /sys/fs/fuse/connections
    '';
  }
