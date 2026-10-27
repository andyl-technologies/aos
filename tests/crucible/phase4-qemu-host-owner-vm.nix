# Runs the combined production resource owner without changing the Nix host.
{
  pkgs,
  lib,
}: let
  inherit (import ./_test-gate.nix {inherit pkgs lib;}) mkCrucibleBinaries workspaceTests;
  probe = mkCrucibleBinaries {
    pname = "crucible-qemu-host-owner-flight";
    builds = [workspaceTests.apacheRelease];
    executables = {
      crucible-qemu-host-owner-flight = "build --release -p crucible-qemu-host --example crucible-qemu-host-owner-flight";
    };
  };
  testing = import ../../lib/testing {inherit pkgs lib;};
in
  testing.mkVMTest {
    name = "crucible-qemu-host-owner";
    memory = 2048;
    rootfsDeps = [
      probe
      pkgs.qemu-crucible
      pkgs.crucible-qemu-plugin
      pkgs.linux
      pkgs.e2fsprogs
      pkgs.coreutils
      pkgs.util-linux
      pkgs.grep
    ];
    testScript = ''
      set -eu
      # This init and all controller/mount changes run in the disposable VM.
      for option in CFS_BANDWIDTH QUOTA QFMT_V2 QUOTACTL; do
        grep -Fxq "CONFIG_$option=y" ${pkgs.linux}/boot/config-*
      done
      mkdir -p /sys/fs/cgroup
      ${pkgs.util-linux}/bin/mount -t cgroup2 none /sys/fs/cgroup
      echo '+cpu +memory +pids' > /sys/fs/cgroup/cgroup.subtree_control
      mkdir /sys/fs/cgroup/crucible
      echo '+cpu +memory +pids' > /sys/fs/cgroup/crucible/cgroup.subtree_control
      truncate -s 2G /tmp/attempts.img
      ${pkgs.e2fsprogs}/sbin/mkfs.ext4 -F -O quota,project -E quotatype=prjquota /tmp/attempts.img
      mkdir /tmp/attempts
      ${pkgs.util-linux}/bin/mount -o loop,prjquota /tmp/attempts.img /tmp/attempts
      # The allocator authenticates an exact-owner private directory, not the
      # filesystem root with its mke2fs-created lost+found directory.
      mkdir -m 700 /tmp/attempts/run
      ${pkgs.coreutils}/bin/timeout -k 5 150 \
        ${probe}/bin/crucible-qemu-host-owner-flight \
        ${pkgs.qemu-crucible}/bin/qemu-system-x86_64 \
        ${pkgs.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so \
        ${pkgs.linux}/boot/vmlinuz-* \
        ${pkgs.qemu-crucible}/share/qemu/bios-256k.bin \
        /sys/fs/cgroup/crucible /tmp/attempts/run > /tmp/owner-result
      cat /tmp/owner-result
      grep -Fxq PASS /tmp/owner-result
      grep -Fxq real_guarded_qemu_launches=2 /tmp/owner-result
      grep -Fxq exclusive_resource_namespace=true /tmp/owner-result
      grep -Fxq child_credentials_unprivileged=true /tmp/owner-result
      grep -Fxq cpu_memory_task_limits_installed=true /tmp/owner-result
      grep -Fxq sticky_cancellation_closes_launch_authority=true /tmp/owner-result
      grep -Fxq process_reaped_before_storage_release=true /tmp/owner-result
      grep -Fxq single_project_slot_reused=true /tmp/owner-result
      ${pkgs.util-linux}/bin/umount /tmp/attempts
    '';
  }
