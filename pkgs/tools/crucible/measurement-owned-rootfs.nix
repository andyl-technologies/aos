# Trusted private PID1 boot image; it carries identities, never Rust credits.
{
  pkgs,
  lib,
  installedImages,
  operatorPolicy,
  imageInventory,
  sourceManifest,
  imageBytes,
  operatorMode,
}: let
  imageFacts = installedImages.passthru;
  swapBytes =
    if operatorMode == "kernelMeasurement"
    then 4294967296
    else 0;
  initExecutable = "${installedImages}/bin/crucible-measurement-init";
  actorExecutable = "${installedImages}/bin/crucible-measurement-actor";
  birth = pkgs.writeTextFile {
    name = "crucible-private-actor-birth";
    destination = "/bin/actor-birth";
    executable = true;
    text = ''
      #!${pkgs.bash}/bin/bash
      set -eu
      # This is the actual child PID. The fixed trusted leaf exists before birth.
      # No subshell or helper runs between placement and fresh actor exec.
      printf '%s\n' "$$" > /sys/fs/cgroup/crucible-measurement-actor/guardian/cgroup.procs
      ulimit -n 1024
      exec ${actorExecutable}
    '';
  };
  init = pkgs.writeTextFile {
    name = "crucible-private-parent-pid1";
    destination = "/init";
    executable = true;
    text = ''
      #!/bin/sh
      set -eu
      export PATH=${pkgs.coreutils}/bin:${pkgs.util-linux}/bin:${pkgs.util-linux}/sbin
      mount -t proc proc /proc
      mount -t sysfs sysfs /sys
      mount -t devtmpfs devtmpfs /dev
      mount -t tmpfs tmpfs /run
      mount -t tmpfs tmpfs /tmp
      mkdir -p /sys/fs/cgroup
      mount -t cgroup2 cgroup2 /sys/fs/cgroup
      # The complete twenty-GiB guest is externally contained from kernel birth.
      # This fresh actor leaf is a sixteen-GiB subdivision, not another grant.
      printf '+cpu +memory +pids\n' > /sys/fs/cgroup/cgroup.subtree_control
      mkdir /sys/fs/cgroup/crucible-measurement-actor
      printf '17179869184\n' > /sys/fs/cgroup/crucible-measurement-actor/memory.max
      printf '${toString swapBytes}\n' > /sys/fs/cgroup/crucible-measurement-actor/memory.swap.max
      printf '1000000 100000\n' > /sys/fs/cgroup/crucible-measurement-actor/cpu.max
      printf '4096\n' > /sys/fs/cgroup/crucible-measurement-actor/pids.max
      printf '+cpu +memory +pids\n' > /sys/fs/cgroup/crucible-measurement-actor/cgroup.subtree_control
      mkdir /sys/fs/cgroup/crucible-measurement-actor/guardian
      printf '0\n' > /sys/fs/cgroup/crucible-measurement-actor/guardian/memory.swap.max
      mkdir /sys/fs/cgroup/crucible-measurement-actor/workload
      printf '${toString swapBytes}\n' > /sys/fs/cgroup/crucible-measurement-actor/workload/memory.swap.max
      printf '+cpu +memory +pids\n' > /sys/fs/cgroup/crucible-measurement-actor/workload/cgroup.subtree_control
      exec ${initExecutable}
    '';
  };
  dependencies = [installedImages operatorPolicy imageInventory sourceManifest birth init pkgs.bash pkgs.coreutils pkgs.util-linux];
  closure = import ../../../lib/build/closure-info.nix {inherit pkgs lib;} {
    rootPaths = dependencies;
    pname = "crucible-private-parent-rootfs-closure";
  };
in
  assert builtins.elem operatorMode ["nativeOnly" "kernelMeasurement"];
  assert imageFacts.privateFixture;
  assert !imageFacts.runtimeAdmission;
  assert builtins.isInt imageBytes && imageBytes > 0 && imageBytes <= 68719476736;
    pkgs.mkDerivation {
      pname = "crucible-private-parent-owned-rootfs";
      version = "0";
      src = null;
      buildDeps = [pkgs.coreutils pkgs.e2fsprogs pkgs.fakeroot];
      runtimeDeps = dependencies;
      phases = [
        {
          name = "assemble-immutable-owned-rootfs";
          script = ''
            mkdir -p rootfs/nix/store rootfs/etc/crucible rootfs/bin rootfs/proc rootfs/sys rootfs/dev rootfs/run rootfs/tmp
            chmod 0755 rootfs/nix rootfs/nix/store
            while IFS= read -r store_path; do
              cp -a "$store_path" rootfs/nix/store/
            done < ${closure}/store-paths
            ln -s ${pkgs.bash}/bin/bash rootfs/bin/sh
            ln -s ${init}/init rootfs/init
            ln -s ${operatorPolicy} rootfs/etc/crucible/measurement-operator.json
            ln -s ${imageInventory} rootfs/etc/crucible/measurement-images.json
            ln -s ${sourceManifest} rootfs/etc/crucible/measurement-source.json
            ln -s ${birth}/bin/actor-birth rootfs/etc/crucible/measurement-actor-birth
            truncate -s ${toString imageBytes} "$out"
            ${pkgs.fakeroot}/bin/fakeroot ${pkgs.bash}/bin/bash -c '
              chown -R 0:0 rootfs
              ${pkgs.e2fsprogs}/bin/mkfs.ext4 -F -d rootfs "$out"
            '
          '';
        }
      ];
      passthru = {
        inherit operatorPolicy imageInventory sourceManifest installedImages birth init operatorMode;
        privateFixture = true;
        runtimeAdmission = false;
      };
    }
