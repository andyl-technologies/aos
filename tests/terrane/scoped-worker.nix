# Joins original child custody, scoped Read and the serialized physical Send.
{
  pkgs,
  lib,
  image,
  crash ? false,
  pressure ? false,
  admission ? false,
  maintenance ? false,
  maintenanceListener ? false,
  workerNetwork ? false,
  workerMounted ? false,
}: let
  testing = import ../../lib/testing {inherit pkgs lib;};
in
  assert builtins.length (builtins.filter (enabled: enabled) [crash pressure admission maintenance maintenanceListener workerNetwork workerMounted]) <= 1;
    testing.mkVMTest {
      name =
        if workerMounted
        then "terrane-mounted-worker-ext4"
        else if workerNetwork
        then "terrane-worker-network-boundary-ext4"
        else if maintenanceListener
        then "terrane-gc-maintenance-listener-ext4"
        else if maintenance
        then "terrane-gc-maintenance-channel-ext4"
        else if admission
        then "terrane-index-admission-pressure-ext4"
        else if pressure
        then "terrane-index-pressure-ext4"
        else if crash
        then "terrane-worker-crash-recovery-ext4"
        else "terrane-scoped-worker-channel-ext4";
      memory = 1024;
      timeout =
        if pressure
        then 120
        else 90;
      rootfsDeps = [image pkgs.coreutils pkgs.util-linux pkgs.e2fsprogs pkgs.python3];
      testScript = ''
        set -eu
        mount -o remount,rw /
        mkdir -p /var/lib/terrane-cache-proof /mnt/terrane-cache-proof
        export TERRANE_CACHE_VM_IMAGE=/var/lib/terrane-cache-proof/cache.img
        export TERRANE_CACHE_VM_ROOT=/mnt/terrane-cache-proof
        truncate -s 128M "$TERRANE_CACHE_VM_IMAGE"
        mkfs.ext4 -F -b 4096 -O project,quota,verity -E quotatype=prjquota "$TERRANE_CACHE_VM_IMAGE"
        mount -t ext4 -o loop,prjquota "$TERRANE_CACHE_VM_IMAGE" "$TERRANE_CACHE_VM_ROOT"
        trap 'umount "$TERRANE_CACHE_VM_ROOT"; rm -f "$TERRANE_CACHE_VM_IMAGE"; rmdir "$TERRANE_CACHE_VM_ROOT" /var/lib/terrane-cache-proof' EXIT
        (cd ${image} && sha256sum --check share/elf-sha256sum && sha256sum --check surface-elf-sha256sum)
        export LD_LIBRARY_PATH="$(cat ${image}/share/runtime-library-path)"
        ${pkgs.python3}/bin/python3 ${image}/share/scoped_worker_vm.py ${image} ${pkgs.terrane.src} ${lib.optionalString crash "--crash"} ${lib.optionalString pressure "--pressure"} ${lib.optionalString admission "--admission"} ${lib.optionalString maintenance "--maintenance"} ${lib.optionalString maintenanceListener "--maintenance-listener"} ${lib.optionalString workerNetwork "--worker-network"} ${lib.optionalString workerMounted "--worker-mounted"}
        (cd ${image} && sha256sum --check share/elf-sha256sum && sha256sum --check surface-elf-sha256sum)
      '';
    }
