# Keeps independent native controls within the enforced whole-guest bound.
{
  pkgs,
  lib,
  image,
  allFeatureUnits,
}: let
  testing = import ../../lib/testing {inherit pkgs lib;};
  profile =
    if allFeatureUnits
    then "all-features"
    else "base";
  scenarios = ["units" "recovery" "eviction"];
  scenarioCheck = scenario:
    testing.mkVMTest {
      name = "terrane-native-host-cache-${profile}-${scenario}-ext4";
      memory = 1024;
      # Actor limits and real 30-second producer/consumer/retirement grace
      # windows are unchanged. Each complete independent sequence must finish
      # within the former whole-guest allowance; none can mask a failed sibling.
      timeout = 870;
      rootfsDeps = [image pkgs.coreutils pkgs.util-linux pkgs.e2fsprogs pkgs.python3];
      testScript = ''
        set -eu
        mount -o remount,rw /
        mkdir -p /var/lib/terrane-cache-proof /mnt/terrane-cache-proof
        export TERRANE_CACHE_VM_IMAGE=/var/lib/terrane-cache-proof/cache.img
        export TERRANE_CACHE_VM_ROOT=/mnt/terrane-cache-proof
        truncate -s 512M "$TERRANE_CACHE_VM_IMAGE"
        mkfs.ext4 -F -b 4096 -O project,quota,verity -E quotatype=prjquota "$TERRANE_CACHE_VM_IMAGE"
        mount -t ext4 -o loop,prjquota "$TERRANE_CACHE_VM_IMAGE" "$TERRANE_CACHE_VM_ROOT"
        trap 'umount "$TERRANE_CACHE_VM_ROOT"; rm -f "$TERRANE_CACHE_VM_IMAGE"; rmdir "$TERRANE_CACHE_VM_ROOT" /var/lib/terrane-cache-proof' EXIT
        (cd ${image} && sha256sum --check share/elf-sha256sum)
        export LD_LIBRARY_PATH="$(cat ${image}/share/runtime-library-path)"
        ${pkgs.python3}/bin/python3 ${image}/share/host_cache_vm.py ${image} ${pkgs.terrane.src} ${lib.escapeShellArg scenario}
        (cd ${image} && sha256sum --check share/elf-sha256sum)
      '';
    };
in
  pkgs.mkDerivation {
    pname = "terrane-native-host-cache-${profile}-scenarios";
    version = "0";
    src = null;
    phases = [
      {
        name = "check";
        script = ''
          set -eu
          mkdir -p "$out"
          ${lib.concatMapStringsSep "\n" (scenario: let
              check = scenarioCheck scenario;
            in ''
              test "$(cat ${check}/result)" = PASS
              ln -s ${check} "$out/${scenario}"
            '')
            scenarios}
          printf '%s\n' PASS > "$out/result"
        '';
      }
    ];
  }
