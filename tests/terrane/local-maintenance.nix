{
  pkgs,
  lib,
  sourceGateWithInputs,
}: let
  testing = import ../../lib/testing {inherit pkgs lib;};
  image = import ./surface-test-image.nix {
    sourceGate = sourceGateWithInputs {
      preserveArtifactBytes = true;
      runtimeDeps = [pkgs.rust pkgs.rust.dev pkgs.diffutils] ++ (pkgs.rust.runtimeDeps or []);
      nukeRefsKeep = [pkgs.terrane.src];
      extraBuildDeps = [pkgs.binutils];
    };
  };
in
  testing.mkVMTest {
    name = "terrane-local-maintenance";
    memory = 1024;
    timeout = 360;
    rootfsDeps = [image pkgs.terrane.src pkgs.python3 pkgs.coreutils pkgs.diffutils pkgs.util-linux];
    testScript = ''
      set -euo pipefail
      umask 077
      unset LD_LIBRARY_PATH
      mount -o remount,rw /
      fixture_root=$(mktemp -d /var/terrane-local-maintenance.XXXXXXXX)
      trap 'rm -rf -- "$fixture_root"' EXIT
      test "$(findmnt --noheadings --output FSTYPE --target "$fixture_root")" = ext4
      chmod 0755 "$fixture_root"
      mkdir "$fixture_root/storage" "$fixture_root/evidence"
      chown 840:840 "$fixture_root/storage" "$fixture_root/evidence"
      chmod 0700 "$fixture_root/storage" "$fixture_root/evidence"
      export src=${pkgs.terrane.src}
      export TERRANE_SURFACE_TEST_IMAGE=${image}
      export TERRANE_MAINTENANCE_EVIDENCE="$fixture_root/evidence"
      export TMPDIR="$fixture_root/storage"
      setpriv --reuid=840 --regid=840 --clear-groups --bounding-set=-all \
        --inh-caps=-all --ambient-caps=-all --no-new-privs \
        python3 ${pkgs.terrane.src}/tests/terrane/local_maintenance_vm.py
    '';
  }
