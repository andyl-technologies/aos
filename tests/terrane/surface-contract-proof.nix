# Keeps each owning gate's original selectors in a private ext4 guest.
{
  pkgs,
  lib,
  testImage,
  nativeImage,
}: let
  testing = import ../../lib/testing {inherit pkgs lib;};
  vmFor = suite:
    testing.mkVMTest {
      name = "terrane-surface-${suite}-ext4";
      memory = 1024;
      timeout = 300;
      rootfsDeps =
        [testImage pkgs.terrane.src pkgs.python3 pkgs.coreutils pkgs.diffutils pkgs.util-linux]
        ++ lib.optional (suite == "schema") nativeImage;
      testScript = ''
        set -euo pipefail
        umask 077
        unset LD_LIBRARY_PATH
        mount -o remount,rw /
        fixture_root=$(mktemp -d /var/terrane-surface-contract.XXXXXXXX)
        trap 'rm -rf -- "$fixture_root"' EXIT
        test "$(findmnt --noheadings --output FSTYPE --target "$fixture_root")" = ext4
        chown 840:840 "$fixture_root"
        chmod 0700 "$fixture_root"
        export TMPDIR="$fixture_root"
        export src=${pkgs.terrane.src}
        export TERRANE_SURFACE_TEST_IMAGE=${testImage}
        setpriv --reuid=840 --regid=840 --clear-groups --bounding-set=-all \
          --inh-caps=-all --ambient-caps=-all --no-new-privs \
          python3 "$src/tests/terrane/surface_contract_vm.py" \
            ${testImage} ${
          if suite == "schema"
          then nativeImage
          else "-"
        } "$src" ${suite}
      '';
    };
in
  builtins.listToAttrs (map (suite: {
    name = suite;
    value = vmFor suite;
  }) ["interface" "commit-path" "schema" "status"])
