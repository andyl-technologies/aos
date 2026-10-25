# Executes the original filesystem selectors in their actual unprivileged guest.
{
  pkgs,
  lib,
  image,
}: let
  testing = import ../../lib/testing {inherit pkgs lib;};
  vmFor = suite:
    testing.mkVMTest {
      name = "terrane-shared-directory-${suite}-ext4";
      memory = 1024;
      timeout = 240;
      rootfsDeps = [image pkgs.terrane.src pkgs.python3 pkgs.coreutils pkgs.diffutils pkgs.util-linux];
      testScript = ''
        set -euo pipefail
        umask 077
        unset LD_LIBRARY_PATH
        mount -o remount,rw /
        fixture_root=$(mktemp -d /var/terrane-shared-directory.XXXXXXXX)
        trap 'rm -rf -- "$fixture_root"' EXIT
        test "$(findmnt --noheadings --output FSTYPE --target "$fixture_root")" = ext4
        chown 840:840 "$fixture_root"
        chmod 0700 "$fixture_root"
        export TMPDIR="$fixture_root"
        export src=${pkgs.terrane.src}
        setpriv --reuid=840 --regid=840 --clear-groups --bounding-set=-all \
          --inh-caps=-all --ambient-caps=-all --no-new-privs \
          python3 "$src/tests/terrane/shared_directory_vm.py" ${image} "$src" ${suite}
      '';
    };
in {
  readOnly = vmFor "read-only";
  isolation = vmFor "isolation";
}
