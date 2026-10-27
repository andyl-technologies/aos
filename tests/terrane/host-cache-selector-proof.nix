# Runs each owning gate's original selectors with private guest storage.
{
  pkgs,
  lib,
  image,
}: let
  testing = import ../../lib/testing {inherit pkgs lib;};
in
  name: selectors: let
    inventory = pkgs.writeTextFile {
      name = "terrane-${name}-selectors.json";
      text = builtins.toJSON selectors;
    };
  in
    testing.mkVMTest {
      name = "terrane-${name}-selectors-ext4";
      memory = 1024;
      timeout = 300;
      rootfsDeps = [image inventory pkgs.terrane.src pkgs.python3 pkgs.coreutils pkgs.diffutils pkgs.util-linux];
      testScript = ''
        set -euo pipefail
        umask 077
        unset LD_LIBRARY_PATH
        mount -o remount,rw /
        fixture_root=$(mktemp -d /var/terrane-host-cache-selectors.XXXXXXXX)
        trap 'rm -rf -- "$fixture_root"' EXIT
        test "$(findmnt --noheadings --output FSTYPE --target "$fixture_root")" = ext4
        chown 840:840 "$fixture_root"
        chmod 0700 "$fixture_root"
        export TMPDIR="$fixture_root"
        export src=${pkgs.terrane.src}
        setpriv --reuid=840 --regid=840 --clear-groups --bounding-set=-all \
          --inh-caps=-all --ambient-caps=-all --no-new-privs \
          python3 "$src/tests/terrane/host_cache_selector_vm.py" \
            ${image} "$src" ${name} ${inventory}
      '';
    }
