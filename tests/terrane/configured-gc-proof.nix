{
  pkgs,
  lib,
  image,
}: let
  testing = import ../../lib/testing {inherit pkgs lib;};
in
  testing.mkVMTest {
    name = "terrane-configured-gc-ext4";
    memory = 1024;
    timeout = 420;
    rootfsDeps = [image pkgs.terrane.src pkgs.python3 pkgs.coreutils pkgs.util-linux];
    testScript = ''
      set -euo pipefail
      umask 077
      unset LD_LIBRARY_PATH
      mount -o remount,rw /
      fixture_root=$(mktemp -d /var/terrane-configured-gc.XXXXXXXX)
      trap 'rm -rf -- "$fixture_root"' EXIT
      test "$(findmnt --noheadings --output FSTYPE --target "$fixture_root")" = ext4
      chmod 0755 "$fixture_root"
      mkdir -m 0700 "$fixture_root/storage"
      chown 840:840 "$fixture_root/storage"
      python3 ${./configured_sdk_proof.py} verify ${image} ${pkgs.terrane.src}
      export TMPDIR="$fixture_root/storage"
      setpriv --reuid=840 --regid=840 --clear-groups --bounding-set=-all \
        --inh-caps=-all --ambient-caps=-all --no-new-privs \
        python3 ${pkgs.terrane.src}/tests/terrane/configured_gc_vm.py \
          ${image} "$fixture_root/storage"
    '';
  }
