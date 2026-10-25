{
  pkgs,
  lib,
  image,
  suite ? "collection-reconciliation",
}:
assert builtins.elem suite ["collection-reconciliation" "maintenance-owner-hints" "local-deletion-hints"]; let
  testing = import ../../lib/testing {inherit pkgs lib;};
in
  testing.mkVMTest {
    name =
      if suite == "collection-reconciliation"
      then "terrane-local-collection-reconciliation"
      else if suite == "maintenance-owner-hints"
      then "terrane-local-maintenance-hints"
      else "terrane-local-deletion-hints";
    memory = 1024;
    timeout =
      if suite == "collection-reconciliation"
      then 1020
      else 240;
    rootfsDeps = [image pkgs.terrane.src pkgs.python3 pkgs.coreutils pkgs.diffutils pkgs.util-linux];
    testScript = ''
      set -euo pipefail
      umask 077
      unset LD_LIBRARY_PATH
      mount -o remount,rw /
      fixture_root=$(mktemp -d /var/terrane-local-collection.XXXXXXXX)
      trap 'rm -rf -- "$fixture_root"' EXIT
      test "$(findmnt --noheadings --output FSTYPE --target "$fixture_root")" = ext4
      chmod 0755 "$fixture_root"
      mkdir "$fixture_root/storage" "$fixture_root/evidence"
      chown 840:840 "$fixture_root/storage" "$fixture_root/evidence"
      chmod 0700 "$fixture_root/storage" "$fixture_root/evidence"
      export src=${pkgs.terrane.src}
      export TERRANE_COLLECTION_TEST_IMAGE=${image}
      export TERRANE_COLLECTION_EVIDENCE="$fixture_root/evidence"
      export TERRANE_COLLECTION_SUITE=${suite}
      export TMPDIR="$fixture_root/storage"
      setpriv --reuid=840 --regid=840 --clear-groups --bounding-set=-all \
        --inh-caps=-all --ambient-caps=-all --no-new-privs \
        python3 ${pkgs.terrane.src}/tests/terrane/local_collection_vm.py
    '';
  }
