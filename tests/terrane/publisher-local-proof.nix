# Host-local transport and native command evidence, prerequisites for broader
# registered gates; they do not qualify process network/capability sandboxing
# or nonempty cache reconciliation.
{
  pkgs,
  lib,
  sourceGateWithInputs,
}: let
  testing = import ../../lib/testing {inherit pkgs lib;};

  image =
    sourceGateWithInputs {
      preserveArtifactBytes = true;
      runtimeDeps = [pkgs.rust pkgs.rust.dev pkgs.binutils] ++ (pkgs.rust.runtimeDeps or []);
      nukeRefsKeep = [pkgs.terrane.src];
    } "publisher-local-proof-image" ''
      cd crates
      cargo test --frozen --offline -p terrane-linux --features native-test-fixtures --lib \
        --test publisher_local_protocol --test publisher_local_vm --test publisher_local_native \
        --no-run --message-format=json-render-diagnostics > "$TMPDIR/publisher-local-build.jsonl"
      cargo build --frozen --offline -p terrane-linux --features native-test-fixtures \
        --example publication_fixture --message-format=json-render-diagnostics >> "$TMPDIR/publisher-local-build.jsonl"
      rustc --print target-libdir > "$TMPDIR/publisher-local-rust-libdir"

      cargo metadata --frozen --offline --no-deps --format-version=1 > "$TMPDIR/publisher-local-packages.json"
      python3 ${./publisher_local_proof.py} ${./.}
    '';

  multiUid = testing.mkVMTest {
    name = "terrane-publisher-local-multuid";
    memory = 512;
    rootfsDeps = [image pkgs.coreutils pkgs.grep pkgs.util-linux];
    testScript = ''
      set -eu
      mkdir -p /var/lib
      export TERRANE_PUBLISHER_VM=1
      export LD_LIBRARY_PATH="${image}/lib"
      result=/var/lib/terrane-publisher-local-multuid.log
      if ! ${image}/bin/publisher_local_vm --exact publisher_local_multuid_vm --ignored --nocapture > "$result" 2>&1; then
        cat "$result"
        exit 1
      fi
      cat "$result"
      grep -F 'test result: ok. 1 passed; 0 failed; 0 ignored;' "$result"
      for role in publisher serve outsider realize gc worker sandbox; do
        grep -E "^PUBLISHER_ROLE_IDENTITY role=$role uid=[0-9]+ gid=[0-9]+ groups=none caps=zero nnp=1$" "$result"
      done
      for role in serve outsider realize gc worker sandbox; do
        grep -Fx "PASS sealed namespace mutations refused role=$role" "$result"
      done
      rm "$result"
    '';
  };
  native = testing.mkVMTest {
    name = "terrane-publisher-local-native-ext4";
    memory = 1024;
    rootfsDeps = [image pkgs.bash pkgs.coreutils pkgs.grep pkgs.util-linux pkgs.e2fsprogs];
    testScript = ''
      set -eu
      mkdir -p /var/lib/terrane-publisher-local /mnt/terrane-publisher-local
      truncate -s 96M /var/lib/terrane-publisher-local/verity.img
      # Inheriting finite projects are provisioned by the guest root supervisor.
      # Linux requires the verity block size to fit the filesystem block size.
      mkfs.ext4 -F -b 4096 -O project,quota,verity -E quotatype=prjquota /var/lib/terrane-publisher-local/verity.img
      mount -t ext4 -o loop,prjquota /var/lib/terrane-publisher-local/verity.img /mnt/terrane-publisher-local
      trap 'umount /mnt/terrane-publisher-local; rm -f /var/lib/terrane-publisher-local/verity.img; rmdir /mnt/terrane-publisher-local /var/lib/terrane-publisher-local' EXIT
      export TERRANE_PUBLISHER_VM=1
      export TERRANE_PUBLISHER_EXT4_ROOT=/mnt/terrane-publisher-local
      export TERRANE_PUBLICATION_FIXTURE="${image}/bin/publication_fixture"
      export LD_LIBRARY_PATH="${image}/lib"
      ${pkgs.bash}/bin/bash ${image}/share/native_socket_units.bash \
        ${image} "$TERRANE_PUBLISHER_EXT4_ROOT/socket-unit" ${pkgs.util-linux}/bin/setpriv
      result=/var/lib/terrane-publisher-local/result.log
      for native_case in publisher_local_native_role publisher_local_native_lifecycle_vm; do
        if ! ${image}/bin/publisher_local_native --exact "$native_case" --ignored --nocapture > "$result" 2>&1; then
          cat "$result"
          exit 1
        fi
        cat "$result"
        grep -F "test $native_case ..." "$result"
        grep -F 'test result: ok. 1 passed; 0 failed; 0 ignored;' "$result"
      done
      grep -Fx 'PASS actual publisher backing is read-only and cannot be reopened writable' "$result"
      rm "$result"
    '';
  };
in {
  inherit image multiUid native;
}
