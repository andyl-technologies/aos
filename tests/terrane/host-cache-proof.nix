# Bounded native owner component evidence, outside owning gate registration.
# Recovery, publication and consumer lease controls qualify their exercised
# component behavior; complete retirement and BKT-15 readiness remain separate.
{
  pkgs,
  lib,
  sourceGateWithInputs,
  surfaceIndex ? false,
}: let
  testing = import ../../lib/testing {inherit pkgs lib;};
  image =
    sourceGateWithInputs {
      preserveArtifactBytes = true;
      runtimeDeps = [pkgs.rust pkgs.rust.dev] ++ (pkgs.rust.runtimeDeps or []);
      nukeRefsKeep = [pkgs.terrane.src];
      extraBuildDeps = [pkgs.binutils];
    } (
      if surfaceIndex
      then "surface-index-owner-image"
      else "host-cache-image"
    ) (''
        cd crates
        # Keep artifact JSON on stdout while Cargo renders diagnostics to stderr.
        # Failed sandboxes are discarded; their original compiler errors must
        # remain available in the retained Nix log without a diagnostic rebuild.
        cargo build --frozen --offline -p terrane-linux --features native-test-fixtures \
          --example host_cache_fixture --message-format=json-render-diagnostics > "$TMPDIR/host-cache-host_cache_fixture.jsonl"
        cargo build --frozen --offline -p terrane-cli --bin terrane \
          --message-format=json-render-diagnostics > "$TMPDIR/host-cache-terrane.jsonl"
        cargo build --frozen --offline -p aos-terrane-integration --bin aos-terrane-host \
          --message-format=json-render-diagnostics > "$TMPDIR/host-cache-aos-terrane-host.jsonl"
        cargo test --frozen --offline -p terrane-linux --features native-test-fixtures \
          --lib --no-run --message-format=json-render-diagnostics > "$TMPDIR/host-cache-terrane-fs-unit.jsonl"
        cargo metadata --frozen --offline --no-deps --format-version=1 > "$TMPDIR/host-cache-packages.json"
        rustc --print target-libdir > "$TMPDIR/host-cache-target-libdir"
        python3 ${./host_cache_image.py} ${./.}
      ''
      + lib.optionalString surfaceIndex ''
        cargo build --frozen --offline -p terrane-linux --no-default-features \
          --features native-test-fixtures,surface-fuse --example surface_index_owner_fixture \
          --message-format=json > "$out/surface-build.jsonl"
        rustc --print target-libdir > "$TMPDIR/structural-target-libdir"
        python3 ../tests/terrane/surface_index_owner_image.py
        cp ${./surface_index_owner_vm.py} "$out/share/surface_index_owner_vm.py"
        cp ${./scoped_worker_vm.py} "$out/share/scoped_worker_vm.py"
      '');
  native =
    if surfaceIndex
    then import ./surface-index-owner.nix {inherit pkgs lib image;}
    else
      testing.mkVMTest {
        name = "terrane-native-host-cache-component-ext4";
        memory = 1024;
        # Encoded FIFO adds seven genuine 30-second producer, consumer and native
        # retirement windows; dictionary promotion and automatic admission pressure
        # each add two more. Extend only the whole-guest allowance for this added
        # work; all per-control and actual
        # production deadlines stay fixed.
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
          ${pkgs.python3}/bin/python3 ${image}/share/host_cache_vm.py ${image} ${pkgs.terrane.src}
        '';
      };
in {
  inherit image native;
}
