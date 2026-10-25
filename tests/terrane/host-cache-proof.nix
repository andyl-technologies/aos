# Bounded native owner component evidence, outside owning gate registration.
# Recovery, publication and consumer lease controls qualify their exercised
# component behavior; complete retirement and BKT-15 readiness remain separate.
{
  pkgs,
  lib,
  sourceGateWithInputs,
  surfaceIndex ? false,
  allFeatureUnits ? false,
}: let
  image =
    sourceGateWithInputs {
      preserveArtifactBytes = true;
      runtimeDeps = [pkgs.rust pkgs.rust.dev] ++ (pkgs.rust.runtimeDeps or []);
      nukeRefsKeep = [pkgs.terrane.src];
      extraBuildDeps = [pkgs.binutils];
    } (
      if surfaceIndex
      then "surface-index-owner-image"
      else if allFeatureUnits
      then "host-cache-all-features-image"
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
        export TERRANE_UNIT_PROFILE=${
          if allFeatureUnits
          then "all"
          else "base"
        }
        cargo test --frozen --offline -p terrane-linux --features ${
          if allFeatureUnits
          then "native-test-fixtures,surface-fuse"
          else "native-test-fixtures"
        } \
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
        cp ${./mounted_worker_vm.py} "$out/share/mounted_worker_vm.py"
      '');
  native =
    if surfaceIndex
    then import ./surface-index-owner.nix {inherit pkgs lib image;}
    else import ./host-cache-scenarios.nix {inherit pkgs lib image allFeatureUnits;};
in {
  inherit image native;
}
