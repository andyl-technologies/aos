##! crucible-fleet-store - RFC-0010 fleet-visible DAG store component
{
  lib,
  mkCargoPackage,
  fetchCargoDeps,
  grep,
}: let
  version = "0.1.0";
  cargoDepsHash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  src = import ./crucible/_source.nix {inherit lib;};
in
  mkCargoPackage {
    pname = "crucible-fleet-store";
    inherit version src;

    cargoDeps = fetchCargoDeps {
      inherit src;
      sourceRoot = "source/crates";
      hash = cargoDepsHash;
    };

    cargoFlags = "-p crucible-cas --bin crucible-fleet-store";
    cargoTestFlags = "-p crucible-cas";
    doCheck = true;
    buildDeps = [grep];
    runtimeDeps = [];

    preBuild = ''
      cd crates
    '';

    postInstall = ''
      test -x "$out/bin/crucible-fleet-store"

      probe_root="$TMPDIR/crucible-fleet-store-probe"
      "$out/bin/crucible-fleet-store" probe "$probe_root" > "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^backend=SharedDagStore$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^location_independent_identity=true$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^location_independent_roots=2$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^concurrent_put=idempotent$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^concurrent_writers=16$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^object_file_count=1$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^claim_lease=ttl-hint$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^claim_key=content-addressed$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^expired_lease=reclaimable$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^stale_claim_lock=reclaimable$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^hash_affinity=priority-only$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^affinity_filters_frontier=false$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^static_partitioning=false$' "$TMPDIR/crucible-fleet-store.probe"

      mkdir -p "$out/nix-support"
      cat > "$out/nix-support/crucible-fleet-store-build-info" <<'INFO'
      package=crucible-fleet-store
      build_system=mkCargoPackage
      cargo_deps=fetchCargoDeps
      cargo_deps_source_root=source/crates
      cargo_deps_hash=${cargoDepsHash}
      cargo_package=crucible-cas
      cargo_binary=crucible-fleet-store
      dag_store_backend=SharedDagStore
      store_interface=DagStore::put,DagStore::get,DagStore::has
      fleet_visible=true
      aos_from_source=true
      dce_task=T-DCE-1
      dce_claim_lease_task=T-DCE-2
      shared_dag_store_proof=location-independent-identity,idempotent-concurrent-put
      frontier_claim_lease=ttl-hint
      stale_claim_lock=reclaimable
      soft_hash_affinity=priority-only
      probe=crucible-fleet-store probe
      INFO
      cat "$TMPDIR/crucible-fleet-store.probe" >> "$out/nix-support/crucible-fleet-store-build-info"
    '';

    meta = {
      description = "Crucible fleet-visible content-addressed DAG store component";
      homepage = "https://github.com/andyl/andyl-os";
      license = "MIT";
      mainProgram = "crucible-fleet-store";
    };
  }
