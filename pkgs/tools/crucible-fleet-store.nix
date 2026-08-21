##! crucible-fleet-store - RFC-0010 fleet-visible DAG store component
{
  lib,
  mkCargoPackage,
  fetchCargoVendor,
  grep,
  crucible-controller,
}: let
  version = "0.1.0";
  cargoDepsHash = import ./crucible/_cargo-deps-hash.nix;
  src = import ./crucible/_source.nix {inherit lib;};
  cargoArtifacts = crucible-controller.passthru.cargoArtifacts;
in
  mkCargoPackage {
    pname = "crucible-fleet-store";
    inherit version src;

    cargoDeps = crucible-controller.passthru.cargoDeps;
    inherit cargoArtifacts;
    cargoArtifactContract = cargoArtifacts.passthru.cargoArtifactContract;
    cargoEnv = cargoArtifacts.passthru.cargoArtifactContract.cargoEnv;
    cargoRoot = "crates";
    cargoNextest = true;

    cargoFlags = "-p crucible-cas --bin crucible-fleet-store";
    cargoTestFlags = "-p crucible-cas";
    doCheck = true;
    buildDeps = [grep];
    runtimeDeps = [];

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
      grep -q '^dedup_layers=exists,coverage-map,reduction-fingerprint,claim-set$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^exists_gated_expansion=skip-existing$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^coverage_map_admission=compare-and-merge$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^coverage_map_repair=entry-markers-before-fingerprint$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^coverage_map_duplicate=skipped$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^reduction_fingerprint=shared-prune$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^claim_set_anti_redundancy=unclaimed-first$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^campaign_store=persistent-dagstore$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^campaign_manifest=content-addressed$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^campaign_head=cas-advanced$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^campaign_head_lock=advisory-head-file$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^campaign_head_log=append-only-checksummed$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^manifest_head_only_mutable=true$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^manifest_root_objects=required$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^lost_cas=bookkeeping-only$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^read_merge_retry=enabled$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^merge_roots=materialized-objects$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^campaign_seed=prior-corpus$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^campaign_seed_artifact=self-contained$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^campaign_seed_replay=bit-identical$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^campaign_seed_process_state=not-required$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^coverage_ratchet=grow-only-union-crdt$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^coverage_ratchet_monotone=true$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^coverage_crdt=commutative-associative-idempotent$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^coverage_novelty=against-accumulated-map$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^findings_ledger=cross-run-grow-only$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^findings_ledger_dedup=content-addressed$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^finding_replay=bit-identical-from-ledger$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^campaign_gc_roots=manifest-roots$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^campaign_gc_scope=corpus,coverage,findings,genesis$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^campaign_gc_unpinned=swept-candidate$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^campaign_gc_value=cache-only$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^fat_to_thin_eviction=value-preserved$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^thin_checkpoint_source=parent-schedule-delta$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^corpus_retention=deterministic-seeded-cap$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^corpus_retention_authorized=explicit-policy$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^corpus_retention_reproducible=true$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^corpus_retention_root=source-cap-seed-proof$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^findings_ledger_retention=never-evict$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^campaign_continuity=implemented$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^campaign_continuity_seed_reproducible=true$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^campaign_continuity_coverage_monotone=true$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^campaign_continuity_cross_provenance_refused=true$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^campaign_continuity_fresh_lineage=forked$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^campaign_continuity_prior_findings_reproducible=true$' "$TMPDIR/crucible-fleet-store.probe"
      grep -q '^provenance_seed_gate=triple-keyed$' "$TMPDIR/crucible-fleet-store.probe"

      mkdir -p "$out/nix-support"
      cat > "$out/nix-support/crucible-fleet-store-build-info" <<'INFO'
      package=crucible-fleet-store
      build_system=mkCargoPackage
      cargo_deps=fetchCargoVendor
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
      dce_four_layer_dedup_task=T-DCE-3
      dce_campaign_manifest_task=T-DCE-4
      dce_campaign_seed_task=T-DCE-5
      dce_campaign_storage_bounding_task=T-DCE-6
      dce_campaign_continuity_task=T-DCE-9
      shared_dag_store_proof=location-independent-identity,idempotent-concurrent-put
      frontier_claim_lease=ttl-hint
      stale_claim_lock=reclaimable
      soft_hash_affinity=priority-only
      four_layer_dedup=exists,coverage-map,reduction-fingerprint,claim-set
      coverage_map_repair=entry-markers-before-fingerprint
      campaign_manifest=content-addressed
      campaign_head=cas-advanced
      campaign_head_lock=advisory-head-file
      campaign_head_log=append-only-checksummed
      manifest_root_objects=required
      merge_roots=materialized-objects
      campaign_seed=prior-corpus
      campaign_seed_artifact=self-contained
      campaign_seed_replay=bit-identical
      coverage_ratchet=grow-only-union-crdt
      findings_ledger=cross-run-grow-only
      campaign_gc_roots=manifest-roots
      campaign_gc_unpinned=swept-candidate
      fat_to_thin_eviction=value-preserved
      corpus_retention=deterministic-seeded-cap
      corpus_retention_authorized=explicit-policy
      corpus_retention_reproducible=true
      findings_ledger_retention=never-evict
      campaign_continuity=implemented
      campaign_continuity_seed_reproducible=true
      campaign_continuity_coverage_monotone=true
      campaign_continuity_cross_provenance_refused=true
      campaign_continuity_fresh_lineage=forked
      campaign_continuity_prior_findings_reproducible=true
      provenance_seed_gate=triple-keyed
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
