# default.nix — ANDYL OS
#
# The single entry point for everything AOS: library, packages, systems,
# modules, and checks. The flake wraps this for Nix flake consumers and
# adds dev-only things (devShell, formatter).
#
# Usage:
#   nix-build -A pkgs.coreutils                     Build a package
#   nix-build -A stdenv                              Build the production stdenv
#   nix-build -A systems.server.build.toplevel       Build the server system
#   nix-build -A systems.server.checks.boot-basics   Run a module check
#   nix-build -A systems.server.checks.system-boot   Run a system-level check
#   nix-build -A checks                              Run all tests
#   nix-build -A checks.eval                         Run evaluation checks only
#
# Architecture:
#   Check derivations are produced inside the module system via
#   modules/base/checks.nix, which transforms system.checks specs
#   into system.build.checks derivations. Each system variant
#   (server, edge) gets its own set of checks accessible as
#   systems.<name>.checks.<check-name>.
#
# Structure:
#   stdenv/  — Bootstrap chain + toolchain ladder + stdenv (self-contained)
#   pkgs/    — Package definitions
#   lib/     — Library functions (derivations, modules, types, etc.)
#   modules/ — NixOS-style configuration modules (including tests)
#   systems/ — Golden image definitions (auto-discovered)
{
  system ? builtins.currentSystem,
  crossSystem ? null,
}: let
  lib = import ./lib {
    inherit system;
    bash = stdenv.bash;
  };
  buildPlatform = lib.platform;
  hostPlatform =
    if crossSystem != null
    then lib.mkPlatform crossSystem
    else buildPlatform;

  # Self-contained stdenv: hex0 bootstrap → toolchain ladder → production stdenv.
  stdenv = import ./stdenv {
    inherit buildPlatform hostPlatform;
    targetPlatform = hostPlatform;
  };

  # All packages are built hermetically from source using only stdenv.
  pkgs = import ./pkgs {inherit lib stdenv;};

  # Auto-discovered module list.
  modules = import ./modules;

  # Build a system from a system definition module (or list of modules).
  #
  # Accepts three calling conventions:
  #   mkSystem ./path.nix                              — single module path
  #   mkSystem [ ./a.nix ./b.nix ]                     — list of modules
  #   mkSystem { modules = [...]; specialArgs = {}; }   — full attrset
  mkSystem = args: let
    moduleList =
      if builtins.isList args
      then args
      else if builtins.isAttrs args && args ? modules
      then args.modules
      else [args];
    specialArgs =
      if builtins.isAttrs args && args ? specialArgs
      then args.specialArgs
      else {};
  in
    lib.evalModules {
      modules = modules ++ moduleList;
      inherit pkgs lib specialArgs;
    };

  # Auto-discover system definitions from ./systems/*.nix
  discoverSystems = let
    entries = builtins.readDir ./systems;
    nixFiles = builtins.filter (
      name:
        entries.${name}
        == "regular"
        && builtins.match ".*\\.nix" name != null
        && builtins.substring 0 1 name != "_"
    ) (builtins.attrNames entries);
  in
    builtins.listToAttrs (
      map (name: {
        name = lib.removeSuffix ".nix" name;
        value = let
          evaluated = mkSystem (./systems + "/${name}");
        in {
          config = evaluated.config;
          options = evaluated.options;
          build = {
            toplevel = evaluated.config.system.build.toplevel;
            kernel = evaluated.config.system.build.kernel;
            initrd = evaluated.config.system.build.initrd;
            image = evaluated.config.system.build.image;
          };
          # VM test derivations — produced inside the module system by
          # modules/base/checks.nix, not by external collection scripts.
          checks = evaluated.config.system.build.checks;
        };
      })
      nixFiles
    );

  # ---------------------------------------------------------------------------
  # Test infrastructure
  # ---------------------------------------------------------------------------

  # The default system used for eval/build checks and package integration tests.
  serverSystem = mkSystem ./systems/server.nix;

  # Testing harness (headless mode for package integration tests)
  testing = import ./lib/testing {inherit pkgs lib;};

  prefixAttrs = prefix: attrs:
    builtins.listToAttrs (
      map (name: {
        name = "${prefix}-${name}";
        value = attrs.${name};
      }) (builtins.attrNames attrs)
    );

  # ---------------------------------------------------------------------------
  # APM/APR VM tests (headless Firecracker, registry + tracking + packages)
  # ---------------------------------------------------------------------------
  apmTests = import ./tests/vm/apm {inherit testing pkgs;};

  # ---------------------------------------------------------------------------
  # Package integration checks (Firecracker-based, defined on packages)
  # ---------------------------------------------------------------------------
  packageChecks = builtins.foldl' (
    acc: name: let
      pkg = pkgs.${name};
    in
      if builtins.isAttrs pkg && pkg ? checks && builtins.isFunction pkg.checks
      then
        acc
        // prefixAttrs name (
          pkg.checks {
            inherit testing pkgs;
            self = pkg;
          }
        )
      else acc
  ) {} (builtins.attrNames pkgs);

  # Stdenv cross-cutting integration check
  stdenvChecks = {
    cross-cutting-c-pipeline = testing.mkVMTest {
      name = "cross-cutting-c-pipeline";
      rootfsDeps = [pkgs.binutils];
      testScript = ''
        cat > /tmp/pipeline.c << 'EOF'
        #include <stdio.h>
        int add(int a, int b) { return a + b; }
        int main(void) {
            int result = add(3, 4);
            printf("3 + 4 = %d\n", result);
            if (result != 7) return 1;
            return 0;
        }
        EOF

        echo "==> Stage 1: Preprocessing (gcc -E)"
        gcc -E /tmp/pipeline.c -o /tmp/pipeline.i

        echo "==> Stage 2: Compile to assembly (gcc -S)"
        gcc -S /tmp/pipeline.i -o /tmp/pipeline.s

        echo "==> Stage 3: Assemble to object (gcc -c)"
        gcc -c /tmp/pipeline.s -o /tmp/pipeline.o

        echo "==> Stage 4: Link to binary"
        gcc /tmp/pipeline.o -o /tmp/pipeline

        echo "==> Stage 5: Run the binary"
        /tmp/pipeline
        echo "C compilation pipeline: PASS"
      '';
    };
  };

  # ---------------------------------------------------------------------------
  # Fleet tests (multi-VM, inherently span multiple systems)
  # ---------------------------------------------------------------------------
  fleetHarness = import ./lib/testing/fleet.nix {inherit pkgs lib;};

  discoverFleetTests = let
    fleetSpec = import ./lib/testing/fleet-spec.nix {inherit lib pkgs;};

    entries = builtins.readDir ./tests/fleet;
    fleetFiles = builtins.filter (
      n:
        entries.${n}
        == "regular"
        && builtins.match ".*\\.nix" n != null
        && builtins.substring 0 1 n != "_"
    ) (builtins.attrNames entries);

    loadSpec = filename: let
      raw = (import (./tests/fleet + "/${filename}")) {
        inherit lib pkgs;
        systems = discoverSystems;
      };
      eval = lib.evalModules {
        modules = [
          {options.spec = lib.mkOption {type = fleetSpec.fleetSpecType;};}
          {config.spec = raw;}
        ];
      };
    in
      eval.config.spec;
  in
    builtins.listToAttrs (
      builtins.map (filename: {
        name = lib.removeSuffix ".nix" filename;
        value = fleetHarness.mkFleetTest (loadSpec filename);
      })
      fleetFiles
    );

  crucibleChecks = import ./tests/crucible {inherit pkgs lib;};

  crucibleFleetChecks = {
    crucible-e2e-determinism = let
      e2eGate = crucibleChecks.phase7.gates.e2eDeterminism.rawGate;
    in
      pkgs.mkDerivation {
        pname = "crucible-fleet-e2e-determinism-surface";
        version = "0";
        src = null;

        buildDeps = [
          pkgs.coreutils
          pkgs.grep
          e2eGate
        ];

        phases = [
          {
            name = "check-fleet-e2e-surface";
            script = ''
              set -eu

              result="${e2eGate}/result"
              grep -q '^PASS$' "$result"
              grep -q '^gate=gate:e2e-determinism$' "$result"
              grep -q '^fleet_check_surface=checks.fleet.crucible-e2e-determinism$' "$result"

              mkdir -p "$out"
              cat > "$out/result" <<'RESULT'
              PASS
              check=checks.fleet.crucible-e2e-determinism
              gate=gate:e2e-determinism
              source_check=checks.crucible.phase7.gates.e2eDeterminism
              e2e_gate_result=${e2eGate}/result
              fleet_surface=true
              lib_testing_runner=deferred-to-T-PKG-15
              tcg_only_vm_runner=deferred-to-T-PKG-15
              RESULT
            '';
          }
        ];
      };
    crucible-distributed-continuous-exploration = let
      fleetStore = pkgs.crucible-fleet-store;
      explorer = pkgs.crucible;
      e2eGate = crucibleChecks.phase7.gates.e2eDeterminism.rawGate;
      fleetStoreGate = crucibleChecks.phase7.crucibleFleetStore;
      sharedDagStoreGate = crucibleChecks.phase7.crucibleSharedDagStore;
      frontierLeaseGate = crucibleChecks.phase7.crucibleFrontierLeases;
      fourLayerDedupGate = crucibleChecks.phase7.crucibleFourLayerDedup;
      campaignManifestGate = crucibleChecks.phase7.crucibleCampaignManifest;
      campaignSeedingGate = crucibleChecks.phase7.crucibleCampaignSeeding;
      campaignStorageBoundingGate = crucibleChecks.phase7.crucibleCampaignStorageBounding;
    in
      pkgs.mkDerivation {
        pname = "crucible-fleet-distributed-continuous-exploration-surface";
        version = "0";
        src = null;

        buildDeps = [
          pkgs.coreutils
          pkgs.grep
          fleetStore
          explorer
          e2eGate
          fleetStoreGate
          sharedDagStoreGate
          frontierLeaseGate
          fourLayerDedupGate
          campaignManifestGate
          campaignSeedingGate
          campaignStorageBoundingGate
        ];

        phases = [
          {
            name = "check-distributed-continuous-exploration-surface";
            script = ''
              set -eu

              result="${e2eGate}/result"
              grep -q '^PASS$' "$result"
              grep -q '^gate=gate:e2e-determinism$' "$result"

              fleet_store_result="${fleetStoreGate}/result"
              grep -q '^PASS$' "$fleet_store_result"
              grep -q '^package=pkgs.crucible-fleet-store$' "$fleet_store_result"
              grep -q '^tcg_only=true$' "$fleet_store_result"
              grep -q '^kvm_required=false$' "$fleet_store_result"

              shared_dag_store_result="${sharedDagStoreGate}/result"
              grep -q '^PASS$' "$shared_dag_store_result"
              grep -q '^tasks=T-DCE-1$' "$shared_dag_store_result"
              grep -q '^shared_store_backend=SharedDagStore$' "$shared_dag_store_result"
              grep -q '^concurrent_put=idempotent$' "$shared_dag_store_result"

              frontier_lease_result="${frontierLeaseGate}/result"
              grep -q '^PASS$' "$frontier_lease_result"
              grep -q '^tasks=T-DCE-2$' "$frontier_lease_result"
              grep -q '^claim_lease=ttl-hint$' "$frontier_lease_result"
              grep -q '^stale_claim_lock=reclaimable$' "$frontier_lease_result"
              grep -q '^hash_affinity=priority-only$' "$frontier_lease_result"

              four_layer_dedup_result="${fourLayerDedupGate}/result"
              grep -q '^PASS$' "$four_layer_dedup_result"
              grep -q '^tasks=T-DCE-3$' "$four_layer_dedup_result"
              grep -q '^dedup_layers=exists,coverage-map,reduction-fingerprint,claim-set$' "$four_layer_dedup_result"
              grep -q '^coverage_map_admission=compare-and-merge$' "$four_layer_dedup_result"
              grep -q '^coverage_map_repair=entry-markers-before-fingerprint$' "$four_layer_dedup_result"
              grep -q '^reduction_fingerprint=shared-prune$' "$four_layer_dedup_result"

              campaign_manifest_result="${campaignManifestGate}/result"
              grep -q '^PASS$' "$campaign_manifest_result"
              grep -q '^tasks=T-DCE-4$' "$campaign_manifest_result"
              grep -q '^campaign_manifest=content-addressed$' "$campaign_manifest_result"
              grep -q '^campaign_head=cas-advanced$' "$campaign_manifest_result"
              grep -q '^campaign_head_lock=advisory-head-file$' "$campaign_manifest_result"
              grep -q '^campaign_head_log=append-only-checksummed$' "$campaign_manifest_result"
              grep -q '^manifest_root_objects=required$' "$campaign_manifest_result"
              grep -q '^lost_cas=bookkeeping-only$' "$campaign_manifest_result"
              grep -q '^merge_roots=materialized-objects$' "$campaign_manifest_result"

              campaign_seeding_result="${campaignSeedingGate}/result"
              grep -q '^PASS$' "$campaign_seeding_result"
              grep -q '^tasks=T-DCE-5$' "$campaign_seeding_result"
              grep -q '^campaign_seed=prior-corpus$' "$campaign_seeding_result"
              grep -q '^campaign_seed_artifact=self-contained$' "$campaign_seeding_result"
              grep -q '^campaign_seed_replay=bit-identical$' "$campaign_seeding_result"
              grep -q '^coverage_ratchet=grow-only-union-crdt$' "$campaign_seeding_result"
              grep -q '^coverage_ratchet_monotone=true$' "$campaign_seeding_result"
              grep -q '^coverage_crdt=commutative-associative-idempotent$' "$campaign_seeding_result"
              grep -q '^coverage_novelty=against-accumulated-map$' "$campaign_seeding_result"
              grep -q '^findings_ledger=cross-run-grow-only$' "$campaign_seeding_result"
              grep -q '^findings_ledger_dedup=content-addressed$' "$campaign_seeding_result"
              grep -q '^finding_replay=bit-identical-from-ledger$' "$campaign_seeding_result"

              campaign_storage_bounding_result="${campaignStorageBoundingGate}/result"
              grep -q '^PASS$' "$campaign_storage_bounding_result"
              grep -q '^tasks=T-DCE-6$' "$campaign_storage_bounding_result"
              grep -q '^campaign_gc_roots=manifest-roots$' "$campaign_storage_bounding_result"
              grep -q '^campaign_gc_unpinned=swept-candidate$' "$campaign_storage_bounding_result"
              grep -q '^campaign_gc_value=cache-only$' "$campaign_storage_bounding_result"
              grep -q '^fat_to_thin_eviction=value-preserved$' "$campaign_storage_bounding_result"
              grep -q '^thin_checkpoint_source=parent-schedule-delta$' "$campaign_storage_bounding_result"
              grep -q '^corpus_retention=deterministic-seeded-cap$' "$campaign_storage_bounding_result"
              grep -q '^corpus_retention_authorized=explicit-policy$' "$campaign_storage_bounding_result"
              grep -q '^corpus_retention_reproducible=true$' "$campaign_storage_bounding_result"
              grep -q '^findings_ledger_retention=never-evict$' "$campaign_storage_bounding_result"

              test -x "${fleetStore}/bin/crucible-fleet-store"
              test -x "${explorer}/bin/crucible"
              probe_root="$TMPDIR/crucible-fleet-store"
              "${fleetStore}/bin/crucible-fleet-store" probe "$probe_root" > "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^backend=SharedDagStore$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^interface=DagStore::put,DagStore::get,DagStore::has$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^location_independent_roots=2$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^concurrent_put=idempotent$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^concurrent_writers=16$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^object_file_count=1$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^claim_lease=ttl-hint$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^claim_key=content-addressed$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^expired_lease=reclaimable$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^stale_claim_lock=reclaimable$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^reclaimed_node_byte_identical=true$' "$TMPDIR/crucible-fleet-store.probe"
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

              mkdir -p "$out"
              cat > "$out/result" <<'RESULT'
              PASS
              check=checks.fleet.crucible-distributed-continuous-exploration
              gate=gate:fleet-equivalence
              source_check=checks.crucible.phase7.crucibleSharedDagStore
              package_check=checks.crucible.phase7.crucibleFleetStore
              e2e_gate_result=${e2eGate}/result
              fleet_store_gate_result=${fleetStoreGate}/result
              shared_dag_store_gate_result=${sharedDagStoreGate}/result
              frontier_lease_gate_result=${frontierLeaseGate}/result
              four_layer_dedup_gate_result=${fourLayerDedupGate}/result
              campaign_manifest_gate_result=${campaignManifestGate}/result
              campaign_seeding_gate_result=${campaignSeedingGate}/result
              campaign_storage_bounding_gate_result=${campaignStorageBoundingGate}/result
              fleet_store_component=${fleetStore}
              fleet_store_build_info=${fleetStore}/nix-support/crucible-fleet-store-build-info
              explorer_closure=${explorer}
              explorer_binary=${explorer}/bin/crucible
              fleet_surface=true
              vm_runner=tcg-only
              tcg_only=true
              required_system_features=none
              kvm_required=false
              shared_store_backend=SharedDagStore
              shared_store_interface=DagStore::put,DagStore::get,DagStore::has
              location_independent_roots=2
              concurrent_put=idempotent
              concurrent_writers=16
              object_file_count=1
              claim_lease=ttl-hint
              claim_key=content-addressed
              expired_lease=reclaimable
              stale_claim_lock=reclaimable
              reclaimed_node_byte_identical=true
              hash_affinity=priority-only
              affinity_filters_frontier=false
              static_partitioning=false
              dedup_layers=exists,coverage-map,reduction-fingerprint,claim-set
              exists_gated_expansion=skip-existing
              coverage_map_admission=compare-and-merge
              coverage_map_repair=entry-markers-before-fingerprint
              coverage_map_duplicate=skipped
              reduction_fingerprint=shared-prune
              claim_set_anti_redundancy=unclaimed-first
              campaign_store=persistent-dagstore
              campaign_manifest=content-addressed
              campaign_head=cas-advanced
              campaign_head_lock=advisory-head-file
              campaign_head_log=append-only-checksummed
              manifest_head_only_mutable=true
              manifest_root_objects=required
              lost_cas=bookkeeping-only
              read_merge_retry=enabled
              merge_roots=materialized-objects
              campaign_seed=prior-corpus
              campaign_seed_artifact=self-contained
              campaign_seed_replay=bit-identical
              campaign_seed_process_state=not-required
              coverage_ratchet=grow-only-union-crdt
              coverage_ratchet_monotone=true
              coverage_crdt=commutative-associative-idempotent
              coverage_novelty=against-accumulated-map
              findings_ledger=cross-run-grow-only
              findings_ledger_dedup=content-addressed
              finding_replay=bit-identical-from-ledger
              campaign_gc_roots=manifest-roots
              campaign_gc_scope=corpus,coverage,findings,genesis
              campaign_gc_unpinned=swept-candidate
              campaign_gc_value=cache-only
              fat_to_thin_eviction=value-preserved
              thin_checkpoint_source=parent-schedule-delta
              corpus_retention=deterministic-seeded-cap
              corpus_retention_authorized=explicit-policy
              corpus_retention_reproducible=true
              corpus_retention_root=source-cap-seed-proof
              findings_ledger_retention=never-evict
              distributed_search_surface=enabled
              continuous_campaign_surface=enabled
              hermetic_inputs=fleet-store,explorer
              RESULT
            '';
          }
        ];
      };
  };
in {
  inherit lib pkgs stdenv modules mkSystem;

  # Auto-discovered golden image systems.
  # Each system has .config, .options, .build, and .checks.
  systems = discoverSystems;

  # Checks hierarchy — module checks come from systems, everything else
  # stays at the top level.
  checks = {
    eval = import ./lib/testing/eval.nix {
      inherit pkgs lib mkSystem;
      system = serverSystem;
    };
    build = let
      critical-pkgs = import ./tests/build/critical-pkgs.nix {inherit pkgs lib;};
      hardening-probe = import ./tests/build/hardening-probe.nix {inherit pkgs lib;};
      kernel-config = import ./tests/build/kernel-config.nix {inherit pkgs lib;};
    in {
      inherit critical-pkgs hardening-probe kernel-config;
      # Single target that pulls in the whole build-check group.
      all = pkgs.mkDerivation {
        pname = "aos-build-checks-all";
        version = "0";
        src = null;
        buildDeps =
          [critical-pkgs kernel-config]
          ++ builtins.attrValues hardening-probe;
        phases = [
          {
            name = "check";
            script = ''
              mkdir -p $out
              echo "PASS" > $out/result
            '';
          }
        ];
      };
    };
    tla = import ./lib/testing/tla.nix {inherit pkgs lib;};
    trivial-builders = import ./lib/testing/trivial-builders.nix {inherit pkgs lib;};
    module-args = import ./lib/testing/module-args.nix {inherit pkgs lib;};
    module-enforcement = import ./lib/testing/module-enforcement.nix {inherit pkgs lib;};
    ignition-format = import ./lib/testing/ignition-format.nix {inherit pkgs lib;};
    fleet-spec = import ./lib/testing/fleet-spec-check.nix {inherit pkgs lib;};
    systemd-lib = import ./lib/testing/systemd-lib.nix {inherit pkgs lib;};
    systemd-generate = import ./lib/testing/systemd-generate.nix {inherit pkgs lib;};
    crucible = crucibleChecks;
    # Module-level VM checks (from server system, for backwards compat)
    vm =
      serverSystem.config.system.build.checks
      // {
        apm = apmTests;
      };
    integration = packageChecks // stdenvChecks;
    fleet = discoverFleetTests // crucibleFleetChecks;
  };
}
