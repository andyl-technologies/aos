{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.crucibleFrontierLeases",
  taskIds ? ["T-DCE-2"],
  dependencies ? [],
}: let
  dceDoc = builtins.readFile ../../docs/rfcs/0010-crucible/35-distributed-continuous-exploration.md;
  casSource =
    builtins.readFile ../../crates/crucible-cas/src/lib.rs
    + builtins.readFile ../../crates/crucible-cas/src/cas/campaign_codec.rs
    + builtins.readFile ../../crates/crucible-cas/src/cas/campaign_model.rs
    + builtins.readFile ../../crates/crucible-cas/src/cas/campaign_store.rs
    + builtins.readFile ../../crates/crucible-cas/src/cas/invalidation.rs
    + builtins.readFile ../../crates/crucible-cas/src/cas/tests.rs;
  fleetStoreProbe = builtins.readFile ../../crates/crucible-cas/src/bin/crucible-fleet-store.rs;
  fleetStorePackage = builtins.readFile ../../pkgs/tools/crucible-fleet-store.nix;
  rootDefault = builtins.readFile ../../default.nix;
  defaultChecks = builtins.readFile ./default.nix;
  gateCiWiring = builtins.readFile ./phase7-crucible-gate-ci-wiring.nix;
  fleetStoreGate = builtins.readFile ./phase7-crucible-fleet-store.nix;
  sharedDagStoreGate = builtins.readFile ./phase7-crucible-shared-dag-store.nix;
  fleetStore = pkgs.crucible-fleet-store;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  fleetEquivalenceRawDependency = "dependencies = [phase2.gates.singleVmFingerprint.rawGate e2eDeterminism.rawGate phase7.crucibleFleetStore phase7.crucibleSharedDagStore phase7.crucibleFrontierLeases phase7.crucibleFourLayerDedup phase7.crucibleDeterminismGuardrail phase7.crucibleCasFleetRatchetSeam];";
  fleetEquivalenceWrapperDependency = "dependencies = [phase2.gates.singleVmFingerprint e2eDeterminism phase7.crucibleFleetStore phase7.crucibleSharedDagStore phase7.crucibleFrontierLeases phase7.crucibleFourLayerDedup phase7.crucibleDeterminismGuardrail phase7.crucibleCasFleetRatchetSeam];";

  failures =
    failuresFor "docs/rfcs/0010-crucible/35-distributed-continuous-exploration.md" dceDoc [
      {
        label = "T-DCE-2 completion note";
        needle = "Completed by `checks.crucible.phase7.crucibleFrontierLeases`";
      }
      {
        label = "DCE-5 claim lease text";
        needle = "content-addressed CLAIM/LEASE\n  work-stealing over the shared frontier";
      }
      {
        label = "DCE-6 TTL lease text";
        needle = "A claim MUST be a short-lived **lease**";
      }
      {
        label = "DCE-7 affinity hint text";
        needle = "soft hash-affinity";
      }
    ]
    ++ forbiddenFor "docs/rfcs/0010-crucible/35-distributed-continuous-exploration.md" dceDoc [
    ]
    ++ failuresFor "crates/crucible-cas/src/lib.rs" casSource [
      {
        label = "shared frontier public type";
        needle = "pub struct SharedFrontier";
      }
      {
        label = "frontier claim request type";
        needle = "pub struct FrontierClaimRequest";
      }
      {
        label = "frontier lease type";
        needle = "pub struct FrontierLease";
      }
      {
        label = "soft hash affinity type";
        needle = "pub struct SoftHashAffinity";
      }
      {
        label = "frontier admission API";
        needle = "pub fn admit(&self, node: &ContentHash)";
      }
      {
        label = "claim next API";
        needle = "pub fn claim_next";
      }
      {
        label = "claimable nodes API";
        needle = "pub fn claimable_nodes";
      }
      {
        label = "affinity ordered nodes API";
        needle = "pub fn ordered_claimable_nodes";
      }
      {
        label = "lease renewal API";
        needle = "pub fn renew";
      }
      {
        label = "lease release API";
        needle = "pub fn release";
      }
      {
        label = "claim path content keyed";
        needle = "content_path(&self.root.join(\"claims\"), node)";
      }
      {
        label = "claim mutation lock content keyed";
        needle = "content_path(&self.root.join(\"claim-locks\"), node)";
      }
      {
        label = "claim lock acquisition";
        needle = "fn try_claim_lock";
      }
      {
        label = "TTL validation";
        needle = "ttl must be greater than zero";
      }
      {
        label = "expired claim test";
        needle = "shared_frontier_claims_expired_leases_again";
      }
      {
        label = "affinity non-filtering test";
        needle = "shared_frontier_affinity_reorders_without_filtering";
      }
      {
        label = "contention single-owner test";
        needle = "shared_frontier_claim_is_single_owner_under_contention";
      }
      {
        label = "stale claim lock reclaim test";
        needle = "shared_frontier_reclaims_expired_claim_lock";
      }
      {
        label = "same content re-put test";
        needle = "store.put(b\"frontier-node\")?, node";
      }
    ]
    ++ failuresFor "crates/crucible-cas/src/bin/crucible-fleet-store.rs" fleetStoreProbe [
      {
        label = "lease probe function";
        needle = "prove_frontier_claim_leases";
      }
      {
        label = "shared frontier in probe";
        needle = "SharedFrontier::new";
      }
      {
        label = "claim request in probe";
        needle = "FrontierClaimRequest::new";
      }
      {
        label = "soft affinity in probe";
        needle = "SoftHashAffinity::prefer";
      }
      {
        label = "expired lease reclaim";
        needle = "expired frontier lease did not become claimable";
      }
      {
        label = "byte-identical reclaim proof";
        needle = "re-expanded frontier node did not dedup to the same content address";
      }
      {
        label = "stale claim lock reclaim proof";
        needle = "expired claim lock did not become reclaimable";
      }
      {
        label = "claim lease output";
        needle = "claim_lease=ttl-hint";
      }
      {
        label = "stale claim lock output";
        needle = "stale_claim_lock=reclaimable";
      }
      {
        label = "affinity hint output";
        needle = "hash_affinity=priority-only";
      }
      {
        label = "static partitioning output";
        needle = "static_partitioning=false";
      }
    ]
    ++ failuresFor "pkgs/tools/crucible-fleet-store.nix" fleetStorePackage [
      {
        label = "package validates claim lease";
        needle = "grep -q '^claim_lease=ttl-hint$'";
      }
      {
        label = "package validates content-addressed claim";
        needle = "grep -q '^claim_key=content-addressed$'";
      }
      {
        label = "package validates expired lease";
        needle = "grep -q '^expired_lease=reclaimable$'";
      }
      {
        label = "package validates stale claim lock";
        needle = "grep -q '^stale_claim_lock=reclaimable$'";
      }
      {
        label = "package validates affinity hint";
        needle = "grep -q '^hash_affinity=priority-only$'";
      }
      {
        label = "package validates no affinity filter";
        needle = "grep -q '^affinity_filters_frontier=false$'";
      }
      {
        label = "package validates no static partitioning";
        needle = "grep -q '^static_partitioning=false$'";
      }
      {
        label = "package records DCE claim lease task";
        needle = "dce_claim_lease_task=T-DCE-2";
      }
    ]
    ++ failuresFor "default.nix" rootDefault [
      {
        label = "distributed wrapper consumes frontier lease gate";
        needle = "frontierLeaseGate = crucibleChecks.phase7.crucibleFrontierLeases;";
      }
      {
        label = "distributed wrapper checks frontier lease result";
        needle = ''frontier_lease_result="''${frontierLeaseGate}/result"'';
      }
      {
        label = "distributed wrapper records frontier lease result";
        needle = ''frontier_lease_gate_result=''${frontierLeaseGate}/result'';
      }
      {
        label = "distributed wrapper records claim lease";
        needle = "claim_lease=ttl-hint";
      }
      {
        label = "distributed wrapper records stale claim lock";
        needle = "stale_claim_lock=reclaimable";
      }
      {
        label = "distributed wrapper records affinity hint";
        needle = "hash_affinity=priority-only";
      }
      {
        label = "distributed wrapper records no static partitioning";
        needle = "static_partitioning=false";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase7 frontier leases check imported";
        needle = "crucibleFrontierLeases = import ./phase7-crucible-frontier-leases.nix";
      }
      {
        label = "fleet equivalence raw gate waits for frontier leases";
        needle = fleetEquivalenceRawDependency;
      }
      {
        label = "fleet equivalence wrapper waits for frontier leases";
        needle = fleetEquivalenceWrapperDependency;
      }
    ]
    ++ failuresFor "tests/crucible/phase7-crucible-gate-ci-wiring.nix" gateCiWiring [
      {
        label = "CI wiring expects frontier leases check";
        needle = "checks.crucible.phase7.crucibleFrontierLeases";
      }
      {
        label = "CI wiring expects frontier leases raw dependency";
        needle = fleetEquivalenceRawDependency;
      }
      {
        label = "CI wiring expects frontier leases wrapper dependency";
        needle = fleetEquivalenceWrapperDependency;
      }
    ]
    ++ failuresFor "tests/crucible/phase7-crucible-fleet-store.nix" fleetStoreGate [
      {
        label = "fleet-store guard expects frontier lease gate";
        needle = "phase7.crucibleFrontierLeases";
      }
    ]
    ++ failuresFor "tests/crucible/phase7-crucible-shared-dag-store.nix" sharedDagStoreGate [
      {
        label = "shared DagStore guard expects frontier lease dependency";
        needle = "phase7.crucibleFrontierLeases";
      }
    ];
in
  if failures != []
  then throw "crucible phase7 frontier leases check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase7-frontier-leases";
      version = "0";
      src = null;

      buildDeps = [pkgs.coreutils pkgs.grep fleetStore] ++ dependencies;

      phases = [
        {
          name = "probe-frontier-leases";
          script = ''
            set -eu
            probe_root="$TMPDIR/crucible-frontier-leases"
            "${fleetStore}/bin/crucible-fleet-store" probe "$probe_root" > "$TMPDIR/crucible-frontier-leases.probe"
            grep -q '^claim_lease=ttl-hint$' "$TMPDIR/crucible-frontier-leases.probe"
            grep -q '^claim_key=content-addressed$' "$TMPDIR/crucible-frontier-leases.probe"
            grep -q '^claim_path_excludes_host=true$' "$TMPDIR/crucible-frontier-leases.probe"
            grep -q '^expired_lease=reclaimable$' "$TMPDIR/crucible-frontier-leases.probe"
            grep -q '^stale_claim_lock=reclaimable$' "$TMPDIR/crucible-frontier-leases.probe"
            grep -q '^reclaimed_node_byte_identical=true$' "$TMPDIR/crucible-frontier-leases.probe"
            grep -q '^hash_affinity=priority-only$' "$TMPDIR/crucible-frontier-leases.probe"
            grep -q '^affinity_filters_frontier=false$' "$TMPDIR/crucible-frontier-leases.probe"
            grep -q '^static_partitioning=false$' "$TMPDIR/crucible-frontier-leases.probe"

            mkdir -p "$out"
            cat > "$out/result" <<RESULT
            PASS
            check=${attrPath}
            tasks=${builtins.concatStringsSep "," taskIds}
            fleet_store_component=${fleetStore}
            runtime_probe=crucible-fleet-store probe
            claim_lease=ttl-hint
            claim_key=content-addressed
            claim_path_excludes_host=true
            expired_lease=reclaimable
            stale_claim_lock=reclaimable
            reclaimed_node_byte_identical=true
            hash_affinity=priority-only
            affinity_filters_frontier=false
            static_partitioning=false
            gate_dependency=checks.crucible.phase7.gates.fleetEquivalence
            RESULT
          '';
        }
      ];
    }
