{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.crucibleFourLayerDedup",
  taskIds ? ["T-DCE-3"],
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
  frontierLeasesGate = builtins.readFile ./phase7-crucible-frontier-leases.nix;
  sharedDagStoreGate = builtins.readFile ./phase7-crucible-shared-dag-store.nix;
  ratchetSeamGate = builtins.readFile ./phase7-crucible-cas-fleet-ratchet-seam.nix;
  fleetStore = pkgs.crucible-fleet-store;

  hasInfix = needle: haystack:
    needle == ""
    || builtins.replaceStrings [needle] [""] haystack != haystack;

  failuresFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (!(hasInfix requirement.needle content)) [
          "${fileLabel}: missing ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  forbiddenFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (hasInfix requirement.needle content) [
          "${fileLabel}: forbidden ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  fleetEquivalenceRawDependency =
    "dependencies = [phase2.gates.singleVmFingerprint.rawGate e2eDeterminism.rawGate phase7.crucibleFleetStore phase7.crucibleSharedDagStore phase7.crucibleFrontierLeases phase7.crucibleFourLayerDedup phase7.crucibleDeterminismGuardrail phase7.crucibleCasFleetRatchetSeam];";
  fleetEquivalenceWrapperDependency =
    "dependencies = [phase2.gates.singleVmFingerprint e2eDeterminism phase7.crucibleFleetStore phase7.crucibleSharedDagStore phase7.crucibleFrontierLeases phase7.crucibleFourLayerDedup phase7.crucibleDeterminismGuardrail phase7.crucibleCasFleetRatchetSeam];";

  failures =
    failuresFor "docs/rfcs/0010-crucible/35-distributed-continuous-exploration.md" dceDoc [
      {
        label = "T-DCE-3 checklist complete";
        needle = "- [x] **T-DCE-3**";
      }
      {
        label = "T-DCE-3 completion note";
        needle = "Completed by `checks.crucible.phase7.crucibleFourLayerDedup`";
      }
      {
        label = "DCE-8 four-layer text";
        needle = "The fleet MUST deduplicate redundant work at four layers";
      }
    ]
    ++ forbiddenFor "docs/rfcs/0010-crucible/35-distributed-continuous-exploration.md" dceDoc [
      {
        label = "stale T-DCE-3 placeholder";
        needle = "- [ ] **T-DCE-3**";
      }
    ]
    ++ failuresFor "crates/crucible-cas/src/lib.rs" casSource [
      {
        label = "shared dedup index public type";
        needle = "pub struct SharedDedupIndex";
      }
      {
        label = "expansion decision public type";
        needle = "pub enum ExpansionDedupDecision";
      }
      {
        label = "coverage admission public type";
        needle = "pub struct CoverageAdmission";
      }
      {
        label = "reduction admission public type";
        needle = "pub struct ReductionAdmission";
      }
      {
        label = "exists-gated expansion API";
        needle = "pub fn exists_gated_expansion";
      }
      {
        label = "coverage map admission API";
        needle = "pub fn admit_coverage_map";
      }
      {
        label = "reduction fingerprint admission API";
        needle = "pub fn admit_reduction_fingerprint";
      }
      {
        label = "coverage map path content keyed";
        needle = "content_path(&self.root.join(\"coverage-map\"), entry)";
      }
      {
        label = "coverage fingerprint path content keyed";
        needle = "content_path(&self.root.join(\"coverage-fingerprints\"), fingerprint)";
      }
      {
        label = "reduction fingerprint path content keyed";
        needle = "content_path(&self.root.join(\"reduction-fingerprints\"), fingerprint)";
      }
      {
        label = "four-layer unit proof";
        needle = "shared_dedup_index_proves_four_layers";
      }
      {
        label = "coverage interruption repair unit proof";
        needle = "coverage-interrupted";
      }
    ]
    ++ failuresFor "crates/crucible-cas/src/bin/crucible-fleet-store.rs" fleetStoreProbe [
      {
        label = "four-layer probe function";
        needle = "prove_four_layer_dedup";
      }
      {
        label = "shared dedup index in probe";
        needle = "SharedDedupIndex::new";
      }
      {
        label = "exists-gated probe";
        needle = "exists_gated_expansion";
      }
      {
        label = "coverage map probe";
        needle = "admit_coverage_map";
      }
      {
        label = "coverage repair probe";
        needle = "interrupted coverage admission was not repaired";
      }
      {
        label = "reduction fingerprint probe";
        needle = "admit_reduction_fingerprint";
      }
      {
        label = "dedup layers output";
        needle = "dedup_layers=exists,coverage-map,reduction-fingerprint,claim-set";
      }
      {
        label = "claim anti-redundancy output";
        needle = "claim_set_anti_redundancy=unclaimed-first";
      }
    ]
    ++ failuresFor "pkgs/tools/crucible-fleet-store.nix" fleetStorePackage [
      {
        label = "package validates dedup layers";
        needle = "grep -q '^dedup_layers=exists,coverage-map,reduction-fingerprint,claim-set$'";
      }
      {
        label = "package validates exists-gated expansion";
        needle = "grep -q '^exists_gated_expansion=skip-existing$'";
      }
      {
        label = "package validates coverage map";
        needle = "grep -q '^coverage_map_admission=compare-and-merge$'";
      }
      {
        label = "package validates coverage repair";
        needle = "grep -q '^coverage_map_repair=entry-markers-before-fingerprint$'";
      }
      {
        label = "package validates reduction fingerprint";
        needle = "grep -q '^reduction_fingerprint=shared-prune$'";
      }
      {
        label = "package records DCE four-layer task";
        needle = "dce_four_layer_dedup_task=T-DCE-3";
      }
    ]
    ++ failuresFor "default.nix" rootDefault [
      {
        label = "distributed wrapper consumes four-layer dedup gate";
        needle = "fourLayerDedupGate = crucibleChecks.phase7.crucibleFourLayerDedup;";
      }
      {
        label = "distributed wrapper checks four-layer result";
        needle = ''four_layer_dedup_result="''${fourLayerDedupGate}/result"'';
      }
      {
        label = "distributed wrapper records four-layer result";
        needle = ''four_layer_dedup_gate_result=''${fourLayerDedupGate}/result'';
      }
      {
        label = "distributed wrapper records dedup layers";
        needle = "dedup_layers=exists,coverage-map,reduction-fingerprint,claim-set";
      }
      {
        label = "distributed wrapper records coverage repair";
        needle = "coverage_map_repair=entry-markers-before-fingerprint";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase7 four-layer dedup check imported";
        needle = "crucibleFourLayerDedup = import ./phase7-crucible-four-layer-dedup.nix";
      }
      {
        label = "fleet equivalence raw gate waits for four-layer dedup";
        needle = fleetEquivalenceRawDependency;
      }
      {
        label = "fleet equivalence wrapper waits for four-layer dedup";
        needle = fleetEquivalenceWrapperDependency;
      }
    ]
    ++ failuresFor "tests/crucible/phase7-crucible-gate-ci-wiring.nix" gateCiWiring [
      {
        label = "CI wiring expects four-layer dedup check";
        needle = "checks.crucible.phase7.crucibleFourLayerDedup";
      }
      {
        label = "CI wiring expects four-layer raw dependency";
        needle = fleetEquivalenceRawDependency;
      }
      {
        label = "CI wiring expects four-layer wrapper dependency";
        needle = fleetEquivalenceWrapperDependency;
      }
    ]
    ++ failuresFor "tests/crucible/phase7-crucible-fleet-store.nix" fleetStoreGate [
      {
        label = "fleet-store guard expects four-layer dedup gate";
        needle = "phase7.crucibleFourLayerDedup";
      }
    ]
    ++ failuresFor "tests/crucible/phase7-crucible-frontier-leases.nix" frontierLeasesGate [
      {
        label = "frontier leases guard expects four-layer dependency";
        needle = "phase7.crucibleFourLayerDedup";
      }
    ]
    ++ failuresFor "tests/crucible/phase7-crucible-shared-dag-store.nix" sharedDagStoreGate [
      {
        label = "shared DagStore guard expects four-layer dependency";
        needle = "phase7.crucibleFourLayerDedup";
      }
    ]
    ++ failuresFor "tests/crucible/phase7-crucible-cas-fleet-ratchet-seam.nix" ratchetSeamGate [
      {
        label = "ratchet seam guard expects four-layer dependency";
        needle = "phase7.crucibleFourLayerDedup";
      }
    ];
in
  if failures != []
  then throw "crucible phase7 four-layer dedup check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase7-four-layer-dedup";
      version = "0";
      src = null;

      buildDeps = [pkgs.coreutils pkgs.grep fleetStore] ++ dependencies;

      phases = [
        {
          name = "probe-four-layer-dedup";
          script = ''
            set -eu
            probe_root="$TMPDIR/crucible-four-layer-dedup"
            "${fleetStore}/bin/crucible-fleet-store" probe "$probe_root" > "$TMPDIR/crucible-four-layer-dedup.probe"
            grep -q '^dedup_layers=exists,coverage-map,reduction-fingerprint,claim-set$' "$TMPDIR/crucible-four-layer-dedup.probe"
            grep -q '^exists_gated_expansion=skip-existing$' "$TMPDIR/crucible-four-layer-dedup.probe"
            grep -q '^coverage_map_admission=compare-and-merge$' "$TMPDIR/crucible-four-layer-dedup.probe"
            grep -q '^coverage_map_repair=entry-markers-before-fingerprint$' "$TMPDIR/crucible-four-layer-dedup.probe"
            grep -q '^coverage_map_duplicate=skipped$' "$TMPDIR/crucible-four-layer-dedup.probe"
            grep -q '^reduction_fingerprint=shared-prune$' "$TMPDIR/crucible-four-layer-dedup.probe"
            grep -q '^claim_set_anti_redundancy=unclaimed-first$' "$TMPDIR/crucible-four-layer-dedup.probe"

            mkdir -p "$out"
            cat > "$out/result" <<RESULT
            PASS
            check=${attrPath}
            tasks=${builtins.concatStringsSep "," taskIds}
            fleet_store_component=${fleetStore}
            runtime_probe=crucible-fleet-store probe
            dedup_layers=exists,coverage-map,reduction-fingerprint,claim-set
            exists_gated_expansion=skip-existing
            coverage_map_admission=compare-and-merge
            coverage_map_repair=entry-markers-before-fingerprint
            coverage_map_duplicate=skipped
            reduction_fingerprint=shared-prune
            claim_set_anti_redundancy=unclaimed-first
            gate_dependency=checks.crucible.phase7.gates.fleetEquivalence
            RESULT
          '';
        }
      ];
    }
