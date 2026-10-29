{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.crucibleDceIntegration",
  dependencies ? [],
}: let
  distributedExplorationDoc = builtins.readFile ../../docs/engineering/crucible/distributed-exploration.md;
  testingAndGatesDoc = builtins.readFile ../../docs/engineering/crucible/testing-and-gates.md;
  packagingDoc = builtins.readFile ../../docs/engineering/crucible/packaging.md;
  phasePlanRust = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible/crucible-test-support/src/phase_plan.rs;
  };
  gateCatalogRust = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible/crucible-test-support/src/lib.rs;
  };
  gateTargets = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible/crucible-test-support/src/gate_targets.rs;
  };
  gateCatalogTest = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible/crucible-test-support/tests/gate_catalog.rs;
  };
  gateTargetMappingTest = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible/crucible-test-support/tests/gate_target_mapping.rs;
  };
  defaultChecks = builtins.readFile ./default.nix;
  rootDefault = builtins.readFile ../../default.nix;
  flake = builtins.readFile ../../flake.nix;
  phaseGateWiring = builtins.readFile ./phase1-phase-gate-wiring.nix;
  gateTargetMapping = builtins.readFile ./phase1-gate-target-mapping.nix;
  gateCiWiring = builtins.readFile ./phase7-crucible-gate-ci-wiring.nix;
  fleetStoreGate = builtins.readFile ./phase7-crucible-fleet-store.nix;
  fleetRatchetSeamGate = builtins.readFile ./phase7-crucible-cas-fleet-ratchet-seam.nix;
  fleetEquivalenceGate = builtins.readFile ./phase7-crucible-fleet-equivalence.nix;
  campaignContinuityGate = builtins.readFile ./phase7-crucible-campaign-continuity.nix;
  fleetStorePackage = builtins.readFile ../../pkgs/tools/crucible-fleet-store.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  fleetCatalogRow = "| `gate:fleet-equivalence` | `Phase7` | `crucible-test-support` | Single-host and fleet search over the same family, seed, and budget find the same content-addressed finding set with byte-identical artifacts; discovery order may differ. |";
  campaignCatalogRow = "| `gate:campaign-continuity` | `Phase7` | `crucible-test-support` | Seeding a run from a previous campaign reproduces each corpus entry, coverage never decreases, and cross-provenance reuse is refused. |";
  fleetEquivalenceRawDependency = "dependencies = [phase2.gates.singleVmFingerprint.rawGate e2eDeterminism.rawGate phase7.crucibleFleetStore phase7.crucibleSharedDagStore phase7.crucibleFrontierLeases phase7.crucibleFourLayerDedup phase7.crucibleDeterminismGuardrail phase7.crucibleCasFleetRatchetSeam];";
  campaignContinuityRawDependency = "dependencies = [fleetEquivalence.rawGate phase7.crucibleCampaignManifest phase7.crucibleCampaignSeeding phase7.crucibleCampaignStorageBounding phase7.crucibleCampaignProvenance];";

  failures =
    failuresFor "docs/engineering/crucible/distributed-exploration.md" distributedExplorationDoc [
      {
        label = "ratchet seam text";
        needle = "The fleet-visible content-addressed store is the **same seam**";
      }
      {
        label = "standalone ratchet seam";
        needle = "Crucible ships standalone.";
      }
      {
        label = "standalone no dependency";
        needle = "The seam is documented text, not a dependency";
      }
      {
        label = "from-source fleet store package";
        needle = "from the `crucible-store` crate hermetically from source";
      }
      {
        label = "from-source AOS fleet check text";
        needle = "Distributed exploration is wired as an AOS VM/fleet check";
      }
      {
        label = "TCG-only fleet check text";
        needle = "It runs TCG-only without\n`requiredSystemFeatures = [ \"kvm\" ]`";
      }
      {
        label = "fleet-equivalence gate";
        needle = "`gate:fleet-equivalence` is the runtime proof";
      }
      {
        label = "campaign-continuity sibling gate";
        needle = "`gate:campaign-continuity` is its sibling";
      }
      {
        label = "performance forward-ref";
        needle = "Measured performance contracts live in\n[performance.md](performance.md)";
      }
    ]
    ++ failuresFor "docs/engineering/crucible/testing-and-gates.md" testingAndGatesDoc [
      {
        label = "fleet-equivalence catalog row verbatim";
        needle = fleetCatalogRow;
      }
      {
        label = "campaign-continuity catalog row verbatim";
        needle = campaignCatalogRow;
      }
    ]
    ++ failuresFor "crates/crucible/crucible-test-support/src/phase_plan.rs" phasePlanRust [
      {
        label = "phase plan fleet equivalence target";
        needle = "\"checks.crucible.phase7.gates.fleetEquivalence\"";
      }
      {
        label = "phase plan campaign continuity target";
        needle = "\"checks.crucible.phase7.gates.campaignContinuity\"";
      }
      {
        label = "phase plan final acceptance predecessor";
        needle = "\"checks.crucible.phase7.gates.e2eDeterminism\"";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-test-support/src/lib.rs" gateCatalogRust [
      {
        label = "fleet-equivalence implemented catalog spec";
        needle = "name: \"gate:fleet-equivalence\",\n        phase: GatePhase::Phase7,\n        owner: \"crucible-test-support\",\n        status: GateStatus::Implemented,";
      }
      {
        label = "campaign-continuity implemented catalog spec";
        needle = "name: \"gate:campaign-continuity\",\n        phase: GatePhase::Phase7,\n        owner: \"crucible-test-support\",\n        status: GateStatus::Implemented,";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-test-support/src/gate_targets.rs" gateTargets [
      {
        label = "fleet-equivalence Cargo gate target";
        needle = "gate: \"gate:fleet-equivalence\",\n        package: \"crucible-engine\",\n        test_target: \"gate_fleet_equivalence\"";
      }
      {
        label = "campaign-continuity Cargo gate target";
        needle = "gate: \"gate:campaign-continuity\",\n        package: \"crucible-store\",\n        test_target: \"gate_campaign_continuity\"";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-test-support/tests/gate_catalog.rs" gateCatalogTest [
      {
        label = "gate catalog documented table test";
        needle = "canonical_gate_catalog_matches_documented_table_and_references";
      }
      {
        label = "fleet-equivalence implemented assertion";
        needle = "find_gate(\"gate:fleet-equivalence\").map(|spec| spec.status)";
      }
      {
        label = "campaign-continuity implemented assertion";
        needle = "find_gate(\"gate:campaign-continuity\").map(|spec| spec.status)";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-test-support/tests/gate_target_mapping.rs" gateTargetMappingTest [
      {
        label = "fleet-equivalence target mapping test";
        needle = "\"gate:fleet-equivalence\",\n                \"crucible-engine\",\n                \"gate_fleet_equivalence\"";
      }
      {
        label = "campaign-continuity target mapping test";
        needle = "\"gate:campaign-continuity\",\n                \"crucible-store\",\n                \"gate_campaign_continuity\"";
      }
    ]
    ++ failuresFor "tests/crucible/phase1-phase-gate-wiring.nix" phaseGateWiring [
      {
        label = "phase gate wiring fleet equivalence";
        needle = "gate = \"gate:fleet-equivalence\";";
      }
      {
        label = "phase gate wiring campaign continuity";
        needle = "gate = \"gate:campaign-continuity\";";
      }
    ]
    ++ failuresFor "tests/crucible/phase1-gate-target-mapping.nix" gateTargetMapping [
      {
        label = "gate target mapping fleet equivalence";
        needle = "gate = \"gate:fleet-equivalence\";\n      package = \"crucible-engine\";\n      testTarget = \"gate_fleet_equivalence\";";
      }
      {
        label = "gate target mapping campaign continuity";
        needle = "gate = \"gate:campaign-continuity\";\n      package = \"crucible-store\";\n      testTarget = \"gate_campaign_continuity\";";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "DCE integration guard imported";
        needle = "crucibleDceIntegration = import ./phase7-crucible-dce-integration.nix";
      }
      {
        label = "fleet-equivalence raw dependency chain";
        needle = fleetEquivalenceRawDependency;
      }
      {
        label = "campaign-continuity raw dependency chain";
        needle = campaignContinuityRawDependency;
      }
    ]
    ++ failuresFor "tests/crucible/phase7-crucible-gate-ci-wiring.nix" gateCiWiring [
      {
        label = "CI wiring classifies fleet-equivalence";
        needle = "gate = \"gate:fleet-equivalence\";";
      }
      {
        label = "CI wiring classifies campaign-continuity";
        needle = "gate = \"gate:campaign-continuity\";";
      }
      {
        label = "CI wiring records fleet surface";
        needle = "checks.fleet.crucible-distributed-continuous-exploration";
      }
      {
        label = "CI wiring records campaign continuity source";
        needle = "campaign_continuity_source=checks.crucible.phase7.gates.campaignContinuity";
      }
    ]
    ++ failuresFor "tests/crucible/phase7-crucible-fleet-store.nix" fleetStoreGate [
      {
        label = "fleet store package check";
        needle = "package=pkgs.crucible-fleet-store";
      }
      {
        label = "fleet check surface";
        needle = "fleet_check_surface=checks.fleet.crucible-distributed-continuous-exploration";
      }
      {
        label = "TCG-only fleet surface";
        needle = "tcg_only=true";
      }
      {
        label = "no KVM fleet surface";
        needle = "kvm_required=false";
      }
    ]
    ++ failuresFor "tests/crucible/phase7-crucible-cas-fleet-ratchet-seam.nix" fleetRatchetSeamGate [
      {
        label = "same shared ratchet seam";
        needle = "shared_seam=SharedDagStore+InvalidationQuery::evaluate";
      }
      {
        label = "no ratchet dependency";
        needle = "no_ratchet_dependency=true";
      }
    ]
    ++ failuresFor "tests/crucible/phase7-crucible-fleet-equivalence.nix" fleetEquivalenceGate [
      {
        label = "fleet-equivalence result gate";
        needle = "gate=gate:fleet-equivalence";
      }
      {
        label = "fleet-equivalence real-QEMU slice";
        needle = "real_qemu_slice_source=checks.crucible.phase2.gates.singleVmFingerprint";
      }
    ]
    ++ failuresFor "tests/crucible/phase7-crucible-campaign-continuity.nix" campaignContinuityGate [
      {
        label = "campaign-continuity result gate";
        needle = "gate=gate:campaign-continuity";
      }
      {
        label = "campaign-continuity provenance gate";
        needle = "provenance_seed_gate=triple-keyed";
      }
    ]
    ++ failuresFor "pkgs/tools/crucible-fleet-store.nix" fleetStorePackage [
      {
        label = "from-source fleet store package";
        needle = ''pname = "crucible-fleet-store";'';
      }
      {
        label = "AOS cargo package builder";
        needle = "mkCargoPackage";
      }
      {
        label = "vendored cargo dependencies";
        needle = "fetchCargoVendor";
      }
      {
        label = "source marker";
        needle = "aos_from_source=true";
      }
      {
        label = "campaign continuity probe marker";
        needle = "campaign_continuity=implemented";
      }
    ]
    ++ forbiddenFor "pkgs/tools/crucible-fleet-store.nix" fleetStorePackage [
      {
        label = "host tools";
        needle = "hostTools";
      }
      {
        label = "nixpkgs import";
        needle = "<nixpkgs>";
      }
    ]
    ++ failuresFor "default.nix" rootDefault [
      {
        label = "fleet store package input";
        needle = "fleetStore = pkgs.crucible-fleet-store;";
      }
      {
        label = "distributed continuous exploration fleet wrapper";
        needle = "crucible-distributed-continuous-exploration = let";
      }
      {
        label = "fleet wrapper consumes fleet-equivalence";
        needle = "fleetEquivalenceGate = crucibleChecks.phase7.gates.fleetEquivalence.rawGate;";
      }
      {
        label = "fleet wrapper consumes campaign-continuity";
        needle = "campaignContinuityGate = crucibleChecks.phase7.gates.campaignContinuity.rawGate;";
      }
      {
        label = "fleet checks exposed";
        needle = "base = discoverFleetTests // crucibleFleetChecks;";
      }
      {
        label = "TCG-only fleet wrapper result";
        needle = "tcg_only=true";
      }
      {
        label = "no KVM fleet wrapper result";
        needle = "kvm_required=false";
      }
    ]
    ++ failuresFor "flake.nix" flake [
      {
        label = "flake exposes fleet checks";
        needle = ''// flattenAttrs "fleet" aos.checks.fleet'';
      }
    ]
    ++ failuresFor "docs/engineering/crucible/packaging.md" packagingDoc [
      {
        label = "fleet store package";
        needle = "`pkgs.crucible-fleet-store`";
      }
      {
        label = "ratchet seam";
        needle = "`SharedDagStore` as the fleet-visible backend of the same seam";
      }
    ];
in
  if failures != []
  then throw "crucible phase7 DCE integration check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase7-dce-integration";
      version = "0";
      src = null;

      buildDeps = [pkgs.coreutils] ++ dependencies;

      phases = [
        {
          name = "write-result";
          script = ''
            set -eu
            mkdir -p "$out"
            cat > "$out/result" <<RESULT
            PASS
            check=${attrPath}
            canonical_gates=gate:fleet-equivalence,gate:campaign-continuity
            canonical_catalog=docs/engineering/crucible/testing-and-gates.md
            phase_plan=crates/crucible/crucible-test-support/src/phase_plan.rs
            fleet_gate=checks.crucible.phase7.gates.fleetEquivalence
            campaign_gate=checks.crucible.phase7.gates.campaignContinuity
            ratchet_seam=crucible_store::SharedDagStore+InvalidationQuery::evaluate
            ratchet_dependency=none
            fleet_store_package=pkgs.crucible-fleet-store
            fleet_surface=checks.fleet.crucible-distributed-continuous-exploration
            from_source=true
            tcg_only=true
            required_system_features=none
            performance_owner=docs/engineering/crucible/performance.md
            RESULT
          '';
        }
      ];
    }
