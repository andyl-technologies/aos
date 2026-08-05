{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.crucibleDceIntegration",
  taskIds ? ["T-DCE-10"],
  dependencies ? [],
}: let
  dceDoc = builtins.readFile ../../docs/rfcs/0010-crucible/35-distributed-continuous-exploration.md;
  gateCatalogDoc = builtins.readFile ../../docs/rfcs/0010-crucible/24-determinism-harness-testing.md;
  phasePlanDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  packagingDoc = builtins.readFile ../../docs/rfcs/0010-crucible/26-packaging-aos-integration.md;
  phasePlanRust = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-harness/src/phase_plan.rs;
  };
  gateCatalogRust = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-harness/src/lib.rs;
  };
  gateTargets = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-harness/src/gate_targets.rs;
  };
  gateCatalogTest = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-harness/tests/gate_catalog.rs;
  };
  gateTargetMappingTest = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-harness/tests/gate_target_mapping.rs;
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

  fleetCatalogRow = "| `gate:fleet-equivalence` | Cross-layer (Phase ≥ L3) | DCE-16, DCE-17, DCE-20; G-6 | Single-host and fleet search over the same `(family, seed, budget)` discover the same content-addressed finding-set with byte-identical artifacts; discovery order may differ. |";
  campaignCatalogRow = "| `gate:campaign-continuity` | Cross-layer (Phase ≥ L3) | DCE-11, DCE-12, DCE-26; PERF-28 | Seeding run N+1 from run N's campaign reproduces each corpus entry bit-identically, accumulated coverage is monotone non-decreasing across runs, and cross-provenance reuse is refused. |";
  fleetEquivalenceRawDependency = "dependencies = [phase2.gates.singleVmFingerprint.rawGate e2eDeterminism.rawGate phase7.crucibleFleetStore phase7.crucibleSharedDagStore phase7.crucibleFrontierLeases phase7.crucibleFourLayerDedup phase7.crucibleDeterminismGuardrail phase7.crucibleCasFleetRatchetSeam];";
  campaignContinuityRawDependency = "dependencies = [fleetEquivalence.rawGate phase7.crucibleCampaignManifest phase7.crucibleCampaignSeeding phase7.crucibleCampaignStorageBounding phase7.crucibleCampaignProvenance];";

  failures =
    failuresFor "docs/rfcs/0010-crucible/35-distributed-continuous-exploration.md" dceDoc [
      {
        label = "T-DCE-10 completion note";
        needle = "Completed by `checks.crucible.phase7.crucibleDceIntegration`";
      }
      {
        label = "DCE-28 same crucible-cas seam";
        needle = "**[DCE-28]** The fleet's shared store";
      }
      {
        label = "DCE-29 standalone ratchet seam";
        needle = "**[DCE-29]** Crucible MUST ship **standalone**";
      }
      {
        label = "DCE-30 canonical gates";
        needle = "**[DCE-30]** `gate:fleet-equivalence` and `gate:campaign-continuity` MUST be";
      }
      {
        label = "DCE-31 from-source fleet check";
        needle = "**[DCE-31]** The fleet/campaign store backend MUST be an AOS package built";
      }
      {
        label = "DCE-32 performance forward-ref";
        needle = "**[DCE-32]** The performance contract for fleet throughput";
      }
      {
        label = "ratchet seam text";
        needle = "The fleet-visible content-addressed store is the **same seam**";
      }
      {
        label = "standalone no dependency";
        needle = "the seam is **documented text, not a\ndependency**";
      }
      {
        label = "from-source AOS fleet check text";
        needle = "wired as an **AOS\nVM/fleet check**";
      }
      {
        label = "TCG-only fleet check text";
        needle = "**TCG-only** without `requiredSystemFeatures = [ \"kvm\" ]`";
      }
      {
        label = "new canonical gates summary";
        needle = "NEW CANONICAL GATES (§35.10): gate:fleet-equivalence, gate:campaign-continuity";
      }
    ]
    ++ forbiddenFor "docs/rfcs/0010-crucible/35-distributed-continuous-exploration.md" dceDoc [
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/24-determinism-harness-testing.md" gateCatalogDoc [
      {
        label = "fleet-equivalence catalog row verbatim";
        needle = fleetCatalogRow;
      }
      {
        label = "campaign-continuity catalog row verbatim";
        needle = campaignCatalogRow;
      }
      {
        label = "fleet and campaign canonical text";
        needle = "`gate:campaign-continuity` (owned";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" phasePlanDoc [
      {
        label = "distributed/continuous phase plan tasks";
        needle = "`T-DCE-1 … T-DCE-10`";
      }
      {
        label = "fleet-equivalence phase plan gate";
        needle = "`gate:fleet-equivalence`";
      }
      {
        label = "campaign-continuity phase plan gate";
        needle = "`gate:campaign-continuity`";
      }
      {
        label = "phase plan after final deterministic gate";
        needle = "and reproduces from its self-contained artifact), `gate:fleet-equivalence`";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/phase_plan.rs" phasePlanRust [
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
    ++ failuresFor "crates/crucible-harness/src/lib.rs" gateCatalogRust [
      {
        label = "fleet-equivalence implemented catalog spec";
        needle = "name: \"gate:fleet-equivalence\",\n        phase: GatePhase::Phase7,\n        owner: \"crucible-harness\",\n        status: GateStatus::Implemented,";
      }
      {
        label = "campaign-continuity implemented catalog spec";
        needle = "name: \"gate:campaign-continuity\",\n        phase: GatePhase::Phase7,\n        owner: \"crucible-harness\",\n        status: GateStatus::Implemented,";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/gate_targets.rs" gateTargets [
      {
        label = "fleet-equivalence Cargo gate target";
        needle = "gate: \"gate:fleet-equivalence\",\n        package: \"crucible\",\n        test_target: \"gate_fleet_equivalence\"";
      }
      {
        label = "campaign-continuity Cargo gate target";
        needle = "gate: \"gate:campaign-continuity\",\n        package: \"crucible-cas\",\n        test_target: \"gate_campaign_continuity\"";
      }
    ]
    ++ failuresFor "crates/crucible-harness/tests/gate_catalog.rs" gateCatalogTest [
      {
        label = "gate catalog RFC table test";
        needle = "canonical_gate_catalog_matches_rfc_table_and_references";
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
    ++ failuresFor "crates/crucible-harness/tests/gate_target_mapping.rs" gateTargetMappingTest [
      {
        label = "fleet-equivalence target mapping test";
        needle = "\"gate:fleet-equivalence\",\n                \"crucible\",\n                \"gate_fleet_equivalence\"";
      }
      {
        label = "campaign-continuity target mapping test";
        needle = "\"gate:campaign-continuity\",\n                \"crucible-cas\",\n                \"gate_campaign_continuity\"";
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
        needle = "gate = \"gate:fleet-equivalence\";\n      package = \"crucible\";\n      testTarget = \"gate_fleet_equivalence\";";
      }
      {
        label = "gate target mapping campaign continuity";
        needle = "gate = \"gate:campaign-continuity\";\n      package = \"crucible-cas\";\n      testTarget = \"gate_campaign_continuity\";";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "T-DCE-10 integration guard imported";
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
        label = "no RFC-0007 dependency";
        needle = "no_rfc_0007_dependency=true";
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
        needle = "fleet = discoverFleetTests // crucibleFleetChecks;";
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
        needle = ''// prefixAttrs "fleet" aos.checks.fleet'';
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/26-packaging-aos-integration.md" packagingDoc [
      {
        label = "PKG fleet store section";
        needle = "Distributed exploration: the fleet store and campaign provenance";
      }
      {
        label = "PKG ratchet seam";
        needle = "fleet-visible store + dependency-gated invalidation as the SAME seam";
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
            tasks=${builtins.concatStringsSep "," taskIds}
            canonical_gates=gate:fleet-equivalence,gate:campaign-continuity
            canonical_catalog=docs/rfcs/0010-crucible/24-determinism-harness-testing.md#1.1
            phase_plan=crates/crucible-harness/src/phase_plan.rs
            fleet_gate=checks.crucible.phase7.gates.fleetEquivalence
            campaign_gate=checks.crucible.phase7.gates.campaignContinuity
            ratchet_seam=crucible-cas::SharedDagStore+InvalidationQuery::evaluate
            ratchet_dependency=none
            fleet_store_package=pkgs.crucible-fleet-store
            fleet_surface=checks.fleet.crucible-distributed-continuous-exploration
            from_source=true
            tcg_only=true
            required_system_features=none
            performance_owner=docs/rfcs/0010-crucible/25-performance-targets.md
            RESULT
          '';
        }
      ];
    }
