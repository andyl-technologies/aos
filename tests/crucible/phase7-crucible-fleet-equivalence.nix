{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.gates.fleetEquivalence",
  taskIds ? ["T-DCE-8"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-ULD9g6d87886b8O6/sGCMktquGwaUAyf+DLHUrFzod0=";
  };

  dceDoc = builtins.readFile ../../docs/rfcs/0010-crucible/35-distributed-continuous-exploration.md;
  harnessTesting = builtins.readFile ../../docs/rfcs/0010-crucible/24-determinism-harness-testing.md;
  crucibleManifest = builtins.readFile ../../crates/crucible/Cargo.toml;
  modelRust = import ./_crucible-model-source.nix {inherit lib;};
  libRust = builtins.readFile ../../crates/crucible/src/lib.rs;
  gateTest = builtins.readFile ../../crates/crucible/tests/gate_fleet_equivalence.rs;
  gateCatalog = builtins.readFile ../../crates/crucible-harness/src/lib.rs;
  gateCatalogTest = builtins.readFile ../../crates/crucible-harness/tests/gate_catalog.rs;
  gateTargets = builtins.readFile ../../crates/crucible-harness/src/gate_targets.rs;
  gateTargetMappingTest = builtins.readFile ../../crates/crucible-harness/tests/gate_target_mapping.rs;
  testingStandards = builtins.readFile ../../crates/crucible-harness/tests/testing_standards.rs;
  gateTargetMapping = builtins.readFile ./phase1-gate-target-mapping.nix;
  phase1TestingStandards = builtins.readFile ./phase1-testing-standards.nix;
  defaultChecks = builtins.readFile ./default.nix;
  gateCiWiring = builtins.readFile ./phase7-crucible-gate-ci-wiring.nix;
  rootDefault = builtins.readFile ../../default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  fleetEquivalenceRawDependency = "dependencies = [phase2.gates.singleVmFingerprint.rawGate e2eDeterminism.rawGate phase7.crucibleFleetStore phase7.crucibleSharedDagStore phase7.crucibleFrontierLeases phase7.crucibleFourLayerDedup phase7.crucibleDeterminismGuardrail phase7.crucibleCasFleetRatchetSeam];";
  fleetEquivalenceWrapperDependency = "dependencies = [phase2.gates.singleVmFingerprint e2eDeterminism phase7.crucibleFleetStore phase7.crucibleSharedDagStore phase7.crucibleFrontierLeases phase7.crucibleFourLayerDedup phase7.crucibleDeterminismGuardrail phase7.crucibleCasFleetRatchetSeam];";

  failures =
    failuresFor "docs/rfcs/0010-crucible/35-distributed-continuous-exploration.md" dceDoc [
      {
        label = "T-DCE-8 completion note";
        needle = "Completed by `checks.crucible.phase7.gates.fleetEquivalence`";
      }
      {
        label = "DCE-20 fleet equivalence requirement";
        needle = "**[DCE-20]** Crucible MUST define and maintain **`gate:fleet-equivalence`**";
      }
      {
        label = "DCE-21 pure check requirement";
        needle = "**[DCE-21]** `gate:fleet-equivalence` MUST be a **pure check**";
      }
      {
        label = "DCE-25 divergence localization";
        needle = "divergence-bisection localization";
      }
      {
        label = "DCE-33 SimDouble/real-QEMU coverage";
        needle = "SimDouble fleet under adversarial host conditions";
      }
      {
        label = "DCE-33 real-QEMU slice coverage";
        needle = "a real-QEMU slice";
      }
    ]
    ++ forbiddenFor "docs/rfcs/0010-crucible/35-distributed-continuous-exploration.md" dceDoc [
      {
        label = "stale fleet equivalence remaining note";
        needle = "Full fleet equivalence remains T-DCE-8";
      }
      {
        label = "stale divergence localization remaining note";
        needle = "divergence localization remain T-DCE-3/T-DCE-8";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/24-determinism-harness-testing.md" harnessTesting [
      {
        label = "fleet-equivalence catalog entry";
        needle = "`gate:fleet-equivalence`";
      }
      {
        label = "catalog says order may differ";
        needle = "discovery order may differ";
      }
    ]
    ++ failuresFor "crates/crucible/Cargo.toml" crucibleManifest [
      {
        label = "fleet equivalence Cargo test target";
        needle = "name = \"gate_fleet_equivalence\"";
      }
      {
        label = "fleet equivalence test target path";
        needle = "path = \"tests/gate_fleet_equivalence.rs\"";
      }
      {
        label = "fleet equivalence test-double feature";
        needle = "required-features = [\"test-double\"]";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" modelRust [
      {
        label = "fleet config type";
        needle = "pub struct FleetWorkStealingConfig";
      }
      {
        label = "fleet search API";
        needle = "pub fn search_with_work_stealing_fleet";
      }
      {
        label = "finding set entry";
        needle = "pub struct FleetFindingSetEntry";
      }
      {
        label = "equivalence report";
        needle = "pub struct FleetEquivalenceReport";
      }
      {
        label = "root equality invariant";
        needle = "pub root_equal: bool";
      }
      {
        label = "budget equality invariant";
        needle = "pub budget_equal: bool";
      }
      {
        label = "explored graph equality invariant";
        needle = "pub explored_graph_equal: bool";
      }
      {
        label = "exhaustion invariant";
        needle = "pub both_exhausted: bool";
      }
      {
        label = "divergence handoff";
        needle = "SearchReplayOracleBisectionRequest";
      }
      {
        label = "host metadata kept in claims";
        needle = "Host identities are\n    /// recorded only as claim/order metadata";
      }
      {
        label = "same expansion path";
        needle = "self.search(\n                &candidate.configuration";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libRust [
      {
        label = "fleet config export";
        needle = "FleetWorkStealingConfig";
      }
      {
        label = "fleet run export";
        needle = "FleetWorkStealingSearchRun";
      }
      {
        label = "fleet report export";
        needle = "FleetEquivalenceReport";
      }
    ]
    ++ failuresFor "crates/crucible/tests/gate_fleet_equivalence.rs" gateTest [
      {
        label = "positive gate test";
        needle = "gate_fleet_equivalence_matches_single_host_finding_set_and_artifacts";
      }
      {
        label = "single-host search path";
        needle = "search_with_strategy_and_failure_oracle";
      }
      {
        label = "fleet work-stealing search path";
        needle = "search_with_work_stealing_fleet";
      }
      {
        label = "same finding set assertion";
        needle = "assert_eq!(report.single_finding_set, report.fleet_finding_set);";
      }
      {
        label = "byte-identical artifact assertion";
        needle = "assert!(report.artifacts_byte_identical);";
      }
      {
        label = "exhaustion assertion";
        needle = "assert!(report.both_exhausted);";
      }
      {
        label = "order-insensitive assertion";
        needle = "assert!(!reordered_report.discovery_order_equal);";
      }
      {
        label = "SimDouble fleet adversarial profile test";
        needle = "gate_fleet_equivalence_drives_simdouble_fleet_under_adversarial_host_profiles";
      }
      {
        label = "SimDouble backend use";
        needle = "SimDouble::new";
      }
      {
        label = "canonical host adversary matrix use";
        needle = "canonical_host_adversary_matrix";
      }
      {
        label = "profiled adversarial host runner use";
        needle = "run_profiled_tasks";
      }
      {
        label = "divergence localization negative control";
        needle = "gate_fleet_equivalence_localizes_mismatched_finding_sets";
      }
      {
        label = "bisection handoff assertion";
        needle = "fleet-equivalence-missing-from-fleet";
      }
      {
        label = "non-exhaustive budget negative control";
        needle = "gate_fleet_equivalence_rejects_non_exhaustive_budget";
      }
      {
        label = "non-exhausted bisection handoff";
        needle = "fleet-equivalence-not-exhausted";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/gate_fleet_equivalence.rs" gateTest [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "pending placeholder";
        needle = "implementation is pending";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/lib.rs" gateCatalog [
      {
        label = "fleet equivalence gate catalog implemented";
        needle = "name: \"gate:fleet-equivalence\",\n        phase: GatePhase::Phase7,\n        owner: \"crucible-harness\",\n        status: GateStatus::Implemented,";
      }
    ]
    ++ failuresFor "crates/crucible-harness/tests/gate_catalog.rs" gateCatalogTest [
      {
        label = "fleet equivalence implemented status assertion";
        needle = "find_gate(\"gate:fleet-equivalence\").map(|spec| spec.status),\n        Some(GateStatus::Implemented)";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/gate_targets.rs" gateTargets [
      {
        label = "fleet equivalence gate target implemented";
        needle = "gate: \"gate:fleet-equivalence\",\n        package: \"crucible\",\n        test_target: \"gate_fleet_equivalence\",\n        required_features: &[\"test-double\"],\n        placeholder: false,";
      }
    ]
    ++ failuresFor "crates/crucible-harness/tests/gate_target_mapping.rs" gateTargetMappingTest [
      {
        label = "fleet equivalence target mapping assertion";
        needle = "\"gate:fleet-equivalence\",\n                \"crucible\",\n                \"gate_fleet_equivalence\"";
      }
    ]
    ++ failuresFor "crates/crucible-harness/tests/testing_standards.rs" testingStandards [
      {
        label = "fleet equivalence testing standard";
        needle = "gate: \"gate:fleet-equivalence\",\n        owner_packages: &[\"crucible\"],\n        layers: &[Layer::L3],\n        shape: TestShape::FleetEquivalence,\n        backend: TestBackend::Mixed,";
      }
      {
        label = "crucible owns fleet equivalence";
        needle = "\"gate:fleet-equivalence\",";
      }
    ]
    ++ failuresFor "tests/crucible/phase1-gate-target-mapping.nix" gateTargetMapping [
      {
        label = "phase1 target lint includes fleet equivalence";
        needle = "gate = \"gate:fleet-equivalence\";\n      package = \"crucible\";\n      testTarget = \"gate_fleet_equivalence\";\n      requiredFeatures = [\"test-double\"];\n      placeholder = false;";
      }
    ]
    ++ failuresFor "tests/crucible/phase1-testing-standards.nix" phase1TestingStandards [
      {
        label = "phase1 testing standards target includes fleet equivalence";
        needle = "gate = \"gate:fleet-equivalence\";\n      package = \"crucible\";\n      testTarget = \"gate_fleet_equivalence\";\n      requiredFeatures = [\"test-double\"];";
      }
      {
        label = "phase1 testing standards include fleet equivalence";
        needle = "gate = \"gate:fleet-equivalence\";\n      ownerPackages = [\"crucible\"];\n      layers = [\"L3\"];\n      shape = \"fleet-equivalence\";\n      backend = \"mixed\";";
      }
      {
        label = "phase1 testing ownership includes fleet equivalence";
        needle = "\"gate:fleet-equivalence\"";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "fleet equivalence gate imported";
        needle = "gate = import ./phase7-crucible-fleet-equivalence.nix";
      }
      {
        label = "fleet equivalence raw dependencies";
        needle = fleetEquivalenceRawDependency;
      }
      {
        label = "fleet equivalence wrapper dependencies";
        needle = fleetEquivalenceWrapperDependency;
      }
    ]
    ++ forbiddenFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "stale fleet equivalence red placeholder";
        needle = "reason = \"fleet equivalence gate is intentionally pending\";";
      }
    ]
    ++ failuresFor "tests/crucible/phase7-crucible-gate-ci-wiring.nix" gateCiWiring [
      {
        label = "CI wiring reads fleet equivalence source";
        needle = "phase7FleetEquivalence = builtins.readFile ./phase7-crucible-fleet-equivalence.nix;";
      }
      {
        label = "CI wiring classifies fleet equivalence gate";
        needle = "gate = \"gate:fleet-equivalence\";";
      }
      {
        label = "CI wiring expects fleet equivalence import";
        needle = "gate = import ./phase7-crucible-fleet-equivalence.nix";
      }
    ]
    ++ failuresFor "default.nix" rootDefault [
      {
        label = "distributed wrapper consumes fleet equivalence gate";
        needle = "fleetEquivalenceGate = crucibleChecks.phase7.gates.fleetEquivalence.rawGate;";
      }
      {
        label = "distributed wrapper checks fleet equivalence result";
        needle = ''fleet_equivalence_result="''${fleetEquivalenceGate}/result"'';
      }
      {
        label = "distributed wrapper records fleet equivalence result";
        needle = ''fleet_equivalence_gate_result=''${fleetEquivalenceGate}/result'';
      }
      {
        label = "distributed wrapper records byte-identical artifacts";
        needle = "fleet_equivalence_artifacts=byte-identical";
      }
      {
        label = "distributed wrapper records structural equivalence";
        needle = "fleet_equivalence_structural=root-budget-graph-exhaustion";
      }
      {
        label = "distributed wrapper records real-QEMU slice source";
        needle = "fleet_equivalence_real_qemu_slice=checks.crucible.phase2.gates.singleVmFingerprint";
      }
    ];
in
  if failures != []
  then throw "crucible phase7 fleet-equivalence check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase7-fleet-equivalence";
      version = "0";
      src = crucibleSrc;

      buildDeps =
        [
          pkgs.coreutils
          pkgs.rust
          pkgs.sed
        ]
        ++ dependencies;

      phases = [
        {
          name = "unpack";
          script = ''
            cp -R "$src" source
            chmod -R u+w source
            cd source
          '';
        }
        {
          name = "configure";
          script = ''
            export CARGO_HOME="$TMPDIR/cargo"
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            mkdir -p "$CARGO_HOME" .cargo
            if [ -f "${cargoDeps}/.cargo/config.toml" ]; then
              sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
                > .cargo/config.toml
            else
              printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "${cargoDeps}"\n\n' \
                > .cargo/config.toml
            fi
          '';
        }
        {
          name = "run-fleet-equivalence";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-phase7-fleet-equivalence-target" \
              --features test-double \
              -p crucible \
              --test gate_fleet_equivalence \
              -- --test-threads=1
          '';
        }
        {
          name = "write-result";
          script = ''
            set -eu
            mkdir -p "$out"
            cat > "$out/result" <<RESULT
            PASS
            check=${attrPath}
            gate=gate:fleet-equivalence
            tasks=${builtins.concatStringsSep "," taskIds}
            single_host_search=exhaustive-breadth-first
            fleet_search=shared-worklist-work-stealing
            simdouble_fleet=host-profile-matrix
            adversarial_host_conditions=canonical-host-adversary-matrix-simdouble-fleet
            real_qemu_slice_source=checks.crucible.phase2.gates.singleVmFingerprint
            finding_set=content-addressed
            artifact_bytes=byte-identical
            structural_equivalence=root-budget-graph-exhaustion
            discovery_order=diagnostic-only
            divergence_bisection=SearchReplayOracleBisectionRequest
            pure_check=true
            RESULT
          '';
        }
      ];
    }
