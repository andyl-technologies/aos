{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.gates.e2eDeterminism",
  taskIds ? ["T-DET-26"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  e2eHarness = builtins.readFile ../../crates/crucible-harness/src/e2e.rs;
  e2eGate = builtins.readFile ../../crates/crucible-harness/tests/gate_e2e_determinism.rs;
  harnessLib = builtins.readFile ../../crates/crucible-harness/src/lib.rs;
  gateTargets = builtins.readFile ../../crates/crucible-harness/src/gate_targets.rs;
  cliE2eGate = builtins.readFile ../../crates/crucible-cli/tests/gate_e2e_determinism.rs;
  defaultChecks = builtins.readFile ./default.nix;
  gateTargetMapping = builtins.readFile ./phase1-gate-target-mapping.nix;
  determinismContract = builtins.readFile ../../docs/rfcs/0010-crucible/04-determinism-contract.md;
  harnessTesting = builtins.readFile ../../docs/rfcs/0010-crucible/24-determinism-harness-testing.md;

  hasInfix = needle: haystack: let
    needleLen = builtins.stringLength needle;
    haystackLen = builtins.stringLength haystack;
    maxStart = haystackLen - needleLen;
    indexes =
      if needleLen == 0
      then [0]
      else if maxStart < 0
      then []
      else builtins.genList (index: index) (maxStart + 1);
  in
    builtins.any (index:
      builtins.substring index needleLen haystack == needle)
    indexes;

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

  failures =
    failuresFor "docs/rfcs/0010-crucible/04-determinism-contract.md" determinismContract [
      {
        label = "T-DET-26 checklist complete";
        needle = "- [x] **T-DET-26**";
      }
      {
        label = "T-DET-26 completion note";
        needle = "Completed by `checks.crucible.phase4.gates.e2eDeterminism`";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/e2e.rs" e2eHarness [
      {
        label = "reproduction artifact type";
        needle = "pub struct E2eReproductionArtifact";
      }
      {
        label = "representative artifact";
        needle = "pub fn representative_mock_e2e_artifact";
      }
      {
        label = "multi-node scenario";
        needle = "quorum-witness";
      }
      {
        label = "fault-injected scenario";
        needle = "partition-client-server";
      }
      {
        label = "mock e2e gate runner";
        needle = "pub fn run_mock_e2e_determinism_gate";
      }
      {
        label = "artifact replay runner";
        needle = "pub fn reproduce_mock_e2e_artifact";
      }
      {
        label = "adversarial comparison";
        needle = "compare_adversarial_runs(&adversarial_runs)";
      }
      {
        label = "shared adversarial host profiles";
        needle = "HostAdversaryProfile";
      }
      {
        label = "producer consumer skew exercised";
        needle = "run_profiled_producer_consumer_tasks";
      }
      {
        label = "build identity drift rejection";
        needle = "BuildIdentityMismatch";
      }
      {
        label = "reproduction mismatch rejection";
        needle = "ReproductionMismatch";
      }
      {
        label = "length-prefixed canonical encoder";
        needle = "fn length_prefixed";
      }
    ]
    ++ failuresFor "crates/crucible-harness/tests/gate_e2e_determinism.rs" e2eGate [
      {
        label = "implemented adversarial e2e test";
        needle = "gate_e2e_determinism_runs_fault_injected_multi_vm_artifact_under_adversarial_profiles";
      }
      {
        label = "build identity negative test";
        needle = "gate_e2e_determinism_rejects_build_identity_drift";
      }
      {
        label = "fault injection negative test";
        needle = "gate_e2e_determinism_rejects_non_fault_injected_scenario";
      }
      {
        label = "fault target negative test";
        needle = "gate_e2e_determinism_rejects_unknown_fault_target";
      }
      {
        label = "schedule drift negative test";
        needle = "gate_e2e_determinism_reproduction_changes_when_schedule_drifts";
      }
      {
        label = "delimiter ambiguity regression test";
        needle = "gate_e2e_determinism_canonical_artifact_encoding_is_length_prefixed";
      }
    ]
    ++ forbiddenFor "crates/crucible-harness/tests/gate_e2e_determinism.rs" e2eGate [
      {
        label = "ignored harness e2e placeholder";
        needle = "#[ignore";
      }
      {
        label = "pending harness e2e panic";
        needle = "implementation is pending";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/lib.rs" harnessLib [
      {
        label = "e2e module export";
        needle = "pub mod e2e;";
      }
      {
        label = "e2e canonical gate implemented";
        needle = "name: \"gate:e2e-determinism\",\n        phase: GatePhase::Phase4,\n        owner: \"crucible-harness\",\n        status: GateStatus::Implemented,";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/gate_targets.rs" gateTargets [
      {
        label = "implemented harness e2e target";
        needle = "gate: \"gate:e2e-determinism\",\n        package: \"crucible-harness\",\n        test_target: \"gate_e2e_determinism\",\n        required_features: &[],\n        placeholder: false,";
      }
      {
        label = "CLI final e2e target remains pending";
        needle = "gate: \"gate:e2e-determinism\",\n        package: \"crucible-cli\",\n        test_target: \"gate_e2e_determinism\",\n        required_features: &[],\n        placeholder: true,";
      }
    ]
    ++ failuresFor "crates/crucible-cli/tests/gate_e2e_determinism.rs" cliE2eGate [
      {
        label = "CLI e2e final acceptance remains placeholder";
        needle = "#[ignore = \"T-HARN-23 implements gate:e2e-determinism\"]";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 e2e gate green check";
        needle = "e2eDeterminism = import ./phase4-e2e-determinism.nix";
      }
      {
        label = "phase7 e2e final acceptance remains red";
        needle = "attrPath = \"checks.crucible.phase7.gates.e2eDeterminism\"";
      }
    ]
    ++ failuresFor "tests/crucible/phase1-gate-target-mapping.nix" gateTargetMapping [
      {
        label = "updated placeholder count";
        needle = "placeholder_targets=3";
      }
      {
        label = "implemented harness e2e target in Nix lint";
        needle = "gate = \"gate:e2e-determinism\";\n      package = \"crucible-harness\";\n      testTarget = \"gate_e2e_determinism\";\n      requiredFeatures = [];\n      placeholder = false;";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/24-determinism-harness-testing.md" harnessTesting [
      {
        label = "T-HARN-23 remains final CLI/AOS placeholder";
        needle = "- [ ] **T-HARN-23**";
      }
    ];
in
  if failures != []
  then throw "crucible phase4 e2e-determinism check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-e2e-determinism";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.coreutils
        pkgs.rust
        pkgs.sed
      ];

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
          name = "run-e2e-determinism";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-e2e-determinism-target" \
              -p crucible-harness \
              --test gate_e2e_determinism \
              -- --test-threads=1
          '';
        }
        {
          name = "write-result";
          script = ''
            set -eu
            mkdir -p "$out"
            cat > "$out/result" <<'RESULT'
            PASS
            check=${attrPath}
            gate=gate:e2e-determinism
            tasks=${builtins.concatStringsSep "," taskIds}
            backend=mock
            scenario=mock-partition-recovery
            artifact=self-contained-seed-scenario-schedule-build-identity
            adversarial_profiles=canonical-host-adversary-matrix
            final_acceptance_cli_target=pending
            RESULT
          '';
        }
      ];
    }
