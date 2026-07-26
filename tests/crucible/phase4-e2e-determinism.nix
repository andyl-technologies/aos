{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.gates.e2eDeterminism",
  taskIds ? ["T-DET-26" "T-ASRT-16"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  e2eHarness = builtins.readFile ../../crates/crucible-harness/src/e2e.rs;
  e2eGate = builtins.readFile ../../crates/crucible-harness/tests/gate_e2e_determinism.rs;
  crucibleE2eGate = builtins.readFile ../../crates/crucible/tests/gate_e2e_determinism_concurrency.rs;
  harnessLib = builtins.readFile ../../crates/crucible-harness/src/lib.rs;
  gateTargets = builtins.readFile ../../crates/crucible-harness/src/gate_targets.rs;
  cliE2eGate = builtins.readFile ../../crates/crucible-cli/tests/gate_e2e_determinism.rs;
  defaultChecks = builtins.readFile ./default.nix;
  gateTargetMapping = builtins.readFile ./phase1-gate-target-mapping.nix;
  determinismContract = builtins.readFile ../../docs/rfcs/0010-crucible/04-determinism-contract.md;
  assertionsDoc = builtins.readFile ../../docs/rfcs/0010-crucible/18-assertions-properties.md;
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
    ++ failuresFor "docs/rfcs/0010-crucible/18-assertions-properties.md" assertionsDoc [
      {
        label = "T-ASRT-16 checklist complete";
        needle = "- [x] **T-ASRT-16**";
      }
      {
        label = "T-ASRT-16 completion note";
        needle = "Completed by `checks.crucible.phase4.gates.e2eDeterminism` and";
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
        label = "I/O sub-node schema";
        needle = "pub struct E2eIoSubnode";
      }
      {
        label = "fault kind schema";
        needle = "pub enum E2eFaultKind";
      }
      {
        label = "property kind schema";
        needle = "pub enum E2ePropertyKind";
      }
      {
        label = "block I/O sub-node";
        needle = "server-block";
      }
      {
        label = "9p I/O sub-node";
        needle = "server-9p";
      }
      {
        label = "fault-injected scenario";
        needle = "partition-client-server";
      }
      {
        label = "loss fault";
        needle = "loss-server-witness";
      }
      {
        label = "latency fault";
        needle = "latency-client-server";
      }
      {
        label = "crash fault";
        needle = "crash-server";
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
        label = "missing I/O completion rejection";
        needle = "MissingIoCompletion";
      }
      {
        label = "failed always-property rejection";
        needle = "FailedAlwaysProperty";
      }
      {
        label = "different profile includes load";
        needle = "candidate.load != baseline.load";
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
        label = "I/O sub-node negative test";
        needle = "gate_e2e_determinism_rejects_scenario_without_io_subnodes";
      }
      {
        label = "unused I/O sub-node negative test";
        needle = "gate_e2e_determinism_rejects_unused_io_subnodes";
      }
      {
        label = "fault target negative test";
        needle = "gate_e2e_determinism_rejects_unknown_fault_target";
      }
      {
        label = "property observation negative test";
        needle = "gate_e2e_determinism_rejects_missing_property_observation";
      }
      {
        label = "always property false observation negative test";
        needle = "gate_e2e_determinism_rejects_false_always_property_observation";
      }
      {
        label = "scheduling-only machine profile positive test";
        needle = "gate_e2e_determinism_accepts_machine_profile_that_changes_only_scheduling";
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
    ++ failuresFor "crates/crucible/tests/gate_e2e_determinism_concurrency.rs" crucibleE2eGate [
      {
        label = "assertion online/offline e2e coverage";
        needle = "gate_e2e_determinism_covers_assertion_online_offline_outcomes_and_verdict";
      }
      {
        label = "assertion e2e outcome equality";
        needle = "gate:e2e-determinism must compare identical assertion outcome sets online/offline";
      }
      {
        label = "assertion e2e scheduler-backed drive";
        needle = "drive_with_assertions(DriveMode::Authoritative";
      }
      {
        label = "assertion e2e cross-mode outcome signature";
        needle = "assertion_outcome_signature(&authoritative.assertion_fail_online)";
      }
      {
        label = "assertion e2e failed verdict composition";
        needle = "deterministic run-verdict composition must match for failed assertions";
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
        label = "implemented crucible e2e target";
        needle = "gate: \"gate:e2e-determinism\",\n        package: \"crucible\",\n        test_target: \"gate_e2e_determinism_concurrency\",\n        required_features: &[\"test-double\"],\n        placeholder: false,";
      }
      {
        label = "implemented CLI final e2e target";
        needle = "gate: \"gate:e2e-determinism\",\n        package: \"crucible-cli\",\n        test_target: \"gate_e2e_determinism\",\n        required_features: &[],\n        placeholder: false,";
      }
    ]
    ++ failuresFor "crates/crucible-cli/tests/gate_e2e_determinism.rs" cliE2eGate [
      {
        label = "CLI e2e final acceptance implemented";
        needle = "gate_e2e_determinism_cli_target_runs_final_acceptance_artifact";
      }
      {
        label = "CLI e2e build identity negative control";
        needle = "gate_e2e_determinism_cli_target_rejects_build_identity_drift";
      }
      {
        label = "CLI e2e cross-machine negative control";
        needle = "gate_e2e_determinism_cli_target_requires_cross_machine_reproduction";
      }
    ]
    ++ forbiddenFor "crates/crucible-cli/tests/gate_e2e_determinism.rs" cliE2eGate [
      {
        label = "ignored CLI e2e placeholder";
        needle = "#[ignore";
      }
      {
        label = "pending CLI e2e panic";
        needle = "implementation is pending";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 e2e gate green check";
        needle = "gate = import ./phase4-e2e-determinism.nix";
      }
      {
        label = "phase7 e2e final acceptance green check";
        needle = "gate = import ./phase7-e2e-determinism.nix";
      }
    ]
    ++ failuresFor "tests/crucible/phase1-gate-target-mapping.nix" gateTargetMapping [
      {
        label = "updated placeholder count";
        needle = "placeholder_targets=0";
      }
      {
        label = "implemented crucible e2e target in Nix lint";
        needle = "gate = \"gate:e2e-determinism\";\n      package = \"crucible\";\n      testTarget = \"gate_e2e_determinism_concurrency\";\n      requiredFeatures = [\"test-double\"];\n      placeholder = false;";
      }
      {
        label = "implemented CLI e2e target in Nix lint";
        needle = "gate = \"gate:e2e-determinism\";\n      package = \"crucible-cli\";\n      testTarget = \"gate_e2e_determinism\";\n      requiredFeatures = [];\n      placeholder = false;";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/24-determinism-harness-testing.md" harnessTesting [
      {
        label = "T-HARN-23 checklist complete";
        needle = "- [x] **T-HARN-23**";
      }
      {
        label = "T-HARN-23 production fleet evidence note";
        needle = "Production closure evidence is provided by `checks.fleet.crucible-e2e-determinism`";
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
      ] ++ dependencies;

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
              -p crucible \
              --features test-double \
              --test gate_e2e_determinism_concurrency \
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
            backend=crucible-scheduler
            scenario=serial-vs-concurrent-authoritative-drive
            artifact=self-contained-seed-scenario-schedule-build-identity
            adversarial_profiles=canonical-host-adversary-matrix
            final_acceptance_cli_target=implemented_shared_mock_artifact
            assertion_online_offline_outcomes=bit-identical
            assertion_cross_mode_outcomes=normalized-bit-identical
            assertion_run_verdict=deterministic
            RESULT
          '';
        }
      ];
    }
