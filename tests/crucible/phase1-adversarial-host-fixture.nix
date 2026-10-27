{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.adversarialHostFixture",
  taskIds ? ["T-DET-25"],
}: let
  inherit (import ./_test-gate.nix {inherit pkgs lib;}) mkCrucibleTestGate;

  harnessAdversarial = builtins.readFile ../../crates/crucible/crucible-test-support/src/adversarial.rs;
  harnessFixtureTest = builtins.readFile ../../crates/crucible/crucible-test-support/tests/adversarial_host_fixture.rs;
  defaultChecks = builtins.readFile ./default.nix;
  determinismContract = builtins.readFile ../../docs/rfcs/0010-crucible/04-determinism-contract.md;
  adversarialGateTest = builtins.readFile ../../crates/crucible/crucible-test-support/tests/gate_adversarial_determinism.rs;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/04-determinism-contract.md" determinismContract [
      {
        label = "T-DET-25 completion note";
        needle = "Completed by `checks.crucible.phase1.adversarialHostFixture`";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes adversarial host fixture check";
        needle = "adversarialHostFixture = import ./phase1-adversarial-host-fixture.nix";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-test-support/src/adversarial.rs" harnessAdversarial [
      {
        label = "shared profile type";
        needle = "pub struct HostAdversaryProfile";
      }
      {
        label = "canonical matrix";
        needle = "pub fn canonical_host_adversary_matrix";
      }
      {
        label = "execution plan";
        needle = "pub struct AdversarialExecutionPlan";
      }
      {
        label = "profiled runner";
        needle = "pub fn run_profiled_tasks";
      }
      {
        label = "producer consumer profiled runner";
        needle = "pub fn run_profiled_producer_consumer_tasks";
      }
      {
        label = "producer consumer role";
        needle = "pub enum ProducerConsumerRole";
      }
      {
        label = "seeded randomized scheduling";
        needle = "SeededPermutation";
      }
      {
        label = "seeded randomized affinity";
        needle = "HostAffinity::Seeded";
      }
      {
        label = "injected jitter load";
        needle = "HostLoad::spinning";
      }
      {
        label = "varied core count";
        needle = "worker_count: 4";
      }
      {
        label = "producer consumer skew";
        needle = "ProducerConsumerSkew::Alternating";
      }
      {
        label = "affinity drives worker assignment";
        needle = "let worker_index = logical_core % profile.worker_count;";
      }
      {
        label = "deterministic seed helper";
        needle = "fn splitmix64";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-test-support/tests/adversarial_host_fixture.rs" harnessFixtureTest [
      {
        label = "matrix dimension coverage test";
        needle = "canonical_host_adversary_matrix_covers_required_dimensions";
      }
      {
        label = "seeded order regression test";
        needle = "seeded_task_order_is_stable_and_nontrivial";
      }
      {
        label = "execution plan regression test";
        needle = "adversarial_execution_plan_records_workers_affinity_and_skew";
      }
      {
        label = "affinity worker assignment regression test";
        needle = "affinity_profiles_drive_worker_assignment";
      }
      {
        label = "canonical result order regression test";
        needle = "profiled_runner_returns_results_in_canonical_task_order";
      }
      {
        label = "producer consumer role skew regression test";
        needle = "producer_consumer_fixture_applies_role_aware_skew";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-test-support/tests/gate_adversarial_determinism.rs" adversarialGateTest [
      {
        label = "phase3 gate consumes shared matrix";
        needle = "canonical_host_adversary_matrix()";
      }
      {
        label = "phase3 gate consumes representative corpus";
        needle = "representative_adversarial_corpus()";
      }
      {
        label = "phase3 gate consumes shared runner";
        needle = "run_adversarial_determinism_gate";
      }
    ]
    ++ forbiddenFor "crates/crucible/crucible-test-support/tests/gate_adversarial_determinism.rs" adversarialGateTest [
      {
        label = "ignored phase3 placeholder";
        needle = "#[ignore";
      }
      {
        label = "pending implementation panic";
        needle = "implementation is pending";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 adversarial-host-fixture check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    mkCrucibleTestGate {
      pname = "crucible-phase1-adversarial-host-fixture";

      buildDeps = [
        pkgs.coreutils
        pkgs.sed
      ];

      phases = [
        {
          name = "run-adversarial-host-fixture";
          script = ''
            set -eu
            cd crates
            crucible-cargo test \
              -p crucible-test-support \
              --test adversarial_host_fixture \
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
            tasks=${builtins.concatStringsSep "," taskIds}
            fixture=canonical-host-adversary-matrix
            dimensions=seeded-scheduling,seeded-affinity,bounded-seeded-work-yield,core-counts,producer-consumer-skew
            rust_tests=crucible_test_support::adversarial_host_fixture
            RESULT
          '';
        }
      ];
    }
