{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.adversarialHostFixture",
  taskIds ? ["T-DET-25"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  harnessAdversarial = builtins.readFile ../../crates/crucible-harness/src/adversarial.rs;
  harnessFixtureTest = builtins.readFile ../../crates/crucible-harness/tests/adversarial_host_fixture.rs;
  modelFingerprintGate = builtins.readFile ../../crates/crucible/tests/gate_single_vm_fingerprint.rs;
  defaultChecks = builtins.readFile ./default.nix;
  determinismContract = builtins.readFile ../../docs/rfcs/0010-crucible/04-determinism-contract.md;
  adversarialGateTest = builtins.readFile ../../crates/crucible-harness/tests/gate_adversarial_determinism.rs;

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
    ++ failuresFor "crates/crucible-harness/src/adversarial.rs" harnessAdversarial [
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
    ++ failuresFor "crates/crucible-harness/tests/adversarial_host_fixture.rs" harnessFixtureTest [
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
    ++ failuresFor "crates/crucible/tests/gate_single_vm_fingerprint.rs" modelFingerprintGate [
      {
        label = "model gate consumes canonical matrix";
        needle = "canonical_host_adversary_matrix()";
      }
      {
        label = "model gate consumes profiled runner";
        needle = "run_profiled_tasks(profile, fixtures.len()";
      }
      {
        label = "model gate keeps adversarial equality assertion";
        needle = "assert_eq!(candidate, baseline";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/gate_single_vm_fingerprint.rs" modelFingerprintGate [
      {
        label = "local adversarial fixture copy";
        needle = "fn with_concurrent_host_load";
      }
      {
        label = "local host adversary type copy";
        needle = "struct HostAdversaryProfile";
      }
    ]
    ++ failuresFor "crates/crucible-harness/tests/gate_adversarial_determinism.rs" adversarialGateTest [
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
    ++ forbiddenFor "crates/crucible-harness/tests/gate_adversarial_determinism.rs" adversarialGateTest [
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
    pkgs.mkDerivation {
      pname = "crucible-phase1-adversarial-host-fixture";
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
          name = "run-adversarial-host-fixture";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-adversarial-host-fixture-target" \
              -p crucible-harness \
              --test adversarial_host_fixture \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-adversarial-host-fixture-target" \
              -p crucible \
              --features test-double \
              --test gate_single_vm_fingerprint \
              gate_single_vm_fingerprint_model_determinism_survives_adversarial_host_profiles \
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
            dimensions=seeded-scheduling,seeded-affinity,jitter-load,core-counts,producer-consumer-skew
            rust_tests=crucible-harness::adversarial_host_fixture,crucible::gate_single_vm_fingerprint::adversarial-host-profiles
            RESULT
          '';
        }
      ];
    }
