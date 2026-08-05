{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase3.gates.schedulerLiveness",
  taskIds ? ["T-HARN-14" "T-SCHED-4"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoVendor {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-fWBTuyTXJ+/0BiVbB5WAtCqVwufg04NH4BJdocT+moU=";
  };
  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  schedulerGate = builtins.readFile ../../crates/crucible/tests/gate_scheduler_liveness.rs;
  gateTargets = builtins.readFile ../../crates/crucible-harness/src/gate_targets.rs;
  gateCatalog = builtins.readFile ../../crates/crucible-harness/src/lib.rs;
  gateCatalogTest = builtins.readFile ../../crates/crucible-harness/tests/gate_catalog.rs;
  gateTargetMapping = builtins.readFile ./phase1-gate-target-mapping.nix;
  defaultChecks = builtins.readFile ./default.nix;
  harnessTesting = builtins.readFile ../../docs/rfcs/0010-crucible/24-determinism-harness-testing.md;
  schedulingSpec = builtins.readFile ../../docs/rfcs/0010-crucible/08-scheduling.md;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  failures =
    failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "authoritative scheduler implementation";
        needle = "pub struct SingleScheduler";
      }
      {
        label = "QuantumLoop implementation";
        needle = "impl QuantumLoop for SingleScheduler";
      }
      {
        label = "liveness checker entry point";
        needle = "pub fn check_scheduler_liveness(";
      }
      {
        label = "generated scenario input type";
        needle = "pub struct SchedulerLivenessScenario";
      }
      {
        label = "explicit node activity model";
        needle = "pub enum SchedulerNodeActivity";
      }
      {
        label = "idle transition after quiescent horizon";
        needle = "SchedulerNodeActivity::Idle";
      }
      {
        label = "quiescent terminal";
        needle = "SchedulerTerminal::Quiescent";
      }
      {
        label = "time-limit terminal";
        needle = "SchedulerTerminal::TimeLimitReached";
      }
      {
        label = "deadlock failure";
        needle = "SchedulerLivenessError::Deadlock";
      }
      {
        label = "livelock failure";
        needle = "SchedulerLivenessError::Livelock";
      }
      {
        label = "held-lock failure";
        needle = "LockHeldAcrossAdvance";
      }
      {
        label = "yield-before-advance evidence";
        needle = "yielded_before_advance";
      }
      {
        label = "global minimum horizon pick";
        needle = "fn pick_global_minimum_horizon_node";
      }
      {
        label = "horizon-first candidate order";
        needle = "left.target_time";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "public liveness checker export";
        needle = "check_scheduler_liveness";
      }
      {
        label = "public scheduler export";
        needle = "SingleScheduler";
      }
    ]
    ++ failuresFor "crates/crucible/tests/gate_scheduler_liveness.rs" schedulerGate [
      {
        label = "generated corpus gate";
        needle = "gate_scheduler_liveness_generated_scenarios_terminate";
      }
      {
        label = "generated scenario corpus";
        needle = "generated_scheduler_liveness_scenarios";
      }
      {
        label = "liveness entry point usage";
        needle = "check_scheduler_liveness(scenario)";
      }
      {
        label = "time-limit terminal assertion";
        needle = "gate_scheduler_liveness_reaches_time_limit_terminal";
      }
      {
        label = "global minimum horizon pick assertion";
        needle = "gate_scheduler_liveness_picks_global_minimum_horizon_before_current_time_order";
      }
      {
        label = "node-id tie-break assertion";
        needle = "gate_scheduler_liveness_breaks_equal_horizon_ties_by_node_id";
      }
      {
        label = "deadlock negative control";
        needle = "gate_scheduler_liveness_rejects_due_event_deadlock";
      }
      {
        label = "livelock negative control";
        needle = "gate_scheduler_liveness_rejects_stalled_runnable_livelock";
      }
      {
        label = "yield evidence assertion";
        needle = "report.yielded_between_quanta";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/gate_scheduler_liveness.rs" schedulerGate [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "red placeholder panic";
        needle = "implementation is pending T-HARN-14";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/gate_targets.rs" gateTargets [
      {
        label = "implemented scheduler liveness target";
        needle = "gate: \"gate:scheduler-liveness\",\n        package: \"crucible\",\n        test_target: \"gate_scheduler_liveness\",\n        required_features: &[\"test-double\"],\n        placeholder: false,";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/lib.rs" gateCatalog [
      {
        label = "implemented canonical scheduler liveness gate status";
        needle = "name: \"gate:scheduler-liveness\",\n        phase: GatePhase::Phase3,\n        owner: \"crucible\",\n        status: GateStatus::Implemented,";
      }
    ]
    ++ failuresFor "crates/crucible-harness/tests/gate_catalog.rs" gateCatalogTest [
      {
        label = "scheduler liveness implemented status assertion";
        needle = "find_gate(\"gate:scheduler-liveness\").map(|spec| spec.status),\n        Some(GateStatus::Implemented)";
      }
    ]
    ++ failuresFor "tests/crucible/phase1-gate-target-mapping.nix" gateTargetMapping [
      {
        label = "implemented scheduler liveness mapping target";
        needle = "gate = \"gate:scheduler-liveness\";\n      package = \"crucible\";\n      testTarget = \"gate_scheduler_liveness\";\n      requiredFeatures = [\"test-double\"];\n      placeholder = false;";
      }
      {
        label = "updated placeholder count";
        needle = "placeholder_targets=0";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase3 uses scheduler liveness check";
        needle = "schedulerLiveness = import ./phase3-scheduler-liveness.nix";
      }
      {
        label = "phase3 scheduler liveness attr path";
        needle = "attrPath = \"checks.crucible.phase3.gates.schedulerLiveness\"";
      }
      {
        label = "phase3 scheduler liveness task id";
        needle = "\"T-HARN-14\"";
      }
      {
        label = "phase3 scheduler progress task id";
        needle = "\"T-SCHED-4\"";
      }
    ]
    ++ forbiddenFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "scheduler liveness red gate";
        needle = "schedulerLiveness = redGate";
      }
      {
        label = "scheduler liveness pending reason";
        needle = "scheduler liveness gate is intentionally pending";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/24-determinism-harness-testing.md" harnessTesting [
      {
        label = "HARN-18 generated scenario requirement";
        needle = "`gate:scheduler-liveness` MUST drive the single authoritative";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/08-scheduling.md" schedulingSpec [
      {
        label = "T-SCHED-4 completion note";
        needle = "Completed by `checks.crucible.phase3.gates.schedulerLiveness`";
      }
      {
        label = "liveness property text";
        needle = "property `gate:scheduler-liveness` checks";
      }
      {
        label = "no spin failure requirement";
        needle = "MUST fail loudly, never";
      }
    ];
in
  if failures != []
  then throw "crucible phase3 scheduler-liveness gate check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase3-scheduler-liveness";
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
            sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
                > .cargo/config.toml
          '';
        }
        {
          name = "run-scheduler-liveness";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-liveness-target" \
              -p crucible \
              --features test-double \
              --test gate_scheduler_liveness \
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
            gate=gate:scheduler-liveness
            tasks=${taskList}
            rust_tests=crucible::gate_scheduler_liveness
            backend=crucible-sim-double-initialized-test-double
            real_qemu_required=false
            terminal_set=Quiescent,TimeLimitReached
            generated_scenarios=48
            deadlock_negative_control=true
            livelock_negative_control=true
            held_lock_spans_node_advance=false
            RESULT
          '';
        }
      ];
    }
