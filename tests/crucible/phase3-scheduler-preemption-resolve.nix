{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase3.schedulerPreemptionResolve",
  taskIds ? ["T-SCHED-29"],
  openTaskIds ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = import ../../pkgs/tools/crucible/_cargo-deps-hash.nix;
  };

  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  preemptionTest = builtins.concatStringsSep "\n" [
    (builtins.readFile ../../crates/crucible/tests/scheduler_preemption_resolve.rs)
    (builtins.readFile ../../crates/crucible/tests/scheduler_preemption_identity.rs)
  ];
  schedulingDoc = builtins.readFile ../../docs/rfcs/0010-crucible/08-scheduling.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/08-scheduling.md" schedulingDoc [
      {
        label = "T-SCHED-29 completion note";
        needle = "Completed by `checks.crucible.phase3.schedulerPreemptionResolve`";
      }
      {
        label = "bounded window note";
        needle = "authorized `[deadline, ceiling]` window";
      }
      {
        label = "total order note";
        needle = "preemption's commanded virtual time";
      }
      {
        label = "no clamp note";
        needle = "never clamps or defers";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "preemption application evidence";
        needle = "pub struct SchedulerPreemptionApplication";
      }
      {
        label = "preemption scenario queue";
        needle = "pub preemption_requests: Vec<PreemptionDecision>";
      }
      {
        label = "preemption scenario builder";
        needle = "with_preemption_request";
      }
      {
        label = "preemption application accessor";
        needle = "pub fn preemption_applications";
      }
      {
        label = "preemption quiescence blocker";
        needle = "PendingPreemption";
      }
      {
        label = "preemption run planner";
        needle = "planned_preemptions_for_run";
      }
      {
        label = "preemption commit hook";
        needle = "commit_preemption_applications";
      }
      {
        label = "window rejection";
        needle = "outside authorized window";
      }
      {
        label = "preemption event-log time";
        needle = "preemption.at.to_virtual(shift)";
      }
      {
        label = "decision ordering helper";
        needle = "scheduler_ordered_decisions";
      }
      {
        label = "scenario material includes requests";
        needle = "preemption_requests={}";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "preemption application exported";
        needle = "SchedulerPreemptionApplication";
      }
    ]
    ++ failuresFor "crates/crucible/tests/scheduler_preemption_resolve.rs" preemptionTest [
      {
        label = "focused preemption RESOLVE test";
        needle = "scheduler-side preemption RESOLVE";
      }
      {
        label = "in-window total-order test";
        needle = "preemption_within_window_records_decision_and_application_in_total_order";
      }
      {
        label = "ceiling boundary test";
        needle = "preemption_at_authorized_ceiling_is_allowed";
      }
      {
        label = "VM-only scheduler node test";
        needle = "preemption_waits_for_vm_node_not_same_named_subnode";
      }
      {
        label = "past ceiling rejection test";
        needle = "preemption_past_authorized_ceiling_fails_without_application";
      }
      {
        label = "before deadline rejection test";
        needle = "preemption_before_deadline_fails_without_application";
      }
      {
        label = "multiple preemptions one RUN rejection test";
        needle = "multiple_preemptions_for_one_run_fail_before_advance";
      }
      {
        label = "concurrent all-or-nothing validation test";
        needle = "concurrent_preemption_validation_is_all_or_nothing";
      }
      {
        label = "concurrent multiple one RUN rejection test";
        needle = "concurrent_multiple_preemptions_for_one_run_fail_before_any_commit";
      }
      {
        label = "concurrent commanded-time ordering test";
        needle = "concurrent_preemptions_record_in_commanded_time_order";
      }
      {
        label = "quiescence blocker test";
        needle = "pending_preemption_blocks_quiescence_until_applied";
      }
      {
        label = "configuration identity test";
        needle = "preemption_requests_participate_in_configuration_identity";
      }
      {
        label = "schedule decision assertion";
        needle = "Decision::Preemption(preemption.clone())";
      }
      {
        label = "event-log time assertion";
        needle = "VirtualTime { ticks: 4 }";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/scheduler_preemption_resolve.rs" preemptionTest [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "pending placeholder";
        needle = "todo!";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase3 exposes scheduler preemption RESOLVE check";
        needle = "schedulerPreemptionResolve = import ./phase3-scheduler-preemption-resolve.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase3 scheduler preemption RESOLVE check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase3-scheduler-preemption-resolve";
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
          name = "run-scheduler-preemption-resolve";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-preemption-resolve-target" \
              -p crucible \
              --test scheduler_preemption_resolve \
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
            tasks=${taskList}
            component=crucible-scheduler
            gate=gate:layer1-injection,gate:replay-oracle
            preemption_window_enforced=true
            preemption_total_order=true
            RESULT
          '';
        }
      ];
    }
