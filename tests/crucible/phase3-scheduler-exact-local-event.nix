{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase3.schedulerExactLocalEvent",
  taskIds ? ["T-SCHED-6"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  exactLocalTest = builtins.readFile ../../crates/crucible/tests/scheduler_exact_local_event.rs;
  schedulingDoc = builtins.readFile ../../docs/rfcs/0010-crucible/08-scheduling.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/08-scheduling.md" schedulingDoc [
      {
        label = "T-SCHED-6 completion note";
        needle = "Completed by `checks.crucible.phase3.schedulerExactLocalEvent`";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "I/O exact local variant";
        needle = "IoCompletion";
      }
      {
        label = "signal fault exact local variant";
        needle = "SignalFaultEvaluation";
      }
      {
        label = "I/O completion bridge";
        needle = "pub fn exact_local_event_from_io_completion";
      }
      {
        label = "scheduled event bridge";
        needle = "pub fn exact_local_event_from_scheduled_event";
      }
      {
        label = "exact local reducer";
        needle = "pub fn next_exact_local_event";
      }
      {
        label = "advance window exact local reducer wiring";
        needle = "let mut exact_local_event = next_exact_local_event";
      }
      {
        label = "backend input exclusion";
        needle = "Backend input is intentionally excluded";
      }
      {
        label = "I/O source horizon";
        needle = "SchedulerHorizonSource::ExactLocalIoCompletion";
      }
      {
        label = "signal fault source horizon";
        needle = "SchedulerHorizonSource::SignalFaultEvaluation";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "I/O exact local export";
        needle = "exact_local_event_from_io_completion";
      }
      {
        label = "scheduled event exact local export";
        needle = "exact_local_event_from_scheduled_event";
      }
      {
        label = "exact local reducer export";
        needle = "next_exact_local_event";
      }
    ]
    ++ failuresFor "crates/crucible/tests/scheduler_exact_local_event.rs" exactLocalTest [
      {
        label = "earliest timer/I/O test";
        needle = "next_exact_local_event_selects_earliest_timer_or_io";
      }
      {
        label = "I/O shift conversion test";
        needle = "next_exact_local_event_converts_io_delivery_icount_with_shift";
      }
      {
        label = "I/O key/payload consistency test";
        needle = "next_exact_local_event_rejects_inconsistent_io_delivery_time";
      }
      {
        label = "I/O target consistency test";
        needle = "next_exact_local_event_rejects_io_target_mismatch";
      }
      {
        label = "network ignored test";
        needle = "next_exact_local_event_ignores_network_input_and_other_nodes";
      }
      {
        label = "scheduler I/O horizon integration test";
        needle = "single_scheduler_uses_pending_io_completion_as_exact_local_horizon";
      }
      {
        label = "I/O horizon source test";
        needle = "horizon_uses_io_completion_as_exact_local_source";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/scheduler_exact_local_event.rs" exactLocalTest [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase3 exposes scheduler exact local check";
        needle = "schedulerExactLocalEvent = import ./phase3-scheduler-exact-local-event.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase3 scheduler exact-local-event check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase3-scheduler-exact-local-event";
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
          name = "run-scheduler-exact-local-event";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-exact-local-event-target" \
              -p crucible \
              --test scheduler_exact_local_event \
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
            next_exact_local_event=timer-io-fault-min
            network_input=excluded
            RESULT
          '';
        }
      ];
    }
