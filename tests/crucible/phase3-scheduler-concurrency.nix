{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase3.schedulerConcurrency",
  taskIds ? ["T-SCHED-25"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoVendor {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-fWBTuyTXJ+/0BiVbB5WAtCqVwufg04NH4BJdocT+moU=";
  };

  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  concurrencyTest = builtins.readFile ../../crates/crucible/tests/scheduler_concurrency.rs;
  schedulingDoc = builtins.readFile ../../docs/rfcs/0010-crucible/08-scheduling.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/08-scheduling.md" schedulingDoc [
      {
        label = "T-SCHED-25 completion note";
        needle = "Completed by `checks.crucible.phase3.schedulerConcurrency`";
      }
      {
        label = "concurrent run set note";
        needle = "bounded concurrent RUN set";
      }
      {
        label = "serialized resolve emit note";
        needle = "serializes each completion through RESOLVE/EMIT/STEP";
      }
      {
        label = "e2e determinism note";
        needle = "gate:e2e-determinism";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "concurrent trait";
        needle = "pub trait ConcurrentQuantumLoop";
      }
      {
        label = "concurrent outcome";
        needle = "pub struct SchedulerConcurrentQuantumOutcome";
      }
      {
        label = "concurrent run set";
        needle = "pub struct SchedulerConcurrentRunSet";
      }
      {
        label = "concurrent candidate";
        needle = "pub struct SchedulerConcurrentRunCandidate";
      }
      {
        label = "read-only run set method";
        needle = "pub fn concurrent_run_set";
      }
      {
        label = "mutating concurrent driver";
        needle = "fn drive_concurrent_authoritative_quantum";
      }
      {
        label = "shared candidate helper";
        needle = "fn advance_candidates";
      }
      {
        label = "worker bound validation";
        needle = "concurrent scheduler max_host_workers must be positive";
      }
      {
        label = "serialized concurrent completions";
        needle = "for (_, _, plan, preemptions) in ordered_plans";
      }
      {
        label = "concurrent completions serialized by deterministic order key";
        needle = "concurrent_completion_order_key(&plan, &preemptions, self.timeline.shift())?";
      }
      {
        label = "common frontier selection";
        needle = "current_time != frontier";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "concurrent trait export";
        needle = "ConcurrentQuantumLoop";
      }
      {
        label = "concurrent outcome export";
        needle = "SchedulerConcurrentQuantumOutcome";
      }
      {
        label = "concurrent run set export";
        needle = "SchedulerConcurrentRunSet";
      }
    ]
    ++ failuresFor "crates/crucible/tests/scheduler_concurrency.rs" concurrencyTest [
      {
        label = "bounded run set test";
        needle = "concurrent_run_set_is_bounded_by_workers_and_horizons";
      }
      {
        label = "zero worker rejection test";
        needle = "concurrent_run_set_rejects_zero_workers";
      }
      {
        label = "skewed peer exclusion test";
        needle = "concurrent_run_set_excludes_skewed_peers_from_same_round";
      }
      {
        label = "serial concurrent bit-identical test";
        needle = "concurrent_round_serializes_resolve_emit_bit_identically_to_serial";
      }
      {
        label = "serial driver comparison";
        needle = "drive_one_quantum";
      }
      {
        label = "concurrent driver exercised";
        needle = "drive_concurrent_quantum";
      }
      {
        label = "event log hash comparison";
        needle = "event_hashes";
      }
      {
        label = "intermediate frontier comparison";
        needle = "concurrent_frontiers";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/scheduler_concurrency.rs" concurrencyTest [
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
        label = "phase3 exposes scheduler concurrency check";
        needle = "schedulerConcurrency = import ./phase3-scheduler-concurrency.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase3 scheduler concurrency check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase3-scheduler-concurrency";
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
            sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
                > .cargo/config.toml
          '';
        }
        {
          name = "run-scheduler-concurrency";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-concurrency-target" \
              -p crucible \
              --test scheduler_concurrency \
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
            host_concurrency=bounded-by-lookahead-and-workers
            resolve_emit=serialized-through-single-scheduler
            serial_concurrent_event_logs=bit-identical
            related_gate=gate:e2e-determinism
            RESULT
          '';
        }
      ];
    }
