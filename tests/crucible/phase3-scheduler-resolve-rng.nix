{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase3.schedulerResolveRng",
  taskIds ? ["T-SCHED-17"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-ULD9g6d87886b8O6/sGCMktquGwaUAyf+DLHUrFzod0=";
  };

  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  resolveRngTest = builtins.readFile ../../crates/crucible/tests/scheduler_resolve_rng.rs;
  schedulingDoc = builtins.readFile ../../docs/rfcs/0010-crucible/08-scheduling.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/08-scheduling.md" schedulingDoc [
      {
        label = "T-SCHED-17 completion note";
        needle = "Completed by `checks.crucible.phase3.schedulerResolveRng`";
      }
      {
        label = "probabilistic resolve requirement";
        needle = "Route every probabilistic RESOLVE choice";
      }
      {
        label = "seeded decision RNG requirement";
        needle = "seeded decision RNG";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "probabilistic choice payload";
        needle = "pub struct SchedulerResolveFaultChoice";
      }
      {
        label = "resolve decision record";
        needle = "pub struct SchedulerResolveDecisionRecord";
      }
      {
        label = "scheduled probabilistic payload";
        needle = "ProbabilisticFault";
      }
      {
        label = "probabilistic resolve helper";
        needle = "pub fn resolve_probabilistic_decisions";
      }
      {
        label = "canonical event order for choices";
        needle = "for event in ordered_scheduled_events(resolved_events)";
      }
      {
        label = "decision recorder seeded from configuration";
        needle = "DecisionRecorder::new(configuration)";
      }
      {
        label = "fault decision recording";
        needle = "recorder.decide_fault";
      }
      {
        label = "quantum emits probabilistic decisions";
        needle = "resolve_probabilistic_decisions_from_seed(";
      }
      {
        label = "raw draw cursor update";
        needle = "Decision::RngDraw(draw)";
      }
      {
        label = "recorded draw cursor stream";
        needle = "advance_decision_rng_cursor_for(draw.stream.clone())";
      }
      {
        label = "probabilistic payload material";
        needle = "payload=probabilistic-fault";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "resolve fault choice export";
        needle = "SchedulerResolveFaultChoice";
      }
      {
        label = "resolve decision record export";
        needle = "SchedulerResolveDecisionRecord";
      }
      {
        label = "probabilistic resolver export";
        needle = "resolve_probabilistic_decisions";
      }
    ]
    ++ failuresFor "crates/crucible/tests/scheduler_resolve_rng.rs" resolveRngTest [
      {
        label = "total-order probabilistic test";
        needle = "probabilistic_resolve_records_rng_draw_and_fault_outcome_in_total_order";
      }
      {
        label = "prior schedule hydration test";
        needle = "probabilistic_resolve_hydrates_streams_from_prior_schedule_decisions";
      }
      {
        label = "deterministic event ignore test";
        needle = "resolve_probabilistic_decisions_ignores_deterministic_events";
      }
      {
        label = "raw draw assertion";
        needle = "Decision::RngDraw";
      }
      {
        label = "fault outcome assertion";
        needle = "Decision::FaultFires";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase3 exposes scheduler resolve RNG check";
        needle = "schedulerResolveRng = import ./phase3-scheduler-resolve-rng.nix";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/scheduler_resolve_rng.rs" resolveRngTest [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "pending placeholder";
        needle = "todo!";
      }
      {
        label = "wall-clock dependency";
        needle = "std::time";
      }
      {
        label = "sleep dependency";
        needle = "sleep(";
      }
    ];
in
  if failures != []
  then throw "crucible phase3 scheduler resolve-rng check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase3-scheduler-resolve-rng";
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
          name = "run-scheduler-resolve-rng";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-resolve-rng-target" \
              -p crucible \
              --test scheduler_resolve_rng \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-resolve-rng-target" \
              -p crucible \
              --test scheduler_resolve \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-resolve-rng-target" \
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
            tasks=${taskList}
            component=crucible-scheduler
            probabilistic_resolve=seeded-decision-rng
            ordering=canonical-event-order
            recorded_decisions=RngDraw+FaultFires
            external_rng_dependency=false
            RESULT
          '';
        }
      ];
    }
