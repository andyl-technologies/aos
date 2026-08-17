{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase3.schedulerEffectiveHorizon",
  taskIds ? ["T-SCHED-13"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-ULD9g6d87886b8O6/sGCMktquGwaUAyf+DLHUrFzod0=";
  };

  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  effectiveHorizonTest = builtins.readFile ../../crates/crucible/tests/scheduler_effective_horizon.rs;
  schedulingDoc = builtins.readFile ../../docs/rfcs/0010-crucible/08-scheduling.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/08-scheduling.md" schedulingDoc [
      {
        label = "T-SCHED-13 completion note";
        needle = "Completed by `checks.crucible.phase3.schedulerEffectiveHorizon`";
      }
      {
        label = "effective horizon requirement";
        needle = "single unified `effective_horizon(node)` projection";
      }
      {
        label = "terminal projection requirement";
        needle = "DONE/Halted → +∞";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "halted scheduler state";
        needle = "SchedulerNodeActivity::Halted";
      }
      {
        label = "done scheduler state";
        needle = "SchedulerNodeActivity::Done";
      }
      {
        label = "effective horizon projection enum";
        needle = "enum EffectiveHorizonProjection";
      }
      {
        label = "effective horizon projection function";
        needle = "fn effective_horizon";
      }
      {
        label = "running projection uses advance window";
        needle = "let window = self.advance_window(\n                    node,\n                    current_time,\n                    rendezvous_cap,\n                    topology_activation_cap,\n                )?";
      }
      {
        label = "idle projection uses idle wake helper";
        needle = "self.idle_advance_candidate(node, rendezvous_cap, topology_activation_cap)";
      }
      {
        label = "terminal states project to infinity";
        needle = "SchedulerNodeActivity::Halted | SchedulerNodeActivity::Done";
      }
      {
        label = "infinite projection";
        needle = "EffectiveHorizonProjection::Infinite";
      }
      {
        label = "PICK target-time ordering";
        needle = "left.target_time";
      }
      {
        label = "PICK node-id tie break";
        needle = "then_with(|| left.key.node.cmp(&right.key.node))";
      }
      {
        label = "RUN target ceiling";
        needle = "node_counter_for_time_ceil(selected_runtime_node, candidate.target_time)";
      }
      {
        label = "RUN conservative overshoot guard";
        needle = "projected_target > dependency.virtual_time";
      }
    ]
    ++ failuresFor "crates/crucible/tests/scheduler_effective_horizon.rs" effectiveHorizonTest [
      {
        label = "mixed projection test";
        needle = "effective_horizon_pick_uses_running_idle_halted_done_projection";
      }
      {
        label = "projection tie-break test";
        needle = "effective_horizon_ties_by_node_id_after_state_projection";
      }
      {
        label = "terminal quiescence test";
        needle = "halted_and_done_nodes_do_not_block_quiescence_with_empty_queues";
      }
      {
        label = "all-infinite no advance test";
        needle = "all_infinite_effective_horizons_yield_no_advance_when_queues_are_empty";
      }
      {
        label = "RUN horizon stop test";
        needle = "run_reaches_horizon_and_never_advances_past_it";
      }
      {
        label = "RUN pending-delivery stop test";
        needle = "run_stops_at_pending_delivery_before_network_horizon";
      }
      {
        label = "halted state coverage";
        needle = "SchedulerNodeActivity::Halted";
      }
      {
        label = "done state coverage";
        needle = "SchedulerNodeActivity::Done";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase3 exposes scheduler effective-horizon check";
        needle = "schedulerEffectiveHorizon = import ./phase3-scheduler-effective-horizon.nix";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/scheduler_effective_horizon.rs" effectiveHorizonTest [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "pending placeholder";
        needle = "todo!";
      }
    ];
in
  if failures != []
  then throw "crucible phase3 scheduler effective-horizon check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase3-scheduler-effective-horizon";
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
          name = "run-scheduler-effective-horizon";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-effective-horizon-target" \
              -p crucible \
              --test scheduler_effective_horizon \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-effective-horizon-target" \
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
            pick=global-minimum-effective-horizon-node-id-tie
            run=icount-ceiling-never-past-horizon
            terminal_projection=halted-done-infinite
            idle_projection=idle-wake-icount
            RESULT
          '';
        }
      ];
    }
