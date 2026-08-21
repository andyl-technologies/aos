{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase3.schedulerIcountCeiling",
  taskIds ? ["T-SCHED-20"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = import ../../pkgs/tools/crucible/_cargo-deps-hash.nix;
  };

  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  model = import ./_crucible-model-source.nix {inherit lib;};
  icountCeilingTest = builtins.readFile ../../crates/crucible/tests/scheduler_icount_ceiling.rs;
  schedulingDoc = builtins.readFile ../../docs/rfcs/0010-crucible/08-scheduling.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/08-scheduling.md" schedulingDoc [
      {
        label = "T-SCHED-20 completion note";
        needle = "Completed by `checks.crucible.phase3.schedulerIcountCeiling`";
      }
      {
        label = "SCHED-34 requirement";
        needle = "horizon virtual times to per-node icount ceilings";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "TIME-4 ceil conversion";
        needle = "pub fn to_icount_ceil";
      }
      {
        label = "ceil remainder handling";
        needle = "u64::from(remainder != 0)";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "shared timeline conversion helper";
        needle = "pub fn max_advance_icount_for_horizon";
      }
      {
        label = "helper uses TIME-4 ceil map";
        needle = "horizon.to_icount_ceil(self.shift)";
      }
      {
        label = "horizon finite uses shared timeline";
        needle = "timeline.max_advance_icount_for_horizon(virtual_time)";
      }
      {
        label = "RUN plan uses shared timeline helper";
        needle = "node_counter_for_time_ceil(selected_runtime_node, candidate.target_time)";
      }
      {
        label = "publication records fixed shift";
        needle = "icount_shift: self.timeline.shift()";
      }
      {
        label = "publication exposes fixed shift";
        needle = "pub icount_shift: Shift";
      }
      {
        label = "strict conservative overshoot guard";
        needle = "!candidate.allow_ceil_past_target && projected_target > candidate.target_time";
      }
      {
        label = "later network cap guard";
        needle = "network_cap_at";
      }
      {
        label = "time limit cap guard";
        needle = "time_limit_at";
      }
      {
        label = "rendezvous cap guard";
        needle = "rendezvous_at";
      }
      {
        label = "exact local ceil allowance";
        needle = "horizon_source_allows_ceiling_past_target";
      }
    ]
    ++ failuresFor "crates/crucible/tests/scheduler_icount_ceiling.rs" icountCeilingTest [
      {
        label = "shared timeline direct test";
        needle = "shared_timeline_converts_horizon_with_time4_ceil_map";
      }
      {
        label = "exact horizon ceil test";
        needle = "exact_horizon_publishes_ceil_icount_not_floor_or_virtual_time";
      }
      {
        label = "network horizon shift test";
        needle = "network_horizon_ceiling_uses_fixed_shift_not_raw_virtual_nanoseconds";
      }
      {
        label = "unaligned conservative reject test";
        needle = "unaligned_conservative_horizon_rejects_ceil_overshoot";
      }
      {
        label = "equal exact and conservative cap reject test";
        needle = "exact_horizon_equal_to_network_cap_rejects_conservative_overshoot";
      }
      {
        label = "later network cap reject test";
        needle = "exact_horizon_rejects_ceil_over_later_network_cap";
      }
      {
        label = "exact over dependency reject test";
        needle = "exact_horizon_rejects_ceil_over_future_cross_node_dependency";
      }
      {
        label = "idle time-limit cap reject test";
        needle = "idle_wake_equal_to_time_limit_rejects_ceil_overshoot";
      }
      {
        label = "idle rendezvous cap reject test";
        needle = "idle_wake_equal_to_rendezvous_rejects_ceil_overshoot";
      }
      {
        label = "idle wake shift test";
        needle = "idle_wake_horizon_uses_same_fixed_shift_ceiling_conversion";
      }
      {
        label = "unaligned ceil assertion";
        needle = "SimInstant { nanos: 65 }";
      }
      {
        label = "not raw virtual nanoseconds assertion";
        needle = "assert_ne!(\n        publication.max_advance_icount,";
      }
      {
        label = "fixed shift publication assertion";
        needle = "assert_eq!(publication.icount_shift, shift(2))";
      }
      {
        label = "overshoot rejection assertion";
        needle = "unaligned conservative horizon must not be rounded past";
      }
      {
        label = "dependency overshoot assertion";
        needle = "dependency_at=7";
      }
      {
        label = "network overshoot assertion";
        needle = "network_cap_at=7";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase3 exposes scheduler icount ceiling check";
        needle = "schedulerIcountCeiling = import ./phase3-scheduler-icount-ceiling.nix";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/scheduler_icount_ceiling.rs" icountCeilingTest [
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
  then throw "crucible phase3 scheduler icount ceiling check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase3-scheduler-icount-ceiling";
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
          name = "run-scheduler-icount-ceiling";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-icount-ceiling-target" \
              -p crucible \
              --test scheduler_icount_ceiling \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-icount-ceiling-target" \
              -p crucible \
              --test scheduler_run_ceiling \
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
            horizon_arithmetic=virtual-time
            ceiling_units=icount
            conversion=time4-ceil-fixed-shift
            RESULT
          '';
        }
      ];
    }
