{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase3.schedulerIcountCeiling",
  taskIds ? ["T-SCHED-20"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  model = import ./_crucible-model-source.nix {inherit lib;};
  nodeTime = builtins.readFile ../../crates/crucible/src/node_time.rs;
  icountCeilingTest = builtins.readFile ../../crates/crucible/tests/scheduler_icount_ceiling.rs;
  runCeilingTest = builtins.readFile ../../crates/crucible/tests/scheduler_run_ceiling.rs;
  schedulingDoc = builtins.readFile ../../docs/rfcs/0010-crucible/08-scheduling.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/08-scheduling.md" schedulingDoc [
      {
        label = "T-SCHED-20 completion names the focused gate";
        needle = "Completed by `checks.crucible.phase3.schedulerIcountCeiling`";
      }
      {
        label = "SCHED-34 requires exact logical ticks";
        needle = "MUST treat each node's clock as exact logical";
      }
      {
        label = "nanosecond rounding cannot move a ceiling";
        needle = "A nanosecond floor/ceil conversion MUST NOT change an authorization boundary";
      }
      {
        label = "RUN publication retains exact ticks";
        needle = "RUN publications retain exact ticks into the shmem ABI `max_advance_icount`";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "one nanosecond has one thousand exact ticks";
        needle = "pub const SIM_TICKS_PER_NS: u64 = 1_000;";
      }
      {
        label = "one retirement advances fifty exact ticks";
        needle = "pub const SIM_TICKS_PER_INSTRUCTION: u64 = 50;";
      }
      {
        label = "guest nanoseconds floor only at projection";
        needle = "self.ticks / SIM_TICKS_PER_NS";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "exact horizon projects to a node counter";
        needle = "pub fn max_advance_counter_for_horizon";
      }
      {
        label = "conservative horizon projects to a safe node counter";
        needle = "pub fn max_advance_counter_for_conservative_horizon";
      }
      {
        label = "VM exact target uses anchored ceil";
        needle = ".counter_for_logical_time_ceil(target_time)";
      }
      {
        label = "VM conservative target uses anchored floor";
        needle = ".counter_for_logical_time_floor(target_time)";
      }
      {
        label = "RUN plan distinguishes exact and conservative targets";
        needle = "SchedulerIcountRounding::ConservativeFloor";
      }
      {
        label = "RUN plan rejects conservative overshoot";
        needle = "&& projected_target > candidate.target_time";
      }
      {
        label = "RUN plan rejects positive zero-progress windows";
        needle = "&& target_counter == before";
      }
      {
        label = "equal-target selection requires representable progress";
        needle = "candidate_has_representable_advance";
      }
      {
        label = "network ceiling limits later exact projection";
        needle = "\"network_cap_at\"";
      }
      {
        label = "time limit bounds later exact projection";
        needle = "\"time_limit_at\"";
      }
      {
        label = "rendezvous bounds later exact projection";
        needle = "\"rendezvous_at\"";
      }
      {
        label = "cross-node dependency bounds later exact projection";
        needle = "\"dependency_at\"";
      }
    ]
    ++ failuresFor "crates/crucible/src/node_time.rs" nodeTime [
      {
        label = "anchored exact-tick ceiling projection";
        needle = "pub fn counter_for_logical_time_ceil";
      }
      {
        label = "anchored exact-tick conservative projection";
        needle = "pub fn counter_for_logical_time_floor";
      }
      {
        label = "counter overflow rejects instead of wrapping";
        needle = "self.anchor_counter.ticks.checked_add(delta)";
      }
      {
        label = "conservative result validates its anchor";
        needle = "let _ = self.logical_time(counter)?;";
      }
    ]
    ++ failuresFor "crates/crucible/tests/scheduler_icount_ceiling.rs" icountCeilingTest [
      {
        label = "both sides of a nanosecond remain distinct";
        needle = "fn shared_timeline_preserves_both_sides_of_nanosecond_boundary()";
      }
      {
        label = "idle jump preserves anchored phase";
        needle = "fn idle_jump_preserves_anchored_tick_phase()";
      }
      {
        label = "anchored counter bounds reject overflow";
        needle = "fn anchored_projection_fails_closed_at_counter_bounds()";
      }
      {
        label = "network lookahead uses exact ticks";
        needle = "fn network_lookahead_uses_exact_tick_horizon()";
      }
      {
        label = "999 picoseconds still floors to zero nanoseconds";
        needle = "SimInstant { ticks: 999 }.nanoseconds_floor(), 0";
      }
      {
        label = "1000 picoseconds projects to one nanosecond";
        needle = "SimInstant { ticks: 1_000 }.nanoseconds_floor(), 1";
      }
    ]
    ++ failuresFor "crates/crucible/tests/scheduler_run_ceiling.rs" runCeilingTest [
      {
        label = "one exact ceiling per selected RUN";
        needle = "fn run_publishes_one_max_advance_ceiling_for_selected_node()";
      }
      {
        label = "control-only quantum publishes no RUN ceiling";
        needle = "fn control_only_quantum_publishes_no_run_ceiling()";
      }
      {
        label = "RUN consumes the published exact target";
        needle = "fn run_consumes_the_published_ceiling_as_its_target()";
      }
      {
        label = "exact ceiling reaches shared memory";
        needle = "fn published_ceiling_converts_to_and_publishes_through_shmem_abi()";
      }
      {
        label = "pending inputs precede the futex wake";
        needle = "fn published_ceiling_writes_pending_inputs_before_futex_wake()";
      }
      {
        label = "published ceiling retains exact tick four";
        needle = "publication.max_advance_icount, 4";
      }
      {
        label = "published target retains exact tick four";
        needle = "publication.target_time, SimInstant { ticks: 4 }";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase3 exposes scheduler icount ceiling check";
        needle = "schedulerIcountCeiling = import ./phase3-scheduler-icount-ceiling.nix";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/scheduler ceiling" (icountCeilingTest + runCeilingTest) [
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
            ceiling_units=exact-ticks-in-max_advance_icount
            conversion=anchored-exact-tick-ceil-and-floor
            RESULT
          '';
        }
      ];
    }
