{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase3.schedulerResolveRng",
  taskIds ? ["T-SCHED-17"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
  executionRuntime = builtins.readFile ../../crates/crucible/src/model/fault_signal/execution_runtime.rs;
  defaultChecks = builtins.readFile ./default.nix;
  inherit (import ./_lib.nix {inherit lib;}) failuresFor forbiddenFor;
  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "crates/crucible/src/model/fault_signal/execution_runtime.rs" executionRuntime [
      {
        label = "seeded signal evaluator ownership";
        needle = "OwnedFaultExecutionRuntime";
      }
      {
        label = "authoritative resolved-effect trace";
        needle = "pub fn recorded_trace(";
      }
      {
        label = "locked replay installation";
        needle = "pub fn install_replay(";
      }
      {
        label = "complete replay consumption";
        needle = "pub fn verify_replay_exhausted(";
      }
      {
        label = "all network replay modes test";
        needle = "recorded_effects_execute_in_every_network_replay_mode";
      }
      {
        label = "recomputed-cause mismatch test";
        needle = "recomputed_replay_rejects_a_derivation_continuation_mismatch";
      }
      {
        label = "failed replay transaction test";
        needle = "failed_replay_installation_leaves_the_owned_continuation_unchanged";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase3 exposes signal resolution RNG check";
        needle = "schedulerResolveRng = import ./phase3-scheduler-resolve-rng.nix";
      }
    ]
    ++ forbiddenFor "crates/crucible/src/model/fault_signal/execution_runtime.rs" executionRuntime [
      {
        label = "legacy scheduler fault outcome";
        needle = "FaultFires";
      }
      {
        label = "wall-clock entropy";
        needle = "thread_rng";
      }
    ];
in
  if failures != []
  then throw "crucible phase3 signal resolution RNG check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase3-signal-resolution-rng";
      version = "0";
      src = crucibleSrc;
      buildDeps = [pkgs.rust pkgs.sed];
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
            mkdir -p "$CARGO_HOME" .cargo
            sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
              > .cargo/config.toml
          '';
        }
        {
          name = "run-signal-resolution-rng";
          script = ''
            cd crates
            cargo test --frozen --offline \
              --target-dir "$TMPDIR/crucible-signal-resolution-target" \
              -p crucible --lib \
              model::fault_signal::execution_runtime::tests::recorded_effects_execute_in_every_network_replay_mode \
              -- --exact --test-threads=1
            cargo test --frozen --offline \
              --target-dir "$TMPDIR/crucible-signal-resolution-target" \
              -p crucible --lib \
              model::fault_signal::execution_runtime::tests::recomputed_replay_rejects_a_derivation_continuation_mismatch \
              -- --exact --test-threads=1
            cargo test --frozen --offline \
              --target-dir "$TMPDIR/crucible-signal-resolution-target" \
              -p crucible --lib \
              model::fault_signal::execution_runtime::tests::failed_replay_installation_leaves_the_owned_continuation_unchanged \
              -- --exact --test-threads=1
          '';
        }
        {
          name = "write-result";
          script = ''
            mkdir -p "$out"
            cat > "$out/result" <<'RESULT'
            PASS
            check=${attrPath}
            tasks=${taskList}
            component=crucible-fault-signal-runtime
            seeded_resolution=canonical-choice-context
            recorded_outcomes=ResolvedEffectTrace
            locked_replay=recomputed-cause,outcome-only-network
            legacy_scheduler_fault_outcomes=absent
            RESULT
          '';
        }
      ];
    }
