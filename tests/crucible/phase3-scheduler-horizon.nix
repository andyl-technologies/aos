{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase3.schedulerHorizon",
  taskIds ? ["T-SCHED-5"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  schedulerHorizonTest = builtins.readFile ../../crates/crucible/tests/scheduler_horizon.rs;
  schedulingDoc = builtins.readFile ../../docs/rfcs/0010-crucible/08-scheduling.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/08-scheduling.md" schedulingDoc [
      {
        label = "T-SCHED-5 completion note";
        needle = "Completed by `checks.crucible.phase3.schedulerHorizon`";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "horizon limit type";
        needle = "pub enum SchedulerHorizonLimit";
      }
      {
        label = "finite horizon limit";
        needle = "SchedulerHorizonLimit::Finite";
      }
      {
        label = "infinite horizon limit";
        needle = "SchedulerHorizonLimit::Infinite";
      }
      {
        label = "network lookahead horizon helper";
        needle = "pub fn horizon_from_network_lookahead";
      }
      {
        label = "network term from current time";
        needle = "current_time + duration";
      }
      {
        label = "exact local event source";
        needle = "SchedulerHorizonSource::ExactLocalTimer";
      }
      {
        label = "scenario stores network lookahead";
        needle = "pub network_lookahead: NetworkLookahead";
      }
      {
        label = "runtime stores network lookahead";
        needle = "network_lookahead: NetworkLookahead";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "horizon limit export";
        needle = "SchedulerHorizonLimit";
      }
      {
        label = "lookahead horizon export";
        needle = "horizon_from_network_lookahead";
      }
      {
        label = "network horizon helper export";
        needle = "network_horizon_from_lookahead";
      }
    ]
    ++ failuresFor "crates/crucible/tests/scheduler_horizon.rs" schedulerHorizonTest [
      {
        label = "current plus lookahead unit";
        needle = "scheduler_horizon_adds_network_lookahead_to_current_time";
      }
      {
        label = "exact local without slack test";
        needle = "scheduler_horizon_uses_exact_local_event_without_conservative_slack";
      }
      {
        label = "unbounded network test";
        needle = "scheduler_horizon_is_unbounded_without_network_or_local_event";
      }
      {
        label = "infinite bounded by exact local test";
        needle = "scheduler_horizon_exact_local_event_bounds_infinite_network";
      }
      {
        label = "live scheduler vt plus lookahead test";
        needle = "single_scheduler_uses_current_time_plus_network_lookahead";
      }
      {
        label = "live scheduler infinite cap test";
        needle = "single_scheduler_caps_unbounded_network_horizon_at_time_limit";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/scheduler_horizon.rs" schedulerHorizonTest [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase3 exposes scheduler horizon check";
        needle = "schedulerHorizon = import ./phase3-scheduler-horizon.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase3 scheduler horizon check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase3-scheduler-horizon";
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
          name = "run-scheduler-horizon";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-horizon-target" \
              -p crucible \
              --test scheduler_horizon \
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
            horizon=min-exact-local-or-vt-plus-lookahead
            exact_local=no-conservative-slack
            network=guest-to-guest-lookahead-only
            RESULT
          '';
        }
      ];
    }
