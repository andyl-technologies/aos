{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.sessionBoundaryControl",
  taskIds ? ["T-SESS-6"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  sessionLib = import ./_crucible-session-source.nix {inherit lib;};
  gateControlResponsive = builtins.readFile ../../crates/crucible-session/tests/gate_control_responsive.rs;
  apiGateControlResponsive = builtins.readFile ../../crates/crucible-api/tests/gate_control_responsive.rs;
  daemonGateControlResponsive = builtins.readFile ../../crates/crucible-daemon/tests/gate_control_responsive.rs;
  schedulerLib = import ./_crucible-scheduler-source.nix {inherit lib;};
  sessionDoc = builtins.readFile ../../docs/rfcs/0010-crucible/20-session-control-plane.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/20-session-control-plane.md" sessionDoc [
      {
        label = "T-SESS-6 completion note";
        needle = "Completed by `checks.crucible.phase5.sessionBoundaryControl`";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "phase5 boundary control status note";
        needle = "`T-SESS-6` is green through `checks.crucible.phase5.sessionBoundaryControl`";
      }
    ]
    ++ failuresFor "crates/crucible-session/src/lib.rs" sessionLib [
      {
        label = "session control log entry";
        needle = "pub struct SessionControlLogEntry";
      }
      {
        label = "control log storage";
        needle = "boundary_control_log: Vec<SessionControlLogEntry>";
      }
      {
        label = "control log accessor";
        needle = "pub fn boundary_control_log(&self) -> &[SessionControlLogEntry]";
      }
      {
        label = "boundary control recorder";
        needle = "fn record_boundary_control";
      }
      {
        label = "immediate scheduler control application";
        needle = "fn apply_control_operations_at_boundary";
      }
      {
        label = "deterministic frontier field";
        needle = "frontier: self.frontier";
      }
      {
        label = "deterministic quanta field";
        needle = "quanta: self.quanta";
      }
      {
        label = "running mutator log test";
        needle = "running_boundary_commands_record_deterministic_control_log";
      }
      {
        label = "fork local boundary coverage";
        needle = "SessionCommandKind::Fork";
      }
      {
        label = "scheduler control delivery coverage";
        needle = "recorded_control_batches";
      }
      {
        label = "pause stop boundary test";
        needle = "pause_and_stop_take_effect_at_boundary_without_extra_quantum";
      }
      {
        label = "shutdown assertion";
        needle = "shutdowns.load(Ordering::SeqCst)";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" schedulerLib [
      {
        label = "quantum loop shutdown hook";
        needle = "fn shutdown(&mut self) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError>";
      }
      {
        label = "quantum loop boundary control hook";
        needle = "fn apply_control_at_boundary";
      }
    ]
    ++ failuresFor "crates/crucible-session/tests/gate_control_responsive.rs" gateControlResponsive [
      {
        label = "integration loop boundary control hook";
        needle = "fn apply_control_at_boundary";
      }
    ]
    ++ failuresFor "crates/crucible-api/tests/gate_control_responsive.rs" apiGateControlResponsive [
      {
        label = "api gate loop boundary control hook";
        needle = "fn apply_control_at_boundary";
      }
    ]
    ++ failuresFor "crates/crucible-daemon/tests/gate_control_responsive.rs" daemonGateControlResponsive [
      {
        label = "daemon gate loop boundary control hook";
        needle = "fn apply_control_at_boundary";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase5 exposes session boundary control check";
        needle = "sessionBoundaryControl = import ./phase5-session-boundary-control.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase5 session-boundary-control check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase5-session-boundary-control";
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
          name = "run-session-boundary-control";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-session-boundary-control-target" \
              -p crucible-session \
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
            component=crucible-session
            boundary_control_log=frontier-quanta
            scheduler_control=typed-boundary-operations
            stopped_drain=read-only-plus-fork
            pause_stop=boundary-no-extra-quantum
            stop=shutdown
            RESULT
          '';
        }
      ];
    }
