{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase3.schedulerControlResponsive",
  taskIds ? ["T-SCHED-27"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  controlResponsiveTest = builtins.readFile ../../crates/crucible/tests/scheduler_control_responsive.rs;
  schedulingDoc = builtins.readFile ../../docs/rfcs/0010-crucible/08-scheduling.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/08-scheduling.md" schedulingDoc [
      {
        label = "T-SCHED-27 completion note";
        needle = "Completed by `checks.crucible.phase3.schedulerControlResponsive`";
      }
      {
        label = "bounded quantum note";
        needle = "one scheduler quantum";
      }
      {
        label = "boundary-only note";
        needle = "only at quantum boundaries";
      }
      {
        label = "scheduler half note";
        needle = "scheduler half of `gate:control-responsive`";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "scheduler control bound";
        needle = "pub const SCHEDULER_CONTROL_RESPONSE_BOUND_QUANTA: u64 = 1;";
      }
      {
        label = "control application evidence";
        needle = "pub struct SchedulerControlApplication";
      }
      {
        label = "control application accessor";
        needle = "pub fn control_applications";
      }
      {
        label = "actor snapshot carries applications";
        needle = "pub control_applications: Vec<SchedulerControlApplication>";
      }
      {
        label = "bounded delta enforced";
        needle = "application_delta_quanta > SCHEDULER_CONTROL_RESPONSE_BOUND_QUANTA";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "bound exported";
        needle = "SCHEDULER_CONTROL_RESPONSE_BOUND_QUANTA";
      }
      {
        label = "application evidence exported";
        needle = "SchedulerControlApplication";
      }
    ]
    ++ failuresFor "crates/crucible/tests/scheduler_control_responsive.rs" controlResponsiveTest [
      {
        label = "focused scheduler control-responsive test";
        needle = "scheduler-side control responsiveness";
      }
      {
        label = "bound assertion";
        needle = "SCHEDULER_CONTROL_RESPONSE_BOUND_QUANTA";
      }
      {
        label = "application evidence asserted";
        needle = "control_applications";
      }
      {
        label = "bounded delta asserted";
        needle = "application_delta_quanta";
      }
      {
        label = "resolved control events asserted";
        needle = "resolved_events";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/scheduler_control_responsive.rs" controlResponsiveTest [
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
        label = "phase3 exposes scheduler control-responsive check";
        needle = "schedulerControlResponsive = import ./phase3-scheduler-control-responsive.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase3 scheduler control-responsive check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase3-scheduler-control-responsive";
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
          name = "run-scheduler-control-responsive";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-control-responsive-target" \
              -p crucible \
              --test scheduler_control_responsive \
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
            gate=gate:control-responsive
            scheduler_control_bound_quanta=1
            control_boundary_only=true
            RESULT
          '';
        }
      ];
    }
