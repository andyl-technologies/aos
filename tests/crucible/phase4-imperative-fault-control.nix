{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.imperativeFaultControl",
  taskIds ? ["T-FAULT-11"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  model = import ./_crucible-model-source.nix {inherit lib;};
  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  session = import ./_crucible-session-source.nix {inherit lib;};
  imperativeTest = builtins.readFile ../../crates/crucible/tests/imperative_fault_control.rs;
  sessionTest = builtins.readFile ../../crates/crucible-session/tests/gate_control_responsive.rs;
  faultDoc = builtins.readFile ../../docs/rfcs/0010-crucible/17-fault-injection.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;



  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/17-fault-injection.md" faultDoc [
      {
        label = "T-FAULT-11 checked off";
        needle = "- [x] **T-FAULT-11**";
      }
      {
        label = "T-FAULT-11 completion note";
        needle = "Completed by `checks.crucible.phase4.imperativeFaultControl`";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "ControlFault schedule decision";
        needle = "ControlFault(ControlFaultDecision)";
      }
      {
        label = "ControlFaultDecision payload";
        needle = "pub struct ControlFaultDecision";
      }
      {
        label = "ControlFaultAction taxonomy payload";
        needle = "pub enum ControlFaultAction";
      }
      {
        label = "ControlFault binary serialization";
        needle = "fn write_control_fault_action_binary";
      }
      {
        label = "ControlFault binary deserialization";
        needle = "fn read_control_fault_action_binary";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "typed imperative inject operation";
        needle = "InjectFault {";
      }
      {
        label = "typed imperative heal operation";
        needle = "HealFault {";
      }
      {
        label = "boundary fault application";
        needle = "fn apply_control_faults_at_boundary";
      }
      {
        label = "schedule-prefix hydration";
        needle = "fn hydrate_control_fault_schedule_prefix";
      }
      {
        label = "control-fault schedule scanner";
        needle = "fn trigger_action_state_from_control_fault_decisions";
      }
      {
        label = "control operation records schedule decision";
        needle = "Decision::ControlFault(ControlFaultDecision";
      }
      {
        label = "shared active-fault helper";
        needle = "fn activate_fault_tag";
      }
    ]
    ++ failuresFor "crates/crucible-session/src/lib.rs" session [
      {
        label = "session typed inject command";
        needle = "SessionCommand::InjectFault";
      }
      {
        label = "session typed heal command";
        needle = "SessionCommand::HealFault";
      }
      {
        label = "session maps typed inject to scheduler";
        needle = "ControlOperationKind::InjectFault";
      }
      {
        label = "session maps typed heal to scheduler";
        needle = "ControlOperationKind::HealFault";
      }
    ]
    ++ failuresFor "crates/crucible/tests/imperative_fault_control.rs" imperativeTest [
      {
        label = "inject records and applies test";
        needle = "imperative_inject_records_decision_and_applies_at_boundary";
      }
      {
        label = "unknown heal no-op test";
        needle = "imperative_heal_records_decision_and_is_noop_for_unknown_tag";
      }
      {
        label = "same-boundary order/final-state test";
        needle = "imperative_fault_controls_are_sorted_and_reduce_to_final_boundary_state";
      }
      {
        label = "same-boundary topology test";
        needle = "imperative_partition_recomputes_topology_at_the_same_boundary";
      }
      {
        label = "schedule-prefix active-fault hydration test";
        needle = "recorded_control_fault_schedule_prefix_rehydrates_active_faults";
      }
      {
        label = "schedule-prefix topology hydration test";
        needle = "recorded_control_partition_schedule_prefix_rehydrates_topology";
      }
      {
        label = "schedule binary and hash round trip test";
        needle = "control_fault_decisions_round_trip_through_schedule_binary_and_hash";
      }
    ]
    ++ failuresFor "crates/crucible-session/tests/gate_control_responsive.rs" sessionTest [
      {
        label = "session typed fault control gate test";
        needle = "gate_control_responsive_accepts_typed_fault_control_commands";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 imperative fault control import";
        needle = "imperativeFaultControl = import ./phase4-imperative-fault-control.nix";
      }
      {
        label = "phase4 imperative fault control attr path";
        needle = "attrPath = \"checks.crucible.phase4.imperativeFaultControl\"";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/imperative_fault_control.rs" imperativeTest [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "unfinished todo";
        needle = "todo!";
      }
      {
        label = "unfinished unimplemented";
        needle = "unimplemented!";
      }
    ];
in
  if failures != []
  then throw "crucible phase4 imperative-fault-control check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-imperative-fault-control";
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
          name = "run-imperative-fault-control";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-imperative-fault-control-target" \
              -p crucible \
              --test imperative_fault_control \
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
            control=imperative-inject-heal
            schedule=control-fault-decision
            boundary=quantum
            RESULT
          '';
        }
      ];
    }
