{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuPluginRegistrationOrder",
  taskIds ? ["T-PLUG-3"],
  openTaskIds ? [],
  livePluginInstall ? import ./phase2-qemu-live-plugin-install.nix {inherit pkgs lib;},
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  pluginLib = builtins.readFile ../../crates/crucible-qemu-plugin/src/lib.rs;
  pluginRegistration = import ./_qemu-plugin-registration-source.nix {inherit lib;};
  pluginTimeControl = import ./_qemu-plugin-time-control-source.nix {inherit lib;};
  pluginSpec = builtins.readFile ../../docs/rfcs/0010-crucible/12-qemu-plugin.md;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;
  openTaskList = builtins.concatStringsSep "," openTaskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/12-qemu-plugin.md" pluginSpec [
      {
        label = "fixed registration order required by spec";
        needle = "Registration MUST proceed in this fixed order";
      }
      {
        label = "failure aborts later registration";
        needle = "no later step runs";
      }
      {
        label = "time control before guest code";
        needle = "guest retires its first architecturally-visible instruction";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/lib.rs" pluginLib [
      {
        label = "registration module exported";
        needle = "pub mod registration;";
      }
      {
        label = "registration sequence exported";
        needle = "PluginRegistrationSequence";
      }
      {
        label = "registration error exported";
        needle = "PluginRegistrationSequenceError";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/time_control.rs" pluginTimeControl [
      {
        label = "canonical order constant";
        needle = "CANONICAL_TIME_CONTROL_REGISTRATION_ORDER";
      }
      {
        label = "parse first";
        needle = "PluginRegistrationStep::ParseArguments";
      }
      {
        label = "handshake after parse";
        needle = "PluginRegistrationStep::ControlHandshake";
      }
      {
        label = "time control before setup";
        needle = "PluginRegistrationStep::RequestTimeControl";
      }
      {
        label = "callbacks before ready ack";
        needle = "PluginRegistrationStep::RegisterCallbacks";
      }
      {
        label = "boot barrier before guest code";
        needle = "PluginRegistrationStep::WaitBootBarrier";
      }
      {
        label = "first visible instruction sentinel";
        needle = "PluginRegistrationStep::FirstVisibleInstruction";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/registration.rs" pluginRegistration [
      {
        label = "registration sequence type";
        needle = "pub struct PluginRegistrationSequence";
      }
      {
        label = "fixed order API";
        needle = "pub const fn fixed_order()";
      }
      {
        label = "parser as first step";
        needle = "pub fn parse_arguments";
      }
      {
        label = "parser delegates to PluginArgs";
        needle = "PluginArgs::parse(raw)";
      }
      {
        label = "successful step recorder";
        needle = "pub fn record_step";
      }
      {
        label = "failure recorder";
        needle = "pub fn fail_step";
      }
      {
        label = "ready token";
        needle = "pub struct PluginRegistrationReady";
      }
      {
        label = "out of order error";
        needle = "OutOfOrderStep";
      }
      {
        label = "step failure error";
        needle = "StepFailed";
      }
      {
        label = "after failure blocker";
        needle = "AfterFailure";
      }
      {
        label = "out-of-order attempts poison sequence";
        needle = "fn poison_out_of_order";
      }
      {
        label = "early handshake blocks parse regression";
        needle = "blocked_step: PluginRegistrationStep::ParseArguments";
      }
      {
        label = "incomplete registration error";
        needle = "IncompleteRegistration";
      }
      {
        label = "canonical time-control validation";
        needle = "TimeControlRegistrationPlan::canonical()";
      }
      {
        label = "happy path test";
        needle = "registration_order_accepts_fixed_happy_path";
      }
      {
        label = "fail-closed parse test";
        needle = "registration_order_parse_step_uses_fail_closed_args";
      }
      {
        label = "handshake before parse rejection";
        needle = "registration_order_rejects_handshake_before_parse";
      }
      {
        label = "later steps blocked after failure";
        needle = "registration_order_aborts_without_later_steps_after_failure";
      }
      {
        label = "boot barrier test";
        needle = "registration_order_requires_boot_barrier_before_first_instruction";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes plugin registration order check";
        needle = "qemuPluginRegistrationOrder = import ./phase2-plugin-registration-order.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase2 plugin-registration-order check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-plugin-registration-order";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
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
          name = "run-plugin-registration-order";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-plugin-registration-order-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              registration_order \
              -- --test-threads=1
            grep -Fxq PASS ${livePluginInstall}/result
            grep -Fxq 'plugin_loaded=rust-control-cdylib' ${livePluginInstall}/result
            grep -Fxq 'setup_ack_ready=true' ${livePluginInstall}/result
            grep -Fxq 'boot_barrier_ceiling_enforced=true' ${livePluginInstall}/result
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
            open_tasks=${openTaskList}
            status=complete
            sequencer=crucible-qemu-plugin::registration
            fixed_order=parse,handshake,time-control,setup,map,arm-wake,callbacks,setup-ack,boot-barrier,first-instruction
            fail_loud=true
            out_of_order_attempts=terminal_failure
            later_steps_after_failure=blocked
            ready_token=PluginRegistrationReady
            live_plugin_install=${livePluginInstall}
            RESULT
          '';
        }
      ];
    }
