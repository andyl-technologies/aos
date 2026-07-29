{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuPluginTimeControl",
  taskIds ? ["T-PLUG-4"],
  openTaskIds ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  pluginLib = builtins.readFile ../../crates/crucible-qemu-plugin/src/lib.rs;
  pluginArgs = builtins.readFile ../../crates/crucible-qemu-plugin/src/args.rs;
  pluginDeadline = builtins.readFile ../../crates/crucible-qemu-plugin/src/deadline.rs;
  pluginRegistration = import ./_qemu-plugin-registration-source.nix {inherit lib;};
  pluginSetup = import ./_qemu-plugin-setup-source.nix {inherit lib;};
  pluginTimeControl = import ./_qemu-plugin-time-control-source.nix {inherit lib;};
  pluginSpec = builtins.readFile ../../docs/rfcs/0010-crucible/12-qemu-plugin.md;
  qemuPatchSpec = builtins.readFile ../../docs/rfcs/0010-crucible/11-qemu-patches.md;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;
  openTaskList = builtins.concatStringsSep "," openTaskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;


  pluginSources = [
    {
      label = "crates/crucible-qemu-plugin/src/lib.rs";
      content = pluginLib;
    }
    {
      label = "crates/crucible-qemu-plugin/src/args.rs";
      content = pluginArgs;
    }
    {
      label = "crates/crucible-qemu-plugin/src/deadline.rs";
      content = pluginDeadline;
    }
    {
      label = "crates/crucible-qemu-plugin/src/registration.rs";
      content = pluginRegistration;
    }
    {
      label = "crates/crucible-qemu-plugin/src/setup.rs";
      content = pluginSetup;
    }
    {
      label = "crates/crucible-qemu-plugin/src/time_control.rs";
      content = pluginTimeControl;
    }
  ];

  forbiddenTimePathApis = [
    "Instant::now"
    "SystemTime::now"
    "std::time::Instant"
    "std::time::SystemTime"
    "clock_gettime"
    "gettimeofday"
    "CLOCK_REALTIME"
    "CLOCK_MONOTONIC"
    "thread_rng"
    "rand::random"
  ];

  hostTimeFailures =
    lib.concatMap (
      source:
        lib.concatMap (
          api:
            lib.optionals (hasInfix api source.content) [
              "${source.label}: forbidden host-time or entropy API on plugin time path: `${api}`"
            ]
        )
        forbiddenTimePathApis
    )
    pluginSources;

  copyableRegistrationReadyFailures =
    lib.optionals (hasInfix "#[derive(Clone, Copy" pluginRegistration) [
      "crates/crucible-qemu-plugin/src/registration.rs: PluginRegistrationReady must remain non-Copy so one completed registration cannot mint multiple clock owners"
    ];

  clonableRegistrationSequenceFailures =
    lib.optionals (hasInfix "#[derive(Clone, Debug, Default" pluginRegistration) [
      "crates/crucible-qemu-plugin/src/registration.rs: PluginRegistrationSequence must remain non-Clone so completed registration cannot be duplicated before finish"
    ];

  failures =
    failuresFor "docs/rfcs/0010-crucible/12-qemu-plugin.md" pluginSpec [
      {
        label = "T-PLUG-4 completed by the live plugin quantum gate";
        needle = "- [x] **T-PLUG-4**";
      }
      {
        label = "T-PLUG-4 live completion evidence";
        needle = "Completed by `checks.crucible.phase2.qemuLivePluginQuantum`";
      }
      {
        label = "plugin clock ownership";
        needle = "The plugin MUST own virtual-time control";
      }
      {
        label = "no host wall clock";
        needle = "The plugin MUST NOT read host wall-clock";
      }
      {
        label = "no host monotonic clock";
        needle = "host monotonic time";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/11-qemu-patches.md" qemuPatchSpec [
      {
        label = "time-control request symbol spec";
        needle = "qemu_plugin_request_time_control";
      }
      {
        label = "queued virtual-time advance symbol spec";
        needle = "qemu_plugin_advance_time_ns";
      }
      {
        label = "time-advance completion registration symbol spec";
        needle = "qemu_plugin_register_time_advance_cb";
      }
      {
        label = "time-control predicate spec";
        needle = "qemu_plugin_has_time_control";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/lib.rs" pluginLib [
      {
        label = "PluginVirtualClock exported";
        needle = "PluginVirtualClock";
      }
      {
        label = "PluginTimeControlOwnership exported";
        needle = "PluginTimeControlOwnership";
      }
      {
        label = "PluginClockError exported";
        needle = "PluginClockError";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/registration.rs" pluginRegistration [
      {
        label = "finish consumes registration sequence";
        needle = "pub fn finish(self)";
      }
      {
        label = "ready token consumption test";
        needle = "registration_ready_token_consumes_sequence";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/time_control.rs" pluginTimeControl [
      {
        label = "request time-control symbol";
        needle = "pub const QEMU_PLUGIN_REQUEST_TIME_CONTROL_SYMBOL: &str = \"qemu_plugin_request_time_control\";";
      }
      {
        label = "queued advance symbol";
        needle = "pub const QEMU_PLUGIN_ADVANCE_TIME_NS_SYMBOL: &str =";
      }
      {
        label = "time-control predicate symbol";
        needle = "pub const QEMU_PLUGIN_HAS_TIME_CONTROL_SYMBOL: &str = \"qemu_plugin_has_time_control\";";
      }
      {
        label = "time-control ownership token";
        needle = "pub struct PluginTimeControlOwnership";
      }
      {
        label = "non-forgeable ownership field";
        needle = "_private: ()";
      }
      {
        label = "registration-gated ownership constructor";
        needle = "pub const fn acquired_after_registration";
      }
      {
        label = "ownership requires registration token";
        needle = "crate::PluginRegistrationReady";
      }
      {
        label = "scheduler ceiling type";
        needle = "pub struct SchedulerCeiling";
      }
      {
        label = "authorized idle jump type";
        needle = "pub struct SchedulerAuthorizedIdleJump";
      }
      {
        label = "virtual clock type";
        needle = "pub struct PluginVirtualClock";
      }
      {
        label = "guest instruction advance";
        needle = "pub fn advance_guest_instructions";
      }
      {
        label = "idle jump authorization";
        needle = "pub fn authorize_idle_jump";
      }
      {
        label = "authorized idle jump advance";
        needle = "pub fn advance_authorized_idle_jump";
      }
      {
        label = "guest instruction advance source";
        needle = "PluginClockAdvanceSource::GuestInstructions";
      }
      {
        label = "scheduler idle jump advance source";
        needle = "PluginClockAdvanceSource::SchedulerAuthorizedIdleJump";
      }
      {
        label = "ceiling rejection";
        needle = "BeyondSchedulerCeiling";
      }
      {
        label = "stale idle authorization rejection";
        needle = "StaleIdleJumpAuthorization";
      }
      {
        label = "checked virtual time projection";
        needle = "fn project_virtual_ns";
      }
      {
        label = "guest instruction test";
        needle = "time_control_clock_advances_by_guest_instructions_up_to_ceiling";
      }
      {
        label = "past-ceiling rejection test";
        needle = "time_control_clock_rejects_guest_instruction_advance_past_ceiling";
      }
      {
        label = "authorized idle jump test";
        needle = "time_control_clock_advances_by_scheduler_authorized_idle_jump";
      }
      {
        label = "stale idle jump test";
        needle = "time_control_clock_rejects_stale_idle_jump_authorization";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes plugin time-control check";
        needle = "qemuPluginTimeControl = import ./phase2-plugin-time-control.nix";
      }
    ]
    ++ hostTimeFailures
    ++ copyableRegistrationReadyFailures
    ++ clonableRegistrationSequenceFailures;
in
  if failures != []
  then throw "crucible phase2 plugin-time-control check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-plugin-time-control";
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
          name = "run-plugin-time-control";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-plugin-time-control-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              time_control \
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
            open_tasks=${openTaskList}
            status=partial
            owner=PluginTimeControlOwnership
            request_symbol=qemu_plugin_request_time_control
            advance_symbol=qemu_plugin_advance_time_ns
            completion_symbol=qemu_plugin_register_time_advance_cb
            predicate_symbol=qemu_plugin_has_time_control
            advance_sources=guest-instructions,scheduler-authorized-idle-jump
            scheduler_ceiling_enforced=true
            registration_sequence_finish=consuming
            registration_ready_token=non-copy
            host_time_apis_on_plugin_time_path=forbidden
            RESULT
          '';
        }
      ];
    }
