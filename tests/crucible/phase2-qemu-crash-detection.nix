{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuCrashDetection",
  taskIds ? ["T-QEMU-9"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  qemuLib = builtins.readFile ../../crates/crucible-qemu/src/lib.rs;
  crashLib = builtins.readFile ../../crates/crucible-qemu/src/crash_detection.rs;
  crashTest = builtins.readFile ../../crates/crucible-qemu/tests/crash_detection.rs;
  qemuSpec = builtins.readFile ../../docs/rfcs/0010-crucible/10-qemu-integration.md;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/10-qemu-integration.md" qemuSpec [
      {
        label = "QEMU-32 crash detection requirement";
        needle = "**[QEMU-32]** The host MUST detect an unexpected child exit";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/lib.rs" qemuLib [
      {
        label = "crash detection module";
        needle = "mod crash_detection;";
      }
      {
        label = "crash detector export";
        needle = "QemuCrashDetector";
      }
      {
        label = "node run status export";
        needle = "QemuNodeRunStatus";
      }
      {
        label = "child exit probe export";
        needle = "QemuChildExitProbe";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/crash_detection.rs" crashLib [
      {
        label = "scheduler-facing status enum";
        needle = "pub enum QemuNodeRunStatus";
      }
      {
        label = "infrastructure crashed variant";
        needle = "Crashed(QemuCrashedNodeStatus)";
      }
      {
        label = "intended crash fault variant";
        needle = "IntendedCrashFault(QemuIntendedCrashFaultStatus)";
      }
      {
        label = "crash cause enum";
        needle = "pub enum QemuCrashCause";
      }
      {
        label = "unexpected child exit cause";
        needle = "UnexpectedChildExit(QemuProcessExit)";
      }
      {
        label = "plugin IPC close cause";
        needle = "PluginIpcClosed(QemuChannelFailure)";
      }
      {
        label = "QMP disconnect cause";
        needle = "QmpDisconnected(QemuChannelFailure)";
      }
      {
        label = "process exit status capture";
        needle = "pub struct QemuProcessExit";
      }
      {
        label = "channel failure details";
        needle = "pub struct QemuChannelFailure";
      }
      {
        label = "report and localize policy";
        needle = "ReportAndLocalize";
      }
      {
        label = "no retry on deterministic gate";
        needle = "retry_on_determinism_gate";
      }
      {
        label = "child exit probe trait";
        needle = "pub trait QemuChildExitProbe";
      }
      {
        label = "production child exit probe";
        needle = "impl QemuChildExitProbe for Child";
      }
      {
        label = "plugin frame I/O dependency";
        needle = "use crucible_protocol::FrameIoError";
      }
      {
        label = "detector API";
        needle = "pub struct QemuCrashDetector";
      }
      {
        label = "unexpected child exit detector";
        needle = "pub fn unexpected_child_exit";
      }
      {
        label = "child exit detection hook";
        needle = "pub fn detect_unexpected_child_exit";
      }
      {
        label = "plugin IPC detector";
        needle = "pub fn plugin_ipc_closed";
      }
      {
        label = "plugin IPC result detection hook";
        needle = "pub fn detect_plugin_ipc_result";
      }
      {
        label = "QMP disconnect detector";
        needle = "pub fn qmp_disconnected";
      }
      {
        label = "QMP result detection hook";
        needle = "pub fn detect_qmp_result";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/tests/crash_detection.rs" crashTest [
      {
        label = "unexpected child exit test";
        needle = "unexpected_child_exit_surfaces_typed_crashed_node_status";
      }
      {
        label = "child exit probe hook test";
        needle = "child_exit_probe_surfaces_real_exit_through_detector";
      }
      {
        label = "production child exit probe compile check";
        needle = "std_process_child_is_the_production_exit_probe";
      }
      {
        label = "plugin IPC close test";
        needle = "plugin_ipc_close_is_crash_not_intended_fault";
      }
      {
        label = "plugin IPC frame failure hook test";
        needle = "plugin_ipc_frame_failure_is_detected_as_crashed_node";
      }
      {
        label = "QMP disconnect test";
        needle = "qmp_disconnect_is_crash_not_retried_on_gated_path";
      }
      {
        label = "QMP I/O failure hook test";
        needle = "qmp_io_failure_is_detected_as_crashed_node";
      }
      {
        label = "intended fault distinction test";
        needle = "intended_crash_fault_is_distinct_from_infrastructure_crash";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes qemu crash-detection check";
        needle = "qemuCrashDetection = import ./phase2-qemu-crash-detection.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase2 qemu crash-detection check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-crash-detection";
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
          name = "run-qemu-crash-detection";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-qemu-crash-detection-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu \
              --test crash_detection \
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
            check_scope=task-level
            related_gates=gate:control-responsive,gate:divergence-bisect
            rust_test=crucible-qemu::crash_detection
            crash_causes=unexpected-child-exit,plugin-ipc-close,qmp-disconnect
            host_hooks=std-process-child,plugin-frame-io,qmp-io
            status=typed-crashed-node
            intended_crash_fault=distinct-status
            deterministic_gate_policy=report-and-localize,no-retry
            RESULT
          '';
        }
      ];
    }
