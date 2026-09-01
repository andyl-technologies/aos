{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuAsyncDriver",
  taskIds ? ["T-QEMU-14"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  qemuLib = builtins.readFile ../../crates/crucible-qemu/src/lib.rs;
  asyncDriver = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-qemu/src/async_driver.rs;
  };
  crashDetection = builtins.readFile ../../crates/crucible-qemu/src/crash_detection.rs;
  nodeLib = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-qemu/src/node.rs;
  };
  quantumLib = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-qemu/src/quantum.rs;
  };
  qmpLib = builtins.readFile ../../crates/crucible-qemu/src/qmp.rs;
  qmpTest = builtins.readFile ../../crates/crucible-qemu/tests/qmp.rs;
  qemuSpec = builtins.readFile ../../docs/rfcs/0010-crucible/10-qemu-integration.md;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  forbiddenHostTimingApis = [
    "Instant::now"
    "SystemTime::now"
    "std::time::Instant"
    "std::time::SystemTime"
    "thread::sleep"
    "park_timeout"
    "clock_gettime"
    "gettimeofday"
    "CLOCK_REALTIME"
    "CLOCK_MONOTONIC"
    "thread_rng"
    "rand::random"
    "tokio::select"
    "select!"
  ];

  failures =
    failuresFor "docs/rfcs/0010-crucible/10-qemu-integration.md" qemuSpec [
      {
        label = "completion note names bounded async driver";
        needle = "bounded async driver";
      }
      {
        label = "completion note preserves shmem-only hot path";
        needle = "no per-quantum QMP or plugin-IPC";
      }
      {
        label = "completion note names timeout crash escalation";
        needle = "timeouts are converted into typed crashed-node";
      }
      {
        label = "completion note names concrete node path";
        needle = "QemuNode::advance_to_ceiling";
      }
      {
        label = "completion note names QMP timeout stream";
        needle = "timeout-capable stream";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/lib.rs" qemuLib [
      {
        label = "async driver module";
        needle = "mod async_driver;";
      }
      {
        label = "async driver exports";
        needle = "QemuAsyncDriverPolicy";
      }
      {
        label = "bounded step export";
        needle = "run_bounded_qemu_node_step";
      }
      {
        label = "bounded await timeout export";
        needle = "QemuBoundedAwaitTimeout";
      }
      {
        label = "node pending quantum export";
        needle = "QemuNodePendingQuantum";
      }
      {
        label = "QMP timeout policy export";
        needle = "QmpIoTimeoutPolicy";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/crash_detection.rs" crashDetection [
      {
        label = "bounded await timeout crash cause";
        needle = "BoundedAwaitTimeout";
      }
      {
        label = "bounded await timeout detector";
        needle = "pub fn bounded_await_timeout";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/async_driver.rs" asyncDriver [
      {
        label = "module docs";
        needle = "Bounded host-I/O bridge";
      }
      {
        label = "timeout policy";
        needle = "pub struct QemuAsyncDriverPolicy";
      }
      {
        label = "nonzero timeout validation";
        needle = "UnboundedAwait";
      }
      {
        label = "host runtime trait";
        needle = "pub trait QemuHostIoRuntime";
      }
      {
        label = "control-plane yield";
        needle = "yield_to_control_plane";
      }
      {
        label = "bounded child await";
        needle = "fn await_child";
      }
      {
        label = "node step target trait";
        needle = "pub trait QemuAsyncNodeStepTarget";
      }
      {
        label = "crash escalation trait";
        needle = "pub trait QemuAsyncCrashEscalationTarget";
      }
      {
        label = "split quantum start";
        needle = "fn start_quantum";
      }
      {
        label = "split quantum finish";
        needle = "fn finish_quantum";
      }
      {
        label = "shutdown after crash";
        needle = "fn shutdown_after_crash";
      }
      {
        label = "bounded node step";
        needle = "pub fn run_bounded_qemu_node_step";
      }
      {
        label = "advance-completion wait";
        needle = "QemuAsyncWait::AdvanceCompletion";
      }
      {
        label = "timeout produces crashed node";
        needle = "bounded_await_timeout";
      }
      {
        label = "shutdown on timeout";
        needle = "ShutdownAfterCrash";
      }
      {
        label = "lifecycle bounded await helper";
        needle = "pub fn await_bounded_lifecycle_event";
      }
      {
        label = "lifecycle report";
        needle = "pub struct QemuAsyncLifecycleAwaitReport";
      }
      {
        label = "lifecycle timeout shutdown";
        needle = "QemuAsyncLifecycleAwaitOutcome::Crashed";
      }
      {
        label = "shmem-only hot path assertion";
        needle = "assert_async_driver_quantum_hot_path_is_shmem_only";
      }
      {
        label = "forbidden QMP plane test";
        needle = "QemuQuantumOperation::QmpCommand";
      }
      {
        label = "forbidden plugin IPC plane test";
        needle = "QemuQuantumOperation::PluginIpcControlFrame";
      }
      {
        label = "successful quantum test";
        needle = "async_driver_completes_one_quantum_with_bounded_wait_and_yields";
      }
      {
        label = "timeout crash test";
        needle = "async_driver_timeout_surfaces_crash_and_escalates_shutdown";
      }
      {
        label = "zero timeout test";
        needle = "async_driver_rejects_zero_timeout_policy";
      }
      {
        label = "lifecycle timeout mapping test";
        needle = "async_driver_lifecycle_awaits_use_policy_timeouts";
      }
      {
        label = "all lifecycle timeout classes test";
        needle = "async_driver_lifecycle_timeouts_crash_and_shutdown_for_each_wait_class";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/node.rs" nodeLib [
      {
        label = "node owns async policy";
        needle = "async_policy: QemuAsyncDriverPolicy";
      }
      {
        label = "node owns crash detector";
        needle = "crash_detector: QemuCrashDetector";
      }
      {
        label = "node owns host runtime";
        needle = "host_io_runtime: Box<dyn QemuHostIoRuntime>";
      }
      {
        label = "node advance uses bounded driver";
        needle = "run_bounded_qemu_node_step";
      }
      {
        label = "node target adapter";
        needle = "struct QemuNodeAsyncStepTarget";
      }
      {
        label = "node split start";
        needle = "fn start_quantum";
      }
      {
        label = "node split finish";
        needle = "fn finish_quantum";
      }
      {
        label = "node timeout crash test";
        needle = "qemu_node_timeout_reports_crash_and_runs_shutdown";
      }
      {
        label = "node QMP timeout crash test";
        needle = "qemu_node_qmp_timeout_reports_crash_and_runs_shutdown";
      }
      {
        label = "QMP channel timeout classification";
        needle = "source.bounded_timeout()";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/quantum.rs" quantumLib [
      {
        label = "quantum channel start adapter";
        needle = "QemuQuantumShmemHotPath::start_quantum";
      }
      {
        label = "quantum channel non-consuming completion adapter";
        needle = "QemuQuantumShmemHotPath::poll_quantum";
      }
      {
        label = "quantum pending token adapter";
        needle = "QemuNodePendingQuantum::new";
      }
      {
        label = "quantum completion adapter";
        needle = "QemuAsyncQuantumCompletion::from";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/qmp.rs" qmpLib [
      {
        label = "QMP timeout stream trait";
        needle = "pub trait QmpTimeoutStream";
      }
      {
        label = "QMP read timeout hook";
        needle = "set_qmp_read_timeout";
      }
      {
        label = "QMP write timeout hook";
        needle = "set_qmp_write_timeout";
      }
      {
        label = "QMP I/O timeout policy";
        needle = "pub struct QmpIoTimeoutPolicy";
      }
      {
        label = "QMP timeout policy validation";
        needle = "UnboundedTimeout";
      }
      {
        label = "QMP total command deadline";
        needle = "struct QmpOperationDeadline";
      }
      {
        label = "QMP remaining deadline check";
        needle = "deadline.remaining";
      }
      {
        label = "QMP async event bound";
        needle = "AsyncEventLimitExceeded";
      }
      {
        label = "QMP line byte bound";
        needle = "LineTooLong";
      }
      {
        label = "QMP timeout channel classification";
        needle = "impl From<QmpError> for QemuNodeChannelError";
      }
      {
        label = "QMP connect with policies";
        needle = "connect_with_policies";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/tests/qmp.rs" qmpTest [
      {
        label = "QMP explicit timeout test";
        needle = "qmp_client_installs_explicit_stream_timeouts";
      }
      {
        label = "QMP unbounded timeout rejection test";
        needle = "qmp_client_rejects_unbounded_stream_timeouts";
      }
      {
        label = "QMP event flood bound test";
        needle = "qmp_client_bounds_async_event_floods";
      }
      {
        label = "QMP partial line bound test";
        needle = "qmp_client_bounds_partial_line_progress";
      }
      {
        label = "QMP timeout channel classification test";
        needle = "qmp_timeout_errors_classify_node_channel_timeouts";
      }
    ]
    ++ forbiddenFor "crates/crucible-qemu/src/async_driver.rs" asyncDriver (
      map (api: {
        label = "host-time, random, or nondeterministic select API";
        needle = api;
      })
      forbiddenHostTimingApis
    )
    ++ forbiddenFor "crates/crucible-qemu/src/async_driver.rs" asyncDriver [
      {
        label = "production unwrap";
        needle = ".unwrap()";
      }
      {
        label = "production expect";
        needle = ".expect(";
      }
      {
        label = "hard-coded host shell";
        needle = "/bin/sh";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes qemu async driver check";
        needle = "qemuAsyncDriver = import ./phase2-qemu-async-driver.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase2 qemu async-driver check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-async-driver";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.rust
        pkgs.sed
      ];

      cargoDeps = cargoDeps;

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
          name = "run-qemu-async-driver";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-qemu-async-driver-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu \
              --lib \
              async_driver::tests \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-qemu-async-driver-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu \
              --lib \
              node::tests \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-qemu-async-driver-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu \
              --test qmp \
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
            attr_path=${attrPath}
            tasks=${taskList}
            qemu_39=sync-node-step-to-host-io-runtime
            qemu_40=one-quantum-bounded-await-yield-between-steps
            qemu_41=advance-hot-path-shmem-only
            qemu_42=no-host-time-random-or-select-in-ordering-path
            timeout_crash=bounded-await-timeout-escalates-shutdown
            lifecycle_awaits=handshake-qmp-process-event-bounded
            qmp_io=read-write-timeouts-required
            node_path=advance-to-ceiling-uses-bounded-driver
            rust_tests=crucible-qemu::async_driver::tests,node::tests,qmp
            RESULT
          '';
        }
      ];

      meta = {
        description = "Crucible Phase 2 QEMU bounded async driver gate";
      };
    }
