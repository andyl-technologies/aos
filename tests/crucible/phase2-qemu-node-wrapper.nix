{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuNodeWrapper",
  taskIds ? ["T-QEMU-3"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  qemuLib = builtins.readFile ../../crates/crucible-qemu/src/lib.rs;
  nodeLib = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-qemu/src/node.rs;
  };
  qemuSpec = builtins.readFile ../../docs/rfcs/0010-crucible/10-qemu-integration.md;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/10-qemu-integration.md" qemuSpec [
      {
        label = "T-QEMU-3 completion note names QemuNode";
        needle = "Completed as the `QemuNode`";
      }
      {
        label = "T-QEMU-3 completion note names private child ownership";
        needle = "private `std::process::Child` handle";
      }
      {
        label = "T-QEMU-3 completion note names shutdown ladder";
        needle = "runs scheduler shutdown through the existing";
      }
      {
        label = "T-QEMU-3 completion note preserves fd-passing follow-up";
        needle = "die-with-host behavior remain tracked by";
      }
      {
        label = "T-QEMU-3 completion note preserves quantum-flow follow-up";
        needle = "concrete per-quantum shmem implementation";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/lib.rs" qemuLib [
      {
        label = "node module";
        needle = "mod node;";
      }
      {
        label = "node wrapper export";
        needle = "QemuNode";
      }
      {
        label = "node child export";
        needle = "QemuNodeChild";
      }
      {
        label = "node channel bundle export";
        needle = "QemuNodeChannels";
      }
      {
        label = "plugin control trait export";
        needle = "QemuPluginIpcControlChannel";
      }
      {
        label = "shmem hot path trait export";
        needle = "QemuShmemHotPathChannel";
      }
      {
        label = "QMP machine control trait export";
        needle = "QemuQmpMachineControlChannel";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/node.rs" nodeLib [
      {
        label = "QemuNode wrapper";
        needle = "pub struct QemuNode {";
      }
      {
        label = "single owned child field";
        needle = "child: QemuNodeChild,";
      }
      {
        label = "owned child type";
        needle = "pub struct QemuNodeChild";
      }
      {
        label = "owned child stores std child";
        needle = "child: Child,";
      }
      {
        label = "owned child constructor is crate-private";
        needle = "pub(crate) const fn new(child: Child) -> Self";
      }
      {
        label = "three-channel bundle field";
        needle = "channels: QemuNodeChannels,";
      }
      {
        label = "shutdown policy field";
        needle = "shutdown_policy: QemuShutdownPolicy,";
      }
      {
        label = "three-channel bundle type";
        needle = "pub struct QemuNodeChannels";
      }
      {
        label = "plugin IPC control channel field";
        needle = "plugin_control: Box<dyn QemuPluginIpcControlChannel>";
      }
      {
        label = "shared-memory hot path channel field";
        needle = "shmem_hot_path: Box<dyn QemuShmemHotPathChannel>";
      }
      {
        label = "QMP machine control channel field";
        needle = "qmp_machine_control: Box<dyn QemuQmpMachineControlChannel>";
      }
      {
        label = "channel role array size";
        needle = "pub const fn roles(&self) -> [QemuNodeChannelPlane; 3]";
      }
      {
        label = "plugin control trait";
        needle = "pub trait QemuPluginIpcControlChannel";
      }
      {
        label = "shmem hot path trait";
        needle = "pub trait QemuShmemHotPathChannel";
      }
      {
        label = "QMP machine control trait";
        needle = "pub trait QemuQmpMachineControlChannel";
      }
      {
        label = "backend implementation";
        needle = "impl Backend for QemuNode";
      }
      {
        label = "shutdown adapter implementation";
        needle = "impl QemuShutdownTarget for QemuNodeShutdownTarget";
      }
      {
        label = "shutdown ladder invocation";
        needle = "shutdown_qemu_child(&mut target, shutdown_policy)";
      }
      {
        label = "repeated shutdown guard";
        needle = "if child.reaped()";
      }
      {
        label = "repeated shutdown empty report";
        needle = "attempts: Vec::new(),";
      }
      {
        label = "signal path uses owned child";
        needle = "self.child.send_sigterm()";
      }
      {
        label = "reap path uses owned child";
        needle = "self.child.reap(timeout)";
      }
      {
        label = "advance maps to shared memory";
        needle = "self.advance_to_ceiling(horizon.icount)";
      }
      {
        label = "fingerprint maps to shared memory";
        needle = "self.execution_fingerprint().map_err(BackendError::from)";
      }
      {
        label = "input delivery maps to shared memory";
        needle = "self.deliver_frame(input).map_err(BackendError::from)";
      }
      {
        label = "snapshot maps to QMP";
        needle = "self.save_checkpoint().map_err(BackendError::from)";
      }
      {
        label = "restore maps to QMP";
        needle = "self.restore_checkpoint(checkpoint)";
      }
      {
        label = "shutdown maps to node shutdown";
        needle = "self.shutdown_child()";
      }
      {
        label = "shared-memory channel plane";
        needle = "QemuNodeChannelPlane::ShmemHotPath";
      }
      {
        label = "plugin channel plane";
        needle = "QemuNodeChannelPlane::PluginIpcControl";
      }
      {
        label = "QMP channel plane";
        needle = "QemuNodeChannelPlane::QmpMachineControl";
      }
    ]
    ++ forbiddenFor "crates/crucible-qemu/src/node.rs" nodeLib [
      {
        label = "clone implementation for node wrapper";
        needle = "impl<C> Clone for QemuNode";
      }
      {
        label = "non-generic clone implementation for node wrapper";
        needle = "impl Clone for QemuNode";
      }
      {
        label = "generic node child owner";
        needle = "pub struct QemuNode<";
      }
      {
        label = "public child reference escape hatch";
        needle = "pub const fn child(&self)";
      }
      {
        label = "public child/channel decomposition escape hatch";
        needle = "pub fn into_parts";
      }
      {
        label = "node child clone implementation";
        needle = "impl Clone for QemuNodeChild";
      }
      {
        label = "public arbitrary child wrapper";
        needle = "pub const fn new(child: Child) -> Self";
      }
      {
        label = "hot path trait can send QMP quit";
        needle = "QemuShmemHotPathChannel for" + " QemuQmpMachineControlChannel";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/node.rs" nodeLib [
      {
        label = "one child three channel role test";
        needle = "qemu_node_owns_one_child_and_exactly_three_channel_roles";
      }
      {
        label = "three channel role assertion";
        needle = "node.channel_roles(),";
      }
      {
        label = "strict routing test";
        needle = "qemu_node_routes_scheduler_operations_over_strict_channels";
      }
      {
        label = "shmem failure test";
        needle = "qemu_node_reports_shmem_failures_as_backend_rejections";
      }
      {
        label = "QMP failure test";
        needle = "qemu_node_reports_qmp_failures_without_touching_hot_path";
      }
      {
        label = "plugin shutdown failure test";
        needle = "qemu_node_shutdown_continues_to_reap_when_plugin_quit_fails";
      }
      {
        label = "idempotent repeated shutdown test";
        needle = "qemu_node_repeated_shutdown_is_idempotent_after_reap";
      }
      {
        label = "real child process spawn";
        needle = "Command::new(\"sleep\").arg(\"60\").spawn()?";
      }
      {
        label = "child ownership reaped assertion";
        needle = "assert!(node.child_reaped());";
      }
      {
        label = "shutdown report reaped assertion";
        needle = "assert!(report.reaped);";
      }
      {
        label = "shared-memory split start recorded";
        needle = "ChannelCall::ShmemStart";
      }
      {
        label = "bounded async wait recorded";
        needle = "ChannelCall::HostAwait";
      }
      {
        label = "plugin quit recorded";
        needle = "ChannelCall::PluginQuit";
      }
      {
        label = "QMP quit recorded";
        needle = "ChannelCall::QmpQuit";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes qemu node wrapper check";
        needle = "qemuNodeWrapper = import ./phase2-qemu-node-wrapper.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase2 qemu node wrapper check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-node-wrapper";
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
          name = "run-qemu-node-wrapper";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-qemu-node-wrapper-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu \
              --lib \
              node::tests \
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
            related_gates=gate:scheduler-liveness,gate:control-responsive,gate:abi-conformance,gate:layer1-injection
            rust_test=crucible-qemu::node
            owner=one-child-qemu-node-wrapper
            channels=plugin-ipc-control,shmem-hot-path,qmp-machine-control
            hot_path=shared-memory-only
            backend_interface=synchronous
            spawn_fd_passing=covered-by-T-QEMU-7
            per_quantum_flow=deferred-to-T-QEMU-12
            child_process_tool=coreutils-sleep
            RESULT
          '';
        }
      ];
    }
