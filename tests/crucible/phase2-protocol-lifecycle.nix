{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.protocolLifecycle",
  taskIds ? ["T-PROTO-6"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = import ../../pkgs/tools/crucible/_cargo-deps-hash.nix;
  };

  protocolLib = builtins.readFile ../../crates/crucible-protocol/src/lib.rs;
  lifecycleTest = builtins.readFile ../../crates/crucible-protocol/tests/lifecycle.rs;
  layer1InjectionTest = builtins.readFile ../../crates/crucible-protocol/tests/gate_layer1_injection.rs;
  protocolSpec = builtins.readFile ../../docs/rfcs/0010-crucible/14-protocol.md;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "crates/crucible-protocol/src/lib.rs" protocolLib [
      {
        label = "lifecycle state enum";
        needle = "pub enum ControlLifecycleState";
      }
      {
        label = "lifecycle event enum";
        needle = "pub enum ControlLifecycleEvent";
      }
      {
        label = "Unix stream socket pair connect event";
        needle = "ConnectUnixStreamSocketPair";
      }
      {
        label = "shared-memory run event";
        needle = "RunViaSharedMemory";
      }
      {
        label = "normal lifecycle constant";
        needle = "pub const NORMAL_CONTROL_LIFECYCLE";
      }
      {
        label = "decoded plugin message lifecycle mapping";
        needle = "pub const fn from_plugin_msg";
      }
      {
        label = "decoded host message lifecycle mapping";
        needle = "pub const fn from_host_msg";
      }
      {
        label = "control tag mapping";
        needle = "pub const fn control_tag";
      }
      {
        label = "lifecycle error type";
        needle = "pub enum ControlLifecycleError";
      }
      {
        label = "control frame during run error";
        needle = "ControlFrameDuringRun";
      }
      {
        label = "lifecycle validator";
        needle = "pub struct ControlLifecycle";
      }
      {
        label = "lifecycle-aware stream wrapper";
        needle = "pub struct ControlLifecycleStream";
      }
      {
        label = "wired host handshake";
        needle = "pub fn host_accept_handshake";
      }
      {
        label = "wired plugin handshake";
        needle = "pub fn plugin_start_handshake";
      }
      {
        label = "wired setup descriptor send";
        needle = "pub fn host_send_setup_with_descriptors";
      }
      {
        label = "wired setup descriptor receive";
        needle = "pub fn plugin_recv_setup_with_descriptors";
      }
      {
        label = "wired host setup ack";
        needle = "pub fn host_accept_setup_ack";
      }
      {
        label = "wired run entry";
        needle = "pub fn enter_run_via_shared_memory";
      }
      {
        label = "wired host run frame reader";
        needle = "pub fn host_read_run_control_frame";
      }
      {
        label = "wired plugin run frame reader";
        needle = "pub fn plugin_read_run_control_frame";
      }
      {
        label = "wired quit sender";
        needle = "pub fn host_send_quit";
      }
      {
        label = "any-direction frame tag decoder";
        needle = "pub fn control_frame_tag";
      }
      {
        label = "trace validator";
        needle = "pub fn validate_control_lifecycle_trace";
      }
      {
        label = "complete lifecycle validator";
        needle = "pub fn validate_complete_control_lifecycle";
      }
      {
        label = "run silence rejects control tags";
        needle = "event.control_tag()";
      }
      {
        label = "plugin run reader rejects non-Quit control tag";
        needle = "if tag != ControlTag::Quit";
      }
      {
        label = "run readers precheck running state";
        needle = "ensure_running_via_shared_memory(self.lifecycle.state())?";
      }
      {
        label = "plugin validates HelloAck before lifecycle advance";
        needle = "let negotiated = plugin_validate_handshake_ack(message.clone(), config)?;\n        self.lifecycle";
      }
      {
        label = "wired setup send observes before sendmsg";
        needle = "lifecycle.observe(ControlLifecycleEvent::HostSetup)?;\n        send_setup_with_descriptors";
      }
      {
        label = "Quit exits run phase";
        needle = "ControlLifecycleEvent::HostQuit => Ok(ControlLifecycleState::QuitSent)";
      }
      {
        label = "nonzero SetupAck never enters run";
        needle = "NonReadySetupAck";
      }
      {
        label = "runtime data-plane contract remains shmem";
        needle = "runtime_data_plane: RuntimeDataPlane::SharedMemory";
      }
      {
        label = "control channel silent contract";
        needle = "control_channel_silent_between_setup_ack_and_quit: true";
      }
    ]
    ++ failuresFor "crates/crucible-protocol/tests/lifecycle.rs" lifecycleTest [
      {
        label = "normal lifecycle test";
        needle = "normal_lifecycle_connects_handshakes_runs_via_shmem_and_quits";
      }
      {
        label = "decoded message event mapping test";
        needle = "lifecycle_events_are_derived_from_decoded_control_messages";
      }
      {
        label = "run silence test";
        needle = "run_phase_accepts_only_shmem_until_quit";
      }
      {
        label = "wired Unix socket lifecycle test";
        needle = "lifecycle_stream_wires_real_frames_setup_descriptors_and_run_silence";
      }
      {
        label = "real Unix stream pair";
        needle = "UnixStream::pair()";
      }
      {
        label = "real descriptor setup send";
        needle = "host.host_send_setup_with_descriptors";
      }
      {
        label = "real descriptor setup receive";
        needle = "recv_setup_with_descriptors(plugin_socket.as_raw_fd())";
      }
      {
        label = "real run frame rejection";
        needle = "host.host_read_run_control_frame()";
      }
      {
        label = "invalid HelloAck regression";
        needle = "lifecycle_stream_does_not_advance_after_invalid_hello_ack";
      }
      {
        label = "role-specific run reader regression";
        needle = "lifecycle_stream_splits_host_faults_from_plugin_quit_acceptance";
      }
      {
        label = "plugin run reader accepts host Quit";
        needle = "plugin.plugin_read_run_control_frame()";
      }
      {
        label = "real quit send";
        needle = "host.host_send_quit()";
      }
      {
        label = "control frame during run assertion";
        needle = "ControlLifecycleError::ControlFrameDuringRun";
      }
      {
        label = "non-ready setup ack test";
        needle = "lifecycle_rejects_non_ready_setup_ack_before_run";
      }
      {
        label = "out of order trace test";
        needle = "lifecycle_rejects_out_of_order_and_incomplete_traces";
      }
      {
        label = "shared-memory runtime assertion";
        needle = "RuntimeDataPlane::SharedMemory";
      }
      {
        label = "Quit allowed after run silence";
        needle = "ControlLifecycleEvent::HostQuit";
      }
    ]
    ++ failuresFor "crates/crucible-protocol/tests/gate_layer1_injection.rs" layer1InjectionTest [
      {
        label = "control channel silent hot-path gate test";
        needle = "gate_layer1_injection_control_protocol_is_silent_on_hot_path";
      }
      {
        label = "runtime data plane is shmem";
        needle = "RuntimeDataPlane::SharedMemory";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/14-protocol.md" protocolSpec [
      {
        label = "T-PROTO-6 live completion evidence";
        needle = "Completed by `checks.crucible.phase2.qemuLivePluginInstall`";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes protocol lifecycle check";
        needle = "protocolLifecycle = import ./phase2-protocol-lifecycle.nix";
      }
      {
        label = "canonical ABI conformance gate is implemented";
        needle = "abiConformance = import ./phase2-abi-conformance.nix";
      }
      {
        label = "canonical ABI conformance task list";
        needle = "taskIds = [\"T-HARN-17\" \"T-API-11\" \"T-API-12\" \"T-PAT-8\"]";
      }
    ];
in
  if failures != []
  then throw "crucible phase2 protocol lifecycle check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-protocol-lifecycle";
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
          name = "run-protocol-lifecycle";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-protocol-lifecycle-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-protocol \
              --test lifecycle \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-protocol-lifecycle-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-protocol \
              --test gate_layer1_injection \
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
            gates=gate:abi-conformance,gate:control-responsive
            rust_tests=crucible-protocol::lifecycle,crucible-protocol::gate_layer1_injection
            lifecycle=connect,Hello,HelloAck,Setup,SetupAck,run-via-shmem,Quit
            run_control_channel=silent-until-Quit
            transport=connected-Unix-stream-socket-pair
            RESULT
          '';
        }
      ];
    }
