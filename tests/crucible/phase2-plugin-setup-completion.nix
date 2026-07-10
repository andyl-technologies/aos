{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuPluginSetupCompletion",
  taskIds ? [],
  openTaskIds ? ["T-PLUG-17"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  pluginLib = builtins.readFile ../../crates/crucible-qemu-plugin/src/lib.rs;
  pluginSetup = import ./_qemu-plugin-setup-source.nix {inherit lib;};
  pluginRegistration = import ./_qemu-plugin-registration-source.nix {inherit lib;};
  pluginHandshake = builtins.readFile ../../crates/crucible-qemu-plugin/src/handshake.rs;
  protocol = builtins.readFile ../../crates/crucible-protocol/src/lib.rs;
  # The setup-region mmap surface was split out of lib.rs into
  # mapped_setup_region.rs; scan both so the needles survive file moves.
  shmem =
    builtins.readFile ../../crates/crucible-shmem/src/lib.rs
    + builtins.readFile ../../crates/crucible-shmem/src/mapped_setup_region.rs;
  pluginSpec = builtins.readFile ../../docs/rfcs/0010-crucible/12-qemu-plugin.md;
  protocolSpec = builtins.readFile ../../docs/rfcs/0010-crucible/14-protocol.md;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;
  openTaskList = builtins.concatStringsSep "," openTaskIds;

  hasInfix = needle: haystack: let
    needleLen = builtins.stringLength needle;
    haystackLen = builtins.stringLength haystack;
    maxStart = haystackLen - needleLen;
    indexes =
      if needleLen == 0
      then [0]
      else if maxStart < 0
      then []
      else builtins.genList (index: index) (maxStart + 1);
  in
    builtins.any (index:
      builtins.substring index needleLen haystack == needle)
    indexes;

  failuresFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (!(hasInfix requirement.needle content)) [
          "${fileLabel}: missing ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  failures =
    lib.optionals (hasInfix "prepare_setup_completion_for_handshake" pluginSetup) [
      "crates/crucible-qemu-plugin/src/setup.rs: forbidden no-longer-used handshake setup helper: `prepare_setup_completion_for_handshake`"
    ]
    ++ lib.optionals (hasInfix "prepare_setup_completion_inner" pluginSetup) [
      "crates/crucible-qemu-plugin/src/setup.rs: forbidden optional-handshake setup path: `prepare_setup_completion_inner`"
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/12-qemu-plugin.md" pluginSpec [
      {
        label = "T-PLUG-17 remains open until live QEMU callback integration";
        needle = "- [ ] **T-PLUG-17**";
      }
      {
        label = "descriptor setup wording";
        needle = "receive exactly two descriptors via";
      }
      {
        label = "ready ack wording";
        needle = "SetupAck(status)";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/14-protocol.md" protocolSpec [
      {
        label = "Setup descriptor order";
        needle = "fixed order: shmem fd";
      }
      {
        label = "SetupAck ready contract";
        needle = "SetupAck` with `status == 0`";
      }
    ]
    ++ failuresFor "crates/crucible-protocol/src/lib.rs" protocol [
      {
        label = "setup descriptor count";
        needle = "pub const SETUP_DESCRIPTOR_COUNT: usize = 2;";
      }
      {
        label = "received setup token";
        needle = "pub struct ReceivedSetup";
      }
      {
        label = "setup descriptor receiver";
        needle = "pub fn recv_setup_with_descriptors";
      }
      {
        label = "wrong descriptor count refused";
        needle = "WrongDescriptorCount";
      }
      {
        label = "ready setup ack sender";
        needle = "pub fn plugin_send_setup_ack";
      }
    ]
    ++ failuresFor "crates/crucible-shmem/src/lib.rs" shmem [
      {
        label = "exact setup mmap";
        needle = "pub fn mmap_setup_region";
      }
      {
        label = "setup header validator";
        needle = "pub fn validate_setup_region_header";
      }
      {
        label = "ABI marker validation";
        needle = "snapshot.abi_version != ABI_VERSION";
      }
      {
        label = "node count geometry validation";
        needle = "snapshot.node_count != layout.node_count";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/handshake.rs" pluginHandshake [
      {
        label = "handshake slot getter";
        needle = "pub const fn slot_index";
      }
      {
        label = "handshake node count getter";
        needle = "pub const fn node_count";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/lib.rs" pluginLib [
      {
        label = "setup receive exported";
        needle = "receive_setup_with_descriptors";
      }
      {
        label = "setup prepare with handshake exported";
        needle = "prepare_setup_completion";
      }
      {
        label = "setup one-shot exported";
        needle = "receive_and_prepare_setup_completion";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/setup.rs" pluginSetup [
      {
        label = "plugin receives setup descriptors";
        needle = "pub fn receive_setup_with_descriptors";
      }
      {
        label = "protocol descriptor receiver used";
        needle = "recv_setup_with_descriptors(stream.as_raw_fd())";
      }
      {
        label = "one-shot setup completion";
        needle = "pub fn receive_and_prepare_setup_completion";
      }
      {
        label = "handshake-aware setup preparation";
        needle = "pub fn prepare_setup_completion";
      }
      {
        label = "setup preparation requires handshake token";
        needle = "handshake: PluginControlHandshake";
      }
      {
        label = "receive failure sends nonzero ack";
        needle = "send_setup_failure_ack(stream, PluginSetupFailureStage::ReceiveSetup)";
      }
      {
        label = "maps advertised region length";
        needle = "mmap_setup_region(shmem_fd.as_fd(), region_len)";
      }
      {
        label = "validates mapped header";
        needle = "PluginShmemOrdering::validate_setup_header";
      }
      {
        label = "setup slot cross-check helper";
        needle = "fn validate_setup_handshake_slot";
      }
      {
        label = "handshake node count checked";
        needle = "handshake.node_count() != region_node_count";
      }
      {
        label = "handshake slot checked";
        needle = "handshake.slot_index() >= region_node_count";
      }
      {
        label = "wake fd armed";
        needle = "ArmedWakeFd::arm(wake_fd)";
      }
      {
        label = "ready setup ack";
        needle = "plugin_send_setup_ack(writer, SETUP_ACK_STATUS_READY)";
      }
      {
        label = "ready setup ack token";
        needle = "pub struct PluginReadySetupAck";
      }
      {
        label = "ready ack returns ack token";
        needle = "Result<PluginReadySetupAck, PluginSetupError>";
      }
      {
        label = "ready ack requires callback token";
        needle = "_callbacks: &PluginCallbackCapabilities";
      }
      {
        label = "ready ack token constructed after write";
        needle = "Ok(PluginReadySetupAck::acknowledged(owned_callbacks))";
      }
      {
        label = "ready ack production constructor is private";
        needle = "const fn acknowledged(_owned_callbacks: &RequiredOwnedCallbacksRegistered) -> Self";
      }
      {
        label = "failure setup ack";
        needle = "plugin_send_setup_ack(writer, SETUP_ACK_STATUS_SETUP_FAILED)";
      }
      {
        label = "wrong descriptor count failure test";
        needle = "receive_setup_sends_nonzero_ack_when_descriptor_count_is_wrong";
      }
      {
        label = "descriptor receive test";
        needle = "receive_and_prepare_setup_receives_descriptors_and_cross_checks_handshake";
      }
      {
        label = "node-count failure test";
        needle = "prepare_setup_sends_nonzero_ack_when_handshake_node_count_disagrees";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/registration.rs" pluginRegistration [
      {
        label = "registration receives setup descriptors";
        needle = "pub fn receive_setup_with_descriptors";
      }
      {
        label = "receive step checked before I/O";
        needle = "ensure_next_step(PluginRegistrationStep::ReceiveSetup)";
      }
      {
        label = "registration prepares setup";
        needle = "pub fn prepare_setup_completion";
      }
      {
        label = "map step recorded";
        needle = "record_step_unchecked(PluginRegistrationStep::MapSharedMemory)";
      }
      {
        label = "wake step recorded";
        needle = "record_step_unchecked(PluginRegistrationStep::ArmWakeFd)";
      }
      {
        label = "registration sends ready ack";
        needle = "pub fn send_ready_setup_ack";
      }
      {
        label = "registration ready ack carries callback token";
        needle = "callbacks: &PluginCallbackCapabilities";
      }
      {
        label = "ready ack step checked before write";
        needle = "ensure_next_step(PluginRegistrationStep::SendSetupAck)";
      }
      {
        label = "registration passes callback token to setup ack";
        needle = "plugin_send_ready_setup_ack(writer, callbacks, owned_callbacks)";
      }
      {
        label = "registration returns ready ack token";
        needle = "Ok(setup_ack)";
      }
      {
        label = "setup receive failure mapping";
        needle = "fail_setup_receive";
      }
      {
        label = "setup preparation failure mapping";
        needle = "fail_setup_preparation";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes plugin setup-completion check";
        needle = "qemuPluginSetupCompletion = import ./phase2-plugin-setup-completion.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase2 plugin setup-completion check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-plugin-setup-completion";
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
          name = "run-plugin-setup-completion";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-plugin-setup-completion-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              setup \
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
            gates=gate:abi-conformance,gate:control-responsive
            rust_tests=crucible-qemu-plugin::setup
            setup_descriptors=exactly-two-SCM_RIGHTS
            setup_region=mmap-region_len-and-validate-ABI
            setup_cross_check=handshake-slot-and-node-count
            setup_ack=nonzero-on-failure-ready-after-callbacks
            RESULT
          '';
        }
      ];
    }
