{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuPluginHandshake",
  taskIds ? ["T-PLUG-16"],
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
  pluginHandshake = builtins.readFile ../../crates/crucible-qemu-plugin/src/handshake.rs;
  pluginRegistration = import ./_qemu-plugin-registration-source.nix {inherit lib;};
  protocol = builtins.readFile ../../crates/crucible-protocol/src/lib.rs;
  shmem = import ./_crucible-shmem-source.nix {inherit lib;};
  pluginSpec = builtins.readFile ../../docs/rfcs/0010-crucible/12-qemu-plugin.md;
  protocolSpec = builtins.readFile ../../docs/rfcs/0010-crucible/14-protocol.md;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;
  openTaskList = builtins.concatStringsSep "," openTaskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/12-qemu-plugin.md" pluginSpec [
      {
        label = "T-PLUG-16 live completion evidence";
        needle = "Completed by `checks.crucible.phase2.qemuLivePluginInstall`";
      }
      {
        label = "handshake wording";
        needle = "Hello`/`HelloAck";
      }
      {
        label = "slot cross-check wording";
        needle = "authoritative slot is the handshake's";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/14-protocol.md" protocolSpec [
      {
        label = "Hello payload spec";
        needle = "Hello` payload";
      }
      {
        label = "HelloAck payload spec";
        needle = "HelloAck` payload";
      }
      {
        label = "slot bounds spec";
        needle = "slot_index < node_count";
      }
    ]
    ++ failuresFor "crates/crucible-protocol/src/lib.rs" protocol [
      {
        label = "plugin handshake config";
        needle = "pub struct PluginHandshakeConfig";
      }
      {
        label = "plugin stream handshake";
        needle = "pub fn plugin_start_handshake";
      }
      {
        label = "plugin validates HelloAck";
        needle = "plugin_validate_handshake_ack";
      }
      {
        label = "protocol version constant";
        needle = "CONTROL_PROTOCOL_VERSION";
      }
    ]
    ++ failuresFor "crates/crucible-shmem/src/lib.rs" shmem [
      {
        label = "shmem ABI version constant";
        needle = "pub const ABI_VERSION: u32 = 8;";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/args.rs" pluginArgs [
      {
        label = "launch slot accessor";
        needle = "pub const fn slot(&self) -> u32";
      }
      {
        label = "slot bounds helper";
        needle = "validate_slot_index";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/lib.rs" pluginLib [
      {
        label = "handshake module exported";
        needle = "pub mod handshake;";
      }
      {
        label = "handshake token exported";
        needle = "PluginControlHandshake";
      }
      {
        label = "handshake function exported";
        needle = "perform_plugin_handshake";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/handshake.rs" pluginHandshake [
      {
        label = "plugin handshake token";
        needle = "pub struct PluginControlHandshake";
      }
      {
        label = "compiled protocol version";
        needle = "CONTROL_PROTOCOL_VERSION";
      }
      {
        label = "compiled ABI version";
        needle = "ABI_VERSION";
      }
      {
        label = "plugin protocol handshake call";
        needle = "plugin_start_handshake";
      }
      {
        label = "slot validation function";
        needle = "pub fn validate_plugin_handshake";
      }
      {
        label = "launch slot checked";
        needle = "let launch_slot = args.slot()";
      }
      {
        label = "launch slot out of range";
        needle = "LaunchSlotOutOfRange";
      }
      {
        label = "launch slot mismatch";
        needle = "LaunchSlotMismatch";
      }
      {
        label = "happy path test";
        needle = "plugin_handshake_sends_compiled_versions_and_accepts_matching_slot";
      }
      {
        label = "slot mismatch test";
        needle = "plugin_handshake_rejects_launch_slot_disagreement";
      }
      {
        label = "v2 plugin rejects v1 and future host ABI";
        needle = "for host_abi in [1, ABI_VERSION + 1]";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/registration.rs" pluginRegistration [
      {
        label = "registration performs handshake";
        needle = "pub fn perform_control_handshake";
      }
      {
        label = "registration checks handshake order before I/O";
        needle = "ensure_next_step(PluginRegistrationStep::ControlHandshake)";
      }
      {
        label = "registration fails handshake loudly";
        needle = "fail_control_handshake";
      }
      {
        label = "registration handshake success test";
        needle = "registration_order_performs_control_handshake_after_parse";
      }
      {
        label = "registration no I/O before parse test";
        needle = "registration_order_rejects_control_handshake_before_parse_without_io";
      }
      {
        label = "registration slot mismatch test";
        needle = "registration_order_fails_loud_when_handshake_slot_disagrees_with_launch_args";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes plugin handshake check";
        needle = "qemuPluginHandshake = import ./phase2-plugin-handshake.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase2 plugin handshake check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-plugin-handshake";
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
          name = "run-plugin-handshake";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-plugin-handshake-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              handshake_ \
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
            handshake=Hello-HelloAck
            version_check=protocol-and-shmem-abi
            slot_check=HelloAck-slot-equals-launch-slot
            setup_order=handshake-before-shmem
            RESULT
          '';
        }
      ];
    }
