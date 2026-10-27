{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuPluginHandshake",
  taskIds ? ["T-PLUG-16"],
  openTaskIds ? [],
}: let
  inherit (import ./_test-gate.nix {inherit pkgs lib;}) mkCrucibleTestGate;

  pluginLib = builtins.readFile ../../crates/crucible/crucible-qemu-plugin/src/lib.rs;
  pluginArgs = builtins.readFile ../../crates/crucible/crucible-qemu-plugin/src/args.rs;
  pluginHandshake = builtins.readFile ../../crates/crucible/crucible-qemu-plugin/src/handshake.rs;
  pluginRegistration = import ./_qemu-plugin-registration-source.nix {inherit lib;};
  protocol = builtins.readFile ../../crates/crucible/crucible-qemu-protocol/src/lib.rs;
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
    ++ failuresFor "crates/crucible/crucible-qemu-protocol/src/lib.rs" protocol [
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
    ++ failuresFor "crates/crucible/crucible-qemu-shmem/src/lib.rs" shmem [
      {
        label = "shmem ABI version constant";
        needle = "pub const ABI_VERSION: u32 = 32;";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-qemu-plugin/src/args.rs" pluginArgs [
      {
        label = "launch slot accessor";
        needle = "pub const fn slot(&self) -> u32";
      }
      {
        label = "slot bounds helper";
        needle = "validate_slot_index";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-qemu-plugin/src/lib.rs" pluginLib [
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
    ++ failuresFor "crates/crucible/crucible-qemu-plugin/src/handshake.rs" pluginHandshake [
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
        label = "current plugin rejects an unsupported host ABI";
        needle = "let host_abi = u32::MAX;";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-qemu-plugin/src/registration.rs" pluginRegistration [
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
    mkCrucibleTestGate {
      pname = "crucible-phase2-plugin-handshake";

      runtimeDeps = [pkgs.sqlite];

      buildDeps = [
        pkgs.sed
      ];

      phases = [
        {
          name = "run-plugin-handshake";
          script = ''
            set -eu
            crucible-cargo test \
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
